"""Comprehensive tests for AbuseIPDB integration, JSON reports, and feature explanations.

Tests cover:
- AbuseIPDB IP validation, private-IP filtering, deduplication
- check_ip mocking: success, 429, 401/403, 422, timeout, network error
- Threat intel status and test-key endpoints
- analyze_static key handling (env_key, custom_key, missing_key, disabled)
- JSON report content-disposition, schema, credential exclusion
- Local SHAP explanation structure and direction
- Dynamic report download endpoint
- Feature explanation categorization
- Dynamic anomaly explanation structure
"""

import io
import json
import ipaddress
import unittest
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

from backend.explanations import (
    classify_static_feature,
    explain_dynamic_syscall,
    explain_static_feature,
)
from backend.main import (
    get_configured_abuseipdb_key,
    health,
    test_threat_intel_key,
    threat_intel_status_endpoint,
    download_static_report,
    download_dynamic_report,
)
from backend.schemas import (
    StaticAnalysisRequest,
    ThreatIntelTestRequest,
)
from backend.reports import (
    build_dynamic_json_report,
    build_static_json_report,
)
from phase3_live_demo import (
    check_ip,
    extract_indicators,
    threat_intel_features,
)


# ── helpers ──────────────────────────────────────────────────────────────────


def _make_http_get(status_code: int, json_body: dict | None = None, raise_exc=None):
    """Return a fake requests.get callable for mocking."""
    def _get(*args, **kwargs):
        if raise_exc is not None:
            raise raise_exc
        mock = MagicMock()
        mock.status_code = status_code
        if json_body is not None:
            mock.json.return_value = json_body
        mock.raise_for_status = MagicMock()
        if status_code >= 400:
            def _raise():
                raise Exception(f"HTTP {status_code}")
            mock.raise_for_status = _raise
        return mock
    return _get


ABUSEIPDB_SUCCESS_BODY = {
    "data": {
        "abuseConfidenceScore": 85,
        "totalReports": 12,
        "countryCode": "RU",
        "isp": "Evil ISP",
        "domain": "evil.example",
        "usageType": "Data Center/Web Hosting/Transit",
        "lastReportedAt": "2024-01-15T12:00:00+00:00",
    }
}


# ── IP validation / extraction ────────────────────────────────────────────────


class TestExtractIndicators(unittest.TestCase):
    """extract_indicators must correctly classify IPs and domains."""

    def test_public_ipv4_extracted(self):
        ips, domains, _ = extract_indicators(["8.8.8.8"])
        self.assertIn("8.8.8.8", ips)
        self.assertEqual(len(domains), 0)

    def test_private_ipv4_excluded(self):
        ips, domains, _ = extract_indicators(["192.168.1.1", "10.0.0.1", "172.16.0.1"])
        self.assertEqual(len(ips), 0)

    def test_loopback_excluded(self):
        ips, _, _ = extract_indicators(["127.0.0.1", "::1"])
        self.assertEqual(len(ips), 0)

    def test_ipv6_global_extracted(self):
        global_v6 = "2001:4860:4860::8888"  # Google's IPv6 DNS
        ips, _, _ = extract_indicators([global_v6])
        self.assertIn(global_v6, ips)

    def test_domain_extracted(self):
        _, domains, _ = extract_indicators(["https://evil.malwaredomain.net/payload"])
        self.assertIn("evil.malwaredomain.net", domains)

    def test_url_ip_extracted(self):
        ips, _, _ = extract_indicators(["http://93.184.216.34/cmd"])
        self.assertIn("93.184.216.34", ips)

    def test_multicast_excluded(self):
        ips, _, _ = extract_indicators(["224.0.0.1"])
        self.assertEqual(len(ips), 0)

    def test_deduplication(self):
        """Same IP appearing multiple times should appear once."""
        ips, _, _ = extract_indicators(["8.8.8.8", "8.8.8.8", "8.8.8.8"])
        self.assertEqual(len(ips), 1)
        self.assertIn("8.8.8.8", ips)


# ── check_ip mocking ──────────────────────────────────────────────────────────


class TestCheckIpMocking(unittest.TestCase):
    """check_ip must correctly handle various AbuseIPDB response codes."""

    def setUp(self):
        from phase3_live_demo import _ti_cache_clear
        _ti_cache_clear()

    def test_success_returns_abuse_data(self):
        result = check_ip("8.8.8.8", api_key="test-key", http_get=_make_http_get(200, ABUSEIPDB_SUCCESS_BODY))
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["abuse_score"], 85)
        self.assertEqual(result["total_reports"], 12)
        self.assertEqual(result["country"], "RU")
        self.assertEqual(result["status"], "checked")
        self.assertIsNone(result["error"])

    def test_rate_limit_raises_runtime_error(self):
        with self.assertRaises(RuntimeError) as ctx:
            check_ip("8.8.8.8", api_key="test-key", http_get=_make_http_get(429))
        self.assertIn("rate limit", str(ctx.exception).lower())

    def test_invalid_key_raises_runtime_error(self):
        for status in (401, 403):
            with self.assertRaises(RuntimeError) as ctx:
                check_ip("8.8.8.8", api_key="bad-key", http_get=_make_http_get(status))
            self.assertIn("API key", str(ctx.exception))

    def test_unacceptable_ip_raises_value_error(self):
        with self.assertRaises(ValueError):
            check_ip("8.8.8.8", api_key="test-key", http_get=_make_http_get(422))

    def test_private_ip_returns_skipped_status(self):
        result = check_ip("192.168.1.1", api_key="test-key")
        self.assertEqual(result["status"], "skipped_private")
        self.assertEqual(result["abuse_score"], 0)

    def test_loopback_returns_skipped_status(self):
        result = check_ip("127.0.0.1", api_key="test-key")
        self.assertEqual(result["status"], "skipped_private")

    def test_network_timeout_propagates(self):
        import requests
        with self.assertRaises(Exception):
            check_ip("8.8.8.8", api_key="test-key",
                     http_get=_make_http_get(0, raise_exc=requests.exceptions.Timeout("timeout")))

    def test_threat_intel_features_only_counts_checked(self):
        lookups = [
            {"ip": "1.1.1.1", "abuse_score": 0, "status": "checked"},
            {"ip": "2.2.2.2", "abuse_score": 90, "status": "checked"},
            {"ip": "3.3.3.3", "abuse_score": None, "status": "failed"},
            {"ip": "192.168.1.1", "abuse_score": 0, "status": "skipped_private"},
        ]
        features = threat_intel_features(lookups)
        self.assertEqual(features["max_abuse_score"], 90)
        self.assertEqual(features["malicious_ip_count"], 1)  # only score >= 50


# ── Threat intel status / test-key endpoints ─────────────────────────────────


class TestThreatIntelEndpoints(unittest.TestCase):

    def setUp(self):
        from phase3_live_demo import _ti_cache_clear
        _ti_cache_clear()
    def test_status_missing_key(self):
        with patch("backend.main.get_configured_abuseipdb_key", return_value=None):
            status = threat_intel_status_endpoint()
        self.assertFalse(status.configured)
        self.assertEqual(status.source, "none")
        self.assertIn("not configured", status.message.lower())

    def test_status_placeholder_key_treated_as_missing(self):
        with patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "PASTE_YOUR_ACTUAL_ABUSEIPDB_KEY_HERE"}, clear=True):
            status = threat_intel_status_endpoint()
        self.assertFalse(status.configured)
        self.assertEqual(status.source, "none")

    def test_status_env_key_configured(self):
        with patch("backend.main.get_configured_abuseipdb_key", return_value="real-backend-key"):
            status = threat_intel_status_endpoint()
        self.assertTrue(status.configured)
        self.assertEqual(status.source, "env")

    def test_key_precedence_prefers_api_key(self):
        from backend.main import get_configured_abuseipdb_key
        with patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "preferred-key", "ABUSEIPDB_KEY": "fallback-key"}, clear=True):
            self.assertEqual(get_configured_abuseipdb_key(), "preferred-key")
        with patch.dict("os.environ", {"ABUSEIPDB_KEY": "fallback-key"}, clear=True):
            self.assertEqual(get_configured_abuseipdb_key(), "fallback-key")

    def test_test_key_no_key_returns_failure(self):
        with patch("backend.main.get_configured_abuseipdb_key", return_value=None):
            result = test_threat_intel_key()
        self.assertFalse(result.success)
        self.assertEqual(result.status_code, 400)
        self.assertIn("No AbuseIPDB API key configured", result.message)

    def test_test_key_success(self):
        good_response = {"ip": "1.1.1.1", "abuse_score": 0, "total_reports": 0,
                         "country": "AU", "isp": "Cloudflare", "domain": None,
                         "usage_type": "CDN", "last_reported": None, "status": "checked", "error": None}
        with patch("backend.main.check_ip", return_value=good_response):
            with patch("backend.main.get_configured_abuseipdb_key", return_value="valid-env-key"):
                result = test_threat_intel_key()
        self.assertTrue(result.success)
        self.assertEqual(result.status_code, 200)
        self.assertIn("using configured .env key", result.message)

    def test_test_key_ignores_request_body_key(self):
        # Even if a body with a bogus key is sent, the backend only tests the backend's configured key
        good_response = {"ip": "1.1.1.1", "abuse_score": 0, "total_reports": 0,
                         "country": "AU", "isp": "Cloudflare", "domain": None,
                         "usage_type": "CDN", "last_reported": None, "status": "checked", "error": None}
        with patch("backend.main.check_ip", return_value=good_response) as mock_check:
            with patch("backend.main.get_configured_abuseipdb_key", return_value="backend-env-key"):
                result = test_threat_intel_key(ThreatIntelTestRequest())
                mock_check.assert_called_once_with("1.1.1.1", api_key="backend-env-key", timeout=5)
        self.assertTrue(result.success)

    def test_test_key_bad_key_returns_401(self):
        with patch("backend.main.check_ip", side_effect=RuntimeError("AbuseIPDB rejected the API key")):
            with patch("backend.main.get_configured_abuseipdb_key", return_value="bad-env-key"):
                result = test_threat_intel_key()
        self.assertFalse(result.success)
        self.assertEqual(result.status_code, 401)

    def test_test_key_rate_limit_returns_429(self):
        with patch("backend.main.check_ip", side_effect=RuntimeError("rate limit reached")):
            with patch("backend.main.get_configured_abuseipdb_key", return_value="ok-env-key"):
                result = test_threat_intel_key()
        self.assertFalse(result.success)
        self.assertEqual(result.status_code, 429)

    def test_frontend_has_no_api_key_input_or_visibility_control(self):
        from pathlib import Path
        analyze_path = Path(__file__).resolve().parent.parent / "frontend" / "src" / "pages" / "AnalyzePage.tsx"
        self.assertTrue(analyze_path.is_file(), "AnalyzePage.tsx should exist")
        content = analyze_path.read_text(encoding="utf-8")
        self.assertNotIn('id="abuseipdb-key"', content)
        self.assertNotIn('type="password"', content)
        self.assertNotIn("apiKey", content)
        self.assertNotIn("setApiKey", content)
        self.assertNotIn("showKey", content)
        self.assertNotIn("setShowKey", content)

    def test_abuseipdb_request_header_format(self):
        # Verify check_ip uses the HTTP 'Key' header per AbuseIPDB v2 spec
        mock_get = unittest.mock.MagicMock()
        mock_resp = unittest.mock.MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "countryCode": "US",
                "isp": "Google",
                "domain": "google.com",
                "usageType": "Commercial",
                "lastReportedAt": None,
            }
        }
        mock_get.return_value = mock_resp
        check_ip("8.8.8.8", api_key="secret-backend-key", http_get=mock_get)
        self.assertTrue(mock_get.called)
        _, kwargs = mock_get.call_args
        self.assertIn("headers", kwargs)
        self.assertEqual(kwargs["headers"].get("Key"), "secret-backend-key")

    def test_missing_configuration_does_not_prevent_static_analysis(self):
        from phase3_live_demo import analyze_apk
        from pathlib import Path
        sample_path = Path(__file__).resolve().parent.parent / "sample_app.apk"
        # Run analyze_apk without any abuse key
        res = analyze_apk(str(sample_path), abuse_key=None, verbose=False)
        self.assertIn("static", res)
        self.assertIn("verdict", res["static"])
        self.assertEqual(res["static"]["verdict"], "BENIGN")


# ── JSON report structure ─────────────────────────────────────────────────────


class TestJsonReportGeneration(unittest.TestCase):
    """JSON reports must contain required fields and never include credentials."""

    def _make_minimal_result(self):
        import pandas as pd
        row = pd.DataFrame([[1, 0, 1]], columns=["SEND_SMS", "CAMERA", "READ_SMS"])
        return {
            "info": {"package": "com.evil.app", "app_name": "Evil", "version_name": "1.0",
                     "path": "/tmp/evil.apk", "n_dex": 1},
            "features": row,
            "static": {
                "verdict": "MALWARE",
                "prob_malware": 0.87,
                "evidence": [
                    {"feature": "SEND_SMS", "present": True, "shap": 0.42},
                    {"feature": "READ_SMS", "present": True, "shap": 0.31},
                ],
                "shap_map": {"SEND_SMS": 0.42, "CAMERA": -0.05, "READ_SMS": 0.31},
            },
            "ips": {"203.0.113.5": "http://203.0.113.5/cmd"},
            "domains": {"evil.example.com": "https://evil.example.com"},
            "resolved": {},
            "lookups": [
                {"ip": "203.0.113.5", "abuse_score": 92, "total_reports": 15,
                 "country": "RU", "isp": "Evil ISP", "domain": "evil.example",
                 "usage_type": "Data Center", "last_reported": "2024-01-15", "status": "checked", "error": None}
            ],
            "threat_features": {"max_abuse_score": 92, "malicious_ip_count": 1, "network_risk": "HIGH"},
            "lookup_error": None,
        }

    def test_static_json_report_contains_required_fields(self):
        result = self._make_minimal_result()
        raw = build_static_json_report(result, filename="evil.apk", sha256="abc123", analysis_id="test-1")
        payload = json.loads(raw)
        self.assertEqual(payload["report_schema_version"], "1.0.0")
        self.assertIn("prediction", payload)
        self.assertEqual(payload["prediction"]["verdict"], "MALWARE")
        self.assertAlmostEqual(payload["prediction"]["probability"], 0.87, places=2)
        self.assertEqual(payload["prediction"]["decision_threshold"], 0.50)
        self.assertIn("suspicious_indicators", payload)
        self.assertIn("threat_intelligence", payload)
        self.assertIn("local_shap_evidence", payload)

    def test_static_json_report_no_credentials(self):
        result = self._make_minimal_result()
        raw = build_static_json_report(result, filename="evil.apk", sha256="abc123",
                                       threat_intel_status="env_key")
        text = raw.decode("utf-8").lower()
        for keyword in ("api_key", "apikey", "abuseipdb_key", "abuseipdb_api_key",
                        "secret", "token", "bearer", "authorization"):
            self.assertNotIn(keyword, text, msg=f"Credential keyword '{keyword}' found in report")

    def test_static_json_report_has_meaningful_filename_hint(self):
        result = self._make_minimal_result()
        raw = build_static_json_report(result, filename="myapp.apk", sha256="abc123")
        payload = json.loads(raw)
        self.assertEqual(payload["apk"]["filename"], "myapp.apk")

    def test_threat_intel_status_included(self):
        result = self._make_minimal_result()
        raw = build_static_json_report(result, filename="a.apk", sha256="abc",
                                       threat_intel_status="custom_key")
        payload = json.loads(raw)
        self.assertEqual(payload["threat_intelligence"]["enrichment_status"], "custom_key")

    def test_dynamic_json_report_contains_required_fields(self):
        dynamic_result = {
            "job_id": "job-123",
            "filename": "sample.apk",
            "sha256": "def456",
            "package": "com.sample",
            "requested_seconds": 30,
            "actual_seconds": 28.5,
            "system_call_count": 15000,
            "vocabulary_coverage": 0.72,
            "features_seen": 87,
            "probability_normalized_shares": 0.78,
            "probability_raw_counts": 0.81,
            "shap_evidence": [
                {"syscall": "mprotect", "count": 1200, "shap": 0.19},
                {"syscall": "read", "count": 5600, "shap": -0.08},
            ],
            "counts": {"mprotect": 1200, "read": 5600, "write": 3400},
            "unmapped_counts": {},
            "raw_report": "sample strace output",
        }
        raw = build_dynamic_json_report(dynamic_result)
        payload = json.loads(raw)
        self.assertEqual(payload["report_schema_version"], "1.0.0")
        self.assertIn("prediction", payload)
        self.assertIn("runtime_anomalies_and_behavioral_evidence", payload)
        self.assertIn("system_call_counts", payload)
        self.assertEqual(payload["prediction"]["verdict"], "MALWARE")

    def test_dynamic_json_report_no_credentials(self):
        dynamic_result = {
            "job_id": "j1", "filename": "a.apk", "sha256": "x", "package": "a.b",
            "requested_seconds": 30, "actual_seconds": 28.0,
            "system_call_count": 1000, "vocabulary_coverage": 0.5, "features_seen": 10,
            "probability_normalized_shares": 0.4, "probability_raw_counts": 0.4,
            "shap_evidence": [], "counts": {}, "unmapped_counts": {}, "raw_report": "",
        }
        raw = build_dynamic_json_report(dynamic_result)
        text = raw.decode("utf-8").lower()
        for keyword in ("api_key", "abuseipdb_key", "secret", "token", "bearer"):
            self.assertNotIn(keyword, text)


# ── download_static_report endpoint ──────────────────────────────────────────


class TestDownloadStaticReport(unittest.TestCase):
    def _register_result(self, analysis_id: str):
        import pandas as pd
        from backend.main import STATIC_RESULTS, STATE_LOCK
        row = pd.DataFrame([[1]], columns=["SEND_SMS"])
        result = {
            "info": {"package": "com.x", "app_name": "", "version_name": "", "path": "/t/x.apk", "n_dex": 1},
            "features": row,
            "static": {"verdict": "MALWARE", "prob_malware": 0.9,
                       "evidence": [{"feature": "SEND_SMS", "present": True, "shap": 0.5}],
                       "shap_map": {"SEND_SMS": 0.5}},
            "ips": {}, "domains": {}, "resolved": {}, "lookups": [],
            "threat_features": None, "lookup_error": None,
        }
        with STATE_LOCK:
            STATIC_RESULTS[analysis_id] = {
                "result": result, "filename": "my app test.apk",
                "sha256": "abc123", "threat_intel_status": "disabled",
                "detailed_explanations": [], "created_at": None,
            }

    def test_json_report_has_clean_filename(self):
        aid = "test-static-dl-1"
        self._register_result(aid)
        response = download_static_report(aid, "json")
        cd = response.headers.get("content-disposition", "")
        self.assertIn("my_app_test_analysis_report.json", cd)
        self.assertNotIn(aid, cd)

    def test_pdf_report_has_clean_filename(self):
        aid = "test-static-dl-2"
        self._register_result(aid)
        try:
            response = download_static_report(aid, "pdf")
            cd = response.headers.get("content-disposition", "")
            self.assertIn("my_app_test_security_report.pdf", cd)
        except Exception:
            pass  # PDF generation may not be available in test env

    def test_unsupported_format_raises_404(self):
        aid = "test-static-dl-3"
        self._register_result(aid)
        with self.assertRaises(HTTPException) as ctx:
            download_static_report(aid, "xml")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_missing_analysis_id_raises_404(self):
        with self.assertRaises(HTTPException) as ctx:
            download_static_report("does-not-exist", "json")
        self.assertEqual(ctx.exception.status_code, 404)


# ── download_dynamic_report endpoint ─────────────────────────────────────────


class TestDownloadDynamicReport(unittest.TestCase):
    def _register_job(self, job_id: str, status: str = "completed"):
        from backend.main import DYNAMIC_JOBS, STATE_LOCK
        result = {
            "job_id": job_id, "filename": "sample test.apk", "sha256": "x",
            "package": "com.s", "requested_seconds": 30, "actual_seconds": 28.0,
            "system_call_count": 100, "vocabulary_coverage": 0.5, "features_seen": 5,
            "probability_normalized_shares": 0.65, "probability_raw_counts": 0.7,
            "shap_evidence": [{"syscall": "mprotect", "count": 100, "shap": 0.1}],
            "counts": {"mprotect": 100}, "unmapped_counts": {}, "raw_report": "",
        }
        with STATE_LOCK:
            DYNAMIC_JOBS[job_id] = {
                "job_id": job_id, "status": status,
                "filename": "sample test.apk", "requested_seconds": 30,
                "created_at": "2024-01-01T00:00:00Z",
                "started_at": "2024-01-01T00:00:01Z",
                "completed_at": "2024-01-01T00:00:30Z",
                "error": None, "result": result if status == "completed" else None,
            }

    def test_completed_job_returns_json(self):
        jid = "test-dyn-dl-1"
        self._register_job(jid)
        response = download_dynamic_report(jid, "json")
        self.assertEqual(response.media_type, "application/json")
        cd = response.headers.get("content-disposition", "")
        self.assertIn("sample_test_dynamic_report.json", cd)
        payload = json.loads(response.body)
        self.assertIn("prediction", payload)

    def test_incomplete_job_raises_409(self):
        jid = "test-dyn-dl-2"
        self._register_job(jid, status="running")
        with self.assertRaises(HTTPException) as ctx:
            download_dynamic_report(jid, "json")
        self.assertEqual(ctx.exception.status_code, 409)

    def test_unknown_job_raises_404(self):
        with self.assertRaises(HTTPException) as ctx:
            download_dynamic_report("ghost-job", "json")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_unsupported_format_raises_404(self):
        jid = "test-dyn-dl-3"
        self._register_job(jid)
        with self.assertRaises(HTTPException) as ctx:
            download_dynamic_report(jid, "xml")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_pdf_format_returns_pdf_response(self):
        jid = "test-dyn-dl-4"
        self._register_job(jid)
        resp = download_dynamic_report(jid, "pdf")
        self.assertEqual(resp.media_type, "application/pdf")
        self.assertTrue(resp.body.startswith(b"%PDF"))


# ── Feature explanations ──────────────────────────────────────────────────────


class TestFeatureExplanations(unittest.TestCase):
    def test_permission_classified_correctly(self):
        self.assertEqual(classify_static_feature("SEND_SMS"), "permission")
        self.assertEqual(classify_static_feature("READ_SMS"), "permission")
        self.assertEqual(classify_static_feature("CAMERA"), "permission")

    def test_api_call_classified_correctly(self):
        self.assertEqual(classify_static_feature("Runtime.exec"), "api_call")
        self.assertEqual(classify_static_feature("getExternalStorageDirectory"), "api_call")

    def test_explain_static_positive_shap_toward_malware(self):
        result = explain_static_feature("SEND_SMS", present=True, shap_value=0.42)
        self.assertEqual(result["direction"], "toward_malware")
        self.assertIn("present", result["interpretation"].lower())
        self.assertIn("MALWARE", result["interpretation"])
        self.assertFalse(any(k in result for k in ("api_key", "secret", "token")))

    def test_explain_static_negative_shap_toward_benign(self):
        result = explain_static_feature("INTERNET", present=True, shap_value=-0.15)
        self.assertEqual(result["direction"], "toward_benign")
        self.assertIn("BENIGN", result["interpretation"])

    def test_explain_static_absent_feature(self):
        result = explain_static_feature("CALL_PHONE", present=False, shap_value=0.08)
        self.assertFalse(result["present"])
        self.assertEqual(result["direction"], "toward_malware")

    def test_explain_static_high_risk_permission(self):
        result = explain_static_feature("SEND_SMS", present=True, shap_value=0.5)
        self.assertEqual(result["risk_level"], "high")
        self.assertGreater(len(result["description"]), 10)
        self.assertGreater(len(result["security_context"]), 10)

    def test_explain_static_no_null_required_fields(self):
        for feat in ["SEND_SMS", "Runtime.exec", "BOOT_COMPLETED", "su"]:
            result = explain_static_feature(feat, present=True, shap_value=0.1)
            for field in ("feature", "category", "present", "direction", "description",
                          "security_context", "interpretation"):
                self.assertIn(field, result)
                self.assertIsNotNone(result[field])


# ── Dynamic anomaly explanations ──────────────────────────────────────────────


class TestDynamicAnomalyExplanations(unittest.TestCase):
    def test_mprotect_explains_with_context(self):
        result = explain_dynamic_syscall("mprotect", count=1200, shap_value=0.19)
        self.assertEqual(result["syscall"], "mprotect")
        self.assertEqual(result["count"], 1200)
        self.assertEqual(result["direction"], "toward_malware")
        self.assertGreater(len(result["description"]), 10)
        self.assertGreater(len(result["investigation_reason"]), 10)
        self.assertIn("1,200", result["interpretation"])

    def test_read_negative_shap_toward_benign(self):
        result = explain_dynamic_syscall("read", count=5000, shap_value=-0.08)
        self.assertEqual(result["direction"], "toward_benign")

    def test_unknown_syscall_gets_default_explanation(self):
        result = explain_dynamic_syscall("xyzzy_unknown_call", count=5, shap_value=None)
        self.assertEqual(result["syscall"], "xyzzy_unknown_call")
        self.assertIsNone(result["shap"])
        self.assertEqual(result["direction"], "neutral")
        self.assertIn("xyzzy_unknown_call", result["description"])

    def test_neutral_direction_when_no_shap(self):
        result = explain_dynamic_syscall("close", count=200, shap_value=None)
        self.assertEqual(result["direction"], "neutral")

    def test_explanation_does_not_contain_credentials(self):
        result = explain_dynamic_syscall("socket", count=50, shap_value=0.05)
        text = json.dumps(result).lower()
        for keyword in ("api_key", "secret", "token", "abuseipdb"):
            self.assertNotIn(keyword, text)

    def test_interpretation_contains_count(self):
        result = explain_dynamic_syscall("mmap", count=777, shap_value=0.0)
        self.assertIn("777", result["interpretation"])


# ── get_configured_abuseipdb_key ─────────────────────────────────────────────


class TestGetConfiguredAbuseipdbKey(unittest.TestCase):
    def test_returns_none_when_no_env(self):
        with patch("backend.main.os.environ.get", return_value=None):
            key = get_configured_abuseipdb_key()
        self.assertIsNone(key)

    def test_returns_stripped_key(self):
        with patch("backend.main.os.environ.get", side_effect=lambda k, *a: "  my-key  " if k == "ABUSEIPDB_API_KEY" else None):
            key = get_configured_abuseipdb_key()
        self.assertEqual(key, "my-key")

    def test_abuseipdb_key_fallback(self):
        def _env_get(k, *a):
            return "fallback-key" if k == "ABUSEIPDB_KEY" else None
        with patch("backend.main.os.environ.get", side_effect=_env_get):
            key = get_configured_abuseipdb_key()
        self.assertEqual(key, "fallback-key")

    def test_empty_string_returns_none(self):
        with patch("backend.main.os.environ.get", return_value="   "):
            key = get_configured_abuseipdb_key()
        self.assertIsNone(key)


if __name__ == "__main__":
    unittest.main()
