"""Unit tests for phase3_live_demo new features:
1. URLhaus host lookup (LISTED, NOT_LISTED, UNAVAILABLE on failure or wrong key)
2. Domain label Shannon entropy with offline tldextract (google.com, xk92mz01a.biz, asdf098zxcv.top)
3. MITRE ATT&CK candidates (rule-based, labelled candidate, no mapping for su/chmod/bare IPs)
"""
import math
import os
import unittest
from unittest.mock import MagicMock

from phase3_live_demo import (
    ENTROPY_THRESHOLD,
    calculate_domain_entropy,
    check_urlhaus_host,
    extract_attack_candidates,
)
from backend.reports import static_report_payload


class TestUrlhausHostLookup(unittest.TestCase):
    """Test URLhaus lookup behavior and error handling."""

    def test_failed_request_returns_unavailable(self):
        """Failed network request (timeout, connection error) must return UNAVAILABLE."""
        def mock_post_fail(url, data=None, headers=None, timeout=None):
            raise TimeoutError("Connection timed out after 10 seconds")

        res = check_urlhaus_host("malicious.example.com", auth_key="dummy_key", http_post=mock_post_fail)
        self.assertEqual(res["status"], "UNAVAILABLE")
        self.assertIn("error", res)
        # Verify key is never exposed
        self.assertNotIn("dummy_key", str(res))

    def test_http_500_returns_unavailable(self):
        """HTTP error must NEVER be reported as clean or not listed."""
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_post = MagicMock(return_value=mock_resp)

        res = check_urlhaus_host("example.com", auth_key="dummy_key", http_post=mock_post)
        self.assertEqual(res["status"], "UNAVAILABLE")
        self.assertIn("HTTP 500", res["error"])

    def test_wrong_key_returns_unavailable_http401(self):
        """Wrong key returning HTTP 401 must return UNAVAILABLE."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_post = MagicMock(return_value=mock_resp)

        res = check_urlhaus_host("example.com", auth_key="wrong_key", http_post=mock_post)
        self.assertEqual(res["status"], "UNAVAILABLE")
        self.assertIn("HTTP 401", res["error"])

    def test_wrong_key_returns_unavailable_no_auth_status(self):
        """Query status 'no_auth' must return UNAVAILABLE."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "no_auth"}
        mock_post = MagicMock(return_value=mock_resp)

        res = check_urlhaus_host("example.com", auth_key="invalid_key", http_post=mock_post)
        self.assertEqual(res["status"], "UNAVAILABLE")
        self.assertIn("no_auth", res["error"])

    def test_missing_key_returns_unavailable(self):
        """If no Auth-Key is provided or present in environment, return UNAVAILABLE."""
        old_env = os.environ.pop("ABUSECH_AUTH_KEY", None)
        try:
            res = check_urlhaus_host("example.com", auth_key=None)
            self.assertEqual(res["status"], "UNAVAILABLE")
            self.assertIn("No Auth-Key", res["error"])
        finally:
            if old_env is not None:
                os.environ["ABUSECH_AUTH_KEY"] = old_env

    def test_success_listed_returns_url_count(self):
        """query_status == 'ok' returns LISTED with url_count."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "url_count": 7,
            "urlhaus_reference": "https://urlhaus.abuse.ch/host/evil.com/",
        }
        mock_post = MagicMock(return_value=mock_resp)

        res = check_urlhaus_host("evil.com", auth_key="valid_key", http_post=mock_post)
        self.assertEqual(res["status"], "LISTED")
        self.assertEqual(res["url_count"], 7)
        self.assertEqual(res["urlhaus_reference"], "https://urlhaus.abuse.ch/host/evil.com/")
        self.assertNotIn("valid_key", str(res))

    def test_success_not_listed(self):
        """query_status == 'no_results' returns NOT_LISTED with url_count 0."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "no_results"
        }
        mock_post = MagicMock(return_value=mock_resp)

        res = check_urlhaus_host("benign.com", auth_key="valid_key", http_post=mock_post)
        self.assertEqual(res["status"], "NOT_LISTED")
        self.assertEqual(res["url_count"], 0)

    def test_not_listed_appears_only_on_no_results(self):
        """NOT_LISTED must appear ONLY when query_status == 'no_results'.
        Any error, unexpected status, or failure must NEVER report NOT_LISTED.
        """
        for bad_status in ["error", "invalid_host", "no_auth", "unknown", ""]:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"query_status": bad_status}
            mock_post = MagicMock(return_value=mock_resp)

            res = check_urlhaus_host("host.com", auth_key="valid_key", http_post=mock_post)
            self.assertEqual(res["status"], "UNAVAILABLE")
            self.assertNotEqual(res["status"], "NOT_LISTED")
            self.assertIn("error", res)

    def test_when_not_queried_outputs_one_entry_per_host_with_unavailable_status_never_empty(self):
        """When URLhaus was not queried (no key) or a lookup failed, output one entry per host
        with status UNAVAILABLE and a reason, never an empty list.
        """
        from phase3_live_demo import analyze_apk

        # Ensure no key in env
        old_env = os.environ.pop("ABUSECH_AUTH_KEY", None)
        try:
            res = analyze_apk("sample_app.apk", abuse_key=None, urlhaus_key=None, verbose=False)
            urlhaus = res.get("urlhaus", [])
            # sample_app.apk has embedded domains (github.com, listen.googlelabs.com)
            self.assertGreater(len(urlhaus), 0, "urlhaus list must never be empty when hosts exist")
            for entry in urlhaus:
                self.assertEqual(entry["status"], "UNAVAILABLE")
                self.assertIn("error", entry)
                self.assertTrue(len(entry["error"]) > 0, "Must provide a clear reason for UNAVAILABLE status")
                self.assertIn("host", entry)
        finally:
            if old_env is not None:
                os.environ["ABUSECH_AUTH_KEY"] = old_env


class TestDomainShannonEntropy(unittest.TestCase):
    """Test Shannon entropy calculation of registrable domain label using offline tldextract."""

    def test_google_not_flagged(self):
        """google.com -> label 'google', entropy ~1.92, not flagged."""
        res = calculate_domain_entropy("google.com")
        self.assertEqual(res["label"], "google")
        self.assertAlmostEqual(res["entropy"], 1.92, delta=0.01)
        self.assertFalse(res["flag"])

    def test_xk92mz01a_not_flagged(self):
        """xk92mz01a.biz -> label 'xk92mz01a', entropy ~3.17, not flagged."""
        res = calculate_domain_entropy("xk92mz01a.biz")
        self.assertEqual(res["label"], "xk92mz01a")
        self.assertAlmostEqual(res["entropy"], 3.17, delta=0.01)
        self.assertFalse(res["flag"])

    def test_asdf098zxcv_flagged(self):
        """asdf098zxcv.top -> label 'asdf098zxcv', entropy ~3.46, flagged (entropy > 3.4)."""
        res = calculate_domain_entropy("asdf098zxcv.top")
        self.assertEqual(res["label"], "asdf098zxcv")
        self.assertAlmostEqual(res["entropy"], 3.46, delta=0.01)
        self.assertTrue(res["flag"])

    def test_theoretical_bound_fewer_than_11_distinct_cannot_exceed_3_4(self):
        """Mathematical theorem: H <= log2(k). For k <= 10, H <= log2(10) ≈ 3.3219 < 3.4."""
        self.assertLess(math.log2(10), ENTROPY_THRESHOLD)
        # Even with maximum possible randomness across 10 distinct characters:
        test_10 = "0123456789"
        res = calculate_domain_entropy(f"{test_10}.com")
        self.assertLess(res["entropy"], ENTROPY_THRESHOLD)
        self.assertFalse(res["flag"])


class TestAttackCandidates(unittest.TestCase):
    """Test rule-based MITRE ATT&CK candidate mapping."""

    def test_send_sms_permission_mapped(self):
        info = {"permissions": {"SEND_SMS"}, "strings": []}
        candidates = extract_attack_candidates(info)
        t_ids = [c["technique_id"] for c in candidates]
        self.assertIn("T1582", t_ids)
        c = next(x for x in candidates if x["technique_id"] == "T1582")
        self.assertEqual(c["technique_name"], "SMS Control")
        self.assertEqual(c["label"], "candidate")
        self.assertIn("Declared permission: SEND_SMS", c["evidence"])

    def test_receive_sms_permission_mapped(self):
        info = {"permissions": {"RECEIVE_SMS"}, "strings": []}
        candidates = extract_attack_candidates(info)
        t_ids = [c["technique_id"] for c in candidates]
        self.assertIn("T1582", t_ids)
        c = next(x for x in candidates if x["technique_id"] == "T1582")
        self.assertIn("Declared permission: RECEIVE_SMS", c["evidence"])

    def test_read_sms_permission_mapped(self):
        info = {"permissions": {"READ_SMS"}, "strings": []}
        candidates = extract_attack_candidates(info)
        t_ids = [c["technique_id"] for c in candidates]
        self.assertIn("T1636.004", t_ids)
        c = next(x for x in candidates if x["technique_id"] == "T1636.004")
        self.assertEqual(c["technique_name"], "Protected User Data: SMS Messages")
        self.assertEqual(c["label"], "candidate")
        self.assertIn("Declared permission: READ_SMS", c["evidence"])

    def test_dexclassloader_reference_mapped(self):
        info = {
            "permissions": set(),
            "strings": ["Ldalvik/system/DexClassLoader;"],
            "type_descs": set(),
            "method_refs": set(),
        }
        candidates = extract_attack_candidates(info)
        t_ids = [c["technique_id"] for c in candidates]
        self.assertIn("T1407", t_ids)
        c = next(x for x in candidates if x["technique_id"] == "T1407")
        self.assertEqual(c["technique_name"], "Download New Code at Runtime")
        self.assertEqual(c["label"], "candidate")
        self.assertIn("DexClassLoader", c["evidence"])

    def test_entropy_flagged_domain_mapped(self):
        domain_entropy = [
            {"domain": "google.com", "label": "google", "entropy": 1.918, "flag": False},
            {"domain": "asdf098zxcv.top", "label": "asdf098zxcv", "entropy": 3.459, "flag": True},
        ]
        candidates = extract_attack_candidates({"permissions": set(), "strings": []}, domain_entropy=domain_entropy)
        t_ids = [c["technique_id"] for c in candidates]
        self.assertIn("T1637.001", t_ids)
        c = next(x for x in candidates if x["technique_id"] == "T1637.001")
        self.assertEqual(c["technique_name"], "Dynamic Resolution: DGA")
        self.assertEqual(c["label"], "candidate")
        self.assertIn("asdf098zxcv.top", c["evidence"])

    def test_negative_constraints_no_su_chmod_bare_ip_mapping(self):
        """CRITICAL: Do NOT map su/chmod strings or a bare embedded IP to any technique."""
        info = {
            "permissions": set(),
            "strings": ["su", "/system/bin/su", "chmod 777", "chmod", "203.0.113.1"],
            "type_descs": set(),
            "method_refs": set(),
        }
        candidates = extract_attack_candidates(info)
        self.assertEqual(len(candidates), 0, msg="su/chmod/bare IP must NOT be mapped to any technique")


class TestReportsIntegration(unittest.TestCase):
    """Test JSON report payload contains the three new candidate features."""

    def test_report_payload_includes_new_features(self):
        result = {
            "info": {"package": "com.example.app"},
            "static": {"prob_malware": 0.85, "verdict": "MALWARE", "evidence": []},
            "features": None,
            "ips": {"93.184.216.34": "example string"},
            "domains": {"asdf098zxcv.top": "example ctx"},
            "lookups": [],
            "threat_features": {"network_risk": "LOW", "max_abuse_score": 0},
            "urlhaus": [{"status": "NOT_LISTED", "host": "asdf098zxcv.top", "url_count": 0}],
            "domain_entropy": [{"domain": "asdf098zxcv.top", "label": "asdf098zxcv", "entropy": 3.459, "flag": True}],
            "attack_candidates": [{
                "technique_id": "T1637.001",
                "technique_name": "Dynamic Resolution: DGA",
                "label": "candidate",
                "type": "heuristic / candidate",
                "evidence": "High entropy domain asdf098zxcv.top",
            }],
        }
        payload = static_report_payload(result)
        self.assertIn("domain_entropy_analysis", payload)
        self.assertEqual(payload["domain_entropy_analysis"]["threshold"], 3.4)
        self.assertIn("attack_candidates", payload)
        self.assertEqual(payload["attack_candidates"][0]["technique_id"], "T1637.001")
        self.assertIn("urlhaus_lookups", payload["threat_intelligence"])




class TestGuardUnknownVerdict(unittest.TestCase):
    """Test guard returning verdict UNKNOWN (not BENIGN) with reason for 0 DEX or 0 active features."""

    def setUp(self):
        from phase3_live_demo import load_static_model, STATIC_MODEL_PATH
        self.bundle = load_static_model(STATIC_MODEL_PATH)

    def test_zero_features_returns_unknown_verdict(self):
        """If all 215 features are zero, verdict MUST be UNKNOWN (not BENIGN), with reason."""
        import pandas as pd
        import numpy as np
        from phase3_live_demo import predict_static

        row = pd.DataFrame([np.zeros(len(self.bundle["feature_names"]), dtype=int)],
                           columns=self.bundle["feature_names"])
        res = predict_static(row, self.bundle, top_n=5)
        self.assertEqual(res["verdict"], "UNKNOWN")
        self.assertNotEqual(res["verdict"], "BENIGN")
        self.assertIsNotNone(res.get("verdict_reason"))
        self.assertTrue(len(res["verdict_reason"]) > 0)
        self.assertIn("zero", res["verdict_reason"].lower())
        self.assertEqual(res["n_active_features"], 0)

    def test_no_dex_returns_unknown_verdict(self):
        """If APK has n_dex == 0, verdict MUST be UNKNOWN (not BENIGN), with reason."""
        import pandas as pd
        import numpy as np
        from phase3_live_demo import predict_static

        # Even if a manifest feature somehow fired, n_dex == 0 forces UNKNOWN
        row = pd.DataFrame([np.zeros(len(self.bundle["feature_names"]), dtype=int)],
                           columns=self.bundle["feature_names"])
        res = predict_static(row, self.bundle, top_n=5, n_dex=0)
        self.assertEqual(res["verdict"], "UNKNOWN")
        self.assertNotEqual(res["verdict"], "BENIGN")
        self.assertIsNotNone(res.get("verdict_reason"))
        self.assertIn("no compiled dex", res["verdict_reason"].lower())
        self.assertEqual(res["n_dex"], 0)

    def test_active_features_returns_standard_verdict(self):
        """If features are active, verdict is standard MALWARE or BENIGN."""
        import pandas as pd
        import numpy as np
        from phase3_live_demo import predict_static

        row = pd.DataFrame([np.zeros(len(self.bundle["feature_names"]), dtype=int)],
                           columns=self.bundle["feature_names"])
        row.iloc[0, 0] = 1
        res = predict_static(row, self.bundle, top_n=5, n_dex=1)
        self.assertIn(res["verdict"], ("BENIGN", "MALWARE"))
        self.assertIsNone(res["verdict_reason"])
        self.assertEqual(res["n_active_features"], 1)
        self.assertEqual(res["n_dex"], 1)


class TestUrlhausNeverEmptyAndUnavailableDetails(unittest.TestCase):
    """Test URLhaus output always returns one UNAVAILABLE entry per host with reason; never empty."""

    def test_urlhaus_output_never_empty_even_when_no_hosts(self):
        """When an APK has zero embedded hosts, urlhaus must still return one UNAVAILABLE entry."""
        from unittest.mock import patch
        from phase3_live_demo import analyze_apk

        with patch("phase3_live_demo.extract_apk_info") as mock_info:
            mock_info.return_value = {
                "path": "test.apk", "package": "com.empty", "app_name": "Empty",
                "version_name": "1.0", "n_dex": 1,
                "permissions": set(), "actions": set(), "method_refs": set(),
                "type_descs": set(), "strings": [], "manifest_strings": [],
            }
            res = analyze_apk("test.apk", abuse_key=None, urlhaus_key=None, verbose=False)
            urlhaus = res.get("urlhaus", [])
            self.assertGreater(len(urlhaus), 0, "URLhaus output must NEVER be an empty list")
            self.assertEqual(urlhaus[0]["status"], "UNAVAILABLE")
            self.assertTrue(len(urlhaus[0]["error"]) > 0)

    def test_urlhaus_one_unavailable_entry_per_host_on_failure(self):
        """When query fails for multiple hosts, each host gets an UNAVAILABLE entry with failure reason."""
        from unittest.mock import patch
        from phase3_live_demo import analyze_apk

        with patch("phase3_live_demo.extract_apk_info") as mock_info,              patch("phase3_live_demo.check_urlhaus_host") as mock_uh:
            mock_info.return_value = {
                "path": "test.apk", "package": "com.twohosts", "app_name": "TwoHosts",
                "version_name": "1.0", "n_dex": 1,
                "permissions": set(), "actions": set(), "method_refs": set(),
                "type_descs": set(), "strings": ["http://bad1.com", "http://bad2.com"],
                "manifest_strings": [],
            }
            mock_uh.side_effect = TimeoutError("Simulated URLhaus timeout")
            res = analyze_apk("test.apk", abuse_key=None, urlhaus_key="dummy_key", verbose=False)
            urlhaus = res.get("urlhaus", [])
            self.assertEqual(len(urlhaus), 2)
            for entry in urlhaus:
                self.assertEqual(entry["status"], "UNAVAILABLE")
                self.assertIn("error", entry)
                self.assertTrue(len(entry["error"]) > 0)


class TestDexAndActiveFeaturesSchema(unittest.TestCase):
    """Test n_dex and n_active_features in result, JSON report, and CSV schema."""

    def test_result_and_json_report_contain_n_dex_and_n_active_features(self):
        from phase3_live_demo import analyze_apk
        from backend.reports import static_report_payload, build_static_csv_report, STATIC_CSV_COLUMNS
        import csv
        import io

        res = analyze_apk("sample_app.apk", verbose=False)
        self.assertIn("n_dex", res)
        self.assertIn("n_active_features", res)
        self.assertGreaterEqual(res["n_dex"], 1)
        self.assertGreaterEqual(res["n_active_features"], 0)

        payload = static_report_payload(res)
        self.assertEqual(payload["n_dex"], res["n_dex"])
        self.assertEqual(payload["n_active_features"], res["n_active_features"])
        self.assertEqual(payload["apk"]["n_dex"], res["n_dex"])
        self.assertEqual(payload["suspicious_indicators"]["n_dex"], res["n_dex"])
        self.assertEqual(payload["suspicious_indicators"]["n_active_features"], res["n_active_features"])

        # CSV schema checks
        self.assertIn("n_dex", STATIC_CSV_COLUMNS)
        self.assertIn("n_active_features", STATIC_CSV_COLUMNS)

        csv_bytes = build_static_csv_report(res, filename="sample_app.apk", sha256="abc123")
        csv_text = csv_bytes.decode("utf-8")
        reader = csv.DictReader(io.StringIO(csv_text))
        rows = list(reader)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertIn("n_dex", row)
        self.assertIn("n_active_features", row)
        self.assertEqual(int(row["n_dex"]), res["n_dex"])
        self.assertEqual(int(row["n_active_features"]), res["n_active_features"])


if __name__ == "__main__":
    unittest.main()
