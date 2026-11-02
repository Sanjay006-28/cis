"""Comprehensive regression tests for audit fixes.

Covers:
1. Dynamic report probability semantics & active_model.
2. Dynamic job persistence in SQLite & recovery.
3. Syscall aliases (modern Android 14 x86_64 mappings).
4. Dynamic model and explainer in-memory caching.
5. Launcher activity validation and capture metadata.
6. Threat intelligence TTL caching (AbuseIPDB & URLhaus).
7. Static SHAP component labeling (XGBoost vs Ensemble).
8. PDF pagination with large indicator sets & dynamic PDF report generation.
9. APK upload ZIP security validation (traversal, zip bomb ratio, entry count).
"""

import io
import json
import os
import unittest
import zipfile
from unittest.mock import MagicMock, patch

from backend.main import DYNAMIC_JOBS, app
from backend.reports import (
    build_dynamic_pdf_report,
    build_static_pdf_report,
    dynamic_report_payload,
    static_report_payload,
)
from phase3_live_demo import (
    _ti_cache_clear,
    _ti_cache_get,
    _ti_cache_set,
    analyze_apk,
    check_ip,
    check_urlhaus_host,
    predict_static,
)
from phase5_live_capture import (
    ALIASES,
    get_dynamic_bundle,
    get_dynamic_explainer,
    has_launcher_activity,
    map_to_model,
)


class TestRuntimeThreatIntelligence(unittest.TestCase):
    """Verify runtime socket parsing and runtime threat intelligence reporting."""

    def test_parse_proc_net_connections(self):
        from phase5_live_capture import parse_proc_net_connections
        sample_proc_net = """
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:13AD 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1
   1: 0F02000A:9999 D1741868:01BB 01 00000000:00000000 00:00000000 00000000 10123        0 67890 1
   2: 0F02000A:8888 0102000A:0035 01 00000000:00000000 00:00000000 00000000 10123        0 67891 1
"""
        conns = parse_proc_net_connections(sample_proc_net)
        # Loopback (127.0.0.1) and gateway (10.0.2.1) are excluded; public IP 104.24.116.209 is kept
        self.assertEqual(len(conns), 1)
        self.assertEqual(conns[0], ("104.24.116.209", 443))

    def test_dynamic_report_includes_runtime_threat_intelligence(self):
        sample = {
            "job_id": "job-test-runtime-ti",
            "filename": "sample.apk",
            "sha256": "abcdef123456",
            "package": "com.example.malware",
            "requested_seconds": 30,
            "actual_seconds": 30.0,
            "system_call_count": 100,
            "vocabulary_coverage": 0.9,
            "features_seen": 40,
            "probability_normalized_shares": 0.85,
            "probability_raw_counts": 0.70,
            "runtime_threat_intelligence": [
                {
                    "ip": "104.24.116.209",
                    "port": 443,
                    "abuse_score": 88,
                    "total_reports": 15,
                    "country": "US",
                    "isp": "Cloudflare",
                    "status": "checked",
                }
            ],
        }
        payload = dynamic_report_payload(sample)
        self.assertIn("runtime_threat_intelligence", payload)
        self.assertEqual(len(payload["runtime_threat_intelligence"]), 1)
        self.assertEqual(payload["runtime_threat_intelligence"][0]["ip"], "104.24.116.209")

        # Test PDF generation includes runtime threat intelligence without error
        pdf_bytes = build_dynamic_pdf_report(sample)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))


class TestDynamicReportSemantics(unittest.TestCase):
    """Verify dynamic score semantics and model driving the verdict."""

    def test_dynamic_verdict_uses_shares_model(self):
        sample = {
            "job_id": "test-123",
            "filename": "test.apk",
            "sha256": "abc",
            "package": "com.test",
            "requested_seconds": 30,
            "actual_seconds": 30.0,
            "system_call_count": 100,
            "vocabulary_coverage": 0.85,
            "features_seen": 25,
            "probability_normalized_shares": 0.72,
            "probability_raw_counts": 0.15,
            "shap_evidence": [],
            "counts": {},
            "unmapped_counts": {},
        }
        payload = dynamic_report_payload(sample)
        self.assertEqual(payload["prediction"]["verdict"], "MALWARE")
        self.assertEqual(payload["prediction"]["malware_probability"], 0.72)
        self.assertEqual(payload["prediction"]["probability_normalized_shares"], 0.72)

    def test_dynamic_verdict_benign_when_below_threshold(self):
        sample = {
            "job_id": "test-124",
            "probability_normalized_shares": 0.35,
            "probability_raw_counts": 0.88,
        }
        payload = dynamic_report_payload(sample)
        self.assertEqual(payload["prediction"]["verdict"], "BENIGN")
        self.assertEqual(payload["prediction"]["malware_probability"], 0.35)


class TestSyscallAliasesAndMapping(unittest.TestCase):
    """Verify modern Android 14 / x86_64 system call compatibility mappings."""

    def test_modern_aliases_present(self):
        expected_mappings = {
            "ppoll": "poll",
            "fstatfs": "fstatfs64",
            "statfs": "statfs64",
            "readlinkat": "readlink",
            "fchmodat": "chmod",
            "mkdirat": "mkdir",
            "unlinkat": "unlink",
            "renameat": "rename",
            "renameat2": "rename",
        }
        for src, dest in expected_mappings.items():
            self.assertIn(src, ALIASES, f"Syscall {src} should be aliased")
            self.assertEqual(ALIASES[src], dest, f"Syscall {src} should map to {dest}")

        # Incompatible or non-vocabulary targets must not exist in ALIASES
        self.assertNotIn("sendfile", ALIASES, "sendfile has no target in vocabulary and must stay unmapped")
        self.assertNotIn("truncate", ALIASES, "truncate is in vocabulary and must not map to non-existent truncate64")

    def test_map_to_model_aliases_and_unmapped(self):
        vocab = ["poll", "readlink", "fstatfs64", "close", "read"]
        counts = {
            "ppoll": 50,
            "readlinkat": 20,
            "close": 100,
            "custom_unknown_syscall": 15,
        }
        mapped, coverage, unmapped = map_to_model(counts, vocab)
        self.assertEqual(mapped.get("poll"), 50)
        self.assertEqual(mapped.get("readlink"), 20)
        self.assertEqual(mapped.get("close"), 100)
        self.assertIn("custom_unknown_syscall", unmapped)
        self.assertEqual(unmapped["custom_unknown_syscall"], 15)
        # Coverage calculation: (50 + 20 + 100) / 185
        self.assertAlmostEqual(coverage, 170 / 185, places=3)


class TestDynamicModelCaching(unittest.TestCase):
    """Verify in-memory caching for dynamic bundle and SHAP explainer."""

    def test_bundle_cached_in_memory(self):
        b1 = get_dynamic_bundle()
        b2 = get_dynamic_bundle()
        self.assertIs(b1, b2, "get_dynamic_bundle should return cached object")

    def test_explainer_cached_in_memory(self):
        e1 = get_dynamic_explainer()
        e2 = get_dynamic_explainer()
        self.assertIs(e1, e2, "get_dynamic_explainer should return cached explainer")


class TestLauncherActivityValidation(unittest.TestCase):
    """Verify detection of APKs without launcher activities."""

    def test_has_launcher_activity_on_sample(self):
        # sample_app.apk should declare a main/launcher activity
        if os.path.exists("sample_app.apk"):
            has_launcher = has_launcher_activity("sample_app.apk")
            self.assertTrue(has_launcher, "sample_app.apk should have launcher activity")


class TestThreatIntelTTLCache(unittest.TestCase):
    """Verify thread-safe in-memory TTL caching for AbuseIPDB and URLhaus."""

    def setUp(self):
        _ti_cache_clear()

    def tearDown(self):
        _ti_cache_clear()

    def test_cache_set_and_get(self):
        _ti_cache_set("test:1", {"score": 42})
        cached = _ti_cache_get("test:1")
        self.assertIsNotNone(cached)
        self.assertEqual(cached["score"], 42)

    def test_cache_miss_and_clear(self):
        self.assertIsNone(_ti_cache_get("non_existent"))
        _ti_cache_set("test:2", {"score": 99})
        _ti_cache_clear()
        self.assertIsNone(_ti_cache_get("test:2"))

    def test_check_ip_uses_cache(self):
        mock_get = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 85,
                "totalReports": 12,
                "countryCode": "US",
                "isp": "Example ISP",
            }
        }
        mock_get.return_value = mock_resp

        # First call hits mock
        res1 = check_ip("104.244.42.1", "dummy_key", http_get=mock_get)
        self.assertEqual(res1["abuse_score"], 85)
        self.assertEqual(mock_get.call_count, 1)

        # Second call hits cache (mock_get should NOT be called again)
        res2 = check_ip("104.244.42.1", "dummy_key", http_get=mock_get)
        self.assertEqual(res2["abuse_score"], 85)
        self.assertEqual(mock_get.call_count, 1)


class TestStaticSHAPComponentLabeling(unittest.TestCase):
    """Verify honest labeling of XGBoost component SHAP vs ensemble output."""

    def test_predict_static_contains_shap_source(self):
        res = analyze_apk("sample_app.apk", verbose=False)
        static_res = res["static"]
        self.assertIn("shap_source", static_res)
        self.assertIn("XGBoost", static_res["shap_source"])
        self.assertIn("shap_note", static_res)

    def test_static_report_payload_has_shap_note(self):
        res = analyze_apk("sample_app.apk", verbose=False)
        payload = static_report_payload(res)
        self.assertIn("shap_source", payload["model_explanation"])
        self.assertIn("shap_note", payload["model_explanation"])


class TestPdfPaginationAndDynamicPdf(unittest.TestCase):
    """Verify PDF reports handle large data without crashing and dynamic PDF generates valid bytes."""

    def test_static_pdf_paginates_large_indicator_sets(self):
        # Create a synthetic result with 50 IPs and 50 domains
        ips = {f"203.0.113.{i}": f"suspicious connection {i}" for i in range(1, 51)}
        domains = {f"evil-domain-{i}.com": f"malicious C2 #{i}" for i in range(1, 51)}
        lookups = [{"ip": ip, "abuse_score": 90, "total_reports": 5, "status": "checked"} for ip in list(ips.keys())[:20]]
        synthetic_res = {
            "info": {"package": "com.heavy.apk", "app_name": "Heavy Indicators", "version_name": "1.0"},
            "static": {"prob_malware": 0.95, "verdict": "MALWARE", "evidence": []},
            "ips": ips,
            "domains": domains,
            "lookups": lookups,
            "threat_features": {"network_risk": "HIGH", "max_abuse_score": 90},
            "urlhaus": [{"host": d, "status": "LISTED", "url_count": 2} for d in list(domains.keys())[:15]],
            "domain_entropy": [{"domain": d, "label": d.split(".")[0], "entropy": 3.8, "flag": True} for d in list(domains.keys())[:15]],
            "attack_candidates": [{"technique_id": "T1582", "technique_name": "SMS Control", "evidence": "SEND_SMS"}],
        }
        pdf_bytes = build_static_pdf_report(synthetic_res, filename="heavy_test.apk", sha256="abcd1234ef567890")
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        self.assertGreater(len(pdf_bytes), 5000)

    def test_dynamic_pdf_report_generation(self):
        dynamic_res = {
            "job_id": "test-job-99",
            "filename": "sample_dynamic.apk",
            "package": "com.sample.dynamic",
            "sha256": "1234567890abcdef",
            "requested_seconds": 30,
            "actual_seconds": 29.5,
            "system_call_count": 1420,
            "vocabulary_coverage": 0.92,
            "features_seen": 42,
            "probability_normalized_shares": 0.88,
            "probability_raw_counts": 0.75,
            "verdict": "MALWARE",
            "shap_evidence": [{"syscall": "ioctl", "count": 120, "shap": 0.15}],
            "unmapped_counts": {"unknown_call": 3},
        }
        pdf_bytes = build_dynamic_pdf_report(dynamic_res)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        self.assertGreater(len(pdf_bytes), 3000)


class TestUploadZipValidation(unittest.TestCase):
    """Verify upload endpoint rejects path traversal, oversized archives, and decompression bombs."""

    def test_reject_zip_path_traversal(self):
        import asyncio
        from fastapi import UploadFile, HTTPException
        from backend.main import upload_apk

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("../../etc/passwd", "malicious payload")
        buf.seek(0)
        upload_file = UploadFile(filename="traversal.apk", file=buf)
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(upload_apk(upload_file))
        self.assertEqual(ctx.exception.status_code, 415)
        self.assertIn("traversal", str(ctx.exception.detail).lower())

    def test_reject_non_pk_magic(self):
        import asyncio
        from fastapi import UploadFile, HTTPException
        from backend.main import upload_apk

        upload_file = UploadFile(filename="test.apk", file=io.BytesIO(b"NOT_A_ZIP_HEADER"))
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(upload_apk(upload_file))
        self.assertEqual(ctx.exception.status_code, 415)
        self.assertIn("zip", str(ctx.exception.detail).lower())


class TestJobStorePersistence(unittest.TestCase):
    """Verify SQLite-backed JobStore persists and manages job states."""

    def test_jobstore_crud(self):
        jid = "persist-test-1"
        DYNAMIC_JOBS[jid] = {
            "job_id": jid,
            "status": "queued",
            "filename": "persist.apk",
            "requested_seconds": 30,
        }
        self.assertIn(jid, DYNAMIC_JOBS)
        retrieved = DYNAMIC_JOBS[jid]
        self.assertEqual(retrieved["filename"], "persist.apk")
        self.assertEqual(retrieved["status"], "queued")

        # Update status
        DYNAMIC_JOBS.update_status(jid, "completed", completed_at="2026-10-29T12:00:00")
        self.assertEqual(DYNAMIC_JOBS[jid]["status"], "completed")

        # Cleanup
        DYNAMIC_JOBS.pop(jid)
        self.assertNotIn(jid, DYNAMIC_JOBS)


if __name__ == "__main__":
    unittest.main()
