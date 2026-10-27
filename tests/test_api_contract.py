import asyncio
import io
import unittest

from unittest.mock import patch

from fastapi import HTTPException, UploadFile
from pydantic import ValidationError

from backend.main import (
    health,
    research_artifact,
    research_benchmarks,
    research_tables,
    resolve_adb_executable,
    start_dynamic_analysis,
    system_status,
    upload_apk,
)
from backend.schemas import DynamicAnalysisRequest


class ApiContractTests(unittest.TestCase):
    def test_health_reports_api_only(self):
        response = health()
        self.assertEqual(response.status, "ok")
        self.assertEqual(response.service, "android-malware-analysis-api")

    def test_benchmarks_reference_existing_artifacts(self):
        groups = research_benchmarks()
        self.assertEqual({group.id for group in groups}, {"static", "dynamic"})
        self.assertTrue(any(
            artifact.available
            for group in groups
            for artifact in group.artifacts
        ))

    def test_benchmark_endpoint_returns_repository_data(self):
        response = research_artifact("static-test-results")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'"rows"', response.body)

    def test_research_tables_returns_all_csv_artifacts(self):
        tables = research_tables()
        self.assertIn("static-test-results", tables)
        self.assertIn("static-cv-results", tables)
        self.assertIn("dynamic-cluster-cv", tables)
        self.assertIn("dynamic-unseen-category", tables)
        for table_id, data in tables.items():
            self.assertTrue(len(data["columns"]) > 0)
            self.assertTrue(len(data["rows"]) > 0)

    def test_research_artifact_returns_image(self):
        response = research_artifact("static-feature-importance")
        self.assertEqual(response.media_type, "image/png")
        self.assertTrue(len(str(response.path)) > 0)

    def test_artifact_endpoint_rejects_arbitrary_paths(self):
        with self.assertRaises(HTTPException) as error:
            research_artifact("../../static_model.joblib")
        self.assertEqual(error.exception.status_code, 404)

    def test_dynamic_run_requires_explicit_confirmation(self):
        request = DynamicAnalysisRequest(
            use_sample=True,
            seconds=30,
            confirmed_execution=False,
        )
        with self.assertRaises(HTTPException) as error:
            start_dynamic_analysis(request)
        self.assertEqual(error.exception.status_code, 400)
        self.assertIn("Explicit confirmation", str(error.exception.detail))

    def test_dynamic_duration_is_bounded(self):
        with self.assertRaises(ValidationError):
            DynamicAnalysisRequest(use_sample=True, seconds=301, confirmed_execution=True)

    def test_upload_rejects_non_apk_extension(self):
        upload = UploadFile(filename="not-an-apk.txt", file=io.BytesIO(b"PK"))
        with self.assertRaises(HTTPException) as error:
            asyncio.run(upload_apk(upload))
        self.assertEqual(error.exception.status_code, 415)

    def test_resolve_adb_executable_finds_wrapper_or_honors_env(self):
        # Discovers wrapper or platform-tools
        resolved = resolve_adb_executable()
        # In this workspace, either /home/ashwith/bin/adb or Windows platform-tools exists
        self.assertTrue(resolved is not None and len(resolved) > 0)

    def test_system_status_reports_actionable_error_when_adb_missing(self):
        with patch("backend.main.resolve_adb_executable", return_value=None):
            status = system_status()
            self.assertFalse(status.adb_available)
            self.assertIsNone(status.adb_path)
            self.assertFalse(status.emulator_connected)
            self.assertFalse(status.emulator_ready)
            self.assertEqual(status.emulator_checks.get("step"), "adb")
            self.assertIn("Expected the ADB wrapper at /home/ashwith/bin/adb", status.emulator_checks.get("message", ""))

    def test_system_status_reports_actionable_error_when_adb_server_fails(self):
        with patch("backend.main.resolve_adb_executable", return_value="/home/ashwith/bin/adb"), \
             patch("backend.main.dynamic_engine.adb", return_value=(1, "", "cannot connect to daemon at tcp:5037")):
            status = system_status()
            self.assertTrue(status.adb_available)
            self.assertEqual(status.adb_path, "/home/ashwith/bin/adb")
            self.assertFalse(status.emulator_connected)
            self.assertFalse(status.emulator_ready)
            self.assertEqual(status.emulator_checks.get("step"), "adb_server")
            self.assertIn("could not communicate with the ADB server", status.emulator_checks.get("message", ""))

    def test_system_status_reports_actionable_error_when_no_emulator_connected(self):
        with patch("backend.main.resolve_adb_executable", return_value="/home/ashwith/bin/adb"), \
             patch("backend.main.dynamic_engine.adb", return_value=(0, "List of devices attached\n\n", "")):
            status = system_status()
            self.assertTrue(status.adb_available)
            self.assertEqual(status.adb_path, "/home/ashwith/bin/adb")
            self.assertFalse(status.emulator_connected)
            self.assertFalse(status.emulator_ready)
            self.assertEqual(status.emulator_checks.get("step"), "emulator")
            self.assertIn("No connected Android emulator was found", status.emulator_checks.get("message", ""))

    def test_system_status_rejects_physical_devices(self):
        with patch("backend.main.resolve_adb_executable", return_value="/home/ashwith/bin/adb"), \
             patch("backend.main.dynamic_engine.adb", return_value=(0, "List of devices attached\nRF8M123456\tdevice\n\n", "")):
            status = system_status()
            self.assertTrue(status.adb_available)
            self.assertFalse(status.emulator_connected)
            self.assertFalse(status.emulator_ready)
            self.assertEqual(status.emulator_checks.get("step"), "emulator")
            self.assertIn("Physical devices are rejected", status.emulator_checks.get("message", ""))

    def test_system_status_supports_arbitrary_emulator_serial(self):
        # Do not hardcode emulator-5554: test with emulator-5556
        with patch("backend.main.resolve_adb_executable", return_value="/home/ashwith/bin/adb"), \
             patch("backend.main.dynamic_engine.adb", return_value=(0, "List of devices attached\nemulator-5556\tdevice\n\n", "")), \
             patch("backend.main.dynamic_engine.check_setup", return_value={"ready": True, "device": "emulator-5556", "props": {}}):
            status = system_status()
            self.assertTrue(status.adb_available)
            self.assertTrue(status.emulator_connected)
            self.assertEqual(status.emulator_serial, "emulator-5556")
            self.assertTrue(status.emulator_ready)
            self.assertTrue(status.emulator_checks.get("ready"))


if __name__ == "__main__":
    unittest.main()
