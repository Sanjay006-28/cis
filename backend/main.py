import glob
import hashlib
import json as _json
import logging
import os
import re
import shutil
import sqlite3 as _sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import FastAPI, File, HTTPException, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from backend.explanations import (
    explain_dynamic_syscall,
    explain_static_feature,
)
from backend.reports import (
    build_dynamic_json_report,
    build_static_csv_report,
    build_static_json_report,
    build_static_pdf_report,
)
from backend.schemas import (
    DynamicAnalysisAccepted,
    DynamicAnalysisRequest,
    DynamicAnalysisResult,
    DynamicAnomalyExplanation,
    DynamicJobStatus,
    HealthResponse,
    ResearchGroup,
    ResearchTableResponse,
    StaticAnalysisRequest,
    StaticAnalysisResponse,
    StaticFeatureExplanation,
    SystemStatusResponse,
    ThreatIntelStatusResponse,
    ThreatIntelTestRequest,
    ThreatIntelTestResponse,
    UploadResponse,
)

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_MODEL = BASE_DIR / "static_outputs" / "static_model.joblib"
DYNAMIC_MODEL = BASE_DIR / "dynamic_outputs_v2" / "dynamic_model.joblib"
UPLOAD_DIR = BASE_DIR / ".api_uploads"
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
UPLOAD_TTL = timedelta(hours=1)
JOB_DB_PATH = BASE_DIR / ".job_store.db"  # SQLite file for persistent dynamic job state

# ---------------------------------------------------------------------------
# Load root .env file securely before reading API key configuration
# ---------------------------------------------------------------------------
DOTENV_PATH = BASE_DIR / ".env"
try:
    from dotenv import load_dotenv
    if DOTENV_PATH.is_file():
        load_dotenv(dotenv_path=DOTENV_PATH, override=False)
except ImportError:
    if DOTENV_PATH.is_file():
        try:
            with open(DOTENV_PATH, "r", encoding="utf-8") as _f:
                for _line in _f:
                    _line = _line.strip()
                    if _line and not _line.startswith("#") and "=" in _line:
                        _k, _v = _line.split("=", 1)
                        _k, _v = _k.strip(), _v.strip().strip("'\"")
                        if _k and _k not in os.environ:
                            os.environ[_k] = _v
        except Exception:
            pass

os.environ.setdefault("MPLBACKEND", "Agg")
import sys

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from phase3_live_demo import analyze_apk, check_ip
import phase5_live_capture as dynamic_engine

dynamic_engine.BUNDLE_PATH = str(DYNAMIC_MODEL)

# Sentinel placeholder values that should not be treated as real API keys
_PLACEHOLDER_KEYS = {
    "PASTE_YOUR_ACTUAL_ABUSEIPDB_KEY_HERE",
    "YOUR_API_KEY_HERE",
    "YOUR_ABUSEIPDB_API_KEY_HERE",
    "PLACEHOLDER",
}


def get_configured_abuseipdb_key() -> str | None:
    """Discover the AbuseIPDB API key from backend environment configuration.

    Primary environment variable: ABUSEIPDB_API_KEY (configured in root .env).
    Backward-compatible fallback: ABUSEIPDB_KEY.
    """
    key = os.environ.get("ABUSEIPDB_API_KEY") or os.environ.get("ABUSEIPDB_KEY")
    if key and key.strip():
        cleaned = key.strip()
        if cleaned not in _PLACEHOLDER_KEYS:
            return cleaned
    return None


def _ensure_in_path(executable_path: str) -> None:
    try:
        parent_dir = str(Path(executable_path).parent)
        current_path = os.environ.get("PATH", "")
        paths = current_path.split(os.pathsep) if current_path else []
        if parent_dir not in paths:
            os.environ["PATH"] = f"{parent_dir}{os.pathsep}{current_path}"
    except Exception:
        pass


def resolve_adb_executable() -> str | None:
    """Discover the ADB executable or wrapper in WSL / Windows and configure the environment.

    Checks in priority order:
    1. Explicit ADB_PATH environment variable if it points to an existing file.
    2. System PATH via shutil.which('adb') or shutil.which('adb.exe').
    3. User home bin paths (e.g. /home/ashwith/bin/adb, ~/.local/bin/adb).
    4. Windows Android SDK platform-tools mounted inside WSL (/mnt/c/Users/.../platform-tools/adb.exe).
    5. Native Windows SDK platform-tools locations if running on Windows.
    6. Standard Linux locations (/usr/local/bin/adb, /usr/bin/adb).

    If found, sets os.environ["ADB_PATH"] and ensures its parent directory is on PATH.
    """
    env_adb = os.environ.get("ADB_PATH")
    if env_adb and os.path.isfile(env_adb):
        _ensure_in_path(env_adb)
        return env_adb

    which_adb = shutil.which("adb") or shutil.which("adb.exe")
    if which_adb and os.path.isfile(which_adb):
        os.environ["ADB_PATH"] = which_adb
        _ensure_in_path(which_adb)
        return which_adb

    home = Path.home()
    candidates: list[Path] = [
        home / "bin" / "adb",
        Path("/home/ashwith/bin/adb"),
        home / ".local" / "bin" / "adb",
    ]

    sdk_patterns = [
        "/mnt/c/Users/*/AppData/Local/Android/Sdk/platform-tools/adb.exe",
        "/mnt/c/Android/Sdk/platform-tools/adb.exe",
        "/mnt/c/Program Files (x86)/Android/android-sdk/platform-tools/adb.exe",
    ]
    for pattern in sdk_patterns:
        for match in sorted(glob.glob(pattern)):
            candidates.append(Path(match))

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidates.append(Path(local_app_data) / "Android" / "Sdk" / "platform-tools" / "adb.exe")
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        val = os.environ.get(var)
        if val:
            candidates.append(Path(val) / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb"))

    candidates.extend([
        Path("/usr/local/bin/adb"),
        Path("/usr/bin/adb"),
    ])

    for candidate in candidates:
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                resolved = str(candidate.resolve())
                os.environ["ADB_PATH"] = resolved
                _ensure_in_path(resolved)
                return resolved
        except (OSError, PermissionError):
            continue

    return None


RESOLVED_ADB = resolve_adb_executable()

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("malware-api")
app = FastAPI(
    title="Android Malware Analysis API",
    version="1.0.0",
    description="HTTP API for the existing static and dynamic Android analysis engines.",
)

frontend_origins = [
    origin.strip()
    for origin in os.getenv(
        "FRONTEND_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=frontend_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOADS: dict[str, dict[str, Any]] = {}
STATIC_RESULTS: dict[str, dict[str, Any]] = {}
STATE_LOCK = threading.Lock()
DYNAMIC_LOCK = threading.Lock()
EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="dynamic-analysis")


# ---------------------------------------------------------------------------
# Persistent SQLite-backed job store for dynamic analysis jobs.
# Survives backend restarts; maintains all job metadata and result payloads.
# ---------------------------------------------------------------------------
class _JobStore:
    """Thread-safe SQLite-backed store for dynamic analysis jobs.

    Provides dict-like interface for backward compatibility with existing tests
    and background workers, while persisting all metadata and results to SQLite.
    On startup, any jobs that were left in 'queued' or 'running' state
    are automatically marked as 'interrupted' because their workers no longer exist.
    """

    def __init__(self, db_path: Path) -> None:
        self._db = str(db_path)
        self._lock = threading.Lock()
        self._init_db()
        self._mark_interrupted_on_startup()

    def _execute(self, query: str, params: tuple = ()):
        with self._lock:
            conn = _sqlite3.connect(self._db, check_same_thread=False)
            conn.row_factory = _sqlite3.Row
            try:
                with conn:
                    cur = conn.execute(query, params)
                    return cur.fetchall()
            finally:
                conn.close()

    def _execute_write(self, query: str, params: tuple = ()):
        with self._lock:
            conn = _sqlite3.connect(self._db, check_same_thread=False)
            try:
                with conn:
                    conn.execute(query, params)
            finally:
                conn.close()

    def _init_db(self) -> None:
        self._execute_write("""
            CREATE TABLE IF NOT EXISTS dynamic_jobs (
                job_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                filename TEXT NOT NULL,
                requested_seconds INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                error TEXT,
                result_json TEXT
            )
        """)

    def _mark_interrupted_on_startup(self) -> None:
        """Mark queued/running jobs as interrupted since their workers no longer exist."""
        self._execute_write(
            "UPDATE dynamic_jobs SET status='interrupted', "
            "error='Job was interrupted: the backend restarted while this job was active.' "
            "WHERE status IN ('queued', 'running')"
        )

    def create(self, job: dict) -> None:
        self._execute_write(
            "INSERT OR REPLACE INTO dynamic_jobs (job_id, status, filename, requested_seconds, "
            "created_at, started_at, completed_at, error, result_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                job["job_id"], job.get("status", "queued"), job.get("filename", "unknown.apk"),
                job.get("requested_seconds", 30), job.get("created_at", _now().isoformat()),
                job.get("started_at"), job.get("completed_at"),
                job.get("error"),
                _json.dumps(job["result"], default=str) if job.get("result") else None,
            ),
        )

    def get(self, job_id: str) -> dict | None:
        rows = self._execute(
            "SELECT * FROM dynamic_jobs WHERE job_id = ?", (job_id,)
        )
        if not rows:
            return None
        d = dict(rows[0])
        result_json = d.pop("result_json", None)
        d["result"] = _json.loads(result_json) if result_json else None
        return d

    def update_status(self, job_id: str, status: str, **kwargs) -> None:
        fields = ["status = ?"]
        params: list = [status]
        for key in ("started_at", "completed_at", "error"):
            if key in kwargs:
                fields.append(f"{key} = ?")
                params.append(kwargs[key])
        params.append(job_id)
        self._execute_write(
            f"UPDATE dynamic_jobs SET {', '.join(fields)} WHERE job_id = ?",
            tuple(params),
        )

    def set_result(self, job_id: str, result: dict) -> None:
        self._execute_write(
            "UPDATE dynamic_jobs SET result_json = ? WHERE job_id = ?",
            (_json.dumps(result, default=str), job_id),
        )

    # Dict-like compatibility for existing tests and code
    def __getitem__(self, job_id: str) -> dict:
        item = self.get(job_id)
        if item is None:
            raise KeyError(job_id)
        return item

    def __setitem__(self, job_id: str, job: dict) -> None:
        if not isinstance(job, dict):
            raise TypeError("job must be a dict")
        job = dict(job)
        job.setdefault("job_id", job_id)
        self.create(job)

    def __contains__(self, job_id: str) -> bool:
        return self.get(job_id) is not None

    def pop(self, job_id: str, default=None):
        item = self.get(job_id)
        if item is not None:
            self._execute_write("DELETE FROM dynamic_jobs WHERE job_id = ?", (job_id,))
            return item
        return default


DYNAMIC_JOBS = _JobStore(JOB_DB_PATH)

ARTIFACTS: dict[str, tuple[str, str, str]] = {
    "static-test-results": ("static", "Held-out test results", "test_results.csv"),
    "static-cv-results": ("static", "Cross-validation results", "cv_results.csv"),
    "static-feature-importance": ("static", "Feature importance", "1_feature_importance.png"),
    "static-confusion-matrices": ("static", "Confusion matrices", "2_confusion_matrices.png"),
    "static-roc-pr": ("static", "ROC and precision-recall curves", "3_roc_pr_curves.png"),
    "static-shap-summary": ("static", "SHAP summary", "4_shap_summary.png"),
    "static-shap-bar": ("static", "Mean absolute SHAP values", "5_shap_bar.png"),
    "dynamic-cluster-cv": ("dynamic", "Cluster-held-out cross-validation", "cv_results_cluster_heldout.csv"),
    "dynamic-cluster-pooled": ("dynamic", "Pooled cluster-held-out results", "pooled_results_cluster_heldout.csv"),
    "dynamic-test-results": ("dynamic", "Random test split results", "test_results.csv"),
    "dynamic-random-xgboost": ("dynamic", "Random-fold XGBoost results", "cv_results_random_xgboost.csv"),
    "dynamic-share-xgboost": ("dynamic", "Share-normalized XGBoost results", "cv_results_shares_xgboost.csv"),
    "dynamic-feature-counts": ("dynamic", "Feature-count analysis", "feature_count_analysis.csv"),
    "dynamic-mcnemar-cluster": ("dynamic", "Cluster-held-out McNemar tests", "mcnemar_cluster_heldout.csv"),
    "dynamic-mcnemar-random": ("dynamic", "Random-split McNemar tests", "mcnemar_random_split.csv"),
    "dynamic-unseen-category": ("dynamic", "Unseen malware-category results", "unseen_category.csv"),
    "dynamic-feature-importance": ("dynamic", "System-call feature importance", "1_feature_importance.png"),
    "dynamic-confusion-matrices": ("dynamic", "Cluster-held-out confusion matrices", "2_confusion_matrices.png"),
    "dynamic-roc-pr": ("dynamic", "ROC and precision-recall curves", "3_roc_pr_curves.png"),
    "dynamic-shap-summary": ("dynamic", "Dynamic SHAP summary", "4_shap_summary.png"),
    "dynamic-shap-bar": ("dynamic", "Mean absolute dynamic SHAP values", "5_shap_bar.png"),
    "dynamic-accuracy-features": ("dynamic", "Accuracy by feature count", "6_accuracy_vs_features.png"),
}

RESEARCH_GROUPS = (
    ("static", "Static analysis benchmarks", tuple(
        artifact for artifact in ARTIFACTS if artifact.startswith("static-")
    )),
    ("dynamic", "Dynamic analysis benchmarks", tuple(
        artifact for artifact in ARTIFACTS if artifact.startswith("dynamic-")
    )),
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _purge_expired_uploads() -> None:
    cutoff = _now() - UPLOAD_TTL
    with STATE_LOCK:
        expired = [
            upload_id for upload_id, item in UPLOADS.items()
            if item["created_at"] < cutoff
        ]
        for upload_id in expired:
            path = UPLOADS.pop(upload_id)["path"]
            try:
                path.unlink(missing_ok=True)
            except OSError:
                logger.exception("Failed to remove expired upload %s", upload_id)
    try:
        UPLOAD_DIR.mkdir(exist_ok=True)
    except OSError:
        logger.exception("Could not create temporary upload directory")
        raise


def _take_upload(upload_id: str) -> dict[str, Any]:
    _purge_expired_uploads()
    with STATE_LOCK:
        item = UPLOADS.pop(upload_id, None)
    if item is None or not item["path"].is_file():
        raise HTTPException(status_code=404, detail="Upload not found or expired.")
    return item


def _readiness(allow_active_check: bool = False) -> dict[str, Any]:
    adb_path = resolve_adb_executable()

    if DYNAMIC_LOCK.locked() and not allow_active_check:
        return {
            "static_model_available": STATIC_MODEL.is_file(),
            "dynamic_model_available": DYNAMIC_MODEL.is_file(),
            "static_analysis_available": STATIC_MODEL.is_file(),
            "adb_available": adb_path is not None,
            "adb_path": adb_path,
            "emulator_connected": False,
            "emulator_serial": None,
            "emulator_ready": False,
            "emulator_checks": {
                "ready": False,
                "message": "An emulator analysis is in progress; readiness checks are deferred.",
            },
            "analysis_busy": True,
        }

    checks: dict[str, Any] = {}
    emulator_ready = False
    connected = False
    serial = None

    if not adb_path:
        checks = {
            "ready": False,
            "step": "adb",
            "message": (
                "ADB executable or wrapper was not found. Expected the ADB wrapper at /home/ashwith/bin/adb, "
                "platform-tools on PATH, or set ADB_PATH."
            ),
        }
        return {
            "static_model_available": STATIC_MODEL.is_file(),
            "dynamic_model_available": DYNAMIC_MODEL.is_file(),
            "static_analysis_available": STATIC_MODEL.is_file(),
            "adb_available": False,
            "adb_path": None,
            "emulator_connected": False,
            "emulator_serial": None,
            "emulator_ready": False,
            "emulator_checks": checks,
            "analysis_busy": DYNAMIC_LOCK.locked(),
        }

    # Verify communication with ADB server
    try:
        code, out, err = dynamic_engine.adb("devices", timeout=10)
        if code != 0:
            err_msg = (err or out or f"exit code {code}").strip()
            checks = {
                "ready": False,
                "step": "adb_server",
                "message": (
                    f"ADB was found at '{adb_path}', but could not communicate with the ADB server. "
                    f"Ensure the Windows ADB server is running and accessible (try running 'adb devices' in Windows or WSL). "
                    f"Error: {err_msg}"
                ),
            }
            return {
                "static_model_available": STATIC_MODEL.is_file(),
                "dynamic_model_available": DYNAMIC_MODEL.is_file(),
                "static_analysis_available": STATIC_MODEL.is_file(),
                "adb_available": True,
                "adb_path": adb_path,
                "emulator_connected": False,
                "emulator_serial": None,
                "emulator_ready": False,
                "emulator_checks": checks,
                "analysis_busy": DYNAMIC_LOCK.locked(),
            }
    except Exception as exc:
        checks = {
            "ready": False,
            "step": "adb_server",
            "message": (
                f"ADB was found at '{adb_path}', but communication failed with an exception: {exc}"
            ),
        }
        return {
            "static_model_available": STATIC_MODEL.is_file(),
            "dynamic_model_available": DYNAMIC_MODEL.is_file(),
            "static_analysis_available": STATIC_MODEL.is_file(),
            "adb_available": True,
            "adb_path": adb_path,
            "emulator_connected": False,
            "emulator_serial": None,
            "emulator_ready": False,
            "emulator_checks": checks,
            "analysis_busy": DYNAMIC_LOCK.locked(),
        }

    # Parse devices from adb output
    lines = [ln.strip() for ln in out.splitlines()[1:] if ln.strip()]
    devices = [ln.split()[0] for ln in lines if ln.split()[-1] == "device"]
    emulator_serials = [
        device for device in devices
        if device.startswith(("emulator-", "127.0.0.1", "localhost"))
    ]

    if not emulator_serials:
        if not devices:
            checks = {
                "ready": False,
                "step": "emulator",
                "message": (
                    "No connected Android emulator was found. Start an Android Virtual Device (AVD) "
                    "in Android Studio (e.g., emulator-5554), wait for it to boot, and run this check again."
                ),
                "devices": [],
            }
        else:
            checks = {
                "ready": False,
                "step": "emulator",
                "message": (
                    f"Connected device(s) '{', '.join(devices)}' do not appear to be an Android emulator. "
                    "Physical devices are rejected for safety; only emulators (e.g. emulator-5554, 127.0.0.1:*, localhost:*) are accepted."
                ),
                "devices": devices,
            }
        return {
            "static_model_available": STATIC_MODEL.is_file(),
            "dynamic_model_available": DYNAMIC_MODEL.is_file(),
            "static_analysis_available": STATIC_MODEL.is_file(),
            "adb_available": True,
            "adb_path": adb_path,
            "emulator_connected": False,
            "emulator_serial": None,
            "emulator_ready": False,
            "emulator_checks": checks,
            "analysis_busy": DYNAMIC_LOCK.locked(),
        }

    serial = emulator_serials[0]
    connected = True
    try:
        checks = dynamic_engine.check_setup(device=serial)
        emulator_ready = bool(checks.get("ready"))
        if not emulator_ready and "message" not in checks:
            checks["message"] = f"Emulator '{serial}' connected, but setup check failed (verify root access and strace availability)."
    except Exception as exc:
        logger.exception("Failed to inspect Android emulator readiness for %s", serial)
        checks = {
            "ready": False,
            "step": "setup",
            "message": f"Emulator '{serial}' connected, but setup check encountered an error: {exc}",
            "error": str(exc),
        }
        emulator_ready = False

    return {
        "static_model_available": STATIC_MODEL.is_file(),
        "dynamic_model_available": DYNAMIC_MODEL.is_file(),
        "static_analysis_available": STATIC_MODEL.is_file(),
        "adb_available": True,
        "adb_path": adb_path,
        "emulator_connected": connected,
        "emulator_serial": serial,
        "emulator_ready": emulator_ready and DYNAMIC_MODEL.is_file(),
        "emulator_checks": checks,
        "analysis_busy": DYNAMIC_LOCK.locked(),
    }


def _artifact_path(artifact_id: str) -> tuple[Path, str, str]:
    artifact = ARTIFACTS.get(artifact_id)
    if artifact is None:
        raise HTTPException(status_code=404, detail="Research artifact not found.")
    group, label, filename = artifact
    folder = BASE_DIR / ("static_outputs" if group == "static" else "dynamic_outputs_v2")
    path = folder / filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"Saved artifact is unavailable: {label}.")
    kind = "image" if path.suffix.lower() == ".png" else "table"
    return path, label, kind


@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse()


@app.get("/api/system/status", response_model=SystemStatusResponse)
def system_status() -> SystemStatusResponse:
    return SystemStatusResponse(**_readiness())


@app.post("/api/uploads", response_model=UploadResponse, status_code=201)
async def upload_apk(file: UploadFile = File(...)) -> UploadResponse:
    if not file.filename or Path(file.filename).suffix.lower() != ".apk":
        raise HTTPException(status_code=415, detail="Only files with an .apk extension are accepted.")

    _purge_expired_uploads()
    try:
        contents = await file.read(MAX_UPLOAD_BYTES + 1)
    finally:
        await file.close()
    if not contents:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="APK exceeds the 100 MiB upload limit.")
    if not contents.startswith(b"PK"):
        raise HTTPException(status_code=415, detail="The uploaded file is not a ZIP-based APK.")

    import zipfile
    import io as _io
    _MAX_ZIP_ENTRIES = 2000
    _MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024  # 500 MiB uncompressed limit
    _MAX_COMPRESSION_RATIO = 50.0
    if zipfile.is_zipfile(_io.BytesIO(contents)):
        try:
            with zipfile.ZipFile(_io.BytesIO(contents)) as zf:
                entries = zf.infolist()
                if len(entries) > _MAX_ZIP_ENTRIES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"APK archive contains {len(entries)} entries (limit: {_MAX_ZIP_ENTRIES}). Possible ZIP bomb.",
                    )
                total_uncompressed = 0
                for entry in entries:
                    if entry.filename.startswith("/") or ".." in entry.filename:
                        raise HTTPException(
                            status_code=415,
                            detail=f"APK entry '{entry.filename[:60]}' contains invalid path traversal characters.",
                        )
                    comp_size = entry.compress_size or 1
                    if entry.file_size > 0 and (entry.file_size / comp_size) > _MAX_COMPRESSION_RATIO:
                        raise HTTPException(
                            status_code=415,
                            detail=f"APK entry '{entry.filename[:60]}' has suspicious compression ratio ({entry.file_size / comp_size:.1f}x). Possible decompression bomb.",
                        )
                    total_uncompressed += entry.file_size
                    if total_uncompressed > _MAX_UNCOMPRESSED_BYTES:
                        raise HTTPException(
                            status_code=413,
                            detail=f"APK archive total uncompressed size exceeds limit ({_MAX_UNCOMPRESSED_BYTES // (1024*1024)} MiB).",
                        )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=415, detail=f"APK archive validation failed: {exc}")

    upload_id = str(uuid.uuid4())
    path = UPLOAD_DIR / f"upload_{upload_id}.apk"
    try:
        path.write_bytes(contents)
    except OSError as exc:
        logger.exception("Could not persist uploaded APK")
        raise HTTPException(status_code=500, detail="Could not save the uploaded APK.") from exc

    record = {
        "path": path,
        "filename": Path(file.filename).name,
        "size_bytes": len(contents),
        "sha256": hashlib.sha256(contents).hexdigest(),
        "created_at": _now(),
    }
    with STATE_LOCK:
        UPLOADS[upload_id] = record
    return UploadResponse(
        upload_id=upload_id,
        filename=record["filename"],
        size_bytes=record["size_bytes"],
        sha256=record["sha256"],
    )


@app.get("/api/threat-intel/status", response_model=ThreatIntelStatusResponse)
def threat_intel_status_endpoint() -> ThreatIntelStatusResponse:
    env_key = get_configured_abuseipdb_key()
    if env_key:
        return ThreatIntelStatusResponse(
            configured=True,
            source="env",
            message="AbuseIPDB API key is configured in backend environment (via .env).",
        )
    return ThreatIntelStatusResponse(
        configured=False,
        source="none",
        message="AbuseIPDB API key is not configured. Add ABUSEIPDB_API_KEY to your local .env file and restart the backend.",
    )


@app.post("/api/threat-intel/test-key", response_model=ThreatIntelTestResponse)
def test_threat_intel_key(body: ThreatIntelTestRequest | None = None) -> ThreatIntelTestResponse:
    # Key is read exclusively from backend environment (.env), never from request
    key = get_configured_abuseipdb_key()

    if not key:
        return ThreatIntelTestResponse(
            success=False,
            status_code=400,
            message="No AbuseIPDB API key configured in backend. Please set ABUSEIPDB_API_KEY in the root .env file and restart the backend.",
            sample_result=None,
        )

    try:
        res = check_ip("1.1.1.1", api_key=key, timeout=5)
        if res.get("status") in ("checked", "success"):
            sample = {
                "ip": res.get("ip"),
                "abuse_score": res.get("abuse_score"),
                "total_reports": res.get("total_reports"),
                "country": res.get("country"),
                "isp": res.get("isp"),
                "status": "checked",
            }
            return ThreatIntelTestResponse(
                success=True,
                status_code=200,
                message="AbuseIPDB connection test succeeded using configured .env key.",
                sample_result=sample,
            )
        else:
            return ThreatIntelTestResponse(
                success=False,
                status_code=400,
                message=f"AbuseIPDB test returned status: {res.get('status')}",
                sample_result=None,
            )
    except Exception as exc:
        err_msg = str(exc)
        if key in err_msg:
            err_msg = err_msg.replace(key, "[REDACTED]")
        status_code = 401 if ("401" in err_msg or "rejected" in err_msg.lower()) else \
                      429 if ("429" in err_msg or "rate limit" in err_msg.lower()) else 400
        return ThreatIntelTestResponse(
            success=False,
            status_code=status_code,
            message=f"AbuseIPDB connection test failed: {err_msg}",
            sample_result=None,
        )


@app.post("/api/analyze/static", response_model=StaticAnalysisResponse)
def analyze_static(request: StaticAnalysisRequest) -> StaticAnalysisResponse:
    if not STATIC_MODEL.is_file():
        raise HTTPException(status_code=503, detail="Static model artifact is unavailable.")
    uploaded = _take_upload(request.upload_id)

    enable_threat_intel = request.enable_threat_intel
    abuse_key = None
    threat_intel_status = "disabled"
    if enable_threat_intel:
        env_key = get_configured_abuseipdb_key()
        if env_key:
            abuse_key = env_key
            threat_intel_status = "configured"
        else:
            threat_intel_status = "missing_key"

    try:
        result = analyze_apk(
            str(uploaded["path"]),
            abuse_key=abuse_key,
            resolve_domains=request.resolve_domains,
            urlhaus_key=os.environ.get("ABUSECH_AUTH_KEY"),
            model_path=str(STATIC_MODEL),
            top_n=12,
            verbose=False,
        )
        info = result["info"]
        row = result["features"]
        detected = [str(feature) for feature in row.columns[row.iloc[0] == 1]]

        shap_map = result["static"].get("shap_map") or {e["feature"]: e["shap"] for e in result["static"]["evidence"]}
        detailed_explanations: list[StaticFeatureExplanation] = []
        explained_keys = set()
        for feat in detected:
            val = shap_map.get(feat)
            exp_data = explain_static_feature(feat, present=True, shap_value=val)
            detailed_explanations.append(StaticFeatureExplanation(**exp_data))
            explained_keys.add(feat)

        for ev in result["static"]["evidence"]:
            feat = ev["feature"]
            if feat not in explained_keys:
                exp_data = explain_static_feature(feat, present=bool(ev.get("present", False)), shap_value=ev.get("shap"))
                detailed_explanations.append(StaticFeatureExplanation(**exp_data))
                explained_keys.add(feat)

        analysis_id = str(uuid.uuid4())
        with STATE_LOCK:
            STATIC_RESULTS[analysis_id] = {
                "result": result,
                "filename": uploaded["filename"],
                "sha256": uploaded["sha256"],
                "threat_intel_status": threat_intel_status,
                "detailed_explanations": [e.model_dump() for e in detailed_explanations],
                "created_at": _now(),
            }
        n_dex = int(result.get("n_dex", info.get("n_dex", 0)))
        n_active_features = int(result.get("n_active_features", row.sum(axis=1).iloc[0]))
        verdict_reason = result["static"].get("verdict_reason") or result["static"].get("reason")
        return StaticAnalysisResponse(
            analysis_id=analysis_id,
            filename=uploaded["filename"],
            sha256=uploaded["sha256"],
            package=str(info.get("package") or "?"),
            app_name=str(info.get("app_name") or ""),
            version_name=str(info.get("version_name") or ""),
            verdict=result["static"]["verdict"],
            verdict_reason=verdict_reason,
            malware_probability=float(result["static"]["prob_malware"]),
            decision_threshold=0.50,
            classifier_info="Ensemble (Random Forest + XGBoost on Drebin-215)",
            detected_features=detected,
            total_features=int(row.shape[1]),
            n_dex=n_dex,
            n_active_features=n_active_features,
            evidence=result["static"]["evidence"],
            detailed_explanations=detailed_explanations,
            embedded_ips=result["ips"],
            embedded_domains=result["domains"],
            resolved_ips=result.get("resolved", {}),
            lookups=result["lookups"],
            threat_features=result.get("threat_features"),
            threat_intel_status=threat_intel_status,
            lookup_error=result.get("lookup_error"),
            urlhaus=result.get("urlhaus", []),
            domain_entropy=result.get("domain_entropy", []),
            attack_candidates=result.get("attack_candidates", []),
            notice=(
                "This is a model prediction, not definitive proof of malicious behavior. "
                "Embedded indicators are not captured live network traffic."
            ),
        )
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Static APK analysis failed")
        raise HTTPException(status_code=500, detail=f"Static analysis failed: {exc}") from exc
    finally:
        uploaded["path"].unlink(missing_ok=True)


@app.get("/api/analysis/{analysis_id}", response_model=StaticAnalysisResponse)
def get_static_result(analysis_id: str) -> StaticAnalysisResponse:
    with STATE_LOCK:
        saved = STATIC_RESULTS.get(analysis_id)
    if saved is None:
        raise HTTPException(status_code=404, detail="Static analysis result not found.")
    result = saved["result"]
    info = result["info"]
    row = result["features"]
    raw_explanations = saved.get("detailed_explanations", [])
    detailed_explanations = [
        StaticFeatureExplanation(**e) if isinstance(e, dict) else e
        for e in raw_explanations
    ]
    n_dex = int(result.get("n_dex", info.get("n_dex", 0)))
    n_active_features = int(result.get("n_active_features", row.sum(axis=1).iloc[0]))
    verdict_reason = result["static"].get("verdict_reason") or result["static"].get("reason")
    return StaticAnalysisResponse(
        analysis_id=analysis_id,
        filename=saved["filename"],
        sha256=saved["sha256"],
        package=str(info.get("package") or "?"),
        app_name=str(info.get("app_name") or ""),
        version_name=str(info.get("version_name") or ""),
        verdict=result["static"]["verdict"],
        verdict_reason=verdict_reason,
        malware_probability=float(result["static"]["prob_malware"]),
        decision_threshold=0.50,
        classifier_info="Ensemble (Random Forest + XGBoost on Drebin-215)",
        detected_features=[str(feature) for feature in row.columns[row.iloc[0] == 1]],
        total_features=int(row.shape[1]),
        n_dex=n_dex,
        n_active_features=n_active_features,
        evidence=result["static"]["evidence"],
        detailed_explanations=detailed_explanations,
        embedded_ips=result["ips"],
        embedded_domains=result["domains"],
        resolved_ips=result.get("resolved", {}),
        lookups=result["lookups"],
        threat_features=result.get("threat_features"),
        threat_intel_status=saved.get("threat_intel_status", "skipped"),
        lookup_error=result.get("lookup_error"),
        urlhaus=result.get("urlhaus", []),
        domain_entropy=result.get("domain_entropy", []),
        attack_candidates=result.get("attack_candidates", []),
        notice=(
            "This is a model prediction, not definitive proof of malicious behavior. "
            "Embedded indicators are not captured live network traffic."
        ),
    )


@app.get("/api/analysis/{analysis_id}/reports/{format}")
def download_static_report(analysis_id: str, format: str) -> Response:
    with STATE_LOCK:
        saved = STATIC_RESULTS.get(analysis_id)
    if saved is None:
        raise HTTPException(status_code=404, detail="Static analysis result not found.")
    result = saved["result"]
    filename = saved.get("filename", "apk")
    clean_stem = re.sub(r'[^a-zA-Z0-9_\-]', '_', Path(filename).stem) or "apk"
    if format == "json":
        json_bytes = build_static_json_report(
            result,
            filename=saved.get("filename"),
            sha256=saved.get("sha256"),
            analysis_id=analysis_id,
            threat_intel_status=saved.get("threat_intel_status", "skipped"),
        )
        return Response(
            content=json_bytes,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{clean_stem}_analysis_report.json"'},
        )
    if format == "pdf":
        pdf_bytes = build_static_pdf_report(
            result,
            filename=saved.get("filename"),
            sha256=saved.get("sha256"),
            analysis_id=analysis_id,
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{clean_stem}_security_report.pdf"'},
        )
    if format == "csv":
        csv_bytes = build_static_csv_report(
            result,
            filename=saved.get("filename"),
            sha256=saved.get("sha256"),
            analysis_id=analysis_id,
            threat_intel_status=saved.get("threat_intel_status", "skipped"),
        )
        return Response(
            content=csv_bytes,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{clean_stem}_analysis_report.csv"'},
        )
    raise HTTPException(status_code=404, detail="Supported report formats are json, pdf, and csv.")


def _run_dynamic_job(job_id: str, apk_path: Path, filename: str, digest: str,
                     seconds: int, remove_upload: bool) -> None:
    with STATE_LOCK:
        DYNAMIC_JOBS.update_status(job_id, "running", started_at=_now().isoformat())
        job = DYNAMIC_JOBS.get(job_id)
        if job is None:
            raise RuntimeError(f"Job {job_id} disappeared from store before it could start.")
    try:
        if Path.cwd().resolve() != BASE_DIR:
            raise RuntimeError(
                f"Start FastAPI from the project directory ({BASE_DIR}) so the existing "
                "WSL-to-Windows ADB relative-path behavior is preserved."
            )
        adb_path = resolve_adb_executable()
        if not adb_path:
            raise RuntimeError(
                "ADB executable or wrapper was not found. Expected wrapper at /home/ashwith/bin/adb or set ADB_PATH."
            )
        package = dynamic_engine.package_name(str(apk_path))
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+", package):
            raise ValueError("The APK package name is not valid for safe emulator command construction.")
        output = dynamic_engine.analyze_dynamic(
            os.path.relpath(apk_path, BASE_DIR),
            seconds=seconds,
            bundle_path=str(DYNAMIC_MODEL),
            verbose=False,
        )
        capture = output["result"]
        prediction = output["prediction"]
        counts = {str(key): int(value) for key, value in capture["counts"].items()}
        evidence = [
            {"syscall": str(row[0]), "count": float(row[1]), "shap": float(row[2])}
            for row in prediction.get("evidence", [])
        ]
        evidence_shap_map = {str(row[0]): float(row[2]) for row in prediction.get("evidence", [])}

        behavioral_anomalies: list[DynamicAnomalyExplanation] = []
        explained_syscalls = set()
        for ev in evidence:
            sc = ev["syscall"]
            cnt = int(counts.get(sc, ev["count"]))
            anomaly_data = explain_dynamic_syscall(sc, count=cnt, shap_value=ev["shap"])
            behavioral_anomalies.append(DynamicAnomalyExplanation(**anomaly_data))
            explained_syscalls.add(sc)

        for sc, cnt in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:15]:
            if sc not in explained_syscalls:
                anomaly_data = explain_dynamic_syscall(sc, count=cnt, shap_value=evidence_shap_map.get(sc))
                behavioral_anomalies.append(DynamicAnomalyExplanation(**anomaly_data))
                explained_syscalls.add(sc)

        # Runtime Threat Intelligence: query live destinations established during trace
        runtime_ti = []
        raw_conns = capture.get("runtime_connections", [])
        abuse_key = get_configured_abuseipdb_key()
        for conn in raw_conns[:10]:
            ip = conn.get("ip")
            port = conn.get("port")
            if not ip:
                continue
            entry = {"ip": ip, "port": port, "status": "unqueried", "abuse_score": 0, "total_reports": 0, "isp": None, "country": None}
            if abuse_key:
                try:
                    ip_data = static_engine.check_ip(ip, api_key=abuse_key, timeout=4)
                    entry.update({
                        "abuse_score": ip_data.get("abuse_score", 0),
                        "total_reports": ip_data.get("total_reports", 0),
                        "isp": ip_data.get("isp"),
                        "country": ip_data.get("country"),
                        "status": ip_data.get("status", "checked"),
                    })
                except Exception as e:
                    entry["status"] = f"error: {str(e)[:50]}"
            else:
                entry["status"] = "unconfigured_key"
            runtime_ti.append(entry)

        result = DynamicAnalysisResult(
            job_id=job_id,
            filename=filename,
            sha256=digest,
            package=str(capture["package"]),
            requested_seconds=seconds,
            actual_seconds=float(capture["seconds"]),
            decision_threshold=0.50,
            classifier_info="Dynamic XGBoost (Normalized Syscall Shares on CICMalDroid2020)",
            # malware_probability = probability_normalized_shares (xgb_share drives verdict)
            malware_probability=float(prediction["shares"]),
            active_model="xgb_share",
            verdict="MALWARE" if float(prediction["shares"]) >= 0.50 else "BENIGN",
            counts=counts,
            mapped_counts={str(k): int(v) for k, v in output["mapped"].items()},
            unmapped_counts={str(k): int(v) for k, v in output["unmapped"].items()},
            system_call_count=sum(counts.values()),
            vocabulary_coverage=float(output["coverage"]),
            features_seen=len(output["mapped"]),
            probability_normalized_shares=float(prediction["shares"]),
            probability_raw_counts=float(prediction["counts"]),
            shap_evidence=evidence,
            behavioral_anomalies=behavioral_anomalies,
            runtime_threat_intelligence=runtime_ti,
            raw_report=str(capture.get("raw_text", "")),
            notice=(
                "A model prediction is not definitive proof of malicious behavior. "
                "This live run is experimental: the model was trained on CICMalDroid2020 "
                "and the emulator may differ in Android version, CPU, and capture duration."
            ),
        )
        with STATE_LOCK:
            DYNAMIC_JOBS.set_result(job_id, result.model_dump())
            DYNAMIC_JOBS.update_status(job_id, "completed", completed_at=_now().isoformat())
    except Exception as exc:
        logger.exception("Dynamic analysis job %s failed", job_id)
        with STATE_LOCK:
            DYNAMIC_JOBS.update_status(job_id, "failed", error=str(exc)[:1000], completed_at=_now().isoformat())
    finally:
        if remove_upload:
            try:
                apk_path.unlink(missing_ok=True)
            except OSError:
                logger.exception("Could not remove dynamic upload for job %s", job_id)
        DYNAMIC_LOCK.release()


@app.post(
    "/api/analyze/dynamic",
    response_model=DynamicAnalysisAccepted,
    status_code=202,
)
def start_dynamic_analysis(request: DynamicAnalysisRequest) -> DynamicAnalysisAccepted:
    if not request.confirmed_execution:
        raise HTTPException(
            status_code=400,
            detail="Explicit confirmation is required before the APK is executed in the emulator.",
        )
    if request.use_sample == (request.upload_id is not None):
        raise HTTPException(
            status_code=400,
            detail="Choose exactly one source: the bundled sample or an uploaded APK.",
        )
    if not DYNAMIC_MODEL.is_file():
        raise HTTPException(status_code=503, detail="Dynamic model artifact is unavailable.")
    if not DYNAMIC_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="A dynamic emulator analysis is already active.")

    uploaded = None
    try:
        if Path.cwd().resolve() != BASE_DIR:
            raise HTTPException(
                status_code=503,
                detail=f"Start FastAPI from the project directory to preserve ADB path handling: {BASE_DIR}",
            )
        readiness = _readiness(allow_active_check=True)
        if not readiness["emulator_ready"]:
            raise HTTPException(
                status_code=409,
                detail={"message": "The emulator is not ready.", "checks": readiness},
            )
        if request.use_sample:
            apk_path = BASE_DIR / "sample_app.apk"
            if not apk_path.is_file():
                raise HTTPException(status_code=404, detail="Bundled sample_app.apk was not found.")
            filename = apk_path.name
            digest = hashlib.sha256(apk_path.read_bytes()).hexdigest()
            remove_upload = False
        else:
            uploaded = _take_upload(request.upload_id or "")
            apk_path = uploaded["path"]
            filename = uploaded["filename"]
            digest = uploaded["sha256"]
            remove_upload = True

        job_id = str(uuid.uuid4())
        DYNAMIC_JOBS.create({
            "job_id": job_id,
            "status": "queued",
            "filename": filename,
            "requested_seconds": request.seconds,
            "created_at": _now().isoformat(),
        })
        EXECUTOR.submit(
            _run_dynamic_job, job_id, apk_path, filename, digest,
            request.seconds, remove_upload,
        )
        return DynamicAnalysisAccepted(job_id=job_id, filename=filename)
    except Exception:
        if uploaded is not None:
            try:
                uploaded["path"].unlink(missing_ok=True)
            except OSError:
                logger.exception("Could not remove unstarted dynamic upload")
        DYNAMIC_LOCK.release()
        raise


@app.get("/api/analyze/dynamic/{job_id}", response_model=DynamicJobStatus)
def dynamic_job_status(job_id: str) -> DynamicJobStatus:
    job = DYNAMIC_JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Dynamic analysis job not found.")
    return DynamicJobStatus(**{
        key: job[key] for key in (
            "job_id", "status", "filename", "requested_seconds",
            "created_at", "started_at", "completed_at", "error",
        )
    })


@app.get("/api/analyze/dynamic/{job_id}/result", response_model=DynamicAnalysisResult)
def dynamic_job_result(job_id: str) -> DynamicAnalysisResult:
    job = DYNAMIC_JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Dynamic analysis job not found.")
    if job["status"] != "completed" or not job.get("result"):
        raise HTTPException(status_code=409, detail=f"Job result is not ready (status: {job['status']}).")
    return DynamicAnalysisResult(**job["result"])


@app.get("/api/analyze/dynamic/{job_id}/reports/{format}")
@app.get("/api/analyze/dynamic/{job_id}/report/{format}")
def download_dynamic_report(job_id: str, format: str) -> Response:
    job = DYNAMIC_JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Dynamic analysis job not found.")
    if job["status"] != "completed" or not job.get("result"):
        raise HTTPException(status_code=409, detail=f"Job report is not ready (status: {job['status']}).")
    result = job["result"]
    filename = job.get("filename", "apk")
    clean_stem = re.sub(r'[^a-zA-Z0-9_\-]', '_', Path(filename).stem) or "apk"
    if format == "json":
        json_bytes = build_dynamic_json_report(result, job_info=job)
        return Response(
            content=json_bytes,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{clean_stem}_dynamic_report.json"'},
        )
    if format == "pdf":
        from backend.reports import build_dynamic_pdf_report
        pdf_bytes = build_dynamic_pdf_report(result, job_info=job)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{clean_stem}_dynamic_report.pdf"'},
        )
    raise HTTPException(status_code=404, detail="Supported dynamic report formats are json and pdf.")


@app.get("/api/research/benchmarks", response_model=list[ResearchGroup])
def research_benchmarks() -> list[ResearchGroup]:
    groups = []
    for group_id, label, artifact_ids in RESEARCH_GROUPS:
        artifacts = []
        for artifact_id in artifact_ids:
            path, artifact_label, kind = _artifact_path_optional(artifact_id)
            artifacts.append({
                "id": artifact_id,
                "label": artifact_label,
                "kind": kind,
                "available": path.is_file(),
            })
        groups.append({"id": group_id, "label": label, "artifacts": artifacts})
    return [ResearchGroup(**group) for group in groups]


def _artifact_path_optional(artifact_id: str) -> tuple[Path, str, str]:
    group, label, filename = ARTIFACTS[artifact_id]
    folder = BASE_DIR / ("static_outputs" if group == "static" else "dynamic_outputs_v2")
    path = folder / filename
    kind = "image" if path.suffix.lower() == ".png" else "table"
    return path, label, kind


def _format_dataframe(frame: pd.DataFrame, path: Path) -> pd.DataFrame:
    if len(frame.columns) > 0 and (str(frame.columns[0]).startswith("Unnamed:") or frame.columns[0] == ""):
        first_col = "Model / Architecture" if ("results" in path.name or "cv" in path.name or "pooled" in path.name) else "Category"
        frame = frame.rename(columns={frame.columns[0]: first_col})
    return frame


@app.get("/api/research/benchmarks/tables", response_model=dict[str, ResearchTableResponse])
def research_tables() -> dict[str, Any]:
    tables: dict[str, Any] = {}
    for artifact_id, (group, label, filename) in ARTIFACTS.items():
        if filename.endswith(".csv"):
            folder = BASE_DIR / ("static_outputs" if group == "static" else "dynamic_outputs_v2")
            path = folder / filename
            if path.is_file():
                try:
                    frame = _format_dataframe(pd.read_csv(path), path)
                    tables[artifact_id] = {
                        "id": artifact_id,
                        "label": label,
                        "columns": [str(c) for c in frame.columns],
                        "rows": frame.astype(object).where(pd.notna(frame), None).to_dict(orient="records"),
                    }
                except Exception as exc:
                    logger.warning("Could not read CSV for %s: %s", artifact_id, exc)
    return tables


@app.get("/api/research/benchmarks/artifacts/{artifact_id}")
def research_artifact(artifact_id: str) -> Response:
    path, label, kind = _artifact_path(artifact_id)
    if kind == "image":
        return FileResponse(path, media_type="image/png", content_disposition_type="inline")
    try:
        frame = _format_dataframe(pd.read_csv(path), path)
        payload = {
            "id": artifact_id,
            "label": label,
            "columns": [str(column) for column in frame.columns],
            "rows": frame.astype(object).where(pd.notna(frame), None).to_dict(orient="records"),
        }
    except Exception as exc:
        logger.exception("Could not read benchmark artifact %s", artifact_id)
        raise HTTPException(status_code=500, detail=f"Could not read saved benchmark data: {exc}") from exc
    return JSONResponse(payload)
