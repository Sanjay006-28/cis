from typing import Any, Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    service: str = "android-malware-analysis-api"


class UploadResponse(BaseModel):
    upload_id: str
    filename: str
    size_bytes: int
    sha256: str


class StaticAnalysisRequest(BaseModel):
    upload_id: str
    resolve_domains: bool = False


class StaticAnalysisResponse(BaseModel):
    analysis_id: str
    filename: str
    sha256: str
    package: str
    app_name: str
    version_name: str
    verdict: str
    malware_probability: float = Field(ge=0, le=1)
    detected_features: list[str]
    total_features: int
    evidence: list[dict[str, Any]]
    embedded_ips: dict[str, str]
    embedded_domains: dict[str, str]
    resolved_ips: dict[str, str]
    lookups: list[dict[str, Any]]
    threat_features: dict[str, Any] | None
    lookup_error: str | None
    notice: str


class DynamicAnalysisRequest(BaseModel):
    upload_id: str | None = None
    use_sample: bool = False
    seconds: int = Field(default=30, ge=10, le=300)
    confirmed_execution: bool = False


class DynamicAnalysisAccepted(BaseModel):
    job_id: str
    status: Literal["queued"] = "queued"
    filename: str


class DynamicJobStatus(BaseModel):
    job_id: str
    status: Literal["queued", "running", "completed", "failed"]
    filename: str
    requested_seconds: int
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    error: str | None = None


class DynamicAnalysisResult(BaseModel):
    job_id: str
    filename: str
    sha256: str
    package: str
    requested_seconds: int
    actual_seconds: float
    counts: dict[str, int]
    mapped_counts: dict[str, int]
    unmapped_counts: dict[str, int]
    system_call_count: int
    vocabulary_coverage: float = Field(ge=0, le=1)
    features_seen: int
    probability_normalized_shares: float = Field(ge=0, le=1)
    probability_raw_counts: float = Field(ge=0, le=1)
    shap_evidence: list[dict[str, Any]]
    raw_report: str
    notice: str


class SystemStatusResponse(BaseModel):
    static_model_available: bool
    dynamic_model_available: bool
    static_analysis_available: bool
    adb_available: bool
    adb_path: str | None
    emulator_connected: bool
    emulator_serial: str | None
    emulator_ready: bool
    emulator_checks: dict[str, Any]
    analysis_busy: bool


class ResearchArtifact(BaseModel):
    id: str
    label: str
    kind: Literal["table", "image"]
    available: bool


class ResearchGroup(BaseModel):
    id: str
    label: str
    artifacts: list[ResearchArtifact]


class ResearchTableResponse(BaseModel):
    id: str
    label: str
    columns: list[str]
    rows: list[dict[str, Any]]
