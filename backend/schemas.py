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


class ThreatIntelStatusResponse(BaseModel):
    configured: bool
    source: Literal["env", "none"]
    message: str = ""


class ThreatIntelTestRequest(BaseModel):
    model_config = {"extra": "ignore"}


class ThreatIntelTestResponse(BaseModel):
    success: bool
    status_code: int
    message: str
    sample_result: dict[str, Any] | None = None


class StaticFeatureExplanation(BaseModel):
    feature: str
    category: str
    present: bool
    shap: float | None = None
    direction: str
    risk_level: str
    description: str
    security_context: str
    interpretation: str


class DynamicAnomalyExplanation(BaseModel):
    syscall: str
    count: int
    category: str
    shap: float | None = None
    direction: str
    description: str
    investigation_reason: str
    benign_context: str
    interpretation: str


class StaticAnalysisRequest(BaseModel):
    upload_id: str
    resolve_domains: bool = False
    enable_threat_intel: bool = True


STATIC_CSV_COLUMNS: list[str] = [
    "analysis_id",
    "filename",
    "sha256",
    "package_name",
    "app_name",
    "version_name",
    "verdict",
    "verdict_reason",
    "malware_probability",
    "decision_threshold",
    "classifier",
    "n_dex",
    "n_active_features",
    "total_features",
    "network_risk",
    "max_abuse_score",
    "malicious_ip_count",
    "timestamp",
]


class StaticAnalysisResponse(BaseModel):
    analysis_id: str
    filename: str
    sha256: str
    package: str
    app_name: str
    version_name: str
    verdict: str
    verdict_reason: str | None = None
    malware_probability: float = Field(ge=0, le=1)
    decision_threshold: float = 0.50
    classifier_info: str = "Ensemble (Random Forest + XGBoost on Drebin-215)"
    detected_features: list[str]
    total_features: int
    n_dex: int = 0
    n_active_features: int = 0
    evidence: list[dict[str, Any]]
    detailed_explanations: list[StaticFeatureExplanation] = Field(default_factory=list)
    embedded_ips: dict[str, str]
    embedded_domains: dict[str, str]
    resolved_ips: dict[str, str]
    lookups: list[dict[str, Any]]
    threat_features: dict[str, Any] | None
    threat_intel_status: str = "skipped"
    lookup_error: str | None
    notice: str
    urlhaus: list[dict[str, Any]] = Field(default_factory=list)
    domain_entropy: list[dict[str, Any]] = Field(default_factory=list)
    attack_candidates: list[dict[str, Any]] = Field(default_factory=list)


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
    status: Literal["queued", "running", "completed", "failed", "interrupted"]
    stage: str | None = None
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
    decision_threshold: float = 0.50
    classifier_info: str = "Dynamic XGBoost (Normalized Syscall Shares on CICMalDroid2020)"
    # Verdict fields - malware_probability mirrors probability_normalized_shares (xgb_share model).
    # The verdict is driven exclusively by the normalized-shares model (active_model = "xgb_share").
    malware_probability: float = Field(ge=0, le=1, default=0.0)
    active_model: str = "xgb_share"
    verdict: str = "UNKNOWN"
    counts: dict[str, int]
    mapped_counts: dict[str, int]
    unmapped_counts: dict[str, int]
    system_call_count: int
    vocabulary_coverage: float = Field(ge=0, le=1)
    features_seen: int
    probability_normalized_shares: float = Field(ge=0, le=1)
    probability_raw_counts: float = Field(ge=0, le=1)
    shap_evidence: list[dict[str, Any]]
    behavioral_anomalies: list[DynamicAnomalyExplanation] = Field(default_factory=list)
    runtime_threat_intelligence: list[dict[str, Any]] = Field(default_factory=list)
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
