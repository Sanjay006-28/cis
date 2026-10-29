export interface Health {
  status: "ok";
  service: string;
}

export interface UploadReceipt {
  upload_id: string;
  filename: string;
  size_bytes: number;
  sha256: string;
}

export interface Evidence {
  feature: string;
  present: boolean;
  shap: number;
}

export interface FeatureExplanation {
  feature: string;
  category: "permission" | "api_call" | "intent_filter" | "shell_command";
  present: boolean;
  shap: number | null;
  direction: "toward_malware" | "toward_benign" | "neutral";
  risk_level: string;
  description: string;
  security_context: string;
  interpretation: string;
}

export interface AbuseIPLookup {
  ip: string;
  abuse_score: number | null;
  total_reports: number;
  country: string | null;
  isp: string | null;
  domain: string | null;
  usage_type: string | null;
  last_reported: string | null;
  status: "checked" | "skipped_private" | "failed";
  error: string | null;
  source?: string;
}

export interface ThreatIntelStatus {
  configured: boolean;
  source: "env" | "none";
  message: string;
}

export interface ThreatIntelTestResult {
  success: boolean;
  status_code: number;
  message: string;
  sample_result: Record<string, unknown> | null;
}

export interface StaticResult {
  analysis_id: string;
  filename: string;
  sha256: string;
  package: string;
  app_name: string;
  version_name: string;
  verdict: string;
  verdict_reason?: string | null;
  malware_probability: number;
  decision_threshold: number;
  classifier_info: string;
  detected_features: string[];
  total_features: number;
  n_dex?: number;
  n_active_features?: number;
  evidence: Evidence[];
  detailed_explanations: FeatureExplanation[];
  embedded_ips: Record<string, string>;
  embedded_domains: Record<string, string>;
  resolved_ips: Record<string, string>;
  lookups: AbuseIPLookup[];
  threat_features: {
    max_abuse_score: number;
    malicious_ip_count: number;
    network_risk: string;
  } | null;
  threat_intel_status: string;
  lookup_error: string | null;
  notice: string;
  urlhaus?: UrlhausLookup[];
  domain_entropy?: DomainEntropyResult[];
  attack_candidates?: AttackCandidate[];
}

export interface UrlhausLookup {
  status: "LISTED" | "NOT_LISTED" | "UNAVAILABLE" | string;
  host: string;
  url_count?: number;
  urlhaus_reference?: string;
  error?: string;
}

export interface DomainEntropyResult {
  domain: string;
  label: string;
  entropy: number;
  flag: boolean;
}

export interface AttackCandidate {
  technique_id: string;
  technique_name: string;
  type: string;
  label: string;
  evidence: string;
}

export interface DynamicAnomalyExplanation {
  syscall: string;
  count: number;
  category: string;
  shap: number | null;
  direction: "toward_malware" | "toward_benign" | "neutral";
  description: string;
  investigation_reason: string;
  benign_context: string;
  interpretation: string;
}

export interface SystemStatus {
  static_model_available: boolean;
  dynamic_model_available: boolean;
  static_analysis_available: boolean;
  adb_available: boolean;
  adb_path: string | null;
  emulator_connected: boolean;
  emulator_serial: string | null;
  emulator_ready: boolean;
  emulator_checks: Record<string, unknown>;
  analysis_busy: boolean;
}

export interface DynamicAccepted {
  job_id: string;
  status: "queued";
  filename: string;
}

export interface DynamicJob {
  job_id: string;
  status: "queued" | "running" | "completed" | "failed";
  filename: string;
  requested_seconds: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
}

export interface DynamicResult {
  job_id: string;
  filename: string;
  sha256: string;
  package: string;
  requested_seconds: number;
  actual_seconds: number;
  decision_threshold: number;
  classifier_info: string;
  counts: Record<string, number>;
  mapped_counts: Record<string, number>;
  unmapped_counts: Record<string, number>;
  system_call_count: number;
  vocabulary_coverage: number;
  features_seen: number;
  probability_normalized_shares: number;
  probability_raw_counts: number;
  shap_evidence: Array<{ syscall: string; count: number; shap: number }>;
  behavioral_anomalies: DynamicAnomalyExplanation[];
  raw_report: string;
  notice: string;
}

export interface ResearchArtifact {
  id: string;
  label: string;
  kind: "table" | "image";
  available: boolean;
}

export interface ResearchGroup {
  id: string;
  label: string;
  artifacts: ResearchArtifact[];
}

export interface ResearchTable {
  label: string;
  columns: string[];
  rows: Array<Record<string, string | number | null>>;
}
