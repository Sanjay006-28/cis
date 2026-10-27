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

export interface StaticResult {
  analysis_id: string;
  filename: string;
  sha256: string;
  package: string;
  app_name: string;
  version_name: string;
  verdict: string;
  malware_probability: number;
  detected_features: string[];
  total_features: number;
  evidence: Evidence[];
  embedded_ips: Record<string, string>;
  embedded_domains: Record<string, string>;
  resolved_ips: Record<string, string>;
  lookups: Array<Record<string, string | number | null>>;
  threat_features: Record<string, string | number> | null;
  lookup_error: string | null;
  notice: string;
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
  counts: Record<string, number>;
  mapped_counts: Record<string, number>;
  unmapped_counts: Record<string, number>;
  system_call_count: number;
  vocabulary_coverage: number;
  features_seen: number;
  probability_normalized_shares: number;
  probability_raw_counts: number;
  shap_evidence: Array<{ syscall: string; count: number; shap: number }>;
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
