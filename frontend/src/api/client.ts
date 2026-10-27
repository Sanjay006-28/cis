import type {
  DynamicAccepted,
  DynamicJob,
  DynamicResult,
  Health,
  ResearchGroup,
  ResearchTable,
  StaticResult,
  SystemStatus,
  UploadReceipt,
} from "../types";

export const API_BASE = import.meta.env.VITE_API_URL ?? "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, init);
  } catch {
    throw new Error(`Could not reach the API at ${API_BASE}. Check that FastAPI is running.`);
  }
  if (!response.ok) {
    const payload: unknown = await response.json().catch(() => null);
    const detail =
      payload &&
      typeof payload === "object" &&
      "detail" in payload
        ? (payload as { detail: unknown }).detail
        : `Request failed (${response.status})`;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return response.json() as Promise<T>;
}

export function getHealth() {
  return request<Health>("/api/health");
}

export function getSystemStatus() {
  return request<SystemStatus>("/api/system/status");
}

export async function uploadApk(file: File) {
  const body = new FormData();
  body.append("file", file);
  return request<UploadReceipt>("/api/uploads", { method: "POST", body });
}

export function analyzeStatic(uploadId: string, resolveDomains: boolean) {
  return request<StaticResult>("/api/analyze/static", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ upload_id: uploadId, resolve_domains: resolveDomains }),
  });
}

export function startDynamic(input: {
  upload_id?: string;
  use_sample: boolean;
  seconds: number;
  confirmed_execution: boolean;
}) {
  return request<DynamicAccepted>("/api/analyze/dynamic", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function getDynamicJob(jobId: string) {
  return request<DynamicJob>(`/api/analyze/dynamic/${encodeURIComponent(jobId)}`);
}

export function getDynamicResult(jobId: string) {
  return request<DynamicResult>(
    `/api/analyze/dynamic/${encodeURIComponent(jobId)}/result`,
  );
}

export function getBenchmarks() {
  return request<ResearchGroup[]>("/api/research/benchmarks");
}

export function getAllBenchmarkTables() {
  return request<Record<string, ResearchTable>>("/api/research/benchmarks/tables");
}

export function getBenchmarkTable(artifactId: string) {
  return request<ResearchTable>(
    `/api/research/benchmarks/artifacts/${encodeURIComponent(artifactId)}`,
  );
}

export function reportUrl(analysisId: string, format: "json" | "pdf") {
  return `${API_BASE}/api/analysis/${encodeURIComponent(analysisId)}/reports/${format}`;
}

export function benchmarkArtifactUrl(artifactId: string) {
  return `${API_BASE}/api/research/benchmarks/artifacts/${encodeURIComponent(artifactId)}`;
}
