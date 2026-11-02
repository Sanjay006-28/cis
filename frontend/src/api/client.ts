import type {
  DynamicAccepted,
  DynamicJob,
  DynamicResult,
  Health,
  ResearchGroup,
  ResearchTable,
  StaticResult,
  SystemStatus,
  ThreatIntelStatus,
  ThreatIntelTestResult,
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

export function getThreatIntelStatus() {
  return request<ThreatIntelStatus>("/api/threat-intel/status");
}

export function testThreatIntelKey() {
  return request<ThreatIntelTestResult>("/api/threat-intel/test-key", {
    method: "POST",
  });
}

export function analyzeStatic(
  uploadId: string,
  resolveDomains: boolean,
  enableThreatIntel: boolean = true,
) {
  return request<StaticResult>("/api/analyze/static", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      upload_id: uploadId,
      resolve_domains: resolveDomains,
      enable_threat_intel: enableThreatIntel,
    }),
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

export function reportUrl(analysisId: string, format: "json" | "pdf" | "csv") {
  return `${API_BASE}/api/analysis/${encodeURIComponent(analysisId)}/reports/${format}`;
}

export function dynamicReportUrl(jobId: string, format: "json" | "pdf" = "json") {
  return `${API_BASE}/api/analyze/dynamic/${encodeURIComponent(jobId)}/reports/${format}`;
}

export function benchmarkArtifactUrl(artifactId: string) {
  return `${API_BASE}/api/research/benchmarks/artifacts/${encodeURIComponent(artifactId)}`;
}

export async function downloadReportFile(url: string, fallbackFilename: string): Promise<void> {
  const response = await fetch(url);
  if (!response.ok) {
    let errorDetail = `Download failed (${response.status})`;
    try {
      const errJson = await response.json();
      if (errJson && errJson.detail) errorDetail = errJson.detail;
    } catch {
      // ignore
    }
    throw new Error(errorDetail);
  }

  let filename = fallbackFilename;
  const disposition = response.headers.get("Content-Disposition");
  if (disposition && disposition.includes("filename=")) {
    const match = disposition.match(/filename=["']?([^"';]+)["']?/);
    if (match && match[1]) {
      filename = match[1].trim();
    }
  }

  const blob = await response.blob();
  const blobUrl = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = blobUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(blobUrl);
}
