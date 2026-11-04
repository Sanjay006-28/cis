import { useEffect, useState } from "react";
import { Activity, AlertTriangle, ChevronDown, ChevronRight, Download, Info, Play, RefreshCw } from "lucide-react";
import {
  downloadReportFile,
  dynamicReportUrl,
  getDynamicJob,
  getDynamicResult,
  getSystemStatus,
  startDynamic,
  uploadApk,
} from "../api/client";
import { SectionHeader } from "../components/SectionHeader";
import { StateMessage } from "../components/StateMessage";
import type { DynamicAnomalyExplanation, DynamicJob, DynamicResult, SystemStatus, UploadReceipt } from "../types";

const SAVED_JOB_KEY = "sentinel.activeDynamicJobId";

function DirectionBadge({ direction }: { direction: string }) {
  if (direction === "toward_malware") return <span className="badge badge-dir-malware">↑ Toward malware</span>;
  if (direction === "toward_benign") return <span className="badge badge-dir-benign">↓ Toward benign</span>;
  return <span className="badge badge-neutral">— Neutral</span>;
}

function AnomalyCategoryGroup({
  category,
  anomalies,
}: {
  category: string;
  anomalies: DynamicAnomalyExplanation[];
}) {
  const [open, setOpen] = useState(false);
  if (!anomalies.length) return null;
  const malwareCount = anomalies.filter((a) => a.direction === "toward_malware").length;

  return (
    <div className="category-card">
      <div className="category-header" onClick={() => setOpen(!open)}>
        <div className="category-header-title">
          {open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
          <span>{category}</span>
          <span className="badge badge-neutral">{anomalies.length} syscalls</span>
          {malwareCount > 0 && (
            <span className="badge badge-dir-malware">{malwareCount} push malware</span>
          )}
        </div>
      </div>
      {open && anomalies.map((a) => (
        <div className="feature-item-card" key={a.syscall}>
          <div className="feature-item-top">
            <span className="feature-name">{a.syscall}</span>
            <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", alignItems: "center" }}>
              <span className="badge badge-neutral" style={{ fontFamily: "monospace" }}>×{a.count.toLocaleString()}</span>
              <DirectionBadge direction={a.direction} />
              {a.shap !== null && (
                <span className="badge badge-neutral" style={{ fontFamily: "monospace" }}>
                  SHAP {(a.shap ?? 0) > 0 ? "+" : ""}{(a.shap ?? 0).toFixed(4)}
                </span>
              )}
            </div>
          </div>
          <p className="feature-desc">{a.description}</p>
          <p className="feature-context">{a.investigation_reason}</p>
          <p className="feature-interpretation">{a.interpretation}</p>
        </div>
      ))}
    </div>
  );
}

function BehavioralAnomaliesPanel({ result }: { result: DynamicResult }) {
  const anomalies = result.behavioral_anomalies ?? [];
  if (!anomalies.length) return null;

  // Group by category
  const byCategory: Record<string, DynamicAnomalyExplanation[]> = {};
  for (const a of anomalies) {
    (byCategory[a.category] ??= []).push(a);
  }
  const cats = Object.keys(byCategory).sort();

  const isMalware = result.verdict === "MALWARE" || (!result.verdict && result.probability_normalized_shares >= result.decision_threshold);
  const pct = ((result.malware_probability ?? result.probability_normalized_shares) * 100).toFixed(1);

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Runtime Anomalies and Behavioral Evidence</h2>
          <p>
            System calls captured during {result.actual_seconds}s emulator trace, categorized with local SHAP contribution direction.
            Investigation reasons are based on known attack patterns — they do not confirm malicious intent on their own.
          </p>
        </div>
        <Activity size={18} />
      </div>

      {/* Dynamic prediction summary */}
      <div className="decision-criteria-card" style={{ marginBottom: "16px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "20px", flexWrap: "wrap" }}>
          <div>
            <div style={{ fontSize: "11px", color: "#7f95ac", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "4px" }}>Dynamic Verdict</div>
            <div style={{ fontSize: "24px", fontWeight: 700, color: isMalware ? "#f19890" : "#72c4a4" }}>
              {result.verdict ?? (isMalware ? "MALWARE" : "BENIGN")}
            </div>
          </div>
          <div>
            <div style={{ fontSize: "11px", color: "#7f95ac", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "4px" }}>Prob (norm. shares)</div>
            <div style={{ fontSize: "20px", fontWeight: 700, color: "#dbe7f2" }}>{pct}%</div>
          </div>
          <div>
            <div style={{ fontSize: "11px", color: "#7f95ac", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "4px" }}>Threshold</div>
            <div style={{ fontSize: "16px", fontWeight: 600, color: "#8cabc4" }}>≥ {(result.decision_threshold * 100).toFixed(0)}%</div>
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: "11px", color: "#7f95ac", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "4px" }}>Classifier</div>
            <div style={{ fontSize: "12px", color: "#b3c4d7" }}>{result.classifier_info}</div>
          </div>
        </div>
        <div className="decision-criteria-grid" style={{ marginTop: "12px" }}>
          <div className="decision-criteria-item">
            <h5>How the dynamic model works</h5>
            <p>System call frequencies are normalized to per-call-type shares, then fed to an XGBoost model trained on CICMalDroid2020. SHAP values show which syscalls increased or decreased the malware probability for this run.</p>
          </div>
          <div className="decision-criteria-item">
            <h5>Interpretation guidance</h5>
            <p>
              Syscalls shown below pushed the prediction. High-frequency counts of specific system calls correlate with malicious behavior patterns in the training set — they do not prove actual malice. No claims of C2, exfiltration, or persistence are made without concrete evidence.
            </p>
          </div>
          <div className="decision-criteria-item">
            <h5>Important limitations</h5>
            <p>The emulator environment, Android version, CPU architecture, and trace duration differ from real devices. Results are experimental. This is a research prototype — not a production security tool.</p>
          </div>
        </div>
      </div>

      <p style={{ margin: "0 0 12px", fontSize: "12px", fontWeight: 600, color: "#9db3c7" }}>
        Categorized behavioral indicators — click a category to expand:
      </p>
      {cats.map((cat) => (
        <AnomalyCategoryGroup key={cat} category={cat} anomalies={byCategory[cat]} />
      ))}

      <p style={{ margin: "10px 0 0", fontSize: "11px", color: "#586f83" }}>
        ⚠ These are runtime observations from a controlled emulator sandbox, not forensic proof. SHAP values represent local statistical attribution for this sample only.
      </p>
    </section>
  );
}

export function DynamicPage() {
  const [file, setFile] = useState<File | null>(null);
  const [useSample, setUseSample] = useState(true);
  const [seconds, setSeconds] = useState(60);
  const [uploadStage, setUploadStage] = useState<string>("");
  const [fileMeta, setFileMeta] = useState<{
    name: string;
    size: number;
    sha256: string;
    valid: boolean;
    computing: boolean;
  } | null>(null);

  useEffect(() => {
    if (!file) {
      setFileMeta(null);
      return;
    }
    let active = true;
    setFileMeta({
      name: file.name,
      size: file.size,
      sha256: "Computing SHA-256...",
      valid: false,
      computing: true,
    });
    const reader = new FileReader();
    reader.onload = async () => {
      if (!active) return;
      try {
        const buffer = reader.result as ArrayBuffer;
        const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
        const isValid = file.name.toLowerCase().endsWith(".apk") && file.size > 0 && file.size <= 120 * 1024 * 1024;
        if (active) {
          setFileMeta({
            name: file.name,
            size: file.size,
            sha256: hashHex,
            valid: isValid,
            computing: false,
          });
        }
      } catch {
        if (active) {
          setFileMeta({
            name: file.name,
            size: file.size,
            sha256: "Error computing hash",
            valid: false,
            computing: false,
          });
        }
      }
    };
    reader.readAsArrayBuffer(file);
    return () => {
      active = false;
    };
  }, [file]);
  const [confirmed, setConfirmed] = useState(false);
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [jobId, setJobId] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    const urlJob = params.get("job_id");
    if (urlJob) {
      sessionStorage.setItem(SAVED_JOB_KEY, urlJob);
      return urlJob;
    }
    return sessionStorage.getItem(SAVED_JOB_KEY);
  });
  const [job, setJob] = useState<DynamicJob | null>(null);
  const [result, setResult] = useState<DynamicResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [checking, setChecking] = useState(false);
  const [downloadBusy, setDownloadBusy] = useState(false);
  const [error, setError] = useState("");

  async function checkReadiness() {
    setChecking(true);
    setError("");
    try {
      setStatus(await getSystemStatus());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not check emulator readiness.");
    } finally {
      setChecking(false);
    }
  }

  useEffect(() => {
    if (!jobId) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = async () => {
      try {
        const next = await getDynamicJob(jobId);
        if (!active) return;
        setJob(next);
        if (next.status === "completed") {
          const actualResult = await getDynamicResult(jobId);
          if (active) setResult(actualResult);
          return;
        }
        if (next.status === "failed") return;
        timer = setTimeout(poll, 2000);
      } catch (reason) {
        if (!active) return;
        const msg = reason instanceof Error ? reason.message : String(reason);
        if (msg.includes("404") || msg.toLowerCase().includes("not found")) {
          sessionStorage.removeItem(SAVED_JOB_KEY);
          setJobId(null);
          setJob(null);
          setError("The previous dynamic analysis job is no longer available (the backend may have restarted). The job state has been cleared so you can start a new analysis.");
        } else {
          setError(msg);
        }
      }
    };
    void poll();
    return () => {
      active = false;
      if (timer) clearTimeout(timer);
    };
  }, [jobId]);

  async function beginAnalysis() {
    setBusy(true);
    setError("");
    setResult(null);
    setJob(null);
    setUploadStage("Uploading APK archive to server...");
    try {
      let receipt: UploadReceipt | null = null;
      if (!useSample && file) {
        receipt = await uploadApk(file);
        setUploadStage("Validating APK archive and initiating dynamic session...");
      }
      const accepted = await startDynamic({
        upload_id: receipt?.upload_id,
        use_sample: useSample,
        seconds,
        confirmed_execution: confirmed,
      });
      setUploadStage("");
      setJobId(accepted.job_id);
      sessionStorage.setItem(SAVED_JOB_KEY, accepted.job_id);
      setJob({
        job_id: accepted.job_id,
        status: accepted.status,
        filename: accepted.filename,
        requested_seconds: seconds,
        created_at: new Date().toISOString(),
        started_at: null,
        completed_at: null,
        error: null,
      });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not start dynamic analysis.");
    } finally {
      setBusy(false);
    }
  }

  function clearJob() {
    setJobId(null);
    setJob(null);
    setResult(null);
    sessionStorage.removeItem(SAVED_JOB_KEY);
  }

  async function downloadDynamicJson() {
    if (!jobId) return;
    setDownloadBusy(true);
    try {
      const stem = (result?.filename ?? "apk").replace(/\.apk$/i, "");
      await downloadReportFile(dynamicReportUrl(jobId, "json"), `${stem}_dynamic_report.json`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Download failed.");
    } finally {
      setDownloadBusy(false);
    }
  }

  return (
    <>
      <SectionHeader
        eyebrow="LIVE EMULATOR WORKFLOW"
        title="Dynamic analysis"
        description="Capture system calls in the configured Android emulator using the existing ADB, strace, and CICMalDroid model pipeline."
      />

      <div className="research-callout-card" style={{ marginBottom: "16px" }}>
        <div className="callout-icon"><Info size={18} /></div>
        <div className="callout-content">
          <h4>Dynamic Analysis Workflow</h4>
          <p>
            The dynamic analysis interface and job queue endpoints are wired to the backend.
            Because dynamic execution runs live inside an Android emulator with root access, it is never executed automatically.
            Use <strong>Environment &amp; Emulator</strong> to verify ADB and emulator readiness before initiating a trace.
          </p>
        </div>
      </div>

      <div className="notice notice-warning">
        <AlertTriangle size={18} aria-hidden="true" />
        <p><b>Execution warning.</b> Dynamic analysis installs and runs the selected APK in the emulator. No APK runs automatically on page load or navigation.</p>
      </div>

      {/* Step 1: Check environment */}
      <section className="panel form-panel">
        <div className="panel-heading">
          <div><h2>1 · Check environment</h2><p>The backend verifies the model and emulator prerequisites before starting a run.</p></div>
          <button className="button button-secondary" onClick={checkReadiness} disabled={checking}>
            <RefreshCw size={15} className={checking ? "animate-spin" : ""} /> {checking ? "Checking…" : "Check readiness"}
          </button>
        </div>
        {status && (
          <div className="readiness-summary">
            <StatusItem label="Dynamic model" good={status.dynamic_model_available} />
            <StatusItem label="ADB wrapper" good={status.adb_available} />
            <StatusItem label="Emulator" good={status.emulator_connected} value={status.emulator_serial ?? undefined} />
            <StatusItem label="Capture readiness" good={status.emulator_ready} />
            {status.analysis_busy && <StateMessage kind="info">Another emulator analysis is active.</StateMessage>}
          </div>
        )}
        {status && !status.emulator_ready && status.emulator_checks && (
          <StateMessage kind="error">
            {String((status.emulator_checks as Record<string, unknown>).message ?? "Emulator is not ready.")}
          </StateMessage>
        )}
      </section>

      {/* Step 2: Configure */}
      <section className="panel form-panel">
        <div className="panel-heading">
          <div><h2>2 · Configure analysis</h2><p>Choose the APK source and capture duration.</p></div>
          <Play size={18} aria-hidden="true" />
        </div>
        <label className="check-row">
          <input type="radio" name="apk-source" checked={useSample} onChange={() => setUseSample(true)} />
          Use bundled sample_app.apk (safe reference)
        </label>
        <label className="check-row">
          <input type="radio" name="apk-source" checked={!useSample} onChange={() => setUseSample(false)} />
          Upload a custom APK
        </label>
        {!useSample && (
          <>
            <input
              id="dynamic-apk-file-input"
              type="file"
              accept=".apk,application/vnd.android.package-archive"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              style={{ display: "block", width: "100%", margin: "8px 0 12px", padding: "10px", background: "#0d1724", border: "1px dashed #40536b", borderRadius: "6px", color: "#bdc9d6", fontSize: "12px" }}
            />
            {fileMeta && (
              <div className="meta-drawer" style={{ margin: "8px 0 14px", background: "#09121d", border: "1px solid #1f3147", borderRadius: "6px", padding: "12px" }}>
                <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--accent)", letterSpacing: "0.08em", marginBottom: "8px" }}>
                  APK ARTIFACT IDENTITY &amp; INTEGRITY PREVIEW
                </div>
                <div className="meta-row">
                  <span className="meta-label">Selected File</span>
                  <span className="meta-val font-mono">{fileMeta.name}</span>
                </div>
                <div className="meta-row">
                  <span className="meta-label">File Size</span>
                  <span className="meta-val font-mono">{(fileMeta.size / (1024 * 1024)).toFixed(2)} MB ({fileMeta.size.toLocaleString()} bytes)</span>
                </div>
                <div className="meta-row">
                  <span className="meta-label">SHA-256 Digest</span>
                  <span className="meta-val font-mono hash-pill" style={{ wordBreak: "break-all" }}>{fileMeta.sha256}</span>
                </div>
                <div className="meta-row">
                  <span className="meta-label">Validation Status</span>
                  <span className="meta-val">
                    {fileMeta.computing ? (
                      <span className="badge badge-neutral">Computing digest…</span>
                    ) : fileMeta.valid ? (
                      <span className="badge badge-success">Valid APK Archive (Verified)</span>
                    ) : (
                      <span className="badge badge-danger">Invalid Archive or Exceeds Limit</span>
                    )}
                  </span>
                </div>
              </div>
            )}
          </>
        )}
        <label className="field-label" htmlFor="trace-seconds">Capture duration (seconds)</label>
        <input
          id="trace-seconds"
          type="number"
          min={10} max={300} step={5}
          value={seconds}
          onChange={(e) => setSeconds(parseInt(e.target.value) || 30)}
          style={{ width: "120px", background: "#09111d", border: "1px solid #283d54", borderRadius: "6px", padding: "7px 10px", color: "#e7edf5", fontSize: "12px" }}
        />
        <label className="check-row" style={{ marginTop: "16px" }}>
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
            id="confirm-execution"
          />
          <b style={{ color: "#e8c07a" }}>I confirm that I want to execute this APK in the emulator.</b>
        </label>
        {uploadStage && (
          <div style={{ marginTop: "10px" }}>
            <StateMessage kind="loading">
              {uploadStage}
            </StateMessage>
          </div>
        )}
        <button
          id="btn-start-dynamic"
          className="button button-primary"
          disabled={!status?.emulator_ready || !confirmed || busy || (!useSample && (!file || fileMeta?.computing || !fileMeta?.valid))}
          onClick={beginAnalysis}
          style={{ marginTop: "10px" }}
        >
          {busy ? "Initiating sandbox analysis…" : "Start dynamic analysis"}
        </button>
        {!status && <p className="field-hint">Check emulator readiness (Step 1) before starting.</p>}
      </section>

      {error && <StateMessage kind="error">{error}</StateMessage>}

      {job && (
        <section className="panel job-panel">
          <div className="panel-heading">
            <div><p className="eyebrow">ANALYSIS JOB</p><h2>{job.filename}</h2></div>
            <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
              <span className={`job-status job-${job.status}`}>{job.status}</span>
              {job.stage && (
                <span className="badge" style={{ background: "#132337", color: "#60a5fa", border: "1px solid #2563eb" }}>
                  Stage: {job.stage}
                </span>
              )}
            </div>
          </div>
          <p className="field-hint">Job {job.job_id} · requested trace {job.requested_seconds}s</p>
          {job.status === "queued" && <StateMessage kind="info">Job accepted and waiting for the analysis worker.</StateMessage>}
          {job.status === "running" && (
            <StateMessage kind="loading">
              <strong>Active Execution Stage: {job.stage || "Capturing system calls"}</strong> · Executing inside dedicated Android emulator (emulator-5554). Watch the application launch and receive UI fuzzing live in the emulator display.
            </StateMessage>
          )}
          {job.status === "failed" && <StateMessage kind="error">{job.error ?? "Dynamic analysis failed."}</StateMessage>}
          {job.status === "interrupted" && <StateMessage kind="error">{job.error ?? "Dynamic analysis was interrupted (e.g. backend restarted). Please start a new run."}</StateMessage>}
          {job.status === "completed" && <StateMessage kind="success">Analysis complete. Results are shown below.</StateMessage>}
          {(job.status === "completed" || job.status === "failed" || job.status === "interrupted") && (
            <button className="button button-secondary" style={{ marginTop: "8px" }} onClick={clearJob}>
              Clear job
            </button>
          )}
        </section>
      )}

      {result && (() => {
        const isMalware = result.verdict === "MALWARE" || result.verdict === "Malicious" || (result.probability_normalized_shares >= result.decision_threshold);
        const probDisplay = (result.probability_normalized_shares * 100).toFixed(1);

        return (
          <div className="results-stack">
            {/* Dynamic Verdict Hero Banner */}
            <section className={`result-banner ${isMalware ? "result-banner-malware" : "result-banner-benign"}`}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                  <span className={`badge ${isMalware ? "badge-danger" : "badge-success"}`}>
                    {isMalware ? "CRITICAL RUNTIME THREAT" : "VERIFIED BENIGN BEHAVIOR"}
                  </span>
                  <span className="topbar-env-pill">CICMalDroid2020 · Dynamic XGBoost (xgb_share)</span>
                </div>
                <h2 className={isMalware ? "verdict-malware" : "verdict-benign"}>
                  {result.verdict ?? (isMalware ? "Malicious" : "Benign")}
                </h2>
                <p style={{ maxWidth: "700px" }}>{result.notice}</p>
              </div>

              <div className="risk-gauge-wrap">
                <div className={`risk-gauge-circle ${isMalware ? "risk-gauge-malware" : "risk-gauge-benign"}`}>
                  <span className="risk-gauge-score" style={{ color: isMalware ? "#f87171" : "#34d399" }}>
                    {(result.probability_normalized_shares * 100).toFixed(0)}%
                  </span>
                  <span className="risk-gauge-label">Runtime Risk</span>
                </div>
                <div className="probability">
                  <span>Threshold: ≥ {(result.decision_threshold * 100).toFixed(0)}%</span>
                  <strong style={{ fontSize: "20px" }}>{probDisplay}%</strong>
                </div>
              </div>
            </section>

            {/* Dual-Column Dynamic Workspace */}
            <div className="analysis-layout">
              {/* Primary Column (Left) */}
              <div style={{ display: "grid", gap: "16px" }}>
                {/* Metric Summary Grids */}
                <div className="metric-grid" style={{ margin: "0" }}>
                  <ResultMetric label="Target Package" value={result.package} />
                  <ResultMetric label="System Calls Intercepted" value={result.system_call_count.toLocaleString()} />
                  <ResultMetric label="Vocabulary Coverage" value={`${(result.vocabulary_coverage * 100).toFixed(1)}%`} />
                  <ResultMetric label="Model Features Active" value={String(result.features_seen)} />
                </div>

                <div className="metric-grid" style={{ margin: "0" }}>
                  <ResultMetric label="Probability (Normalized Shares)" value={`${probDisplay}%`} />
                  <ResultMetric label="Probability (Raw Counts)" value={`${(result.probability_raw_counts * 100).toFixed(1)}%`} />
                  <ResultMetric label="Execution Trace Window" value={`${result.actual_seconds}s`} />
                  <ResultMetric label="Unmapped Syscall Types" value={String(Object.keys(result.unmapped_counts).length)} />
                </div>

                {/* Behavioral Anomalies */}
                <BehavioralAnomaliesPanel result={result} />

                {/* Runtime Threat Intelligence Panel */}
                {result.runtime_threat_intelligence && result.runtime_threat_intelligence.length > 0 && (
                  <section className="panel">
                    <div className="panel-heading">
                      <div>
                        <h2>Runtime Network Threat Intelligence</h2>
                        <p>Remote public IP destinations observed on active sockets (/proc/net/tcp) during emulator execution, cross-referenced with live threat intelligence feeds.</p>
                      </div>
                    </div>
                    <div className="notice notice-info" style={{ margin: "12px 0", background: "#0b1624", border: "1px solid #1e385c" }}>
                      <p style={{ margin: 0, fontSize: "11px", color: "#93b2ce", lineHeight: "1.5" }}>
                        <strong>Network Attribution Limitation:</strong> Sockets are sampled system-wide from <code>/proc/net/tcp</code> and <code>/proc/net/tcp6</code> during the execution window. Background system processes (such as Google Play Services / GMS check-ins) are captured at the operating system level and cannot be conclusively attributed to the tested application package without socket-to-PID inode resolution.
                      </p>
                      <span className="badge badge-danger">
                        {result.runtime_threat_intelligence.length} Active Public Sockets
                      </span>
                    </div>
                    <div className="table-scroll">
                      <table>
                        <thead>
                          <tr>
                            <th>Observed Destination</th>
                            <th>Port</th>
                            <th>Country</th>
                            <th>ISP / Organization</th>
                            <th>Abuse Confidence</th>
                            <th>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {result.runtime_threat_intelligence.map((conn, idx) => (
                            <tr key={`${conn.ip}-${idx}`}>
                              <td className="font-mono">{conn.ip}</td>
                              <td className="font-mono">{conn.port}</td>
                              <td>{conn.country || "Unknown"}</td>
                              <td>{conn.isp || "—"}</td>
                              <td>
                                <span className={`badge ${conn.abuse_score >= 50 ? "badge-danger" : conn.abuse_score > 0 ? "badge-warning" : "badge-success"}`}>
                                  {conn.abuse_score}% ({conn.total_reports} reports)
                                </span>
                              </td>
                              <td><span className="badge">{conn.status}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </section>
                )}

                {/* SHAP Evidence Table */}
                <section className="panel">
                  <div className="panel-heading">
                    <div>
                      <h2>System Call Attribution (SHAP Normalized Shares)</h2>
                      <p>Positive contributions push toward malware; negative contributions push toward benign.</p>
                    </div>
                    <span className="legend">
                      <i className="legend-positive" /> Toward malware{" "}
                      <i className="legend-negative" /> Toward benign
                    </span>
                  </div>
                  {result.shap_evidence.length ? (
                    <div className="table-scroll">
                      <table>
                        <thead>
                          <tr>
                            <th>System Call</th>
                            <th>Observed Count</th>
                            <th>SHAP Contribution</th>
                            <th>Attribution Direction</th>
                          </tr>
                        </thead>
                        <tbody>
                          {result.shap_evidence.map((row) => (
                            <tr key={row.syscall}>
                              <td className="font-mono">{row.syscall}</td>
                              <td>{row.count.toLocaleString()}</td>
                              <td className="font-mono">
                                <span className={`badge ${row.shap > 0 ? "badge-dir-malware" : "badge-dir-benign"}`}>
                                  {row.shap > 0 ? "+" : ""}{row.shap.toFixed(4)}
                                </span>
                              </td>
                              <td>{row.shap > 0 ? "Toward malware" : "Toward benign"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : <p className="empty-state">The model did not return SHAP evidence for this run.</p>}
                </section>

                {/* Raw strace report + syscall breakdown */}
                <section className="panel">
                  <details className="details-list" open>
                    <summary>Raw strace capture report</summary>
                    <pre className="raw-report">{result.raw_report || "The capture engine returned no raw report text."}</pre>
                  </details>
                  <details className="details-list" style={{ marginTop: "12px" }}>
                    <summary>Interpreted System-Call Counts ({Object.keys(result.counts).length})</summary>
                    <div className="table-scroll">
                      <table>
                        <thead><tr><th>System Call</th><th>Observed Count</th></tr></thead>
                        <tbody>
                          {Object.entries(result.counts)
                            .sort(([, a], [, b]) => b - a)
                            .map(([name, count]) => (
                              <tr key={name}><td className="font-mono">{name}</td><td>{count.toLocaleString()}</td></tr>
                            ))}
                        </tbody>
                      </table>
                    </div>
                  </details>
                </section>
              </div>

              {/* Inspector Sidebar (Right) */}
              <aside className="inspector-sticky">
                {/* Export Dossier */}
                <div className="meta-drawer">
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
                    <Download size={16} style={{ color: "var(--accent)" }} />
                    <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--text)", letterSpacing: "0.05em" }}>
                      EXPORT DYNAMIC DOSSIER
                    </span>
                  </div>
                  <div style={{ display: "grid", gap: "8px" }}>
                    {jobId && (
                      <a
                        className="button button-primary"
                        href={`/api/analyze/dynamic/${jobId}/reports/pdf`}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ justifyContent: "center" }}
                      >
                        <Download size={15} /> Download Dynamic PDF
                      </a>
                    )}
                    <button
                      id="btn-download-dynamic-json"
                      className="button button-secondary"
                      disabled={downloadBusy || !jobId}
                      onClick={downloadDynamicJson}
                      style={{ justifyContent: "center" }}
                    >
                      <Download size={15} /> {downloadBusy ? "Downloading…" : "Export JSON (SIEM)"}
                    </button>
                  </div>
                </div>

                {/* Sandbox Telemetry Specs */}
                <div className="meta-drawer">
                  <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--accent)", letterSpacing: "0.1em", marginBottom: "12px" }}>
                    SANDBOX TELEMETRY SPECS
                  </div>
                  <div className="meta-row">
                    <span className="meta-label">APK SHA-256</span>
                    <span className="meta-val font-mono hash-pill" style={{ wordBreak: "break-all" }}>{result.sha256}</span>
                  </div>
                  <div className="meta-row">
                    <span className="meta-label">Sandbox Target</span>
                    <span className="meta-val font-mono">emulator-5554 (Android 14 x86_64)</span>
                  </div>
                  <div className="meta-row">
                    <span className="meta-label">Sandbox Execution</span>
                    <span className="meta-val" style={{ color: "#34d399", fontWeight: 600 }}>SUCCESS (Installed &amp; Traced)</span>
                  </div>
                  <div className="meta-row">
                    <span className="meta-label">Capture Duration</span>
                    <span className="meta-val font-mono">{result.actual_seconds}s</span>
                  </div>
                  <div className="meta-row">
                    <span className="meta-label">Kernel Interceptor</span>
                    <span className="meta-val font-mono">strace -c -f -p PID</span>
                  </div>
                  <div className="meta-row">
                    <span className="meta-label">Network Sockets Sampled</span>
                    <span className="meta-val font-mono">/proc/net/tcp + tcp6</span>
                  </div>
                  <div className="meta-row">
                    <span className="meta-label">Active Outbound Sockets</span>
                    <span className="meta-val font-mono hash-pill">
                      {result.runtime_threat_intelligence?.length ?? 0} destinations
                    </span>
                  </div>
                  <div className="meta-row">
                    <span className="meta-label">Job Reference</span>
                    <span className="meta-val font-mono hash-pill">{jobId ?? result.job_id}</span>
                  </div>
                </div>

                {/* Model Engine Specs */}
                <div className="meta-drawer">
                  <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--accent)", letterSpacing: "0.1em", marginBottom: "12px" }}>
                    DYNAMIC INFERENCE ENGINE
                  </div>
                  <div className="meta-row">
                    <span className="meta-label">Operational Model</span>
                    <span className="meta-val">XGBoost (xgb_share)</span>
                  </div>
                  <div className="meta-row">
                    <span className="meta-label">Feature Representation</span>
                    <span className="meta-val">Normalized Syscall Shares</span>
                  </div>
                  <div className="meta-row">
                    <span className="meta-label">Vocabulary Domain</span>
                    <span className="meta-val">139 CICMalDroid2020 Syscalls</span>
                  </div>
                  <div className="meta-row">
                    <span className="meta-label">Decision Threshold</span>
                    <span className="meta-val">≥ 50% Probability</span>
                  </div>
                </div>
              </aside>
            </div>
          </div>
        );
      })()}
    </>
  );
}

function StatusItem({ label, good, value }: { label: string; good: boolean; value?: string }) {
  return (
    <div className="readiness-item">
      <span className={`readiness-dot ${good ? "good" : "bad"}`} />
      {label}
      <b>{value ?? (good ? "Available" : "Unavailable")}</b>
    </div>
  );
}

function ResultMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="metric-panel">
      <div className="metric-top">{label}</div>
      <strong className="metric-compact">{value}</strong>
    </div>
  );
}
