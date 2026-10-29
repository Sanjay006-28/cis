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

  const isMalware = result.probability_normalized_shares >= result.decision_threshold;
  const pct = (result.probability_normalized_shares * 100).toFixed(1);

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
              {isMalware ? "MALWARE" : "BENIGN"}
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
  const [seconds, setSeconds] = useState(30);
  const [confirmed, setConfirmed] = useState(false);
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [jobId, setJobId] = useState(() => sessionStorage.getItem(SAVED_JOB_KEY));
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
        if (active) setError(reason instanceof Error ? reason.message : "Could not retrieve job status.");
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
    try {
      let receipt: UploadReceipt | null = null;
      if (!useSample && file) receipt = await uploadApk(file);
      const accepted = await startDynamic({
        upload_id: receipt?.upload_id,
        use_sample: useSample,
        seconds,
        confirmed_execution: confirmed,
      });
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
          <input
            type="file"
            accept=".apk,application/vnd.android.package-archive"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            style={{ display: "block", width: "100%", margin: "8px 0 12px", padding: "10px", background: "#0d1724", border: "1px dashed #40536b", borderRadius: "6px", color: "#bdc9d6", fontSize: "12px" }}
          />
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
        <button
          className="button button-primary"
          disabled={!status?.emulator_ready || !confirmed || busy || (!useSample && !file)}
          onClick={beginAnalysis}
          style={{ marginTop: "10px" }}
        >
          {busy ? "Submitting…" : "Start dynamic analysis"}
        </button>
        {!status && <p className="field-hint">Check emulator readiness (Step 1) before starting.</p>}
      </section>

      {error && <StateMessage kind="error">{error}</StateMessage>}

      {job && (
        <section className="panel job-panel">
          <div className="panel-heading">
            <div><p className="eyebrow">ANALYSIS JOB</p><h2>{job.filename}</h2></div>
            <span className={`job-status job-${job.status}`}>{job.status}</span>
          </div>
          <p className="field-hint">Job {job.job_id} · requested trace {job.requested_seconds}s</p>
          {job.status === "queued" && <StateMessage kind="info">Job accepted and waiting for the analysis worker.</StateMessage>}
          {job.status === "running" && <StateMessage kind="loading">The backend is capturing syscalls in the emulator. Progress percentages are not available from the capture engine.</StateMessage>}
          {job.status === "failed" && <StateMessage kind="error">{job.error ?? "Dynamic analysis failed."}</StateMessage>}
          {job.status === "completed" && <StateMessage kind="success">Analysis complete. Results are shown below.</StateMessage>}
          {(job.status === "completed" || job.status === "failed") && (
            <button className="button button-secondary" style={{ marginTop: "8px" }} onClick={clearJob}>
              Clear job
            </button>
          )}
        </section>
      )}

      {result && (
        <div className="results-stack">
          <div className="notice notice-info"><Activity size={17} /><p>{result.notice}</p></div>

          <div className="metric-grid">
            <ResultMetric label="Package" value={result.package} />
            <ResultMetric label="System calls counted" value={result.system_call_count.toLocaleString()} />
            <ResultMetric label="Vocabulary coverage" value={`${(result.vocabulary_coverage * 100).toFixed(1)}%`} />
            <ResultMetric label="Model features seen" value={String(result.features_seen)} />
          </div>
          <div className="metric-grid">
            <ResultMetric label="Probability · normalized shares" value={`${(result.probability_normalized_shares * 100).toFixed(1)}%`} />
            <ResultMetric label="Probability · raw counts" value={`${(result.probability_raw_counts * 100).toFixed(1)}%`} />
            <ResultMetric label="Trace duration" value={`${result.actual_seconds}s`} />
            <ResultMetric label="Unmapped syscall types" value={String(Object.keys(result.unmapped_counts).length)} />
          </div>

          {/* Behavioral anomalies with SHAP explanations */}
          <BehavioralAnomaliesPanel result={result} />

          {/* SHAP evidence table */}
          <section className="panel">
            <h2>SHAP evidence · normalized-share model</h2>
            <p>Positive values push the model toward malware; negative values push toward benign. These are local values for this run only.</p>
            {result.shap_evidence.length ? (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>System call</th>
                      <th>Observed count</th>
                      <th>SHAP contribution</th>
                      <th>Direction</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.shap_evidence.map((row) => (
                      <tr key={row.syscall}>
                        <td style={{ fontFamily: "monospace" }}>{row.syscall}</td>
                        <td>{row.count.toLocaleString()}</td>
                        <td style={{ fontFamily: "monospace" }}>
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

          {/* Raw report + syscall counts */}
          <section className="panel">
            <details className="details-list" open>
              <summary>Raw strace report</summary>
              <pre className="raw-report">{result.raw_report || "The capture engine returned no raw report text."}</pre>
            </details>
            <details className="details-list">
              <summary>System-call counts ({Object.keys(result.counts).length})</summary>
              <div className="table-scroll">
                <table>
                  <thead><tr><th>System call</th><th>Count</th></tr></thead>
                  <tbody>
                    {Object.entries(result.counts)
                      .sort(([, a], [, b]) => b - a)
                      .map(([name, count]) => (
                        <tr key={name}><td style={{ fontFamily: "monospace" }}>{name}</td><td>{count.toLocaleString()}</td></tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </details>
          </section>

          {/* Download */}
          <section className="panel export-panel">
            <div>
              <h2>Export dynamic report</h2>
              <p>Downloads the dynamic analysis result as a structured JSON file. No API keys or credentials are included.</p>
            </div>
            <div className="button-row">
              <button
                id="btn-download-dynamic-json"
                className="button button-secondary"
                disabled={downloadBusy || !jobId}
                onClick={downloadDynamicJson}
              >
                <Download size={16} />
                {downloadBusy ? "Downloading…" : "Download JSON Report"}
              </button>
            </div>
          </section>
        </div>
      )}
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
