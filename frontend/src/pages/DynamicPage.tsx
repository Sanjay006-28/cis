import { useEffect, useState } from "react";
import { Activity, AlertTriangle, Info, Play, RefreshCw } from "lucide-react";
import {
  getDynamicJob,
  getDynamicResult,
  getSystemStatus,
  startDynamic,
  uploadApk,
} from "../api/client";
import { SectionHeader } from "../components/SectionHeader";
import { StateMessage } from "../components/StateMessage";
import type { DynamicJob, DynamicResult, SystemStatus, UploadReceipt } from "../types";

const SAVED_JOB_KEY = "sentinel.activeDynamicJobId";

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

  return (
    <>
      <SectionHeader
        eyebrow="LIVE EMULATOR WORKFLOW"
        title="Dynamic analysis"
        description="Capture system calls in the configured Android emulator using the existing ADB, strace, and CICMalDroid model pipeline."
      />

      <div className="research-callout-card" style={{ marginBottom: "16px" }}>
        <div className="callout-icon">
          <Info size={18} />
        </div>
        <div className="callout-content">
          <h4>Milestone 1 Interface · Dynamic Analysis Workflow</h4>
          <p>
            The dynamic analysis interface and job queue endpoints are wired to the backend.
            Because dynamic execution runs live inside an Android emulator with root access, it is never executed automatically.
            Use <strong>Environment & Emulator</strong> to verify ADB and emulator readiness before initiating a trace.
          </p>
        </div>
      </div>

      <div className="notice notice-warning">
        <AlertTriangle size={18} aria-hidden="true" />
        <p><b>Execution warning.</b> Dynamic analysis installs and runs the selected APK in the emulator. No APK runs automatically on page load or navigation.</p>
      </div>

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

        <div className="form-divider" />
        <div className="panel-heading">
          <div><h2>2 · Select APK and trace duration</h2><p>Use the bundled sample or upload a package to this backend session.</p></div>
        </div>
        <label className="check-row">
          <input type="radio" checked={useSample} onChange={() => { setUseSample(true); setFile(null); clearJob(); }} />
          Use bundled sample_app.apk
        </label>
        <label className="check-row">
          <input type="radio" checked={!useSample} onChange={() => { setUseSample(false); clearJob(); }} />
          Upload a different APK
        </label>
        {!useSample && (
          <input type="file" accept=".apk,application/vnd.android.package-archive" onChange={(event) => {
            setFile(event.target.files?.[0] ?? null);
            clearJob();
          }} />
        )}
        <label className="field-label" htmlFor="trace-seconds">Trace duration: {seconds} seconds</label>
        <input
          id="trace-seconds"
          type="range"
          min="10"
          max="300"
          step="5"
          value={seconds}
          onChange={(event) => setSeconds(Number(event.target.value))}
          className="range-input"
        />

        <div className="form-divider" />
        <div className="panel-heading">
          <div><h2>3 · Confirm execution</h2><p>Starting the job will run the selected app inside the connected emulator.</p></div>
        </div>
        <label className="check-row check-confirm">
          <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
          I explicitly authorize installing and executing this APK in the emulator for {seconds} seconds.
        </label>
        <button
          className="button button-primary"
          disabled={
            busy || !confirmed || !status?.emulator_ready ||
            (!useSample && !file) || Boolean(job && ["queued", "running"].includes(job.status))
          }
          onClick={beginAnalysis}
        >
          <Play size={16} /> {busy ? "Submitting…" : "Start dynamic analysis"}
        </button>
        {!status && <p className="field-hint">Check emulator readiness before starting.</p>}
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
          {job.status === "running" && <StateMessage kind="loading">The backend reports that analysis is running. Progress percentages are not available from the capture engine.</StateMessage>}
          {job.status === "failed" && <StateMessage kind="error">{job.error ?? "Dynamic analysis failed."}</StateMessage>}
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
          <section className="panel">
            <h2>SHAP evidence · normalized-share model</h2>
            <p>Positive values push the model toward malware; negative values push toward benign.</p>
            {result.shap_evidence.length ? (
              <div className="table-scroll"><table>
                <thead><tr><th>System call</th><th>Observed count</th><th>SHAP contribution</th><th>Direction</th></tr></thead>
                <tbody>{result.shap_evidence.map((row) => (
                  <tr key={row.syscall}><td>{row.syscall}</td><td>{row.count}</td><td>{row.shap.toFixed(4)}</td><td>{row.shap > 0 ? "Toward malware" : "Toward benign"}</td></tr>
                ))}</tbody>
              </table></div>
            ) : <p className="empty-state">The model did not return SHAP evidence for this run.</p>}
          </section>
          <section className="panel">
            <details className="details-list" open>
              <summary>Raw strace report</summary>
              <pre className="raw-report">{result.raw_report || "The capture engine returned no raw report text."}</pre>
            </details>
            <details className="details-list">
              <summary>System-call counts ({Object.keys(result.counts).length})</summary>
              <div className="table-scroll"><table><thead><tr><th>System call</th><th>Count</th></tr></thead>
                <tbody>{Object.entries(result.counts).map(([name, count]) => <tr key={name}><td>{name}</td><td>{count}</td></tr>)}</tbody></table></div>
            </details>
          </section>
        </div>
      )}
    </>
  );
}

function StatusItem({ label, good, value }: { label: string; good: boolean; value?: string }) {
  return <div className="readiness-item"><span className={`readiness-dot ${good ? "good" : "bad"}`} />{label}<b>{value ?? (good ? "Available" : "Unavailable")}</b></div>;
}

function ResultMetric({ label, value }: { label: string; value: string }) {
  return <div className="metric-panel"><div className="metric-top">{label}</div><strong className="metric-compact">{value}</strong></div>;
}
