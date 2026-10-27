import { useState } from "react";
import { Cpu, RefreshCw } from "lucide-react";
import { getSystemStatus } from "../api/client";
import { SectionHeader } from "../components/SectionHeader";
import { StateMessage } from "../components/StateMessage";
import type { SystemStatus } from "../types";

export function EnvironmentPage() {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function checkEnvironment() {
    setBusy(true);
    setError("");
    try {
      setStatus(await getSystemStatus());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Environment check failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <SectionHeader
        eyebrow="SYSTEM READINESS"
        title="Environment & emulator"
        description="Inspect the actual backend artifacts, ADB wrapper, and connected emulator. A readiness check does not execute an APK."
        action={<button className="button button-secondary" onClick={checkEnvironment} disabled={busy}><RefreshCw size={15} className={busy ? "animate-spin" : ""} /> {busy ? "Checking…" : "Run readiness check"}</button>}
      />
      {error && <StateMessage kind="error">{error}</StateMessage>}
      {!status && !busy && <div className="panel empty-state"><Cpu size={20} /><p>Run an explicit check to query the backend and emulator environment.</p></div>}
      {busy && <StateMessage kind="loading">Checking model files and emulator prerequisites…</StateMessage>}
      {status && (
        <div className="results-stack">
          <section className={`result-banner ${status.emulator_ready ? "banner-ready" : "banner-not-ready"}`}>
            <div>
              <p className="eyebrow">CURRENT CHECK</p>
              <h2>{status.emulator_ready ? "Dynamic analysis ready" : "Dynamic analysis not ready"}</h2>
              <p>{status.emulator_checks.message ? String(status.emulator_checks.message) : status.emulator_checks.ready ? "ADB setup check passed." : "Review the individual checks below."}</p>
            </div>
            <div className={`job-status ${status.emulator_ready ? "job-completed" : "job-failed"}`}>
              {status.analysis_busy ? "Analysis active" : status.emulator_ready ? "Ready" : "Needs attention"}
            </div>
          </section>
          <section className="panel">
            <h2>Backend and model artifacts</h2>
            <StatusRow label="Static model" value={status.static_model_available ? "Found" : "Missing"} good={status.static_model_available} />
            <StatusRow label="Dynamic model" value={status.dynamic_model_available ? "Found" : "Missing"} good={status.dynamic_model_available} />
            <StatusRow label="ADB executable / wrapper" value={status.adb_path ?? "Not found"} good={status.adb_available} />
            <StatusRow label="Emulator" value={status.emulator_serial ?? "No emulator connected"} good={status.emulator_connected} />
          </section>
          {Object.keys(status.emulator_checks).length > 0 && (
            <section className="panel">
              <h2>Readiness detail</h2>
              <pre className="raw-report">{JSON.stringify(status.emulator_checks, null, 2)}</pre>
            </section>
          )}
          <StateMessage kind="info">The check may run the project’s existing `adb root` readiness step on the selected emulator. It does not install or launch an APK.</StateMessage>
        </div>
      )}
    </>
  );
}

function StatusRow({ label, value, good }: { label: string; value: string; good: boolean }) {
  return <div className="status-row"><span>{label}</span><span className={good ? "text-good" : "text-bad"}>{value}</span></div>;
}
