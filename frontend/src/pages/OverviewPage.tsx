import { useEffect, useState } from "react";
import { Activity, Database, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { getHealth } from "../api/client";
import { Metric } from "../components/Metric";
import { SectionHeader } from "../components/SectionHeader";
import { StateMessage } from "../components/StateMessage";
import type { Health } from "../types";

export function OverviewPage() {
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    getHealth().then(setHealth).catch((reason: Error) => setError(reason.message));
  }, []);

  return (
    <>
      <SectionHeader
        eyebrow="OPERATIONS OVERVIEW"
        title="Android threat analysis"
        description="Inspect APKs with the existing Drebin-215 static pipeline, or explicitly run a dynamic trace on the configured emulator."
      />
      {error && <StateMessage kind="error">{error}</StateMessage>}
      {health && (
        <StateMessage kind="success">
          API connected · {health.service}
        </StateMessage>
      )}
      {!health && !error && (
        <StateMessage kind="loading">Checking API connection…</StateMessage>
      )}

      <div className="metric-grid">
        <Metric label="Analysis modes" value="Static + Dynamic" detail="Existing Python engines" icon={Activity} />
        <Metric label="Research data" value="Saved artifacts" detail="Historical benchmarks, not live detections" icon={Database} />
        <Metric label="Execution policy" value="User initiated" detail="Dynamic runs require explicit confirmation" icon={ShieldCheck} />
      </div>

      <section className="panel overview-note">
        <div>
          <p className="eyebrow">SAFE OPERATING MODEL</p>
          <h2>Analysis stays local</h2>
          <p>
            Model files remain in the Python backend. Static analysis reads APK contents;
            dynamic analysis installs and runs an APK only after you confirm the operation.
            Predictions are model outputs, not proof of malicious behavior.
          </p>
        </div>
        <div className="overview-actions">
          <Link className="button button-primary" to="/analyze">Analyze an APK</Link>
          <Link className="button button-secondary" to="/research">Review research</Link>
        </div>
      </section>

      <div className="section-title-row">
        <div>
          <p className="eyebrow">WORKSPACE</p>
          <h2>Analysis paths</h2>
        </div>
      </div>
      <div className="path-grid">
        <Link to="/analyze" className="path-card">
          <span className="path-icon"><ShieldCheck size={19} /></span>
          <h3>Static APK analysis</h3>
          <p>Drebin feature extraction, ensemble prediction, SHAP evidence, and optional threat intelligence.</p>
          <span className="path-link">Open static analysis <span aria-hidden="true">→</span></span>
        </Link>
        <Link to="/dynamic" className="path-card">
          <span className="path-icon"><Activity size={19} /></span>
          <h3>Dynamic emulator analysis</h3>
          <p>Check readiness, set a trace duration, confirm execution, and inspect captured system calls.</p>
          <span className="path-link">Open dynamic analysis <span aria-hidden="true">→</span></span>
        </Link>
      </div>
    </>
  );
}
