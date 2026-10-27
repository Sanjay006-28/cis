import { useState } from "react";
import { Download, FileSearch, Info, ShieldAlert } from "lucide-react";
import {
  analyzeStatic,
  reportUrl,
  uploadApk,
} from "../api/client";
import { SectionHeader } from "../components/SectionHeader";
import { StateMessage } from "../components/StateMessage";
import type { StaticResult } from "../types";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

export function AnalyzePage() {
  const [file, setFile] = useState<File | null>(null);
  const [resolveDomains, setResolveDomains] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<StaticResult | null>(null);

  async function runAnalysis() {
    if (!file) return;
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const uploaded = await uploadApk(file);
      const analysis = await analyzeStatic(uploaded.upload_id, resolveDomains);
      setResult(analysis);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Static analysis failed.");
    } finally {
      setBusy(false);
    }
  }

  const shapData = result?.evidence.map((item) => ({
    ...item,
    direction: item.shap > 0 ? "Toward malware" : "Toward benign",
  })) ?? [];

  return (
    <>
      <SectionHeader
        eyebrow="STATIC INSPECTION"
        title="Analyze APK"
        description="The existing analysis engine reads the package, extracts Drebin-215 features, applies the saved ensemble, and calculates local SHAP evidence."
      />

      <div className="research-callout-card" style={{ marginBottom: "20px" }}>
        <div className="callout-icon">
          <Info size={18} />
        </div>
        <div className="callout-content">
          <h4>Milestone 1 Interface · Static Analysis Workflow</h4>
          <p>
            The React interface structure and backend API contract (<code>POST /api/analyze/static</code>) are established.
            You can select an APK to inspect static feature extraction and model inference against the saved Drebin-215 model, or explore the comprehensive historical benchmarks under <strong>Research & Benchmarks</strong>.
          </p>
        </div>
      </div>

      <section className="panel form-panel">
        <div className="panel-heading">
          <div>
            <h2>APK input</h2>
            <p>Static analysis does not install or execute the APK.</p>
          </div>
          <FileSearch size={19} aria-hidden="true" />
        </div>
        <label className="field-label" htmlFor="static-apk">APK file</label>
        <input
          id="static-apk"
          type="file"
          accept=".apk,application/vnd.android.package-archive"
          onChange={(event) => {
            setFile(event.target.files?.[0] ?? null);
            setResult(null);
            setError("");
          }}
        />
        {file && <p className="field-hint">{file.name} · {(file.size / 1024 / 1024).toFixed(2)} MiB</p>}
        <label className="check-row">
          <input
            type="checkbox"
            checked={resolveDomains}
            onChange={(event) => setResolveDomains(event.target.checked)}
          />
          Resolve embedded domains to IP addresses
          <span className="field-hint">Makes DNS requests from the backend host.</span>
        </label>
        <button className="button button-primary" disabled={!file || busy} onClick={runAnalysis}>
          {busy ? "Analyzing…" : "Run static analysis"}
        </button>
      </section>

      {busy && <StateMessage kind="loading">Uploading the APK and running the real static pipeline…</StateMessage>}
      {error && <StateMessage kind="error">{error}</StateMessage>}

      {result && (
        <div className="results-stack">
          <section className="result-banner">
            <div>
              <p className="eyebrow">MODEL PREDICTION · {result.filename}</p>
              <h2 className={result.verdict === "MALWARE" ? "verdict-malware" : "verdict-benign"}>
                {result.verdict}
              </h2>
              <p>{result.notice}</p>
            </div>
            <div className="probability">
              <span>Malware probability</span>
              <strong>{(result.malware_probability * 100).toFixed(1)}%</strong>
            </div>
          </section>
          <div className="metric-grid">
            <ResultMetric label="Package" value={result.package} />
            <ResultMetric label="Features detected" value={`${result.detected_features.length} / ${result.total_features}`} />
            <ResultMetric label="Embedded IPs" value={String(Object.keys(result.embedded_ips).length)} />
            <ResultMetric label="Embedded domains" value={String(Object.keys(result.embedded_domains).length)} />
          </div>

          <section className="panel">
            <div className="panel-heading">
              <div>
                <h2>Local model evidence</h2>
                <p>SHAP values describe contribution direction; they do not establish intent.</p>
              </div>
              <span className="legend"><i className="legend-positive" /> Toward malware <i className="legend-negative" /> Toward benign</span>
            </div>
            {shapData.length ? (
              <div className="chart-wrap chart-tall">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={shapData} layout="vertical" margin={{ left: 12, right: 24 }}>
                    <CartesianGrid stroke="#25354a" horizontal={false} />
                    <XAxis type="number" tick={{ fill: "#98a9bd", fontSize: 11 }} />
                    <YAxis type="category" dataKey="feature" width={190} tick={{ fill: "#d9e2ed", fontSize: 11 }} />
                    <Tooltip
                      contentStyle={{ background: "#111c2b", border: "1px solid #34465c", color: "#e7edf5" }}
                      formatter={(value: number, _name, item) => [
                        `${value.toFixed(4)} · ${item.payload.present ? "present" : "absent"} · ${item.payload.direction}`,
                        "SHAP",
                      ]}
                    />
                    <Bar dataKey="shap" radius={[0, 3, 3, 0]}>
                      {shapData.map((item) => (
                        <Cell key={item.feature} fill={item.shap > 0 ? "#c36b62" : "#55a98c"} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : <p className="empty-state">No SHAP evidence was returned.</p>}
          </section>

          <section className="panel">
            <div className="panel-heading">
              <div><h2>Threat intelligence</h2><p>Indicator extraction is static; it is not captured network traffic.</p></div>
              <ShieldAlert size={18} />
            </div>
            {result.lookup_error && <StateMessage kind="error">{result.lookup_error}</StateMessage>}
            {result.threat_features && (
              <div className="inline-facts">
                <span>Network risk <b>{String(result.threat_features.network_risk ?? "UNKNOWN")}</b></span>
                <span>Maximum abuse score <b>{String(result.threat_features.max_abuse_score ?? "Unknown")}</b></span>
              </div>
            )}
            {!result.lookups.length && !result.lookup_error && (
              <p className="empty-state">No reputation lookup result is available. Unknown does not mean safe.</p>
            )}
            {result.lookups.length > 0 && (
              <div className="table-scroll">
                <table>
                  <thead><tr>{Object.keys(result.lookups[0]).map((key) => <th key={key}>{key}</th>)}</tr></thead>
                  <tbody>{result.lookups.map((row, index) => (
                    <tr key={`${String(row.ip)}-${index}`}>
                      {Object.keys(result.lookups[0]).map((key) => <td key={key}>{String(row[key] ?? "—")}</td>)}
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            )}
            <DetailsList title={`Detected features (${result.detected_features.length})`} items={result.detected_features} />
            <DetailsList title={`Embedded IPs (${Object.keys(result.embedded_ips).length})`} items={Object.entries(result.embedded_ips).map(([ip, context]) => `${ip} — ${context}`)} />
            <DetailsList title={`Embedded domains (${Object.keys(result.embedded_domains).length})`} items={Object.entries(result.embedded_domains).map(([host, context]) => `${host} — ${context}`)} />
          </section>

          <section className="panel export-panel">
            <div><h2>Export report</h2><p>Downloads are generated from this analysis result; API keys are never included.</p></div>
            <div className="button-row">
              <a className="button button-secondary" href={reportUrl(result.analysis_id, "json")}><Download size={16} /> JSON report</a>
              <a className="button button-secondary" href={reportUrl(result.analysis_id, "pdf")}><Download size={16} /> PDF report</a>
            </div>
          </section>
        </div>
      )}
    </>
  );
}

function ResultMetric({ label, value }: { label: string; value: string }) {
  return <div className="metric-panel"><div className="metric-top">{label}</div><strong className="metric-compact">{value}</strong></div>;
}

function DetailsList({ title, items }: { title: string; items: string[] }) {
  return (
    <details className="details-list">
      <summary>{title}</summary>
      {items.length ? <ul>{items.map((item) => <li key={item}>{item}</li>)}</ul> : <p>None reported.</p>}
    </details>
  );
}
