import { useEffect, useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  Download,
  FileSearch,
  Info,
  Shield,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import {
  analyzeStatic,
  downloadReportFile,
  getThreatIntelStatus,
  reportUrl,
  testThreatIntelKey,
  uploadApk,
} from "../api/client";
import { SectionHeader } from "../components/SectionHeader";
import { StateMessage } from "../components/StateMessage";
import type { FeatureExplanation, StaticResult, ThreatIntelStatus } from "../types";
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

const CATEGORY_LABELS: Record<string, string> = {
  permission: "Sensitive Permissions",
  api_call: "Suspicious API Calls",
  intent_filter: "Intent Filters",
  shell_command: "Shell Commands",
};

const CATEGORY_ORDER = ["permission", "api_call", "intent_filter", "shell_command"];

function DirectionBadge({ direction }: { direction: string }) {
  if (direction === "toward_malware") return <span className="badge badge-dir-malware">↑ Toward malware</span>;
  if (direction === "toward_benign") return <span className="badge badge-dir-benign">↓ Toward benign</span>;
  return <span className="badge badge-neutral">— Neutral</span>;
}

function RiskBadge({ level }: { level: string }) {
  const cls = level === "high" ? "badge-high" : level === "medium" ? "badge-medium" : level === "low" ? "badge-low" : "badge-none";
  return <span className={`badge ${cls}`}>{level.toUpperCase()}</span>;
}

function ThreatRiskBadge({ risk }: { risk: string }) {
  const r = String(risk ?? "UNKNOWN").toUpperCase();
  const cls = r === "HIGH" ? "badge-high" : r === "MEDIUM" ? "badge-medium" : r === "LOW" ? "badge-low" : "badge-none";
  return <span className={`badge ${cls}`}>{r}</span>;
}

function CategoryAccordion({
  category,
  explanations,
}: {
  category: string;
  explanations: FeatureExplanation[];
}) {
  const [open, setOpen] = useState(false);
  if (!explanations.length) return null;
  const label = CATEGORY_LABELS[category] ?? category;
  const malwareCount = explanations.filter((e) => e.direction === "toward_malware").length;

  return (
    <div className="category-card">
      <div className="category-header" onClick={() => setOpen(!open)}>
        <div className="category-header-title">
          {open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
          <span>{label}</span>
          <span className="badge badge-neutral">{explanations.length} indicators</span>
          {malwareCount > 0 && (
            <span className="badge badge-dir-malware">{malwareCount} push malware</span>
          )}
        </div>
      </div>
      {open && explanations.map((exp) => (
        <div className="feature-item-card" key={exp.feature}>
          <div className="feature-item-top">
            <span className="feature-name">{exp.feature}</span>
            <div style={{ display: "flex", gap: "6px", alignItems: "center", flexWrap: "wrap" }}>
              <span className={`badge ${exp.present ? "badge-malware" : "badge-neutral"}`}>
                {exp.present ? "Present" : "Absent"}
              </span>
              <RiskBadge level={exp.risk_level} />
              <DirectionBadge direction={exp.direction} />
              {exp.shap !== null && (
                <span className="badge badge-neutral" style={{ fontFamily: "monospace" }}>
                  SHAP {exp.shap > 0 ? "+" : ""}{exp.shap?.toFixed(4)}
                </span>
              )}
            </div>
          </div>
          <p className="feature-desc">{exp.description}</p>
          <p className="feature-context">{exp.security_context}</p>
          <p className="feature-interpretation">{exp.interpretation}</p>
        </div>
      ))}
    </div>
  );
}

function PredictionSummary({ result }: { result: StaticResult }) {
  const pct = (result.malware_probability * 100).toFixed(1);
  const isMalware = result.verdict === "MALWARE";

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Prediction Summary &amp; Decision Criteria</h2>
          <p>How the ensemble classifier reached this verdict for this specific APK.</p>
        </div>
        {isMalware ? <ShieldAlert size={18} style={{ color: "#e58b82" }} /> : <ShieldCheck size={18} style={{ color: "#72c4a4" }} />}
      </div>

      <div className="decision-criteria-card">
        <div style={{ display: "flex", alignItems: "center", gap: "16px", flexWrap: "wrap" }}>
          <div>
            <div style={{ fontSize: "11px", color: "#7f95ac", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "4px" }}>Verdict</div>
            <div style={{ fontSize: "28px", fontWeight: 700, color: isMalware ? "#f19890" : "#72c4a4", letterSpacing: "-0.02em" }}>
              {result.verdict}
            </div>
          </div>
          <div>
            <div style={{ fontSize: "11px", color: "#7f95ac", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "4px" }}>Malware Probability</div>
            <div style={{ fontSize: "24px", fontWeight: 700, color: "#dbe7f2" }}>{pct}%</div>
          </div>
          <div>
            <div style={{ fontSize: "11px", color: "#7f95ac", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "4px" }}>Decision Threshold</div>
            <div style={{ fontSize: "16px", fontWeight: 600, color: "#8cabc4" }}>≥ {(result.decision_threshold * 100).toFixed(0)}%</div>
          </div>
        </div>
        <p style={{ margin: "12px 0 0", fontSize: "12px", color: "#8c9eb4" }}>
          Classifier: <span style={{ color: "#dbe7f2" }}>{result.classifier_info}</span>
        </p>
      </div>

      <div className="decision-criteria-grid">
        <div className="decision-criteria-item">
          <h5>ML Static Evidence</h5>
          <p>Random Forest + XGBoost ensemble trained on Drebin-215 ({result.total_features} binary features). Probability fused as average. SHAP values show local contribution per feature — positive values push toward malware, negative toward benign.</p>
        </div>
        <div className="decision-criteria-item">
          <h5>Detected Indicators</h5>
          <p>
            {result.detected_features.length} of {result.total_features} Drebin-215 features active in this APK. Features cover permissions, API calls, intent filters, and shell commands.
            {result.detected_features.length === 0 && " No features detected — this APK may lack compiled code (.dex)."}
          </p>
        </div>
        <div className="decision-criteria-item">
          <h5>Threat Intelligence</h5>
          <p>
            {result.threat_intel_status === "disabled" && "Threat intel was disabled for this run."}
            {result.threat_intel_status === "missing_key" && "No AbuseIPDB key configured — network indicators were not checked."}
            {result.threat_intel_status === "env_key" && `${Object.keys(result.embedded_ips).length} embedded IPs extracted and checked against AbuseIPDB. Domains listed separately (not checked by AbuseIPDB).`}
            {result.threat_intel_status === "custom_key" && `${Object.keys(result.embedded_ips).length} embedded IPs checked using the provided API key. Domains listed separately.`}
          </p>
        </div>
        <div className="decision-criteria-item">
          <h5>Important Limitations</h5>
          <p>This prediction is not legal or definitional proof of malice. Embedded indicators are extracted from APK code, not live network traffic. SHAP evidence shows statistical feature influence, not ground truth.</p>
        </div>
      </div>
    </section>
  );
}

function ExplanationsPanel({ result }: { result: StaticResult }) {
  const byCategory: Record<string, FeatureExplanation[]> = {};
  for (const exp of result.detailed_explanations ?? []) {
    (byCategory[exp.category] ??= []).push(exp);
  }
  const hasAny = Object.values(byCategory).some((arr) => arr.length > 0);
  if (!hasAny) return null;

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Suspicious Indicators &amp; Explanations</h2>
          <p>Detected Drebin-215 features categorised by type, with security context and SHAP attribution direction.</p>
        </div>
        <Shield size={18} />
      </div>
      {CATEGORY_ORDER.map((cat) => (
        <CategoryAccordion key={cat} category={cat} explanations={byCategory[cat] ?? []} />
      ))}
      <p style={{ margin: "10px 0 0", fontSize: "11px", color: "#68808f" }}>
        Indicator presence alone does not establish malicious intent. SHAP values reflect statistical attribution for this specific sample.
      </p>
    </section>
  );
}

function ThreatIntelPanel({ result }: { result: StaticResult }) {
  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Threat Intelligence Results</h2>
          <p>Indicators extracted from APK code (not live traffic) and checked against AbuseIPDB reputation database.</p>
        </div>
        <ShieldAlert size={18} />
      </div>

      {result.lookup_error && <StateMessage kind="error">{result.lookup_error}</StateMessage>}

      {result.threat_intel_status === "disabled" && (
        <StateMessage kind="info">Threat intelligence was disabled for this analysis run.</StateMessage>
      )}
      {result.threat_intel_status === "missing_key" && (
        <StateMessage kind="info">No AbuseIPDB API key is configured. Network risk is unknown — unknown does not mean safe. Enable threat intel and provide a key to check embedded IPs.</StateMessage>
      )}

      {result.threat_features && (
        <div className="inline-facts">
          <span>Network risk <ThreatRiskBadge risk={String(result.threat_features.network_risk)} /></span>
          <span>Max abuse score <b>{result.threat_features.max_abuse_score}</b></span>
          <span>Malicious IPs <b>{result.threat_features.malicious_ip_count}</b></span>
        </div>
      )}

      {result.lookups.length > 0 && (
        <div className="table-scroll" style={{ marginTop: "14px" }}>
          <table>
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Status</th>
                <th>Abuse Score</th>
                <th>Reports</th>
                <th>Country</th>
                <th>ISP</th>
                <th>Last Reported</th>
              </tr>
            </thead>
            <tbody>
              {result.lookups.map((row, i) => {
                const score = row.abuse_score ?? 0;
                const scoreCls = score >= 75 ? "badge-high" : score >= 25 ? "badge-medium" : "badge-low";
                const statusCls = row.status === "checked" ? "badge-benign" : row.status === "failed" ? "badge-malware" : "badge-neutral";
                return (
                  <tr key={`${String(row.ip)}-${i}`}>
                    <td style={{ fontFamily: "monospace", fontSize: "12px" }}>{String(row.ip)}</td>
                    <td><span className={`badge ${statusCls}`}>{row.status}</span></td>
                    <td>
                      {row.status === "checked"
                        ? <span className={`badge ${scoreCls}`}>{score}/100</span>
                        : <span style={{ color: "#68808f" }}>—</span>}
                    </td>
                    <td>{row.status === "checked" ? String(row.total_reports) : "—"}</td>
                    <td>{String(row.country ?? "—")}</td>
                    <td style={{ maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", fontSize: "11px" }}>{String(row.isp ?? "—")}</td>
                    <td style={{ fontSize: "11px" }}>{row.last_reported ? String(row.last_reported).split("T")[0] : "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {!result.lookups.length && !result.lookup_error && result.threat_intel_status !== "disabled" && result.threat_intel_status !== "missing_key" && (
        <p className="empty-state">No public IPs found in the APK. Unknown does not mean safe.</p>
      )}

      {Object.keys(result.embedded_domains).length > 0 && (
        <details className="details-list" style={{ marginTop: "14px" }}>
          <summary>Embedded domain strings ({Object.keys(result.embedded_domains).length}) — not checked by AbuseIPDB</summary>
          <ul>
            {Object.entries(result.embedded_domains).map(([host, ctx]) => (
              <li key={host}><code>{host}</code> — <span style={{ color: "#7b90a6", fontSize: "11px" }}>{ctx}</span></li>
            ))}
          </ul>
          <p style={{ margin: "6px 0 0", fontSize: "11px", color: "#586f83" }}>
            AbuseIPDB checks IP addresses only. Domains are listed for reference; they may be legitimate CDN, SDK, or API endpoints.
          </p>
        </details>
      )}

      {Object.keys(result.embedded_ips).length > 0 && (
        <details className="details-list" style={{ marginTop: "10px" }}>
          <summary>All embedded public IPs ({Object.keys(result.embedded_ips).length})</summary>
          <ul>
            {Object.entries(result.embedded_ips).map(([ip, ctx]) => (
              <li key={ip}><code>{ip}</code> — <span style={{ color: "#7b90a6", fontSize: "11px" }}>{ctx}</span></li>
            ))}
          </ul>
        </details>
      )}

      <p style={{ margin: "14px 0 0", fontSize: "11px", color: "#586f83" }}>
        ⚠ Embedded indicators are extracted from APK code — they are not captured live network traffic. Low or zero abuse scores do not guarantee safety.
      </p>
    </section>
  );
}

function AttackCandidatesPanel({ result }: { result: StaticResult }) {
  const candidates = result.attack_candidates ?? [];
  if (!candidates.length) return null;

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>MITRE ATT&CK Candidate Techniques</h2>
          <p>Rule-based behavioral mapping <span className="category-pill pill-neutral" style={{ fontSize: "11px", marginLeft: "6px" }}>heuristic / candidate</span></p>
        </div>
        <span className="count-badge">{candidates.length} identified</span>
      </div>
      <div className="table-wrap">
        <table className="compact-table">
          <thead>
            <tr>
              <th style={{ width: "130px" }}>Technique ID</th>
              <th>Technique Name</th>
              <th>Classification</th>
              <th>Evidence / Indicator</th>
            </tr>
          </thead>
          <tbody>
            {candidates.map((c, idx) => (
              <tr key={idx}>
                <td><code style={{ color: "#e88080", fontWeight: "bold" }}>{c.technique_id}</code></td>
                <td><strong>{c.technique_name}</strong></td>
                <td><span className="direction-badge badge-malware">candidate</span></td>
                <td><span style={{ fontSize: "11px", color: "#a5b8cc" }}>{c.evidence}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p style={{ margin: "10px 0 0", fontSize: "11px", color: "#586f83" }}>
        Note: ATT&CK mappings are rule-based heuristic candidates derived from declared permissions, bytecode DEX class references, and domain entropy. They do not constitute verified exploit execution.
      </p>
    </section>
  );
}

function DomainEntropyPanel({ result }: { result: StaticResult }) {
  const entropyList = result.domain_entropy ?? [];
  if (!entropyList.length) return null;

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Domain Shannon Entropy Analysis</h2>
          <p>Evaluates registrable domain labels using offline tldextract <span className="category-pill pill-neutral" style={{ fontSize: "11px", marginLeft: "6px" }}>heuristic / candidate</span></p>
        </div>
        <span className="count-badge">{entropyList.length} domains</span>
      </div>
      <div className="table-wrap">
        <table className="compact-table">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Registrable Label</th>
              <th>Shannon Entropy</th>
              <th>Threshold (&gt; 3.4)</th>
              <th>DGA Assessment</th>
            </tr>
          </thead>
          <tbody>
            {entropyList.map((de, idx) => (
              <tr key={idx}>
                <td><code>{de.domain}</code></td>
                <td><code>{de.label}</code></td>
                <td><strong>{de.entropy.toFixed(3)}</strong> bits</td>
                <td>3.400</td>
                <td>
                  {de.flag ? (
                    <span className="direction-badge badge-malware" style={{ backgroundColor: "rgba(195, 107, 98, 0.2)", color: "#e88080" }}>
                      FLAGGED (High Entropy)
                    </span>
                  ) : (
                    <span className="direction-badge badge-benign" style={{ backgroundColor: "rgba(85, 169, 140, 0.2)", color: "#74c9aa" }}>
                      Normal
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p style={{ margin: "10px 0 0", fontSize: "11px", color: "#586f83" }}>
        Mathematical context: Shannon entropy measures character distribution randomness. Labels with fewer than 11 distinct characters cannot exceed 3.4 (log₂(10) ≈ 3.32 &lt; 3.4). High entropy flags algorithmic DGA candidates.
      </p>
    </section>
  );
}

function UrlhausPanel({ result }: { result: StaticResult }) {
  const urlhaus = result.urlhaus ?? [];
  if (!urlhaus.length) return null;

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>URLhaus Threat Intelligence</h2>
          <p>Host malware reputation queried from abuse.ch <span className="category-pill pill-neutral" style={{ fontSize: "11px", marginLeft: "6px" }}>heuristic / candidate</span></p>
        </div>
        <span className="count-badge">{urlhaus.length} checked</span>
      </div>
      <div className="table-wrap">
        <table className="compact-table">
          <thead>
            <tr>
              <th>Host (IP / Domain)</th>
              <th>Status</th>
              <th>Associated URLs</th>
              <th>Reference / Detail</th>
            </tr>
          </thead>
          <tbody>
            {urlhaus.map((uh, idx) => (
              <tr key={idx}>
                <td><code>{uh.host}</code></td>
                <td>
                  {uh.status === "LISTED" ? (
                    <span className="direction-badge badge-malware" style={{ fontWeight: "bold" }}>LISTED</span>
                  ) : uh.status === "NOT_LISTED" ? (
                    <span className="direction-badge badge-benign">NOT_LISTED</span>
                  ) : (
                    <span className="direction-badge badge-neutral">{uh.status}</span>
                  )}
                </td>
                <td>{uh.url_count ?? 0}</td>
                <td>
                  {uh.urlhaus_reference ? (
                    <a href={uh.urlhaus_reference} target="_blank" rel="noopener noreferrer" style={{ color: "#55d6d8", textDecoration: "underline" }}>
                      URLhaus Link
                    </a>
                  ) : (
                    <span style={{ color: "#7b90a6", fontSize: "11px" }}>{uh.error || "—"}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p style={{ margin: "10px 0 0", fontSize: "11px", color: "#586f83" }}>
        URLhaus is a project from abuse.ch tracking malware distribution sites. An error or connection issue is never reported as clean or not listed.
      </p>
    </section>
  );
}

function EvidenceCorrelationPanel({ result }: { result: StaticResult }) {
  const detected = new Set(result.detected_features ?? []);
  const ipCount = Object.keys(result.embedded_ips ?? {}).length;

  const correlations = [
    {
      capability: "Network Communication",
      runtimeSyscalls: "socket, connect, sendto, recvfrom, poll/ppoll",
      hasStatic: detected.has("INTERNET") || ipCount > 0 || Object.keys(result.embedded_domains ?? {}).length > 0,
      detail: ipCount > 0
        ? `Declared network access with ${ipCount} embedded public IP(s)`
        : detected.has("INTERNET") ? "Declared INTERNET permission in AndroidManifest.xml" : "No declared network permission or embedded IPs",
      note: "Static declaration indicates capability; dynamic verification observes live socket creation."
    },
    {
      capability: "Local Filesystem & Storage",
      runtimeSyscalls: "open/openat, fstat64, read, write, lseek",
      hasStatic: detected.has("READ_EXTERNAL_STORAGE") || detected.has("WRITE_EXTERNAL_STORAGE"),
      detail: detected.has("WRITE_EXTERNAL_STORAGE")
        ? "Requests external storage write access"
        : detected.has("READ_EXTERNAL_STORAGE") ? "Requests external storage read access" : "Standard app-private sandbox storage only",
      note: "Absence of storage permissions does not prevent internal cache operations."
    },
    {
      capability: "Dynamic Code Loading & Execution",
      runtimeSyscalls: "mprotect, clone, execve, ioctl",
      hasStatic: detected.has("Ldalvik/system/DexClassLoader;") || detected.has("Runtime.exec") || detected.has("chmod"),
      detail: detected.has("Ldalvik/system/DexClassLoader;")
        ? "Embedded DexClassLoader reference detected in bytecode"
        : detected.has("Runtime.exec") ? "Runtime.exec invocation found in bytecode" : "No dynamic class loader or shell execution references",
      note: "JIT runtimes frequently invoke mprotect; runtime evidence requires contextual investigation."
    },
    {
      capability: "Telephony & SMS",
      runtimeSyscalls: "ioctl, binder IPC, write",
      hasStatic: detected.has("SEND_SMS") || detected.has("RECEIVE_SMS") || detected.has("READ_SMS") || detected.has("READ_PHONE_STATE"),
      detail: detected.has("SEND_SMS")
        ? "Declared SEND_SMS permission (candidate ATT&CK T1582)"
        : detected.has("READ_PHONE_STATE") ? "Requests device state identification" : "No telephony or SMS permissions declared",
      note: "Modern Android routes telephony via Binder IPC; direct telephony system calls are rarely exposed."
    }
  ];

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Static-Dynamic Evidence Correlation</h2>
          <p>
            Cross-references statically declared permissions and APIs against their expected runtime system-call counterparts.
            Correlations indicate capability coverage &mdash; missing runtime evidence represents unobserved behavior, not proof of absence.
          </p>
        </div>
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Security Capability</th>
              <th>Static Finding</th>
              <th>Expected Runtime Counterparts</th>
              <th>Correlation Status &amp; Detail</th>
            </tr>
          </thead>
          <tbody>
            {correlations.map((c) => (
              <tr key={c.capability}>
                <td style={{ fontWeight: 600 }}>{c.capability}</td>
                <td>
                  <span className={`badge ${c.hasStatic ? "badge-dir-malware" : "badge-dir-benign"}`}>
                    {c.hasStatic ? "Declared / Present" : "Not Declared"}
                  </span>
                </td>
                <td style={{ fontFamily: "monospace", fontSize: "11px", color: "#a5b8cc" }}>
                  {c.runtimeSyscalls}
                </td>
                <td>
                  <div style={{ fontSize: "12px", color: "#e7edf5" }}>{c.detail}</div>
                  <div style={{ fontSize: "11px", color: "#74889c", marginTop: "2px" }}>{c.note}</div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function AnalyzePage() {
  const [file, setFile] = useState<File | null>(null);
  const [resolveDomains, setResolveDomains] = useState(false);
  const [enableThreatIntel, setEnableThreatIntel] = useState(true);
  const [serverKeyStatus, setServerKeyStatus] = useState<ThreatIntelStatus | null>(null);
  const [testingKey, setTestingKey] = useState(false);
  const [testMessage, setTestMessage] = useState<{ success: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [downloadBusy, setDownloadBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<StaticResult | null>(null);

  useEffect(() => {
    getThreatIntelStatus()
      .then(setServerKeyStatus)
      .catch(() => setServerKeyStatus(null));
  }, []);

  async function testConnection() {
    setTestingKey(true);
    setTestMessage(null);
    try {
      const res = await testThreatIntelKey();
      setTestMessage({ success: res.success, text: res.message });
    } catch (err) {
      setTestMessage({ success: false, text: err instanceof Error ? err.message : "Test failed." });
    } finally {
      setTestingKey(false);
    }
  }

  async function runAnalysis() {
    if (!file) return;
    setBusy(true);
    setError("");
    setResult(null);
    setTestMessage(null);
    try {
      const uploaded = await uploadApk(file);
      const analysis = await analyzeStatic(
        uploaded.upload_id,
        resolveDomains,
        enableThreatIntel,
      );
      setResult(analysis);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Static analysis failed.");
    } finally {
      setBusy(false);
    }
  }

  async function downloadJson() {
    if (!result) return;
    setDownloadBusy(true);
    try {
      const stem = result.filename.replace(/\.apk$/i, "") || "apk";
      await downloadReportFile(reportUrl(result.analysis_id, "json"), `${stem}_analysis_report.json`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Download failed.");
    } finally {
      setDownloadBusy(false);
    }
  }

  const shapData = result?.evidence.map((item) => ({
    ...item,
    direction: item.shap > 0 ? "Toward malware" : "Toward benign",
  })) ?? [];

  const keyConfigured = Boolean(serverKeyStatus?.configured);
  const pillClass = !enableThreatIntel ? "disabled" : keyConfigured ? "configured" : "missing";
  const pillText = !enableThreatIntel ? "disabled" : keyConfigured ? "API key configured" : "API key not configured";

  return (
    <>
      <SectionHeader
        eyebrow="STATIC INSPECTION"
        title="Analyze APK"
        description="The existing analysis engine reads the package, extracts Drebin-215 features, applies the saved ensemble, and calculates local SHAP evidence."
      />

      <div className="research-callout-card" style={{ marginBottom: "20px" }}>
        <div className="callout-icon"><Info size={18} /></div>
        <div className="callout-content">
          <h4>Static Analysis Workflow</h4>
          <p>
            Upload an APK to run static feature extraction and model inference against the saved Drebin-215 ensemble.
            Optionally enable AbuseIPDB threat intelligence to check embedded IP indicators.
            Explore historical benchmarks under <strong>Research &amp; Benchmarks</strong>.
          </p>
        </div>
      </div>

      {/* Input Panel */}
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
            onChange={(e) => setResolveDomains(e.target.checked)}
          />
          Resolve embedded domains to IPs via DNS
          <span className="field-hint">Makes DNS queries from the backend host.</span>
        </label>

        {/* AbuseIPDB Threat Intelligence Status Panel */}
        <div className="config-group">
          <div className="config-title">
            <h3>AbuseIPDB Threat Intelligence</h3>
            <span className={`status-pill ${pillClass}`}>{pillText}</span>
          </div>
          <label className="check-row" style={{ marginTop: 0 }}>
            <input
              type="checkbox"
              checked={enableThreatIntel}
              onChange={(e) => {
                setEnableThreatIntel(e.target.checked);
                setTestMessage(null);
              }}
            />
            Enable IP reputation lookup
            <span className="field-hint">Checks embedded public IPs against AbuseIPDB — never sends domains.</span>
          </label>
          {enableThreatIntel && (
            <div style={{ marginTop: "12px" }}>
              {keyConfigured ? (
                <div style={{ marginBottom: "12px" }}>
                  <StateMessage kind="success">
                    <strong>API key configured.</strong> IP reputation lookups can be performed by the backend for embedded public indicators.
                  </StateMessage>
                  <div style={{ display: "flex", gap: "12px", alignItems: "center", marginTop: "10px" }}>
                    <button
                      type="button"
                      className="button button-secondary"
                      onClick={testConnection}
                      disabled={testingKey}
                      style={{ whiteSpace: "nowrap" }}
                    >
                      {testingKey ? "Testing Connection…" : "Test Connection"}
                    </button>
                    <span style={{ fontSize: "12px", color: "var(--soc-muted)" }}>
                      Tests the configured backend <code>.env</code> key against AbuseIPDB.
                    </span>
                  </div>
                </div>
              ) : (
                <div style={{ marginBottom: "12px" }}>
                  <StateMessage kind="info">
                    <strong>API key not configured.</strong> To enable live reputation lookups, configure{" "}
                    <code>ABUSEIPDB_API_KEY</code> in the project's local <code>.env</code> file (or copy <code>.env.example</code> to <code>.env</code>) and restart the FastAPI backend. Static APK analysis remains fully available without threat-intelligence lookups.
                  </StateMessage>
                </div>
              )}
              {testMessage && (
                <StateMessage kind={testMessage.success ? "success" : "error"}>
                  {testMessage.text}
                </StateMessage>
              )}
            </div>
          )}
          {!enableThreatIntel && (
            <p className="field-hint">Enable the toggle above to perform IP reputation lookups.</p>
          )}
        </div>

        <button
          className="button button-primary"
          style={{ marginTop: "16px" }}
          disabled={!file || busy}
          onClick={runAnalysis}
        >
          {busy ? "Analyzing…" : "Run static analysis"}
        </button>
      </section>

      {busy && <StateMessage kind="loading">Uploading APK and running the static analysis pipeline…</StateMessage>}
      {error && <StateMessage kind="error">{error}</StateMessage>}

      {result && (
        <div className="results-stack">
          {/* Enhanced Verdict Hero Banner */}
          <section className={`result-banner ${result.verdict === "MALWARE" ? "result-banner-malware" : "result-banner-benign"}`}>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                <span className={`badge ${result.verdict === "MALWARE" ? "badge-danger" : "badge-success"}`}>
                  {result.verdict === "MALWARE" ? "CRITICAL MALICIOUS VERDICT" : "VERIFIED BENIGN APPLICATION"}
                </span>
                <span className="topbar-env-pill">Drebin-215 · RF + XGBoost Fused Ensemble</span>
              </div>
              <h2 className={result.verdict === "MALWARE" ? "verdict-malware" : "verdict-benign"}>
                {result.verdict}
              </h2>
              <p style={{ maxWidth: "700px" }}>{result.notice}</p>
            </div>

            <div className="risk-gauge-wrap">
              <div className={`risk-gauge-circle ${result.verdict === "MALWARE" ? "risk-gauge-malware" : "risk-gauge-benign"}`}>
                <span className="risk-gauge-score" style={{ color: result.verdict === "MALWARE" ? "#f87171" : "#34d399" }}>
                  {(result.malware_probability * 100).toFixed(0)}%
                </span>
                <span className="risk-gauge-label">Malware Risk</span>
              </div>
              <div className="probability">
                <span>Threshold: ≥ {(result.decision_threshold * 100).toFixed(0)}%</span>
                <strong style={{ fontSize: "20px" }}>{(result.malware_probability * 100).toFixed(1)}%</strong>
              </div>
            </div>
          </section>

          {/* Dual-Column Analysis Workspace */}
          <div className="analysis-layout">
            {/* Primary Analysis Column (Left) */}
            <div style={{ display: "grid", gap: "16px" }}>
              {/* Quick Metrics */}
              <div className="metric-grid" style={{ margin: "0" }}>
                <ResultMetric label="Target Package" value={result.package} />
                <ResultMetric label="Features Detected" value={`${result.detected_features.length} / ${result.total_features}`} />
                <ResultMetric label="Embedded Public IPs" value={String(Object.keys(result.embedded_ips).length)} />
                <ResultMetric label="Embedded Domains" value={String(Object.keys(result.embedded_domains).length)} />
              </div>

              {/* Local SHAP Evidence Chart */}
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Local SHAP Feature Attributions</h2>
                    <p>
                      Contribution direction for this specific APK sample. Positive = toward malware; negative = toward benign.
                      <br />
                      <span style={{ fontSize: "11px", color: "#8cabc4" }}>
                        <b>Component Note:</b> Local SHAP attributions reflect the XGBoost component. The final verdict averages Random Forest (100 trees) and XGBoost probabilities with equal weight.
                      </span>
                    </p>
                  </div>
                  <span className="legend">
                    <i className="legend-positive" /> Toward malware{" "}
                    <i className="legend-negative" /> Toward benign
                  </span>
                </div>
                {shapData.length ? (
                  <div className="chart-wrap chart-tall">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={shapData} layout="vertical" margin={{ left: 12, right: 24 }}>
                        <CartesianGrid stroke="#25354a" horizontal={false} />
                        <XAxis type="number" tick={{ fill: "#98a9bd", fontSize: 11 }} />
                        <YAxis type="category" dataKey="feature" width={190} tick={{ fill: "#d9e2ed", fontSize: 11 }} />
                        <Tooltip
                          contentStyle={{ background: "#111c2b", border: "1px solid #34465c", color: "#e7edf5", borderRadius: "6px" }}
                          formatter={(value: number, _name, item) => [
                            `${value.toFixed(4)} · ${item.payload.present ? "present" : "absent"} · ${item.payload.direction}`,
                            "SHAP",
                          ]}
                        />
                        <Bar dataKey="shap" radius={[0, 4, 4, 0]}>
                          {shapData.map((item) => (
                            <Cell key={item.feature} fill={item.shap > 0 ? "#f87171" : "#34d399"} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                ) : <p className="empty-state">No SHAP evidence was returned.</p>}
              </section>

              {/* Suspicious Indicators & Explanations */}
              {(result.detailed_explanations?.length ?? 0) > 0 && <ExplanationsPanel result={result} />}

              {/* Threat Intelligence */}
              <ThreatIntelPanel result={result} />

              {/* MITRE ATT&CK Candidates */}
              <AttackCandidatesPanel result={result} />

              {/* Domain Shannon Entropy */}
              <DomainEntropyPanel result={result} />

              {/* URLhaus Threat Intelligence */}
              <UrlhausPanel result={result} />

              {/* Evidence Correlation */}
              <EvidenceCorrelationPanel result={result} />

              {/* Prediction summary & decision criteria */}
              <PredictionSummary result={result} />
            </div>

            {/* Inspector / Artifact Sidebar (Right) */}
            <aside className="inspector-sticky">
              {/* Quick Actions / Export */}
              <div className="meta-drawer">
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
                  <Download size={16} style={{ color: "var(--accent)" }} />
                  <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--text)", letterSpacing: "0.05em" }}>
                    EXPORT AUDIT DOSSIER
                  </span>
                </div>
                <div style={{ display: "grid", gap: "8px" }}>
                  <a
                    className="button button-primary"
                    href={reportUrl(result.analysis_id, "pdf")}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ justifyContent: "center" }}
                  >
                    <Download size={15} /> Download PDF Report
                  </a>
                  <button
                    id="btn-download-json"
                    className="button button-secondary"
                    disabled={downloadBusy}
                    onClick={downloadJson}
                    style={{ justifyContent: "center" }}
                  >
                    <Download size={15} /> {downloadBusy ? "Downloading…" : "Export JSON (SIEM)"}
                  </button>
                </div>
              </div>

              {/* Artifact Specifications */}
              <div className="meta-drawer">
                <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--accent)", letterSpacing: "0.1em", marginBottom: "12px" }}>
                  APK ARTIFACT SPECIFICATIONS
                </div>
                <div className="meta-row">
                  <span className="meta-label">File Name</span>
                  <span className="meta-val font-mono">{result.filename}</span>
                </div>
                <div className="meta-row">
                  <span className="meta-label">Package Identifier</span>
                  <span className="meta-val font-mono" style={{ color: "#76d7d7" }}>{result.package}</span>
                </div>
                {result.sha256 && (
                  <div className="meta-row">
                    <span className="meta-label">SHA-256 Digest</span>
                    <span className="meta-val font-mono hash-pill" title={result.sha256}>
                      {result.sha256.substring(0, 16)}…{result.sha256.substring(result.sha256.length - 8)}
                    </span>
                  </div>
                )}
                <div className="meta-row">
                  <span className="meta-label">Analysis Session ID</span>
                  <span className="meta-val font-mono hash-pill">{result.analysis_id}</span>
                </div>
              </div>

              {/* Inference Engine Specs */}
              <div className="meta-drawer">
                <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--accent)", letterSpacing: "0.1em", marginBottom: "12px" }}>
                  DETECTION ENGINE SPECS
                </div>
                <div className="meta-row">
                  <span className="meta-label">Active Classifier</span>
                  <span className="meta-val">{result.classifier_info}</span>
                </div>
                <div className="meta-row">
                  <span className="meta-label">Decision Boundary</span>
                  <span className="meta-val">≥ {(result.decision_threshold * 100).toFixed(0)}% Probability</span>
                </div>
                <div className="meta-row">
                  <span className="meta-label">Feature Dimension</span>
                  <span className="meta-val">215 Drebin Binary Indicators</span>
                </div>
              </div>
            </aside>
          </div>
        </div>
      )}
    </>
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
