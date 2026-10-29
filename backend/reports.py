"""Audit report generation for Android Malware Detection System.

Builds publication-quality JSON and PDF security audit reports containing genuine
model predictions, local SHAP attributions, suspicious static indicators,
dynamic runtime anomalies, and AbuseIPDB cyber threat intelligence findings.
Credentials and API keys are strictly excluded from all outputs.
"""

import io
import json
from datetime import datetime, timezone
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np

from backend.explanations import (
    classify_static_feature,
    explain_static_feature,
    explain_dynamic_syscall,
)

STATIC_CSV_COLUMNS = [
    "analysis_id",
    "filename",
    "sha256",
    "package_name",
    "app_name",
    "version_name",
    "verdict",
    "verdict_reason",
    "malware_probability",
    "decision_threshold",
    "classifier",
    "n_dex",
    "n_active_features",
    "total_features",
    "network_risk",
    "max_abuse_score",
    "malicious_ip_count",
    "timestamp",
]


def build_static_csv_report(
    result: dict[str, Any],
    filename: str = "unknown.apk",
    sha256: str = "unknown",
    analysis_id: str | None = None,
    threat_intel_status: str | None = None,
    **_kwargs: Any,
) -> bytes:
    """Serialize static analysis report into a standardized CSV summary row."""
    import csv
    payload = static_report_payload(result, filename=filename, sha256=sha256, analysis_id=analysis_id)
    if threat_intel_status is not None:
        payload["threat_intelligence"]["enrichment_status"] = threat_intel_status

    row = {
        "analysis_id": payload.get("analysis_id") or "",
        "filename": payload["apk"]["filename"],
        "sha256": payload["apk"]["sha256"],
        "package_name": payload["apk"]["package_name"],
        "app_name": payload["apk"]["app_name"],
        "version_name": payload["apk"]["version_name"],
        "verdict": payload["prediction"]["verdict"],
        "verdict_reason": payload["prediction"].get("verdict_reason") or "",
        "malware_probability": payload["prediction"]["malware_probability"],
        "decision_threshold": payload["prediction"]["decision_threshold"],
        "classifier": payload["prediction"]["classifier"],
        "n_dex": payload["apk"]["n_dex"],
        "n_active_features": payload["suspicious_indicators"]["n_active_features"],
        "total_features": payload["suspicious_indicators"]["total_feature_space"],
        "network_risk": payload["threat_intelligence"]["network_risk_level"],
        "max_abuse_score": payload["threat_intelligence"]["max_abuse_confidence_score"],
        "malicious_ip_count": payload["threat_intelligence"]["malicious_ip_count"],
        "timestamp": payload["timestamp"],
    }
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=STATIC_CSV_COLUMNS)
    writer.writeheader()
    writer.writerow(row)
    return buf.getvalue().encode("utf-8")



def static_report_payload(
    result: dict[str, Any],
    filename: str = "unknown.apk",
    sha256: str = "unknown",
    analysis_id: str | None = None,
) -> dict[str, Any]:
    """Generate a structured, standardized JSON payload for static analysis audit reports."""
    info = result.get("info") or {}
    static = result.get("static") or {}
    threat = result.get("threat_features") or {}
    prob = round(float(static.get("prob_malware", 0.0)), 4)
    verdict = static.get("verdict", "UNKNOWN")
    verdict_reason = static.get("verdict_reason") or static.get("reason")
    decision_threshold = 0.50

    # Classify detected features
    row = result.get("features")
    detected_features = []
    if row is not None and hasattr(row, "columns"):
        detected_features = [str(col) for col in row.columns[row.iloc[0] == 1]]

    n_dex = int(result.get("n_dex", info.get("n_dex", 0)))
    n_active = int(result.get("n_active_features", len(detected_features)))

    categorized_indicators: dict[str, list[str]] = {
        "sensitive_permissions": [],
        "suspicious_apis": [],
        "intent_filters": [],
        "shell_commands": [],
        "other": [],
    }
    for f in detected_features:
        cat = classify_static_feature(f)
        if cat == "permission":
            categorized_indicators["sensitive_permissions"].append(f)
        elif cat == "api_call":
            categorized_indicators["suspicious_apis"].append(f)
        elif cat == "intent_filter":
            categorized_indicators["intent_filters"].append(f)
        elif cat == "shell_command":
            categorized_indicators["shell_commands"].append(f)
        else:
            categorized_indicators["other"].append(f)

    # Detailed local SHAP explanations
    evidence = static.get("evidence") or []
    detailed_evidence = [
        explain_static_feature(
            feature=str(item.get("feature")),
            present=bool(item.get("present")),
            shap_value=float(item.get("shap", 0.0)),
        )
        for item in evidence
    ]

    # Threat Intelligence status and scrubbed lookups (guaranteeing NO credentials)
    raw_lookups = result.get("lookups") or []
    scrubbed_lookups = []
    for item in raw_lookups:
        scrubbed_lookups.append({
            "ip": item.get("ip"),
            "abuse_confidence_score": item.get("abuse_score"),
            "total_reports": item.get("total_reports", 0),
            "country_code": item.get("country"),
            "isp": item.get("isp"),
            "domain": item.get("domain"),
            "usage_type": item.get("usageType") or item.get("usage_type"),
            "last_reported_at": item.get("last_reported"),
            "lookup_status": item.get("status", "checked"),
            "error": item.get("error"),
        })

    # Prepare URLhaus lookups (ensure one entry per host with status UNAVAILABLE if not queried)
    raw_urlhaus = result.get("urlhaus")
    if raw_urlhaus:
        scrubbed_urlhaus = [
            {
                "host": u.get("host"),
                "status": u.get("status", "UNAVAILABLE"),
                "url_count": int(u.get("url_count", 0)),
                "urlhaus_reference": u.get("urlhaus_reference"),
                "error": u.get("error"),
            }
            for u in raw_urlhaus
        ]
    else:
        seen_hosts = set()
        all_hosts = []
        for h in list(result.get("ips", {}).keys()) + list(result.get("domains", {}).keys()):
            if h not in seen_hosts:
                seen_hosts.add(h)
                all_hosts.append(h)
        if all_hosts:
            scrubbed_urlhaus = [
                {
                    "host": h,
                    "status": "UNAVAILABLE",
                    "url_count": 0,
                    "error": "URLhaus lookup not queried: No Auth-Key provided or configured in ABUSECH_AUTH_KEY environment variable",
                }
                for h in all_hosts
            ]
        else:
            scrubbed_urlhaus = [
                {
                    "host": "none",
                    "status": "UNAVAILABLE",
                    "url_count": 0,
                    "error": "No embedded IP or domain hosts found in APK to query",
                }
            ]

    has_lookups = len(scrubbed_lookups) > 0
    ti_status = "enriched" if has_lookups else ("error" if result.get("lookup_error") else "skipped")

    supporting_evidence = []
    if verdict == "MALWARE":
        supporting_evidence.append(
            f"Machine Learning Ensemble evaluated {len(detected_features)} features and estimated {prob:.1%} malware probability, exceeding the 50.0% threshold."
        )
        top_positive = [e["feature"] for e in evidence if e.get("shap", 0) > 0][:3]
        if top_positive:
            supporting_evidence.append(
                f"Strongest local features pushing toward malware classification: {', '.join(top_positive)}."
            )
        if threat.get("max_abuse_score", 0) >= 50:
            supporting_evidence.append(
                f"Threat intelligence identified high-risk embedded IP with AbuseIPDB confidence score of {threat['max_abuse_score']}%."
            )
    elif verdict == "UNKNOWN":
        supporting_evidence.append(
            f"Classification verdict is UNKNOWN: {verdict_reason or 'APK contains no DEX code or all static features are zero; verdict cannot be reliably determined as BENIGN.'}"
        )
    else:
        supporting_evidence.append(
            f"Machine Learning Ensemble estimated {prob:.1%} malware probability, remaining below the 50.0% decision threshold."
        )
        top_negative = [e["feature"] for e in evidence if e.get("shap", 0) < 0][:3]
        if top_negative:
            supporting_evidence.append(
                f"Strongest local features pushing toward benign classification: {', '.join(top_negative)}."
            )

    return {
        "report_schema_version": "1.0.0",
        "analysis_id": analysis_id,
        "analysis_type": "static",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "n_dex": n_dex,
        "n_active_features": n_active,
        "apk": {
            "filename": filename,
            "sha256": sha256,
            "package_name": info.get("package", "unknown"),
            "app_name": info.get("app_name", ""),
            "version_name": info.get("version_name", ""),
            "n_dex": n_dex,
        },
        "prediction": {
            "verdict": verdict,
            "verdict_reason": verdict_reason,
            "probability": prob,
            "malware_probability": prob,
            "decision_threshold": decision_threshold,
            "classifier": "Soft-Voting Ensemble (Random Forest + XGBoost)",
            "training_dataset": "Drebin-215 (7,254 deduplicated applications)",
            "score_interpretation": (
                "Probability of malicious sideloaded APK behavior generated by averaging output probabilities "
                "from Random Forest (100 estimators) and XGBoost (max depth 6). Scores >= 0.50 are classified as MALWARE."
            ),
        },
        "model_explanation": {
            "method": "SHAP TreeExplainer (local feature attributions)",
            "evidence": detailed_evidence,
            "interpretation_guide": "Positive SHAP values push verdict toward MALWARE; negative values push toward BENIGN.",
        },
        "local_shap_evidence": detailed_evidence,
        "suspicious_indicators": {
            "n_dex": n_dex,
            "n_active_features": n_active,
            "total_features_detected": len(detected_features),
            "total_feature_space": int(row.shape[1]) if row is not None and hasattr(row, "shape") else 215,
            "categorized_findings": categorized_indicators,
        },
        "threat_intelligence": {
            "service": "AbuseIPDB REST API v2 & URLhaus API",
            "enrichment_status": ti_status,
            "network_risk_level": threat.get("network_risk", "UNKNOWN"),
            "max_abuse_confidence_score": threat.get("max_abuse_score", 0),
            "malicious_ip_count": threat.get("malicious_ip_count", 0),
            "embedded_public_ips": result.get("ips", {}),
            "embedded_domains": result.get("domains", {}),
            "dns_resolved_ips": result.get("resolved", {}),
            "ip_reputation_lookups": scrubbed_lookups,
            "urlhaus_lookups": scrubbed_urlhaus,
            "lookup_error": result.get("lookup_error"),
            "domain_disclosure": (
                "Domains are extracted statically from application DEX bytecode string tables. "
                "AbuseIPDB is an IP reputation service; domain names are reported separately as extracted indicators."
            ),
        },
        "domain_entropy_analysis": {
            "status": "heuristic / candidate",
            "threshold": 3.4,
            "description": "Shannon entropy of registrable domain label (offline tldextract). Labels with fewer than 11 distinct characters cannot exceed 3.4.",
            "domains": result.get("domain_entropy", []),
        },
        "attack_candidates": [
            {
                "technique_id": ac.get("technique_id"),
                "technique_name": ac.get("technique_name"),
                "status": "heuristic / candidate",
                "label": "candidate",
                "evidence": ac.get("evidence"),
            }
            for ac in result.get("attack_candidates", [])
        ],
        "supporting_evidence": supporting_evidence,
        "analysis_limitations": [
            "Static analysis decompiles bytecode and manifest structures without executing code in an emulator.",
            "Dynamic reflection, runtime string decryption, or runtime payload dropping can evade static inspection.",
            "AbuseIPDB data represents historical crowd-sourced reports and does not constitute captured live network traffic.",
            "Model predictions provide probabilistic decision support and should be paired with dynamic sandbox verification.",
        ],
    }


def build_static_json_report(
    result: dict[str, Any],
    filename: str = "unknown.apk",
    sha256: str = "unknown",
    analysis_id: str | None = None,
    threat_intel_status: str | None = None,
    **_kwargs: Any,
) -> bytes:
    """Serialize static analysis report payload into formatted UTF-8 JSON bytes."""
    payload = static_report_payload(result, filename=filename, sha256=sha256, analysis_id=analysis_id)
    if threat_intel_status is not None:
        payload["threat_intelligence"]["enrichment_status"] = threat_intel_status
    return json.dumps(payload, indent=2, default=str).encode("utf-8")


def dynamic_report_payload(
    dynamic_result: dict[str, Any],
) -> dict[str, Any]:
    """Generate a structured, standardized JSON payload for dynamic analysis audit reports."""
    prob_shares = round(float(dynamic_result.get("probability_normalized_shares", 0.0)), 4)
    prob_counts = round(float(dynamic_result.get("probability_raw_counts", 0.0)), 4)
    verdict = "MALWARE" if prob_shares >= 0.50 else "BENIGN"

    evidence = dynamic_result.get("shap_evidence") or []
    anomalies = [
        explain_dynamic_syscall(
            syscall=str(item.get("syscall")),
            count=int(item.get("count", 0)),
            shap_value=float(item.get("shap", 0.0)),
        )
        for item in evidence
    ]

    return {
        "report_schema_version": "1.0.0",
        "job_id": dynamic_result.get("job_id"),
        "analysis_type": "dynamic",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "apk": {
            "filename": dynamic_result.get("filename", "unknown.apk"),
            "sha256": dynamic_result.get("sha256", "unknown"),
            "package_name": dynamic_result.get("package", "unknown"),
        },
        "emulation_environment": {
            "requested_trace_seconds": dynamic_result.get("requested_seconds"),
            "actual_trace_seconds": dynamic_result.get("actual_seconds"),
            "total_system_calls_counted": dynamic_result.get("system_call_count"),
            "vocabulary_coverage": round(float(dynamic_result.get("vocabulary_coverage", 0.0)), 4),
            "features_seen": dynamic_result.get("features_seen"),
        },
        "prediction": {
            "verdict": verdict,
            "decision_threshold": 0.50,
            "malware_probability": prob_shares,
            "probability_normalized_shares": prob_shares,
            "probability_raw_counts": prob_counts,
            "classifier": "Dynamic XGBoost (Normalized System-Call Shares)",
            "training_dataset": "CICMalDroid2020 (11,520 applications across 139 system calls)",
            "score_interpretation": (
                "Probability of malicious behavior derived from frequency-normalized system calls captured "
                "via Linux strace during automated Monkey UI fuzzing in a rooted Android emulator."
            ),
        },
        "runtime_anomalies_and_behavioral_evidence": anomalies,
        "system_call_counts": dynamic_result.get("counts", {}),
        "unmapped_system_calls": dynamic_result.get("unmapped_counts", {}),
        "raw_strace_summary": dynamic_result.get("raw_report", ""),
        "analysis_limitations": [
            "Dynamic analysis was performed in a virtual emulator environment; advanced malware may employ anti-sandbox evasion.",
            "Short trace durations may miss delayed or trigger-based malicious payloads.",
            "CICMalDroid2020 was trained on 32-bit ARM architectures; syscall frequency patterns may vary on modern x86/ARM64 images.",
            "System calls like mprotect or socket creation are common in benign runtime JIT and networking operations and require contextual review.",
        ],
    }


def build_dynamic_json_report(dynamic_result: dict[str, Any], job_info: dict[str, Any] | None = None, **_kwargs: Any) -> bytes:
    """Serialize dynamic analysis report payload into formatted UTF-8 JSON bytes."""
    payload = dynamic_report_payload(dynamic_result)
    if job_info:
        payload["job_created_at"] = job_info.get("created_at")
        payload["job_started_at"] = job_info.get("started_at")
        payload["job_completed_at"] = job_info.get("completed_at")
    return json.dumps(payload, indent=2, default=str).encode("utf-8")


def build_static_pdf_report(
    result: dict[str, Any],
    filename: str = "unknown.apk",
    sha256: str = "unknown",
    analysis_id: str | None = None,
    **_kwargs: Any,
) -> bytes:
    """Build a publication-quality 2-page PDF audit report with embedded charts and metadata."""
    info = result.get("info") or {}
    static = result.get("static") or {}
    evidence = static.get("evidence") or []
    threat = result.get("threat_features") or {}
    output = io.BytesIO()

    with PdfPages(output) as pdf:
        figure = plt.figure(figsize=(8.5, 11), dpi=140)
        figure.text(0.5, 0.96, "APK SECURITY ANALYSIS REPORT", ha="center",
                    fontsize=17, fontweight="bold")
        figure.text(0.5, 0.935, "AI-Based Sideloaded Malware Detection & Explainable AI",
                    ha="center", fontsize=9.5, color="#536273")
        verdict = static.get("verdict", "UNKNOWN")
        prob = float(static.get("prob_malware", 0))

        # Verdict Banner
        is_malware = verdict == "MALWARE"
        is_unknown = verdict == "UNKNOWN"
        box_color = "#fce8e6" if is_malware else "#fef7e0" if is_unknown else "#e6f4ea"
        text_color = "#c5221f" if is_malware else "#b06000" if is_unknown else "#137333"

        ax_banner = figure.add_axes([0.08, 0.83, 0.84, 0.08])
        ax_banner.set_facecolor(box_color)
        ax_banner.set_xticks([])
        ax_banner.set_yticks([])
        for spine in ax_banner.spines.values():
            spine.set_color(text_color)
            spine.set_linewidth(1.5)
        ax_banner.text(0.5, 0.60, f"VERDICT: {verdict}", fontsize=16, fontweight="bold", color=text_color, ha="center", va="center")
        ax_banner.text(
            0.5, 0.22,
            f"Malware Probability: {prob:.1%} (Threshold: 50.0%)   |   Network Risk: {threat.get('network_risk', 'UNKNOWN')}   |   Max Abuse Score: {threat.get('max_abuse_score', 0)}",
            fontsize=9, color=text_color, ha="center", va="center"
        )

        figure.text(
            0.08, 0.79,
            "\n".join((
                f"Target File:        {filename} (SHA-256: {sha256[:16]}...)",
                f"Package Name:       {info.get('package', 'Unknown')}",
                f"Application Name:   {info.get('app_name', 'Unknown')}",
                f"Version:            {info.get('version_name', 'Unknown')}",
                f"Analysis Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                f"Classifier:         Ensemble (Random Forest + XGBoost on Drebin-215)",
            )),
            family="monospace", fontsize=8.5, va="top", linespacing=1.6,
        )

        if evidence:
            axis = figure.add_axes([0.16, 0.14, 0.76, 0.44])
            values = [float(row["shap"]) for row in evidence]
            labels = [
                f"{row['feature']} ({'present' if row['present'] else 'absent'})"
                for row in evidence
            ]
            colors = ["#c36b62" if value > 0 else "#277c64" for value in values]
            positions = np.arange(len(values))
            axis.barh(positions, values, color=colors, height=0.62)
            axis.set_yticks(positions, labels, fontsize=8)
            axis.invert_yaxis()
            axis.axvline(0, color="#536273", linewidth=0.8)
            axis.set_xlabel("SHAP Impact (+ pushes toward MALWARE, - pushes toward BENIGN)")
            axis.set_title("Local Explainable AI Evidence (SHAP TreeExplainer)")
            axis.spines[["top", "right"]].set_visible(False)
        else:
            figure.text(0.5, 0.4, "No SHAP evidence was returned.", ha="center")

        figure.text(
            0.08, 0.05,
            "DISCLOSURE: This prediction is generated probabilistically by a machine learning ensemble. "
            "Indicators are read statically from the APK container and do not reflect captured network traffic.",
            fontsize=7.5, color="#536273", wrap=True,
        )
        pdf.savefig(figure, bbox_inches="tight")
        plt.close(figure)

        # Page 2: Threat Intelligence & Extracted Indicators
        figure = plt.figure(figsize=(8.5, 11), dpi=140)
        figure.text(0.08, 0.94, "INDICATORS AND THREAT INTELLIGENCE AUDIT", fontsize=14,
                    fontweight="bold")

        lines = [
            f"Threat Intelligence Status: {threat.get('network_risk', 'UNKNOWN')} network risk",
            f"Max Abuse Confidence Score: {threat.get('max_abuse_score', 0)}% (malicious threshold >= 50%)",
            "",
            "Embedded Public IP Addresses:",
        ]
        ips = result.get("ips", {})
        if ips:
            lines.extend(f"  • {ip:18s} context: {ctx[:60]}" for ip, ctx in ips.items())
        else:
            lines.append("  (None detected)")

        lines.extend(["", "Embedded Hostnames and Domains:"])
        domains = result.get("domains", {})
        if domains:
            lines.extend(f"  • {d:30s} context: {ctx[:50]}" for d, ctx in list(domains.items())[:12])
            if len(domains) > 12:
                lines.append(f"  ... and {len(domains) - 12} additional domains")
        else:
            lines.append("  (None detected)")

        lines.extend(["", "AbuseIPDB Reputation Lookups:"])
        lookups = result.get("lookups", [])
        if lookups:
            for item in lookups:
                status_str = f"score: {item.get('abuse_score')}%, reports: {item.get('total_reports')}" if item.get('status') == 'checked' else f"status: {item.get('status')} ({item.get('error')})"
                lines.append(f"  • {item.get('ip'):18s} -> {status_str}")
        else:
            lines.append("  No live reputation lookups were performed (API key was not supplied or enrichment was skipped).")

        if result.get("lookup_error"):
            lines.extend(["", f"Lookup Error Encountered: {result['lookup_error']}"])

        # URLhaus section
        urlhaus = result.get("urlhaus", [])
        if urlhaus:
            lines.extend(["", "URLhaus Threat Intelligence (abuse.ch, heuristic / candidate):"])
            for uh in urlhaus[:8]:
                lines.append(f"  • {uh.get('host'):25s} -> {uh.get('status')} (urls: {uh.get('url_count', 0)})")

        # Domain Shannon Entropy section
        domain_entropy = result.get("domain_entropy", [])
        if domain_entropy:
            lines.extend(["", "Domain Shannon Entropy (heuristic / candidate, threshold > 3.4):"])
            for de in domain_entropy[:6]:
                flag_txt = "[FLAGGED DGA CANDIDATE]" if de.get("flag") else "normal"
                lines.append(f"  • {de.get('domain'):25s} label: {de.get('label'):14s} entropy: {de.get('entropy', 0):.3f} ({flag_txt})")

        # MITRE ATT&CK Candidate Techniques
        attack_candidates = result.get("attack_candidates", [])
        if attack_candidates:
            lines.extend(["", "MITRE ATT&CK Techniques (heuristic / candidate):"])
            for ac in attack_candidates[:8]:
                lines.append(f"  • [{ac.get('technique_id')}] {ac.get('technique_name')} (candidate) - {ac.get('evidence')[:45]}")

        figure.text(0.08, 0.88, "\n".join(lines), va="top", family="monospace",
                    fontsize=7.5, linespacing=1.35)
        figure.text(
            0.08, 0.05,
            "NOTE: AbuseIPDB reputation data is gathered from external threat intelligence feeds and is never stored permanently. "
            "All lookup requests are performed securely through the backend proxy.",
            fontsize=7.5, color="#536273", wrap=True,
        )
        pdf.savefig(figure, bbox_inches="tight")
        plt.close(figure)

    return output.getvalue()
