import io
import json
from datetime import datetime, timezone
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np


def static_report_payload(result: dict[str, Any]) -> dict[str, Any]:
    info = result["info"]
    static = result["static"]
    return {
        "package": info.get("package"),
        "app_name": info.get("app_name"),
        "version_name": info.get("version_name"),
        "verdict": static["verdict"],
        "malware_probability": round(float(static["prob_malware"]), 4),
        "evidence": static["evidence"],
        "embedded_ips": result["ips"],
        "embedded_domains": result["domains"],
        "resolved_ips": result.get("resolved", {}),
        "lookups": result["lookups"],
        "threat_features": result["threat_features"],
        "lookup_error": result.get("lookup_error"),
    }


def build_static_json_report(result: dict[str, Any]) -> bytes:
    return json.dumps(static_report_payload(result), indent=2, default=str).encode("utf-8")


def build_static_pdf_report(result: dict[str, Any]) -> bytes:
    info = result.get("info") or {}
    static = result.get("static") or {}
    evidence = static.get("evidence") or []
    threat = result.get("threat_features") or {}
    output = io.BytesIO()

    with PdfPages(output) as pdf:
        figure = plt.figure(figsize=(8.5, 11), dpi=140)
        figure.text(0.5, 0.96, "APK SECURITY ANALYSIS REPORT", ha="center",
                    fontsize=17, fontweight="bold")
        figure.text(0.5, 0.93, "Static Drebin-215 ensemble and local SHAP evidence",
                    ha="center", fontsize=10, color="#536273")
        verdict = static.get("verdict", "UNKNOWN")
        figure.text(
            0.08, 0.86,
            f"Verdict: {verdict}     Malware probability: {float(static.get('prob_malware', 0)):.1%}",
            fontsize=12, fontweight="bold",
        )
        figure.text(
            0.08, 0.78,
            "\n".join((
                f"Package: {info.get('package', 'Unknown')}",
                f"Application: {info.get('app_name', 'Unknown')}",
                f"Version: {info.get('version_name', 'Unknown')}",
                f"Network risk: {threat.get('network_risk', 'UNKNOWN')}",
                f"Max AbuseIPDB score: {threat.get('max_abuse_score', 'Unknown')}",
                f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            )),
            family="monospace", fontsize=9, va="top", linespacing=1.7,
        )
        if evidence:
            axis = figure.add_axes([0.16, 0.14, 0.78, 0.46])
            values = [float(row["shap"]) for row in evidence]
            labels = [
                f"{row['feature']} ({'present' if row['present'] else 'absent'})"
                for row in evidence
            ]
            colors = ["#b4473d" if value > 0 else "#277c64" for value in values]
            positions = np.arange(len(values))
            axis.barh(positions, values, color=colors, height=0.62)
            axis.set_yticks(positions, labels, fontsize=8)
            axis.invert_yaxis()
            axis.axvline(0, color="#536273", linewidth=0.8)
            axis.set_xlabel("SHAP impact (positive: malware; negative: benign)")
            axis.set_title("Local model evidence")
            axis.spines[["top", "right"]].set_visible(False)
        else:
            figure.text(0.5, 0.4, "No SHAP evidence was returned.", ha="center")
        figure.text(
            0.08, 0.06,
            "A model prediction is not definitive proof of malicious behavior. "
            "Embedded indicators are read from the APK, not captured from live traffic.",
            fontsize=8, color="#536273", wrap=True,
        )
        pdf.savefig(figure, bbox_inches="tight")
        plt.close(figure)

        figure = plt.figure(figsize=(8.5, 11), dpi=140)
        figure.text(0.08, 0.94, "INDICATORS AND THREAT INTELLIGENCE", fontsize=14,
                    fontweight="bold")
        lines = [
            "Embedded public IP addresses:",
            *(f"  {ip} — {context}" for ip, context in result.get("ips", {}).items()),
            "",
            "Embedded domains:",
            *(f"  {domain} — {context}" for domain, context in result.get("domains", {}).items()),
            "",
            "AbuseIPDB lookups:",
            *(f"  {item.get('ip')} — score {item.get('abuse_score')}, "
              f"reports {item.get('total_reports')}" for item in result.get("lookups", [])),
        ]
        if result.get("lookup_error"):
            lines.extend(["", f"Lookup error: {result['lookup_error']}"])
        if not result.get("lookups"):
            lines.extend(["", "No reputation lookup result is available; unknown does not mean safe."])
        figure.text(0.08, 0.88, "\n".join(lines), va="top", family="monospace",
                    fontsize=8.5, linespacing=1.45)
        figure.text(
            0.08, 0.06,
            "Threat-intelligence checks are optional and depend on backend configuration. "
            "They do not represent captured network traffic.",
            fontsize=8, color="#536273", wrap=True,
        )
        pdf.savefig(figure, bbox_inches="tight")
        plt.close(figure)

    return output.getvalue()
