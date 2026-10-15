"""
Streamlit UI for:
  AI-Based Detection of Malicious Sideloaded Android Applications
  Using Runtime Threat Intelligence

This file is the interface only. All machine-learning and analysis logic
lives in phase3_live_demo.py and is imported, never reimplemented.
"""

import datetime
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import matplotlib
matplotlib.use("Agg")                              # non-interactive backend for Streamlit
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np
import pandas as pd
import streamlit as st

# ---------------------------------------------------------------------------
# The existing analysis API
# ---------------------------------------------------------------------------
from phase3_live_demo import analyze_apk, INTENT_FEATURES, COMMAND_FEATURES

# ---------------------------------------------------------------------------
# Paths (relative to this file, works on Windows)
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent

STATIC_DIR   = BASE_DIR / "static_outputs"
DYNAMIC_DIR  = BASE_DIR / "dynamic_outputs_v2"
SAMPLE_APK   = BASE_DIR / "sample_app.apk"

# ========================== page config ====================================
st.set_page_config(
    page_title=(
        "AI-Based Detection of Malicious Sideloaded Android Applications "
        "Using Runtime Threat Intelligence"
    ),
    layout="wide",
)

# ========================== global styles ==================================
st.markdown("""
<style>
    /* Clean academic look: neutral palette, readable typography */
    .main .block-container { max-width: 1100px; }
    h1, h2, h3, h4 { font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; }
    .verdict-benign {
        background-color: #d4edda; color: #155724;
        padding: 1rem 1.5rem; border-radius: 8px;
        font-size: 1.6rem; font-weight: 700; text-align: center;
    }
    .verdict-malware {
        background-color: #f8d7da; color: #721c24;
        padding: 1rem 1.5rem; border-radius: 8px;
        font-size: 1.6rem; font-weight: 700; text-align: center;
    }
    .caption-text { color: #555; font-size: 0.85rem; }
</style>
""", unsafe_allow_html=True)


# ========================== helper functions ===============================
def safe_read_csv(path: Path, index_col=None, label: str = ""):
    """Read a CSV and return a DataFrame, or None with a warning on failure."""
    if not path.exists():
        st.warning(f"File not found: {path.name}" + (f" ({label})" if label else ""))
        return None
    try:
        return pd.read_csv(path, index_col=index_col)
    except Exception as exc:
        st.warning(f"Could not read {path.name}: {exc}")
        return None


def safe_show_image(path: Path, caption: str = ""):
    """Display a PNG with st.image, or show a warning if missing."""
    if not path.exists():
        st.warning(f"Image not found: {path.name}")
        return
    try:
        st.image(str(path), caption=caption, use_container_width=True)
    except Exception as exc:
        st.warning(f"Could not display {path.name}: {exc}")


def classify_feature(name: str) -> str:
    """Assign a feature to one of four groups."""
    if name in COMMAND_FEATURES:
        return "commands"
    if name in INTENT_FEATURES:
        return "intents"
    if re.fullmatch(r"[A-Z][A-Z_]+", name):
        return "permissions"
    return "API calls"


def build_shap_chart(evidence: list):
    """Create a horizontal bar chart of SHAP evidence values."""
    features = [e["feature"] for e in evidence]
    shap_vals = [e["shap"] for e in evidence]
    labels = [
        f"{e['feature']}  ({'present' if e['present'] else 'absent'})"
        for e in evidence
    ]

    colours = ["#c0392b" if v > 0 else "#27ae60" for v in shap_vals]

    fig, ax = plt.subplots(figsize=(8, max(3, 0.45 * len(features))))
    y_pos = np.arange(len(features))
    ax.barh(y_pos, shap_vals, color=colours, edgecolor="none", height=0.6)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel("SHAP value (impact on prediction)", fontsize=9)
    ax.axvline(0, color="#333", linewidth=0.8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    return fig


def build_report_json(result: dict) -> str:
    """Build a downloadable JSON report. Never includes the API key."""
    info = result["info"]
    report = {
        "package": info.get("package"),
        "app_name": info.get("app_name"),
        "version_name": info.get("version_name"),
        "verdict": result["static"]["verdict"],
        "malware_probability": round(result["static"]["prob_malware"], 4),
        "evidence": result["static"]["evidence"],
        "embedded_ips": result["ips"],
        "embedded_domains": result["domains"],
        "resolved_ips": result.get("resolved", {}),
        "lookups": result["lookups"],
        "threat_features": result["threat_features"],
    }
    return json.dumps(report, indent=2, default=str)


def build_report_pdf(result: dict) -> bytes:
    """Build a publication-quality 2-page PDF audit report."""
    buf = io.BytesIO()
    with PdfPages(buf) as pdf:
        # ---------------- Page 1: Executive Summary & SHAP ----------------
        fig1 = plt.figure(figsize=(8.5, 11), dpi=150)
        
        fig1.text(0.5, 0.96, "APK SECURITY AUDIT REPORT", fontsize=18, fontweight="bold", ha="center", color="#1a1a1a")
        fig1.text(0.5, 0.938, "AI-Based Detection Using Runtime Threat Intelligence & Explainable AI", fontsize=9.5, ha="center", color="#555555")
        
        info = result.get("info") or {}
        static = result.get("static") or {}
        verdict = static.get("verdict", "UNKNOWN")
        prob = static.get("prob_malware", 0.0)
        ti = result.get("threat_features") or {}
        
        is_benign = verdict == "BENIGN"
        box_color = "#d4edda" if is_benign else "#f8d7da"
        text_color = "#155724" if is_benign else "#721c24"
        
        # Verdict Banner Box
        ax_banner = fig1.add_axes([0.1, 0.835, 0.8, 0.08])
        ax_banner.set_facecolor(box_color)
        ax_banner.set_xticks([])
        ax_banner.set_yticks([])
        for spine in ax_banner.spines.values():
            spine.set_color(text_color)
            spine.set_linewidth(1.5)
        ax_banner.text(0.5, 0.60, f"VERDICT: {verdict}", fontsize=17, fontweight="bold", color=text_color, ha="center", va="center")
        ax_banner.text(
            0.5, 0.22,
            f"Malware Probability: {prob:.1%}   |   Network Risk: {ti.get('network_risk', 'UNKNOWN')}   |   Max Abuse Score: {ti.get('max_abuse_score', 0)}",
            fontsize=9.5, color=text_color, ha="center", va="center"
        )
        
        # Metadata Block
        ax_meta = fig1.add_axes([0.1, 0.725, 0.8, 0.095])
        ax_meta.axis("off")
        meta_lines = [
            f"Target Package:      {info.get('package', 'Unknown')}",
            f"Application Name:    {info.get('app_name', 'Unknown')}",
            f"Version:             {info.get('version_name', 'Unknown')} (Code: {info.get('version_code', 'Unknown')})",
            f"Analysis Timestamp:  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC",
            f"Classifier:          Ensemble (Random Forest + XGBoost on Drebin-215)",
        ]
        ax_meta.text(0, 0.5, "\n".join(meta_lines), fontsize=9, family="monospace", va="center", linespacing=1.4)
        
        # SHAP Evidence Chart
        evidence = static.get("evidence", [])
        if evidence:
            ax_shap = fig1.add_axes([0.22, 0.12, 0.68, 0.56])
            features = [e["feature"] for e in evidence]
            shap_vals = [e["shap"] for e in evidence]
            labels = [
                f"{e['feature']} ({'present' if e['present'] else 'absent'})"
                for e in evidence
            ]
            colours = ["#c0392b" if v > 0 else "#27ae60" for v in shap_vals]
            y_pos = np.arange(len(features))
            ax_shap.barh(y_pos, shap_vals, color=colours, height=0.6)
            ax_shap.set_yticks(y_pos)
            ax_shap.set_yticklabels(labels, fontsize=8)
            ax_shap.invert_yaxis()
            ax_shap.axvline(0, color="#333333", linewidth=0.8)
            ax_shap.set_xlabel("SHAP Impact (Red: pushes toward Malware | Green: pushes toward Benign)", fontsize=8.5)
            ax_shap.set_title("Decision Evidence: Local Feature Attributions (SHAP)", fontsize=10.5, fontweight="bold", pad=8)
            ax_shap.spines["top"].set_visible(False)
            ax_shap.spines["right"].set_visible(False)
        else:
            ax_no_shap = fig1.add_axes([0.1, 0.3, 0.8, 0.2])
            ax_no_shap.axis("off")
            ax_no_shap.text(0.5, 0.5, "No SHAP feature evidence available.", ha="center", fontsize=11, color="#777777")

        fig1.text(0.5, 0.04, "Page 1 of 2  •  AI-Based Detection of Malicious Sideloaded Android Applications", fontsize=8, ha="center", color="#888888")
        pdf.savefig(fig1)
        plt.close(fig1)

        # ---------------- Page 2: Indicator Inventory & Findings ----------------
        fig2 = plt.figure(figsize=(8.5, 11), dpi=150)
        fig2.text(0.5, 0.96, "TECHNICAL INVENTORY & AUDIT FINDINGS", fontsize=16, fontweight="bold", ha="center", color="#1a1a1a")
        fig2.text(0.5, 0.938, f"Package: {info.get('package', 'Unknown')}  •  Verdict: {verdict}", fontsize=9.5, ha="center", color="#555555")

        row = result.get("features")
        detected_names = list(row.columns[row.iloc[0] == 1]) if row is not None else []
        total_feats = row.shape[1] if row is not None else 215
        group_counts = {"permissions": 0, "intents": 0, "API calls": 0, "commands": 0}
        for f in detected_names:
            group_counts[classify_feature(f)] += 1

        ips = result.get("ips") or {}
        domains = result.get("domains") or {}
        lookups = result.get("lookups") or []

        ax_text = fig2.add_axes([0.1, 0.08, 0.8, 0.83])
        ax_text.axis("off")

        lines = [
            f"1. DREBIN-215 FEATURE PROFILE ({len(detected_names)} of {total_feats} features active)",
            f"   - Android Permissions: {group_counts['permissions']}",
            f"   - Action Intents:      {group_counts['intents']}",
            f"   - Sensitive API Calls: {group_counts['API calls']}",
            f"   - Shell Commands:      {group_counts['commands']}",
            "",
            "2. DETECTED PERMISSIONS & INTENTS (SAMPLE):",
        ]
        perms = [f for f in detected_names if classify_feature(f) in ("permissions", "intents")]
        if perms:
            for p in sorted(perms)[:14]:
                lines.append(f"   [+] {p}")
            if len(perms) > 14:
                lines.append(f"   ... and {len(perms) - 14} more permissions/intents")
        else:
            lines.append("   [x] No dangerous permissions or actions detected in manifest.")

        lines.extend([
            "",
            f"3. EMBEDDED NETWORK INDICATORS IN BYTECODE:",
            f"   - Public IP Addresses ({len(ips)} found):",
        ])
        if ips:
            for ip, ctx in list(ips.items())[:6]:
                lines.append(f"     * {ip:<18} (context: {ctx[:45]})")
        else:
            lines.append("     * None embedded in application DEX code.")

        lines.append(f"   - Embedded Domain Names ({len(domains)} found):")
        if domains:
            for d, ctx in list(domains.items())[:6]:
                lines.append(f"     * {d:<30} (context: {ctx[:40]})")
        else:
            lines.append("     * None embedded in application DEX code.")

        if lookups:
            lines.extend([
                "",
                "4. ABUSEIPDB REPUTATION LOOKUP RESULTS:",
            ])
            for lk in lookups[:5]:
                lines.append(f"     * IP: {lk.get('ip', '?'):<16} Score: {lk.get('abuse_score', 0):>3}%  Country: {lk.get('country', '?')}  ISP: {str(lk.get('isp', '?'))[:30]}")

        lines.extend([
            "",
            "5. METHODOLOGY & ACADEMIC AUDIT NOTES:",
            "   - Analysis performed strictly on decompiled bytecode and XML manifest without execution.",
            "   - Threat intelligence relies on public telemetry and may not capture dynamic C2 infrastructure.",
            "   - Drebin-215 static benchmark provides standard academic comparability.",
        ])

        ax_text.text(0, 0.98, "\n".join(lines), fontsize=9, family="monospace", va="top", linespacing=1.35)

        fig2.text(0.5, 0.04, "Page 2 of 2  •  AI-Based Detection of Malicious Sideloaded Android Applications", fontsize=8, ha="center", color="#888888")
        pdf.savefig(fig2)
        plt.close(fig2)

    return buf.getvalue()


# ========================== sidebar ========================================
with st.sidebar:
    st.header("⚙️ Configuration")
    api_key_input = st.text_input(
        "AbuseIPDB API key", type="password",
        help="Used only to query AbuseIPDB. Never stored or logged.",
    )
    # Resolve the effective key: user input first, then env var
    abuse_key = api_key_input.strip() or os.environ.get("ABUSEIPDB_KEY", "").strip() or None

    resolve_domains = st.checkbox(
        "Resolve domains to IPs and check them",
        value=False,
        help=(
            "Makes live DNS queries from this computer for every domain "
            "found in the app. Use only on purpose."
        ),
    )

    st.markdown("---")
    st.subheader("🛡️ Pipeline Status")
    st.markdown(
        "- **Static Pipeline:** 🟢 Drebin-215 (RF + XGB)\n"
        "- **Dynamic Engine:** 🟢 CICMalDroid2020\n"
        f"- **Threat Intelligence:** {'🟢 API Connected' if abuse_key else '⚪ Passive (No API Key)'}"
    )

    st.markdown("---")
    with st.expander("📖 Analysis Protocol"):
        st.markdown(
            "1. **Upload APK**: Target APK bytecode is unpacked in isolated memory.\n"
            "2. **Drebin-215 Extraction**: 215 permissions, API calls, and intents are vectorized.\n"
            "3. **Inference & SHAP**: Model scores malware probability and generates local attribution charts.\n"
            "4. **Threat Intel**: Embedded indicators are checked against AbuseIPDB.\n"
            "5. **Audit Export**: Full JSON and 2-page PDF reports available."
        )


# ========================== page header ====================================
st.title("AI-Based Detection of Malicious Sideloaded Android Applications Using Runtime Threat Intelligence")
st.markdown("A dual-pipeline framework combining static Drebin-215 features, dynamic CICMalDroid2020 system calls, Explainable AI (SHAP), and live IP reputation intelligence.")
st.markdown("---")

# ========================== tabs ===========================================
tab_analyze, tab_static, tab_dynamic, tab_about = st.tabs([
    "🔍 Analyze an APK",
    "📊 Static Model Results",
    "⚡ Dynamic Model Results",
    "ℹ️ About and Limitations",
])


# ============================= TAB 1 ======================================
with tab_analyze:
    st.header("Analyze an APK")

    uploaded = st.file_uploader(
        "Upload an APK file", type=["apk"],
        help="The APK is only read (like opening a zip). It is never installed or run.",
    )

    # State initialization
    if "analysis_result" not in st.session_state:
        st.session_state["analysis_result"] = None
    if "analyzed_app_name" not in st.session_state:
        st.session_state["analyzed_app_name"] = None
    if "use_sample_active" not in st.session_state:
        st.session_state["use_sample_active"] = False
    if "last_uploaded_name" not in st.session_state:
        st.session_state["last_uploaded_name"] = None

    # Reset result if a new file is uploaded
    if uploaded is not None and uploaded.name != st.session_state.get("last_uploaded_name"):
        st.session_state["last_uploaded_name"] = uploaded.name
        st.session_state["use_sample_active"] = False
        st.session_state["analysis_result"] = None
    elif uploaded is None and not st.session_state.get("use_sample_active", False):
        st.session_state["last_uploaded_name"] = None

    # Check whether an APK has been added or not
    if uploaded is not None and not st.session_state.get("use_sample_active", False):
        file_bytes = uploaded.getvalue()
        file_size_kb = len(file_bytes) / 1024
        size_str = f"{file_size_kb:.1f} KB" if file_size_kb < 1024 else f"{file_size_kb / 1024:.2f} MB"
        apk_ready = True
        active_app_label = f"Uploaded APK: {uploaded.name}"
        st.success(f"✅ **APK Added:** `{uploaded.name}` ({size_str}) &mdash; Ready for analysis.")
    elif st.session_state.get("use_sample_active", False) and SAMPLE_APK.exists():
        apk_ready = True
        sample_size_kb = SAMPLE_APK.stat().st_size / 1024
        size_str = f"{sample_size_kb:.1f} KB" if sample_size_kb < 1024 else f"{sample_size_kb / 1024:.2f} MB"
        active_app_label = f"Sample APK: {SAMPLE_APK.name}"
        st.info(f"📦 **Sample APK Selected:** `{SAMPLE_APK.name}` ({size_str}) &mdash; Ready for analysis.")
    else:
        apk_ready = False
        active_app_label = None
        st.warning("⚠️ **No APK added yet.** Please upload an `.apk` file above or click **Use sample app** below.")

    # Control buttons
    col_start, col_stop, col_sample = st.columns([2, 2, 2])
    with col_start:
        start_analysis = st.button(
            "▶️ Start Analysis",
            type="primary",
            disabled=not apk_ready,
            use_container_width=True,
            help="Run static ML analysis, SHAP attribution, and Threat Intelligence on the selected APK.",
        )
    with col_stop:
        stop_analysis = st.button(
            "⏹️ Stop / Reset",
            type="secondary",
            use_container_width=True,
            help="Halt/clear the current analysis and reset the application.",
        )
    with col_sample:
        use_sample = st.button(
            "📦 Use sample app",
            use_container_width=True,
            help="Load the bundled sample APK (sample_app.apk).",
        )

    if use_sample:
        if SAMPLE_APK.exists():
            st.session_state["use_sample_active"] = True
            st.session_state["analysis_result"] = None
            st.session_state["analyzed_app_name"] = SAMPLE_APK.name
            st.rerun()
        else:
            st.error(f"Sample APK not found: {SAMPLE_APK.name}")

    if stop_analysis:
        st.session_state["analysis_result"] = None
        st.session_state["analyzed_app_name"] = None
        st.session_state["use_sample_active"] = False
        st.toast("Analysis stopped and cleared.", icon="⏹️")
        st.rerun()

    # Trigger analysis on explicit start
    if start_analysis and apk_ready:
        apk_source = None
        tmp_path = None
        try:
            if uploaded is not None and not st.session_state.get("use_sample_active", False):
                fd, tmp_path = tempfile.mkstemp(suffix=".apk")
                os.write(fd, uploaded.getvalue())
                os.close(fd)
                apk_source = tmp_path
            elif SAMPLE_APK.exists():
                apk_source = str(SAMPLE_APK)

            if apk_source:
                with st.spinner(f"Analysing {active_app_label} ... (parsing bytecode, extracting features & computing SHAP)"):
                    res = analyze_apk(
                        apk_source,
                        abuse_key=abuse_key,
                        resolve_domains=resolve_domains,
                        verbose=False,
                        top_n=12,
                    )
                    st.session_state["analysis_result"] = res
                    st.session_state["analyzed_app_name"] = active_app_label
        except ValueError as exc:
            st.error(str(exc))
        except Exception as exc:
            st.error(f"Analysis failed: {exc}")
        finally:
            if tmp_path is not None and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    # Retrieve cached analysis result from session state
    result = st.session_state.get("analysis_result")
    if result is not None:
        info = result["info"]
        static = result["static"]
        prob = static["prob_malware"]
        verdict = static["verdict"]
        ti = result.get("threat_features") or {}

        row = result["features"]
        detected_names = list(row.columns[row.iloc[0] == 1])
        total_features = row.shape[1]
        n_detected = len(detected_names)

        # 1. Verdict banner & Metrics
        css_class = "verdict-benign" if verdict == "BENIGN" else "verdict-malware"
        st.markdown(
            f'<div class="{css_class}">'
            f'{verdict} &mdash; {prob:.1%} malware probability'
            f'</div>',
            unsafe_allow_html=True,
        )

        st.markdown("")
        col_m1, col_m2, col_m3, col_m4 = st.columns(4)
        col_m1.metric("Detection Verdict", verdict)
        col_m2.metric("Malware Probability", f"{prob:.1%}")
        col_m3.metric("Features Detected", f"{n_detected} / {total_features}")
        col_m4.metric("Network Risk", ti.get("network_risk", "UNKNOWN"))

        st.progress(float(min(max(prob, 0.0), 1.0)), text=f"Ensemble Malware Confidence: {prob:.1%}")

        st.markdown(
            f"**Package:** `{info.get('package', '?')}`"
            f"&emsp; **App name:** {info.get('app_name', '?')}"
            f"&emsp; **Version:** {info.get('version_name', '?')}"
        )

        st.markdown("---")

        # 2. SHAP evidence chart
        st.subheader("Why did the model decide this?")
        evidence = static["evidence"]
        if evidence:
            fig = build_shap_chart(evidence)
            st.pyplot(fig, use_container_width=True)
            plt.close(fig)
            st.caption(
                "Red bars push the verdict toward malware; "
                "green bars push it toward benign."
            )
        else:
            st.info("No SHAP evidence available.")

        st.markdown("---")

        # 3. Features detected
        st.subheader("Features detected")
        # Count per group
        group_counts = {"permissions": 0, "intents": 0, "API calls": 0, "commands": 0}
        for f in detected_names:
            group_counts[classify_feature(f)] += 1

        st.markdown(
            f"**{n_detected} of {total_features}** features detected: "
            f"{group_counts['permissions']} permissions, "
            f"{group_counts['intents']} intents, "
            f"{group_counts['API calls']} API calls, "
            f"{group_counts['commands']} commands."
        )

        DANGEROUS_PERMS = {
            "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "READ_PHONE_STATE", "CALL_PHONE",
            "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "CAMERA", "RECORD_AUDIO",
            "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG",
            "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "INSTALL_PACKAGES",
            "SYSTEM_ALERT_WINDOW", "GET_ACCOUNTS", "USE_CREDENTIALS",
        }

        with st.expander("Full list of detected features"):
            for group_name in ["permissions", "intents", "API calls", "commands"]:
                items = [f for f in detected_names if classify_feature(f) == group_name]
                if items:
                    st.markdown(f"**{group_name.capitalize()}** ({len(items)})")
                    if group_name == "permissions":
                        dang = [p for p in items if any(dp in p for dp in DANGEROUS_PERMS)]
                        norm = [p for p in items if not any(dp in p for dp in DANGEROUS_PERMS)]
                        if dang:
                            st.markdown("🚨 **High-Risk / Sensitive:** " + ", ".join([f"`{p}`" for p in sorted(dang)]))
                        if norm:
                            st.markdown("🛡️ **Standard / Normal:** " + ", ".join([f"`{p}`" for p in sorted(norm)]))
                    else:
                        st.write(", ".join(sorted(items)))

        st.markdown("---")

        # 4. Threat intelligence
        st.subheader("Threat intelligence")

        ips = result["ips"]
        domains = result["domains"]
        lookups = result["lookups"]
        ti = result["threat_features"]
        lookup_err = result["lookup_error"]

        if abuse_key is None:
            st.info(
                "No API key entered, so no IP reputation check was done."
            )
        elif lookup_err:
            st.error(lookup_err)
        elif not ips and not result.get("resolved"):
            st.info(
                "No public IP addresses were found in this app. "
                "The network risk is UNKNOWN. This does not mean the app is safe."
            )
        else:
            # Show metrics
            if ti:
                col1, col2 = st.columns(2)
                col1.metric("Network risk level", ti["network_risk"])
                col2.metric("Max abuse score", ti["max_abuse_score"])

            # Lookups table
            if lookups:
                st.markdown("**IP reputation lookups**")
                st.dataframe(pd.DataFrame(lookups), use_container_width=True)

        # Embedded indicators
        if ips:
            with st.expander(f"Embedded IPs ({len(ips)})"):
                for ip, ctx in ips.items():
                    st.text(f"{ip:20s}  found in: {ctx}")
        else:
            st.caption(f"Embedded public IPs: 0")

        if domains:
            with st.expander(f"Embedded domains ({len(domains)})"):
                for d, ctx in domains.items():
                    st.text(f"{d:40s}  found in: {ctx}")
            if not resolve_domains:
                st.caption(
                    "Domains were not resolved to IPs. "
                    "Enable the sidebar option to include them in the lookup."
                )
        else:
            st.caption("Embedded domains: 0")

        st.markdown("---")

        # 5. Download report
        st.subheader("Export Security Report")
        col_dl_json, col_dl_pdf = st.columns(2)
        with col_dl_json:
            st.download_button(
                "📥 Download report (JSON)",
                data=build_report_json(result),
                file_name=f"{info.get('package', 'apk')}_analysis_report.json",
                mime="application/json",
                use_container_width=True,
                help="Download full raw metrics, feature vectors, and indicator data in JSON format.",
            )
        with col_dl_pdf:
            st.download_button(
                "📄 Download report (PDF)",
                data=build_report_pdf(result),
                file_name=f"{info.get('package', 'apk')}_security_report.pdf",
                mime="application/pdf",
                use_container_width=True,
                help="Download a formatted 2-page executive and technical audit report with embedded SHAP charts.",
            )

    # Permanent caption (always visible)
    st.caption(
        "Indicators are read from the app's code, not captured from live traffic. "
        "Some API-call and command features are matched by code search, so a live "
        "prediction approximates the benchmark and is not a validated result."
    )


# ============================= TAB 2 ======================================
with tab_static:
    st.header(
        "Static analysis: Random Forest + XGBoost on Drebin-215 (7,254 unique apps)"
    )

    # Test results
    df_test = safe_read_csv(
        STATIC_DIR / "test_results.csv", index_col=0, label="static test results"
    )
    if df_test is not None:
        st.subheader("Held-out test set (20%)")
        st.dataframe(df_test, use_container_width=True)

    # CV results
    df_cv = safe_read_csv(
        STATIC_DIR / "cv_results.csv", index_col=0, label="static CV results"
    )
    if df_cv is not None:
        st.subheader("5-fold cross-validation (mean +/- std)")
        st.dataframe(df_cv, use_container_width=True)

    st.markdown("---")

    # Charts in two columns
    col_a, col_b = st.columns(2)
    with col_a:
        safe_show_image(
            STATIC_DIR / "1_feature_importance.png", "Feature importance"
        )
        safe_show_image(
            STATIC_DIR / "3_roc_pr_curves.png", "ROC and precision-recall curves"
        )
        safe_show_image(
            STATIC_DIR / "5_shap_bar.png", "SHAP bar (mean |SHAP|)"
        )
    with col_b:
        safe_show_image(
            STATIC_DIR / "2_confusion_matrices.png", "Confusion matrices"
        )
        safe_show_image(
            STATIC_DIR / "4_shap_summary.png", "SHAP summary (beeswarm)"
        )


# ============================= TAB 3 ======================================
with tab_dynamic:
    st.header(
        "Dynamic analysis: system-call model on CICMalDroid2020 (11,520 unique apps)"
    )
    st.info(
        "This tab shows benchmark results from the CICMalDroid2020 dataset "
        "and includes a live emulator analysis interface in the **Phase 5** subtab below."
    )

    if not DYNAMIC_DIR.exists():
        st.warning(
            f"The folder '{DYNAMIC_DIR.name}' was not found. "
            "Dynamic model results are unavailable."
        )
    else:
        dyn_tab1, dyn_tab2, dyn_tab3, dyn_tab4, dyn_tab5 = st.tabs([
            "🏆 Cluster-Held-Out (Primary Benchmark)",
            "📊 Architecture Comparison (DL vs XGBoost)",
            "📉 Feature Reduction Analysis",
            "🔬 Statistical Tests & Generalization",
            "📲 Phase 5: Live Emulator Pre-flight Check",
        ])

        with dyn_tab1:
            st.subheader("Cluster-Held-Out 5-Fold Cross-Validation (Conservative Ground Truth)")
            st.caption(
                "Apps with similar behavior are grouped together in clusters and held out, "
                "ensuring test apps differ substantially from training apps. This avoids optimistic family leakage."
            )
            df_cv_cluster = safe_read_csv(
                DYNAMIC_DIR / "cv_results_cluster_heldout.csv", index_col=0,
            )
            if df_cv_cluster is not None:
                st.dataframe(df_cv_cluster, use_container_width=True)

            df_pooled = safe_read_csv(
                DYNAMIC_DIR / "pooled_results_cluster_heldout.csv", index_col=0,
            )
            if df_pooled is not None:
                st.subheader("Pooled Fold Results")
                st.caption("Pooled confusion metrics across the 5 cluster-held-out folds")
                st.dataframe(df_pooled, use_container_width=True)

            col_a, col_b = st.columns(2)
            with col_a:
                safe_show_image(DYNAMIC_DIR / "2_confusion_matrices.png", "Confusion matrices (cluster-held-out, pooled)")
            with col_b:
                safe_show_image(DYNAMIC_DIR / "3_roc_pr_curves.png", "ROC and precision-recall curves")

        with dyn_tab2:
            st.subheader("Random 80/20 Benchmark Split")
            st.caption("Standard random split comparable with literature (optimistic baseline).")
            df_test_dyn = safe_read_csv(DYNAMIC_DIR / "test_results.csv", index_col=0)
            if df_test_dyn is not None:
                st.dataframe(df_test_dyn, use_container_width=True)

            st.markdown("---")
            st.subheader("XGBoost Normalization Variants")
            df_rand_xgb = safe_read_csv(DYNAMIC_DIR / "cv_results_random_xgboost.csv", index_col=0)
            df_shares_xgb = safe_read_csv(DYNAMIC_DIR / "cv_results_shares_xgboost.csv", index_col=0)
            col_x1, col_x2 = st.columns(2)
            with col_x1:
                if df_rand_xgb is not None:
                    st.caption("Random 5-fold CV (Raw Counts)")
                    st.dataframe(df_rand_xgb, use_container_width=True)
            with col_x2:
                if df_shares_xgb is not None:
                    st.caption("Share-Normalized System Calls")
                    st.dataframe(df_shares_xgb, use_container_width=True)

            col_c1, col_c2 = st.columns(2)
            with col_c1:
                safe_show_image(DYNAMIC_DIR / "1_feature_importance.png", "Feature importance (top system calls)")
            with col_c2:
                safe_show_image(DYNAMIC_DIR / "4_shap_summary.png", "SHAP summary (beeswarm)")

        with dyn_tab3:
            st.subheader("Feature Count Sensitivity (139 System Calls)")
            st.caption("Evaluation of how many system calls are required to maintain detection accuracy.")
            df_feat = safe_read_csv(DYNAMIC_DIR / "feature_count_analysis.csv")
            if df_feat is not None:
                st.dataframe(df_feat, use_container_width=True)
            safe_show_image(DYNAMIC_DIR / "6_accuracy_vs_features.png", "Accuracy vs. number of features kept")
            safe_show_image(DYNAMIC_DIR / "5_shap_bar.png", "Global mean |SHAP| values")

        with dyn_tab4:
            st.subheader("McNemar's Statistical Significance Tests")
            st.caption("Statistical pairwise differences between deep learning architectures (TCN) and baselines (significance threshold p < 0.0167).")
            df_mcn_cluster = safe_read_csv(DYNAMIC_DIR / "mcnemar_cluster_heldout.csv")
            df_mcn_random = safe_read_csv(DYNAMIC_DIR / "mcnemar_random_split.csv")
            if df_mcn_cluster is not None:
                st.markdown("**Cluster-Held-Out Split Comparison**")
                st.dataframe(df_mcn_cluster, use_container_width=True)
            if df_mcn_random is not None:
                st.markdown("**Random Split Comparison**")
                st.dataframe(df_mcn_random, use_container_width=True)

            st.markdown("---")
            st.subheader("Zero-Day & Unseen Malware Category Detection")
            df_unseen = safe_read_csv(DYNAMIC_DIR / "unseen_category.csv")
            if df_unseen is not None:
                st.dataframe(df_unseen, use_container_width=True)

        with dyn_tab5:
            st.subheader("Phase 5: Live Emulator Dynamic Analysis")

            # ------------------------------------------------------------------
            # Session-state keys for Phase 5
            # ------------------------------------------------------------------
            if "p5_result" not in st.session_state:
                st.session_state["p5_result"] = None
            if "p5_running" not in st.session_state:
                st.session_state["p5_running"] = False

            # ------------------------------------------------------------------
            # Description
            # ------------------------------------------------------------------
            st.markdown(
                "Live dynamic analysis installs the selected APK in the connected Android emulator, "
                "launches the application, simulates user interaction with `monkey`, and captures "
                "kernel system calls via `strace`. The raw call counts are then mapped to the model's "
                "139-feature vocabulary and passed through the trained XGBoost classifier."
            )

            st.warning(
                "⚠️ **The selected APK will be installed and executed inside the connected Android emulator.** "
                "Use only an emulator — never a real device — and only with APKs you are permitted to analyse."
            )

            st.markdown("---")

            # ------------------------------------------------------------------
            # ADB readiness check (independent button)
            # ------------------------------------------------------------------
            if st.button("🔍 Check Live ADB & Emulator Readiness", key="p5_check_btn", use_container_width=False):
                try:
                    from phase5_live_capture import find_adb, list_devices, find_strace
                    adb_path = find_adb()
                    if adb_path:
                        st.success(f"✅ **ADB found:** `{adb_path}`")
                        devs = list_devices()
                        if devs:
                            st.success(f"📱 **Emulator connected:** `{', '.join(devs)}`")
                            strace_bin = find_strace(devs[0])
                            if strace_bin:
                                st.success(f"🔧 **strace available on device:** `{strace_bin}`")
                            else:
                                st.warning("⚠️ `strace` was not found on the emulator. "
                                           "Follow the instructions in phase5_live_capture.py to push a static binary.")
                        else:
                            st.warning("⚠️ **No running emulator detected.** "
                                       "Start an AVD in Android Studio and wait for the home screen.")
                    else:
                        st.error("❌ **ADB not found.** "
                                 "Install Android Studio or add platform-tools to your PATH / `~/bin/adb`.")
                except Exception as _exc:
                    st.error(f"Readiness check failed: {_exc}")

            st.markdown("---")

            # ------------------------------------------------------------------
            # APK selection
            # ------------------------------------------------------------------
            st.subheader("1. Select APK")
            apk_choice = st.radio(
                "APK source",
                ["Use bundled sample_app.apk", "Upload a different APK"],
                key="p5_apk_choice",
                horizontal=True,
            )

            p5_apk_path = None   # will be set to the resolved path string
            p5_tmp_path  = None  # will be set if we write a temp file

            if apk_choice == "Use bundled sample_app.apk":
                if SAMPLE_APK.exists():
                    p5_apk_path = str(SAMPLE_APK)
                    st.info(f"📦 Bundled APK selected: `{SAMPLE_APK.name}` "
                            f"({SAMPLE_APK.stat().st_size / 1024:.1f} KB)")
                else:
                    st.error(f"❌ `sample_app.apk` not found at `{SAMPLE_APK}`.")
            else:
                p5_uploaded = st.file_uploader(
                    "Upload APK for live analysis",
                    type=["apk"],
                    key="p5_uploader",
                    help="The file will be saved to a temporary path accessible from Ubuntu/WSL and deleted after analysis.",
                )
                if p5_uploaded is not None:
                    if not p5_uploaded.name.lower().endswith(".apk"):
                        st.error("❌ The uploaded file does not have an `.apk` extension.")
                    else:
                        st.success(f"✅ Uploaded: `{p5_uploaded.name}` "
                                   f"({len(p5_uploaded.getvalue()) / 1024:.1f} KB)")
                        # We defer writing the temp file until the Run button is clicked
                        # to avoid writing on every Streamlit rerun.
                else:
                    st.warning("No APK uploaded yet.")

            # ------------------------------------------------------------------
            # Trace duration
            # ------------------------------------------------------------------
            st.subheader("2. Trace Duration")
            p5_seconds = st.slider(
                "System-call capture duration (seconds)",
                min_value=10, max_value=300, value=30, step=5,
                key="p5_seconds",
                help="How long to run strace on the application. Longer runs give more stable counts but take more time.",
            )

            # ------------------------------------------------------------------
            # Confirmation & run
            # ------------------------------------------------------------------
            st.subheader("3. Confirm & Run")
            p5_confirmed = st.checkbox(
                f"I confirm that the selected APK will be installed and executed inside the connected Android emulator for {p5_seconds} s.",
                key="p5_confirm",
            )

            # Determine whether we have a valid APK ready to run
            _p5_apk_ready = (
                p5_apk_path is not None                          # sample APK resolved
                or (
                    apk_choice != "Use bundled sample_app.apk"
                    and "p5_uploader" in st.session_state
                    and st.session_state["p5_uploader"] is not None
                )
            )

            run_col, _ = st.columns([2, 3])
            with run_col:
                p5_run = st.button(
                    "🚀 Run Live Dynamic Analysis",
                    key="p5_run_btn",
                    type="primary",
                    disabled=(not _p5_apk_ready) or (not p5_confirmed) or st.session_state["p5_running"],
                    use_container_width=True,
                )

            if not _p5_apk_ready:
                st.caption("Select a valid APK above to enable the Run button.")
            elif not p5_confirmed:
                st.caption("Tick the confirmation checkbox to enable the Run button.")

            # ------------------------------------------------------------------
            # Execute analysis
            # ------------------------------------------------------------------
            if p5_run and not st.session_state["p5_running"]:
                st.session_state["p5_running"] = True
                st.session_state["p5_result"] = None

                # Resolve the actual APK path (writing temp file if needed)
                _run_apk_path = None
                _temp_apk    = None
                _run_error   = None

                try:
                    if apk_choice == "Use bundled sample_app.apk":
                        if not SAMPLE_APK.exists():
                            _run_error = f"sample_app.apk not found at {SAMPLE_APK}"
                        else:
                            _run_apk_path = str(SAMPLE_APK)
                    else:
                        _uploaded_file = st.session_state.get("p5_uploader")
                        if _uploaded_file is None:
                            _run_error = "No APK was uploaded."
                        elif not _uploaded_file.name.lower().endswith(".apk"):
                            _run_error = "Uploaded file does not have an .apk extension."
                        else:
                            # Write to a temp file inside the project dir so
                            # the WSL path resolves correctly.
                            _fd, _temp_apk = tempfile.mkstemp(
                                suffix=".apk",
                                dir=str(BASE_DIR),
                                prefix="_p5upload_",
                            )
                            os.write(_fd, _uploaded_file.getvalue())
                            os.close(_fd)
                            _run_apk_path = _temp_apk

                    if _run_error:
                        st.error(f"❌ {_run_error}")
                    elif _run_apk_path:
                        # Build a safe subprocess command — no shell interpolation.
                        # We call the existing CLI of phase5_live_capture.py with an
                        # extra --json-out flag that we will add to the script.
                        _script = str(BASE_DIR / "phase5_live_capture.py")
                        _json_out = str(BASE_DIR / "_p5_last_result.json")
                        _cmd = [
                            sys.executable, _script,
                            "run", _run_apk_path, str(p5_seconds),
                            "--json-out", _json_out,
                        ]

                        # Make ~/bin available so the adb wrapper is on PATH
                        _env = os.environ.copy()
                        _home = os.environ.get("HOME", os.path.expanduser("~"))
                        _bin  = os.path.join(_home, "bin")
                        if os.path.isdir(_bin) and _bin not in _env.get("PATH", ""):
                            _env["PATH"] = _bin + ":" + _env.get("PATH", "")

                        # Total timeout = install (~60s) + trace + inference + cleanup (~60s)
                        _timeout = 120 + p5_seconds + 60

                        with st.spinner(
                            f"Running live analysis on `{os.path.basename(_run_apk_path)}` "
                            f"({p5_seconds} s trace) — this will take at least {p5_seconds + 30} s …"
                        ):
                            try:
                                _proc = subprocess.run(
                                    _cmd,
                                    capture_output=True,
                                    text=True,
                                    timeout=_timeout,
                                    cwd=str(BASE_DIR),
                                    env=_env,
                                )
                                _stdout = _proc.stdout or ""
                                _stderr = _proc.stderr or ""
                                _combined_output = _stdout + ("\n" + _stderr if _stderr.strip() else "")

                                if _proc.returncode != 0:
                                    st.error(
                                        f"❌ Analysis process exited with code {_proc.returncode}.\n\n"
                                        f"```\n{_combined_output[-3000:]}\n```"
                                    )
                                else:
                                    # Try to load structured JSON result
                                    _structured = None
                                    if os.path.exists(_json_out):
                                        try:
                                            with open(_json_out) as _jf:
                                                _structured = json.load(_jf)
                                        except Exception as _je:
                                            st.warning(f"Could not parse JSON result file: {_je}")

                                    st.session_state["p5_result"] = {
                                        "structured": _structured,
                                        "raw_report": _combined_output,
                                        "apk_name": os.path.basename(_run_apk_path),
                                        "requested_seconds": p5_seconds,
                                    }
                                    st.success("✅ Analysis complete.")

                            except subprocess.TimeoutExpired:
                                st.error(
                                    f"❌ Analysis timed out after {_timeout} s. "
                                    "The emulator may be busy or the APK took too long to start."
                                )
                            except Exception as _run_exc:
                                st.error(f"❌ Unexpected error: {_run_exc}")

                except Exception as _outer_exc:
                    st.error(f"❌ Setup error before running analysis: {_outer_exc}")
                finally:
                    # Clean up temp APK
                    if _temp_apk and os.path.exists(_temp_apk):
                        try:
                            os.remove(_temp_apk)
                        except OSError:
                            pass
                    st.session_state["p5_running"] = False

            # ------------------------------------------------------------------
            # Display results from session state
            # ------------------------------------------------------------------
            _p5_res = st.session_state.get("p5_result")
            if _p5_res is not None:
                st.markdown("---")
                st.subheader("📊 Live Analysis Results")
                st.caption(
                    f"APK: `{_p5_res['apk_name']}` · "
                    f"Requested trace duration: {_p5_res['requested_seconds']} s"
                )

                _s = _p5_res.get("structured")

                # Academic limitation notice (always visible with results)
                st.info(
                    "🎓 **Academic Limitation Notice** — "
                    "The probability below is a model prediction, not definitive proof of malware. "
                    "The model was trained on CICMalDroid2020 (older Android, ARM, longer captures) "
                    "and applied here to an Android 14 x86_64 emulator — a different environment. "
                    "Results are experimental until validated under representative conditions. "
                    "SHAP values explain the model's decision but do not independently prove malicious behaviour."
                )

                if _s is not None:
                    # ---- A. Analysis Summary --------------------------------
                    _res    = _s.get("result", {})
                    _pred   = _s.get("prediction", {})
                    _mapped = _s.get("mapped", {})
                    _cov    = _s.get("coverage", 0.0)

                    st.markdown("#### A. Analysis Summary")
                    _total_calls = sum(_res.get("counts", {}).values())
                    _col1, _col2, _col3, _col4 = st.columns(4)
                    _col1.metric("Package", _res.get("package", "?"))
                    _col2.metric("Total syscalls", f"{_total_calls:,}")
                    _col3.metric("Vocab coverage", f"{_cov:.0%}")
                    _col4.metric("Features seen", str(len(_mapped)))

                    if _cov < 0.8:
                        st.warning(
                            f"⚠️ Only {_cov:.0%} of system calls matched the model vocabulary. "
                            "The emulator's syscall names differ substantially from the ARM training data. "
                            "Treat the prediction as unreliable."
                        )

                    # ---- B. Model Predictions -------------------------------
                    st.markdown("#### B. Model Predictions")
                    _prob_shares = _pred.get("shares")
                    _prob_counts = _pred.get("counts")

                    if _prob_shares is not None:
                        # Make the shares prediction visually prominent
                        _pct = _prob_shares * 100
                        if _pct >= 70:
                            _badge_color = "#f8d7da"
                            _badge_text_color = "#721c24"
                            _risk_label = "HIGH MALWARE PROBABILITY"
                        elif _pct >= 40:
                            _badge_color = "#fff3cd"
                            _badge_text_color = "#856404"
                            _risk_label = "MODERATE MALWARE PROBABILITY"
                        else:
                            _badge_color = "#d4edda"
                            _badge_text_color = "#155724"
                            _risk_label = "LOW MALWARE PROBABILITY"

                        st.markdown(
                            f'<div style="background:{_badge_color};color:{_badge_text_color};'
                            f'padding:1rem 1.5rem;border-radius:8px;font-size:1.4rem;'
                            f'font-weight:700;text-align:center;margin-bottom:0.5rem;">'
                            f'{_risk_label}<br/>'
                            f'<span style="font-size:2rem;">{_pct:.1f}%</span>'
                            f'</div>',
                            unsafe_allow_html=True,
                        )
                        st.caption(
                            "Normalised-share probability (recommended for live runs — "
                            "less sensitive to capture duration than raw counts)."
                        )
                        st.progress(float(min(max(_prob_shares, 0.0), 1.0)),
                                    text=f"Malware probability (normalised shares): {_pct:.1f}%")

                    _pred_col1, _pred_col2 = st.columns(2)
                    if _prob_shares is not None:
                        _pred_col1.metric("Malware prob — normalised shares (recommended)",
                                          f"{_prob_shares:.1%}")
                    if _prob_counts is not None:
                        _pred_col2.metric("Malware prob — raw counts",
                                          f"{_prob_counts:.1%}")

                    st.caption(
                        "No binary malware/benign verdict is applied: the model outputs a continuous "
                        "probability and no validated decision threshold exists for this live environment."
                    )

                    # ---- C. System-Call Evidence ----------------------------
                    _evidence = _pred.get("evidence", [])
                    if _evidence:
                        st.markdown("#### C. System-Call Evidence (SHAP — normalised-shares model)")
                        st.caption(
                            "Positive SHAP values (🔴) push the prediction **toward malware**. "
                            "Negative SHAP values (🟢) push the prediction **toward benign**."
                        )

                        # Table
                        _ev_rows = []
                        for _name, _cnt, _sv in _evidence:
                            _ev_rows.append({
                                "System call": _name,
                                "Count (raw)": int(_cnt),
                                "SHAP value": round(_sv, 4),
                                "Direction": "▲ toward malware" if _sv > 0 else "▼ toward benign",
                            })
                        _ev_df = pd.DataFrame(_ev_rows)
                        st.dataframe(_ev_df, use_container_width=True, hide_index=True)

                        # Horizontal bar chart
                        _names_ev = [r["System call"] for r in _ev_rows]
                        _shap_vals = [r["SHAP value"] for r in _ev_rows]
                        _colours_ev = ["#c0392b" if v > 0 else "#27ae60" for v in _shap_vals]
                        _labels_ev = [
                            f"{r['System call']}  (count={int(r['Count (raw)'])})"
                            for r in _ev_rows
                        ]
                        _fig_ev, _ax_ev = plt.subplots(
                            figsize=(8, max(3, 0.5 * len(_names_ev)))
                        )
                        _y_ev = np.arange(len(_names_ev))
                        _ax_ev.barh(_y_ev, _shap_vals, color=_colours_ev,
                                    edgecolor="none", height=0.6)
                        _ax_ev.set_yticks(_y_ev)
                        _ax_ev.set_yticklabels(_labels_ev, fontsize=9)
                        _ax_ev.invert_yaxis()
                        _ax_ev.set_xlabel(
                            "SHAP value  (red = toward malware, green = toward benign)",
                            fontsize=9,
                        )
                        _ax_ev.axvline(0, color="#333", linewidth=0.8)
                        _ax_ev.spines["top"].set_visible(False)
                        _ax_ev.spines["right"].set_visible(False)
                        _fig_ev.tight_layout()
                        st.pyplot(_fig_ev, use_container_width=True)
                        plt.close(_fig_ev)
                    else:
                        st.info("No SHAP evidence was returned (SHAP may have failed — "
                                "check the raw report below for details).")

                else:
                    # Structured result not available — fall back gracefully
                    st.warning(
                        "Structured result data was not available. "
                        "The raw report is shown below."
                    )

                # ---- D. Raw Report (always shown in expander) ---------------
                _raw = _p5_res.get("raw_report", "")
                if _raw.strip():
                    with st.expander("📄 Raw Phase 5 Report (click to expand)", expanded=(_s is None)):
                        st.code(_raw, language="text")


# ============================= TAB 4 ======================================
with tab_about:
    st.header("About the System & Research Methodology")

    col_ab1, col_ab2 = st.columns(2)
    with col_ab1:
        st.subheader("🛡️ Static Analysis (Drebin-215)")
        st.markdown("""
- **Model**: Fused Ensemble of Random Forest & XGBoost.
- **Dataset**: Drebin-215 benchmark comprising 7,254 unique Android applications.
- **Feature Space**: 215 static indicators spanning permissions, intents, API calls, and commands.
- **Explainability**: SHAP TreeExplainer delivers exact local feature attributions for every prediction.
""")
        st.subheader("🌐 Threat Intelligence (AbuseIPDB)")
        st.markdown("""
- **Mechanism**: Bytecode inspection extracts embedded IPv4 addresses and domains.
- **Querying**: Live queries against the AbuseIPDB API v2 retrieve confidence scores and reputation history.
- **Interpretation**: Absence of embedded IPs indicates *unknown network risk*, not guaranteed safety.
""")

    with col_ab2:
        st.subheader("⚡ Dynamic Analysis (CICMalDroid2020)")
        st.markdown("""
- **Model Suite**: XGBoost alongside deep architectures (TCN, BiLSTM, Transformer).
- **Dataset**: CICMalDroid2020 dataset of 11,520 applications across 139 kernel system calls.
- **Rigorous Validation**: Cluster-held-out splits prevent family leakage, ensuring genuine generalization estimates.
""")
        st.subheader("📲 Phase 5: Live Emulation Extension")
        st.markdown("""
- **Execution**: Android Virtual Device (AVD) running under `adb root`.
- **Instrumentation**: Traces Linux kernel system calls using `strace` while simulating user interaction with `monkey`.
""")

    st.markdown("---")
    st.subheader("⚠️ Academic Transparency & Limitations")
    st.warning("""
1. **Independent Pipelines**: Static and dynamic models operate on distinct benchmark datasets with no shared application IDs; results are presented side-by-side rather than fused into a single joint vector.
2. **Static Approximation**: Static features are extracted via safe code analysis; obfuscated bytecode or dynamically loaded DEX files (reflection/packers) require runtime dynamic evaluation.
3. **Dataset Imbalance**: Malware forms the majority class in both historical datasets; models require continued calibration on novel benign utility apps.
""")
