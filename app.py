"""
Streamlit UI for:
  AI-Based Detection of Malicious Sideloaded Android Applications
  Using Runtime Threat Intelligence

This file is the interface only. All machine-learning and analysis logic
lives in phase3_live_demo.py and is imported, never reimplemented.
"""

import json
import os
import re
import tempfile
from pathlib import Path

import matplotlib
matplotlib.use("Agg")                              # non-interactive backend for Streamlit
import matplotlib.pyplot as plt
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


# ========================== sidebar ========================================
with st.sidebar:
    st.header("Settings")
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


# ========================== tabs ===========================================
tab_analyze, tab_static, tab_dynamic, tab_about = st.tabs([
    "Analyze an APK",
    "Static model results",
    "Dynamic model results",
    "About and limitations",
])


# ============================= TAB 1 ======================================
with tab_analyze:
    st.header("Analyze an APK")

    uploaded = st.file_uploader(
        "Upload an APK file", type=["apk"],
        help="The APK is only read (like opening a zip). It is never installed or run.",
    )

    use_sample = st.button("Use the included sample app")

    # Decide which APK to analyse
    apk_source = None   # will be set to a file path string
    tmp_path = None      # only set when we create a temp file

    if use_sample:
        if SAMPLE_APK.exists():
            apk_source = str(SAMPLE_APK)
        else:
            st.warning(f"Sample APK not found: {SAMPLE_APK.name}")

    elif uploaded is not None:
        # Save uploaded bytes to a temp file
        try:
            fd, tmp_path = tempfile.mkstemp(suffix=".apk")
            os.write(fd, uploaded.getvalue())
            os.close(fd)
            apk_source = tmp_path
        except Exception as exc:
            st.error(f"Could not save the uploaded file: {exc}")

    # Run analysis
    if apk_source is not None:
        try:
            with st.spinner("Analysing the APK ..."):
                result = analyze_apk(
                    apk_source,
                    abuse_key=abuse_key,
                    resolve_domains=resolve_domains,
                    verbose=False,
                    top_n=12,
                )
        except ValueError as exc:
            st.error(str(exc))
            result = None
        except Exception as exc:
            st.error(f"Analysis failed: {exc}")
            result = None
        finally:
            # Always delete the temp file
            if tmp_path is not None:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

        # ----- display results -----
        if result is not None:
            info = result["info"]
            static = result["static"]
            prob = static["prob_malware"]
            verdict = static["verdict"]

            # 1. Verdict banner
            css_class = "verdict-benign" if verdict == "BENIGN" else "verdict-malware"
            st.markdown(
                f'<div class="{css_class}">'
                f'{verdict} &mdash; {prob:.1%} malware probability'
                f'</div>',
                unsafe_allow_html=True,
            )
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
            row = result["features"]
            detected_names = list(row.columns[row.iloc[0] == 1])
            total_features = row.shape[1]
            n_detected = len(detected_names)

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

            with st.expander("Full list of detected features"):
                for group_name in ["permissions", "intents", "API calls", "commands"]:
                    items = [f for f in detected_names if classify_feature(f) == group_name]
                    if items:
                        st.markdown(f"**{group_name.capitalize()}** ({len(items)})")
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
            st.download_button(
                "Download report (JSON)",
                data=build_report_json(result),
                file_name="apk_analysis_report.json",
                mime="application/json",
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
        "This app does NOT run uploaded APKs. These are results on a public, "
        "pre-collected dataset of system-call counts. Live emulator analysis "
        "is a separate, later extension."
    )

    if not DYNAMIC_DIR.exists():
        st.warning(
            f"The folder '{DYNAMIC_DIR.name}' was not found. "
            "Dynamic model results are unavailable."
        )
    else:
        # ---- Main result: cluster-held-out CV ----
        st.subheader("Main result")
        df_cv_cluster = safe_read_csv(
            DYNAMIC_DIR / "cv_results_cluster_heldout.csv", index_col=0,
        )
        if df_cv_cluster is not None:
            st.caption(
                "Cluster-held-out 5-fold cross-validation: apps with similar "
                "behaviour are kept together, so the test apps are unlike the "
                "training apps. This is the conservative estimate of real performance."
            )
            st.dataframe(df_cv_cluster, use_container_width=True)

        df_pooled = safe_read_csv(
            DYNAMIC_DIR / "pooled_results_cluster_heldout.csv", index_col=0,
        )
        if df_pooled is not None:
            st.caption("Pooled results across the 5 cluster-held-out folds")
            st.dataframe(df_pooled, use_container_width=True)

        st.markdown("---")

        # ---- Random 80/20 split ----
        df_test_dyn = safe_read_csv(
            DYNAMIC_DIR / "test_results.csv", index_col=0,
        )
        if df_test_dyn is not None:
            st.subheader("Random 80/20 split")
            st.caption(
                "Comparable with most papers, but optimistic because similar apps "
                "appear in both training and test sets."
            )
            st.dataframe(df_test_dyn, use_container_width=True)

        st.markdown("---")

        # ---- XGBoost variants ----
        df_rand_xgb = safe_read_csv(
            DYNAMIC_DIR / "cv_results_random_xgboost.csv", index_col=0,
        )
        df_shares_xgb = safe_read_csv(
            DYNAMIC_DIR / "cv_results_shares_xgboost.csv", index_col=0,
        )
        if df_rand_xgb is not None or df_shares_xgb is not None:
            st.subheader("XGBoost variants")
            st.caption(
                "XGBoost with random 5-fold cross-validation, and XGBoost using "
                "each system call's share of all calls instead of raw counts."
            )
            if df_rand_xgb is not None:
                st.dataframe(df_rand_xgb, use_container_width=True)
            if df_shares_xgb is not None:
                st.dataframe(df_shares_xgb, use_container_width=True)

        st.markdown("---")

        # ---- Feature count analysis ----
        df_feat = safe_read_csv(DYNAMIC_DIR / "feature_count_analysis.csv")
        if df_feat is not None:
            st.subheader("Feature count analysis")
            st.caption(
                "How many of the 139 system calls are needed "
                "(XGBoost, cluster-held-out)."
            )
            st.dataframe(df_feat, use_container_width=True)
        safe_show_image(
            DYNAMIC_DIR / "6_accuracy_vs_features.png",
            "Accuracy vs. number of features kept",
        )

        st.markdown("---")

        # ---- McNemar's tests ----
        df_mcn_cluster = safe_read_csv(
            DYNAMIC_DIR / "mcnemar_cluster_heldout.csv",
        )
        df_mcn_random = safe_read_csv(
            DYNAMIC_DIR / "mcnemar_random_split.csv",
        )
        if df_mcn_cluster is not None or df_mcn_random is not None:
            st.subheader("McNemar's test")
            st.caption(
                "Does the TCN differ from each other model? With 3 comparisons "
                "the corrected cut-off is p < 0.0167. The columns 'Only TCN correct' "
                "and 'Only other correct' show which model is right more often when "
                "they disagree."
            )
            if df_mcn_cluster is not None:
                st.markdown("**Cluster-held-out split**")
                st.dataframe(df_mcn_cluster, use_container_width=True)
            if df_mcn_random is not None:
                st.markdown("**Random split**")
                st.dataframe(df_mcn_random, use_container_width=True)

        st.markdown("---")

        # ---- Unseen category ----
        df_unseen = safe_read_csv(DYNAMIC_DIR / "unseen_category.csv")
        if df_unseen is not None:
            st.subheader("Unseen malware category")
            st.caption(
                "Detecting a malware category the model never saw in training."
            )
            st.dataframe(df_unseen, use_container_width=True)

        st.markdown("---")

        # ---- Charts ----
        st.subheader("Charts")
        col_a, col_b = st.columns(2)
        with col_a:
            safe_show_image(
                DYNAMIC_DIR / "1_feature_importance.png",
                "Feature importance (top system calls)",
            )
            safe_show_image(
                DYNAMIC_DIR / "3_roc_pr_curves.png",
                "ROC and precision-recall curves",
            )
            safe_show_image(
                DYNAMIC_DIR / "5_shap_bar.png",
                "SHAP bar (mean |SHAP|)",
            )
        with col_b:
            safe_show_image(
                DYNAMIC_DIR / "2_confusion_matrices.png",
                "Confusion matrices (cluster-held-out, pooled)",
            )
            safe_show_image(
                DYNAMIC_DIR / "4_shap_summary.png",
                "SHAP summary (beeswarm)",
            )


# ============================= TAB 4 ======================================
with tab_about:
    st.header("About and limitations")
    st.markdown("""
**Two independent pipelines** -- static and dynamic -- trained on two different
public datasets with no shared application IDs. Their results are reported side
by side, not fused into one model.

**Static analysis (Drebin-215).** A Random Forest and an XGBoost classifier
trained on the Drebin-215 feature set (an older benchmark from the 2010s,
7,254 unique apps). The live APK demo fills the 215 features itself, and some
API-call and command features are matched by code search, so it approximates the
benchmark rather than reproducing it exactly.

**Dynamic analysis (CICMalDroid2020).** System-call counts from 11,520 apps
(139 Linux system calls, no ordering or timestamps). XGBoost scored highest.
The neural networks (TCN, BiLSTM, Transformer) scored lower and varied more
between runs, so no ranking among them is claimed. The honest estimate is the
cluster-held-out cross-validation, not the random split.

**Live emulator analysis** (running an app in an emulator and counting its
system calls) is a planned later extension and is not part of this app yet.

**Threat intelligence.** IP addresses and domain names embedded in the app's
code are checked on AbuseIPDB. They are read from the code, not captured from
live network traffic. Finding no IPs means the network risk is unknown, not
that the app is safe.

**Majority class.** Malware is the majority class in both datasets. The model
is weakest on benign apps with new or unusual patterns.
""")
