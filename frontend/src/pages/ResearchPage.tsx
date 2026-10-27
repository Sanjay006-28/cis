import { useEffect, useState } from "react";
import {
  Activity,
  AlertCircle,
  BarChart3,
  ExternalLink,
  Info,
  Layers,
  Maximize2,
  Shield,
  Table2,
  X,
} from "lucide-react";
import {
  benchmarkArtifactUrl,
  getAllBenchmarkTables,
  getBenchmarks,
} from "../api/client";
import { SectionHeader } from "../components/SectionHeader";
import { StateMessage } from "../components/StateMessage";
import type { ResearchGroup, ResearchTable } from "../types";

export function ResearchPage() {
  const [groups, setGroups] = useState<ResearchGroup[]>([]);
  const [tables, setTables] = useState<Record<string, ResearchTable>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState<"all" | "static" | "dynamic">("all");
  const [expandedImage, setExpandedImage] = useState<{
    id: string;
    title: string;
    caption: string;
  } | null>(null);
  const [imageErrors, setImageErrors] = useState<Record<string, boolean>>({});

  useEffect(() => {
    let isMounted = true;
    setLoading(true);

    Promise.all([
      getBenchmarks().catch(() => [] as ResearchGroup[]),
      getAllBenchmarkTables().catch(() => ({} as Record<string, ResearchTable>)),
    ])
      .then(([benchmarkGroups, benchmarkTables]) => {
        if (!isMounted) return;
        setGroups(benchmarkGroups);
        setTables(benchmarkTables);
      })
      .catch((err: Error) => {
        if (isMounted) setError(err.message || "Failed to load research artifacts.");
      })
      .finally(() => {
        if (isMounted) setLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const handleImageError = (id: string) => {
    setImageErrors((prev) => ({ ...prev, [id]: true }));
  };

  const isArtifactAvailable = (id: string): boolean => {
    for (const group of groups) {
      const match = group.artifacts.find((a) => a.id === id);
      if (match) return match.available;
    }
    return true;
  };

  return (
    <>
      <SectionHeader
        eyebrow="OFFLINE BENCHMARKS & EVALUATION ARCHIVE"
        title="Research & Benchmarks"
        description="Comprehensive evaluation results, cross-validation metrics, feature importance, and explainability artifacts from Drebin-215 (static) and CICMalDroid2020 (dynamic) research pipelines. These represent offline research validation, not live individual APK predictions."
      />

      {error && <StateMessage kind="error">{error}</StateMessage>}
      {loading && (
        <StateMessage kind="loading">
          Loading benchmark datasets, evaluation metrics, and visualization artifacts…
        </StateMessage>
      )}

      {/* Filter and Quick Jump Navigation */}
      <div className="research-controls-bar">
        <div className="filter-pill-group" role="tablist" aria-label="Benchmark pipeline selector">
          <button
            role="tab"
            aria-selected={filter === "all"}
            className={`filter-pill ${filter === "all" ? "active" : ""}`}
            onClick={() => setFilter("all")}
          >
            <Layers size={14} />
            <span>All Benchmarks</span>
          </button>
          <button
            role="tab"
            aria-selected={filter === "static"}
            className={`filter-pill ${filter === "static" ? "active" : ""}`}
            onClick={() => setFilter("static")}
          >
            <Shield size={14} />
            <span>Static Analysis (Drebin-215)</span>
          </button>
          <button
            role="tab"
            aria-selected={filter === "dynamic"}
            className={`filter-pill ${filter === "dynamic" ? "active" : ""}`}
            onClick={() => setFilter("dynamic")}
          >
            <Activity size={14} />
            <span>Dynamic Analysis (CICMalDroid2020)</span>
          </button>
        </div>

        <div className="quick-jump-links" aria-label="Jump to section">
          <span className="quick-jump-label">Jump to:</span>
          {(filter === "all" || filter === "static") && (
            <>
              <a href="#static-eval" className="quick-jump-item">Static CV & Test</a>
              <a href="#static-charts" className="quick-jump-item">Static Figures</a>
            </>
          )}
          {(filter === "all" || filter === "dynamic") && (
            <>
              <a href="#dyn-cluster-cv" className="quick-jump-item">Cluster-Held-Out CV</a>
              <a href="#dyn-random-split" className="quick-jump-item">Random Split</a>
              <a href="#dyn-xgb-variants" className="quick-jump-item">XGB Variants</a>
              <a href="#dyn-features" className="quick-jump-item">Feature Sensitivity</a>
              <a href="#dyn-mcnemar" className="quick-jump-item">McNemar Tests</a>
              <a href="#dyn-unseen" className="quick-jump-item">Unseen Categories</a>
            </>
          )}
        </div>
      </div>

      <div className="research-sections-container">
        {/* ========================================================================= */}
        {/* SECTION 1: STATIC-ANALYSIS BENCHMARKS                                     */}
        {/* ========================================================================= */}
        {(filter === "all" || filter === "static") && (
          <section className="research-main-section" id="static-benchmarks">
            <div className="section-title-banner">
              <div className="section-title-badge">
                <Shield size={18} />
                <span>STATIC PIPELINE</span>
              </div>
              <h2>Static-Analysis Benchmarks (Drebin-215)</h2>
              <p className="section-description">
                Saved evaluation results and visualizations from the Drebin-215 research pipeline
                (7,254 applications across 215 static indicators spanning permissions, intents, API calls, and commands).
              </p>
            </div>

            {/* Evaluation Tables */}
            <div className="research-subsection" id="static-eval">
              <div className="subsection-header">
                <div>
                  <h3 className="subsection-title">Model Evaluation Tables</h3>
                  <p className="subsection-caption">
                    Performance comparison between Random Forest, XGBoost, and the Fused Ensemble on held-out and cross-validation splits.
                  </p>
                </div>
              </div>

              <div className="tables-side-by-side">
                <TableCard
                  id="static-test-results"
                  title="Held-out Test Set (20%)"
                  caption="Evaluated on 1,451 independent test applications never seen during model training."
                  table={tables["static-test-results"]}
                  available={isArtifactAvailable("static-test-results")}
                />
                <TableCard
                  id="static-cv-results"
                  title="5-Fold Cross-Validation (mean ± std)"
                  caption="Stratified 5-fold cross-validation results across the 5,803 training applications."
                  table={tables["static-cv-results"]}
                  available={isArtifactAvailable("static-cv-results")}
                />
              </div>
            </div>

            {/* Static Visualizations */}
            <div className="research-subsection" id="static-charts">
              <div className="subsection-header">
                <div>
                  <h3 className="subsection-title">Static Visualizations & Explainability</h3>
                  <p className="subsection-caption">
                    Artifacts generated during model training illustrating feature attributions, classification boundaries, and error distributions.
                  </p>
                </div>
              </div>

              <div className="visualizations-grid">
                <ImageCard
                  id="static-feature-importance"
                  title="Feature Importance"
                  caption="Top predictive static indicators ranked by Gini importance in Random Forest and XGBoost."
                  onExpand={setExpandedImage}
                  hasError={Boolean(imageErrors["static-feature-importance"])}
                  onError={() => handleImageError("static-feature-importance")}
                  available={isArtifactAvailable("static-feature-importance")}
                />
                <ImageCard
                  id="static-confusion-matrices"
                  title="Confusion Matrices"
                  caption="Confusion matrices showing True Positive, True Negative, False Positive, and False Negative counts on the 20% test partition."
                  onExpand={setExpandedImage}
                  hasError={Boolean(imageErrors["static-confusion-matrices"])}
                  onError={() => handleImageError("static-confusion-matrices")}
                  available={isArtifactAvailable("static-confusion-matrices")}
                />
                <ImageCard
                  id="static-roc-pr"
                  title="ROC and Precision-Recall Curves"
                  caption="Receiver Operating Characteristic (ROC) and Precision-Recall (PR) curves demonstrating discriminative ability across decision thresholds."
                  onExpand={setExpandedImage}
                  hasError={Boolean(imageErrors["static-roc-pr"])}
                  onError={() => handleImageError("static-roc-pr")}
                  available={isArtifactAvailable("static-roc-pr")}
                />
                <ImageCard
                  id="static-shap-summary"
                  title="SHAP Summary (Beeswarm)"
                  caption="TreeExplainer beeswarm visualization showing how high and low feature values push predictions toward malicious or benign classifications."
                  onExpand={setExpandedImage}
                  hasError={Boolean(imageErrors["static-shap-summary"])}
                  onError={() => handleImageError("static-shap-summary")}
                  available={isArtifactAvailable("static-shap-summary")}
                />
                <ImageCard
                  id="static-shap-bar"
                  title="SHAP Bar (Mean |SHAP|)"
                  caption="Global feature impact ordering measured by the mean absolute SHAP value across the entire evaluation dataset."
                  onExpand={setExpandedImage}
                  hasError={Boolean(imageErrors["static-shap-bar"])}
                  onError={() => handleImageError("static-shap-bar")}
                  available={isArtifactAvailable("static-shap-bar")}
                />
              </div>
            </div>

            {/* Permanent Limitations Caption */}
            <div className="research-callout-card">
              <div className="callout-icon">
                <Info size={18} />
              </div>
              <div className="callout-content">
                <h4>Static Analysis Research Context & Limitations</h4>
                <p>
                  Indicators are read from the application’s DEX code and manifest structures, not captured from live network traffic.
                  Some API-call and command features are matched by code search, so a live prediction approximates the benchmark and is not a validated ground truth.
                </p>
              </div>
            </div>
          </section>
        )}

        {/* ========================================================================= */}
        {/* SECTION 2: DYNAMIC-ANALYSIS BENCHMARKS                                    */}
        {/* ========================================================================= */}
        {(filter === "all" || filter === "dynamic") && (
          <section className="research-main-section" id="dynamic-benchmarks">
            <div className="section-title-banner">
              <div className="section-title-badge dynamic-badge">
                <Activity size={18} />
                <span>DYNAMIC PIPELINE</span>
              </div>
              <h2>Dynamic-Analysis Benchmarks (CICMalDroid2020)</h2>
              <p className="section-description">
                Historical CICMalDroid2020 evaluation results across 11,520 applications and 139 kernel system calls.
                Live emulator runtime results are executed separately.
              </p>
            </div>

            {/* Subsection 1: Cluster Held-Out 5-Fold CV */}
            <div className="research-subsection" id="dyn-cluster-cv">
              <div className="subsection-header">
                <div>
                  <h3 className="subsection-title">
                    Cluster-Held-Out 5-Fold Cross-Validation (Conservative Ground Truth)
                  </h3>
                  <p className="subsection-caption">
                    Applications with similar behavior are grouped together into clusters and held out, ensuring test apps differ substantially
                    from training apps. This rigorously prevents optimistic family leakage.
                  </p>
                </div>
              </div>

              <div className="tables-stacked">
                <TableCard
                  id="dynamic-cluster-cv"
                  title="Cluster-Held-Out 5-Fold Cross-Validation (mean ± std)"
                  caption="Deep learning architectures and XGBoost evaluated with strict cluster isolation."
                  table={tables["dynamic-cluster-cv"]}
                  available={isArtifactAvailable("dynamic-cluster-cv")}
                />
              </div>
            </div>

            {/* Subsection 2: Pooled Fold Results and Visualizations */}
            <div className="research-subsection" id="dyn-pooled">
              <div className="subsection-header">
                <div>
                  <h3 className="subsection-title">Pooled Fold Results & Generalization Curves</h3>
                  <p className="subsection-caption">
                    Pooled confusion metrics aggregated across the 5 cluster-held-out folds alongside corresponding discriminative curves.
                  </p>
                </div>
              </div>

              <div className="table-and-charts-row">
                <div className="table-container-flex">
                  <TableCard
                    id="dynamic-cluster-pooled"
                    title="Pooled Fold Results (Conservative Evaluation)"
                    caption="Combined confusion metrics across all 5 cluster-held-out folds."
                    table={tables["dynamic-cluster-pooled"]}
                    available={isArtifactAvailable("dynamic-cluster-pooled")}
                  />
                </div>
                <div className="charts-container-flex">
                  <ImageCard
                    id="dynamic-confusion-matrices"
                    title="Confusion Matrices (Cluster-Held-Out, Pooled)"
                    caption="Aggregated confusion matrices across cluster folds for TCN, BiLSTM, and baselines."
                    onExpand={setExpandedImage}
                    hasError={Boolean(imageErrors["dynamic-confusion-matrices"])}
                    onError={() => handleImageError("dynamic-confusion-matrices")}
                    available={isArtifactAvailable("dynamic-confusion-matrices")}
                  />
                  <ImageCard
                    id="dynamic-roc-pr"
                    title="ROC and Precision-Recall Curves"
                    caption="ROC and PR curves under conservative cluster-held-out evaluation."
                    onExpand={setExpandedImage}
                    hasError={Boolean(imageErrors["dynamic-roc-pr"])}
                    onError={() => handleImageError("dynamic-roc-pr")}
                    available={isArtifactAvailable("dynamic-roc-pr")}
                  />
                </div>
              </div>
            </div>

            {/* Subsection 3: Random 80/20 Benchmark Split */}
            <div className="research-subsection" id="dyn-random-split">
              <div className="subsection-header">
                <div>
                  <h3 className="subsection-title">Random 80/20 Benchmark Split</h3>
                  <p className="subsection-caption">
                    Standard random train/test split comparable with prior academic literature (serves as an optimistic baseline).
                  </p>
                </div>
              </div>

              <TableCard
                id="dynamic-test-results"
                title="Random 80/20 Test Split Performance"
                caption="Architecture comparison on standard random split without cluster constraint."
                table={tables["dynamic-test-results"]}
                available={isArtifactAvailable("dynamic-test-results")}
              />
            </div>

            {/* Subsection 4: XGBoost Normalization Variants */}
            <div className="research-subsection" id="dyn-xgb-variants">
              <div className="subsection-header">
                <div>
                  <h3 className="subsection-title">XGBoost Normalization Variants & Dynamic Explainability</h3>
                  <p className="subsection-caption">
                    Evaluating the impact of raw kernel system-call counts versus share-normalized representation on XGBoost accuracy.
                  </p>
                </div>
              </div>

              <div className="tables-side-by-side">
                <TableCard
                  id="dynamic-random-xgboost"
                  title="Random 5-Fold CV (Raw Counts)"
                  caption="XGBoost performance trained on unnormalized system call execution counts."
                  table={tables["dynamic-random-xgboost"]}
                  available={isArtifactAvailable("dynamic-random-xgboost")}
                />
                <TableCard
                  id="dynamic-share-xgboost"
                  title="Share-Normalized System Calls (Cluster Split)"
                  caption="XGBoost performance trained on percentage distribution of kernel system calls."
                  table={tables["dynamic-share-xgboost"]}
                  available={isArtifactAvailable("dynamic-share-xgboost")}
                />
              </div>

              <div className="visualizations-grid two-column">
                <ImageCard
                  id="dynamic-feature-importance"
                  title="Feature Importance (Top System Calls)"
                  caption="Ranking of the most discriminative Linux kernel system calls in dynamic execution."
                  onExpand={setExpandedImage}
                  hasError={Boolean(imageErrors["dynamic-feature-importance"])}
                  onError={() => handleImageError("dynamic-feature-importance")}
                  available={isArtifactAvailable("dynamic-feature-importance")}
                />
                <ImageCard
                  id="dynamic-shap-summary"
                  title="Dynamic SHAP Summary (Beeswarm)"
                  caption="SHAP beeswarm distribution for system call frequencies across malicious and benign traces."
                  onExpand={setExpandedImage}
                  hasError={Boolean(imageErrors["dynamic-shap-summary"])}
                  onError={() => handleImageError("dynamic-shap-summary")}
                  available={isArtifactAvailable("dynamic-shap-summary")}
                />
              </div>
            </div>

            {/* Subsection 5: Feature Count Sensitivity */}
            <div className="research-subsection" id="dyn-features">
              <div className="subsection-header">
                <div>
                  <h3 className="subsection-title">Feature Count Sensitivity & Dimensionality Reduction</h3>
                  <p className="subsection-caption">
                    Evaluation of how many system calls are required to maintain detection fidelity (10 to 139 features).
                  </p>
                </div>
              </div>

              <div className="table-and-charts-row">
                <div className="table-container-flex">
                  <TableCard
                    id="dynamic-feature-counts"
                    title="Feature Count Analysis (10 to 139 Calls)"
                    caption="Detection accuracy and specificity as the feature space is compressed."
                    table={tables["dynamic-feature-counts"]}
                    available={isArtifactAvailable("dynamic-feature-counts")}
                  />
                </div>
                <div className="charts-container-flex">
                  <ImageCard
                    id="dynamic-accuracy-features"
                    title="Accuracy vs. Number of Features Kept"
                    caption="Dimensionality reduction curve showing accuracy retention with compact feature subsets."
                    onExpand={setExpandedImage}
                    hasError={Boolean(imageErrors["dynamic-accuracy-features"])}
                    onError={() => handleImageError("dynamic-accuracy-features")}
                    available={isArtifactAvailable("dynamic-accuracy-features")}
                  />
                  <ImageCard
                    id="dynamic-shap-bar"
                    title="Global Mean |SHAP| Values (Dynamic)"
                    caption="Overall impact ranking of kernel system calls according to mean absolute SHAP attributions."
                    onExpand={setExpandedImage}
                    hasError={Boolean(imageErrors["dynamic-shap-bar"])}
                    onError={() => handleImageError("dynamic-shap-bar")}
                    available={isArtifactAvailable("dynamic-shap-bar")}
                  />
                </div>
              </div>
            </div>

            {/* Subsection 6: McNemar's Statistical Significance Tests */}
            <div className="research-subsection" id="dyn-mcnemar">
              <div className="subsection-header">
                <div>
                  <h3 className="subsection-title">McNemar's Statistical Significance Tests</h3>
                  <p className="subsection-caption">
                    Rigorous pairwise contingency tests comparing deep architectures (TCN) against BiLSTM and Transformer baselines
                    (Bonferroni-adjusted significance threshold α = 0.05 / 3 = 0.0167).
                  </p>
                </div>
              </div>

              <div className="tables-side-by-side">
                <TableCard
                  id="dynamic-mcnemar-cluster"
                  title="Cluster-Held-Out Split Comparison"
                  caption="Statistical significance under conservative cluster partitioning."
                  table={tables["dynamic-mcnemar-cluster"]}
                  available={isArtifactAvailable("dynamic-mcnemar-cluster")}
                />
                <TableCard
                  id="dynamic-mcnemar-random"
                  title="Random Split Comparison"
                  caption="Statistical significance under standard random 80/20 partitioning."
                  table={tables["dynamic-mcnemar-random"]}
                  available={isArtifactAvailable("dynamic-mcnemar-random")}
                />
              </div>
            </div>

            {/* Subsection 7: Unseen Malware Category Evaluation */}
            <div className="research-subsection" id="dyn-unseen">
              <div className="subsection-header">
                <div>
                  <h3 className="subsection-title">Zero-Day & Unseen Malware Category Detection</h3>
                  <p className="subsection-caption">
                    Evaluating generalization capability when models encounter entire malware families or categories (e.g., Adware, Banking)
                    completely excluded from the training dataset.
                  </p>
                </div>
              </div>

              <div className="tables-stacked">
                <TableCard
                  id="dynamic-unseen-category"
                  title="Unseen Category Generalization Performance"
                  caption="Percentage of malware caught and benign applications cleared when evaluated on zero-day categories."
                  table={tables["dynamic-unseen-category"]}
                  available={isArtifactAvailable("dynamic-unseen-category")}
                />
              </div>
            </div>
          </section>
        )}
      </div>

      {/* High-Resolution Image Modal */}
      {expandedImage && (
        <div
          className="image-lightbox-overlay"
          onClick={() => setExpandedImage(null)}
          role="dialog"
          aria-modal="true"
          aria-label={expandedImage.title}
        >
          <div className="image-lightbox-content" onClick={(e) => e.stopPropagation()}>
            <div className="lightbox-header">
              <div>
                <h3>{expandedImage.title}</h3>
                <p>{expandedImage.caption}</p>
              </div>
              <button
                className="lightbox-close-btn"
                onClick={() => setExpandedImage(null)}
                aria-label="Close high-resolution preview"
              >
                <X size={20} />
              </button>
            </div>
            <div className="lightbox-body">
              <img
                src={benchmarkArtifactUrl(expandedImage.id)}
                alt={expandedImage.title}
                className="lightbox-img"
              />
            </div>
            <div className="lightbox-footer">
              <span className="eyebrow">SAVED RESEARCH ARTIFACT · {expandedImage.id}</span>
              <a
                href={benchmarkArtifactUrl(expandedImage.id)}
                target="_blank"
                rel="noreferrer"
                className="button button-secondary button-sm"
              >
                <ExternalLink size={13} />
                <span>Open Raw Image</span>
              </a>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Reusable Component: TableCard
// ---------------------------------------------------------------------------
interface TableCardProps {
  id: string;
  title: string;
  caption: string;
  table?: ResearchTable;
  available: boolean;
}

function TableCard({ id, title, caption, table, available }: TableCardProps) {
  return (
    <div className="panel research-table-card">
      <div className="card-top-header">
        <div className="card-title-group">
          <div className="card-icon-pill">
            <Table2 size={15} />
          </div>
          <div>
            <h4 className="card-title">{title}</h4>
            <p className="card-caption">{caption}</p>
          </div>
        </div>
        <span className="badge badge-subtle">{id}</span>
      </div>

      {!available ? (
        <div className="artifact-state-box error">
          <AlertCircle size={16} />
          <span>Artifact is unavailable on the server filesystem.</span>
        </div>
      ) : !table ? (
        <div className="artifact-state-box loading">
          <span className="spinner-sm" />
          <span>Loading table rows from repository CSV…</span>
        </div>
      ) : table.rows.length === 0 ? (
        <div className="artifact-state-box empty">
          <Info size={16} />
          <span>Table artifact is empty (0 rows).</span>
        </div>
      ) : (
        <div className="table-scroll-wrapper">
          <table className="research-data-table">
            <thead>
              <tr>
                {table.columns.map((col) => (
                  <th key={col}>{col}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {table.rows.map((row, rowIdx) => (
                <tr key={rowIdx}>
                  {table.columns.map((col) => {
                    const val = row[col];
                    const displayVal = val === null || val === undefined ? "—" : String(val);
                    return <td key={col}>{displayVal}</td>;
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Reusable Component: ImageCard
// ---------------------------------------------------------------------------
interface ImageCardProps {
  id: string;
  title: string;
  caption: string;
  onExpand: (img: { id: string; title: string; caption: string }) => void;
  hasError: boolean;
  onError: () => void;
  available: boolean;
}

function ImageCard({
  id,
  title,
  caption,
  onExpand,
  hasError,
  onError,
  available,
}: ImageCardProps) {
  return (
    <div className="panel research-image-card">
      <div className="card-top-header">
        <div className="card-title-group">
          <div className="card-icon-pill image-icon-pill">
            <BarChart3 size={15} />
          </div>
          <div>
            <h4 className="card-title">{title}</h4>
            <p className="card-caption">{caption}</p>
          </div>
        </div>
        <button
          className="expand-btn"
          title="Click to view full size"
          onClick={() => onExpand({ id, title, caption })}
          disabled={!available || hasError}
        >
          <Maximize2 size={14} />
        </button>
      </div>

      <div
        className="image-frame"
        onClick={() => {
          if (available && !hasError) onExpand({ id, title, caption });
        }}
      >
        {!available ? (
          <div className="artifact-state-box error">
            <AlertCircle size={16} />
            <span>Image file is unavailable in the project directory.</span>
          </div>
        ) : hasError ? (
          <div className="artifact-state-box error">
            <AlertCircle size={16} />
            <span>Failed to load image from backend endpoint ({id}).</span>
          </div>
        ) : (
          <>
            <img
              src={benchmarkArtifactUrl(id)}
              alt={title}
              className="benchmark-preview-image"
              onError={onError}
              loading="lazy"
            />
            <div className="image-hover-overlay">
              <span className="hover-expand-pill">
                <Maximize2 size={13} />
                <span>Expand High-Res</span>
              </span>
            </div>
          </>
        )}
      </div>
      <div className="card-footer-meta">
        <span className="artifact-id-text">{id}</span>
        <span className="image-aspect-tag">PNG · Research Artifact</span>
      </div>
    </div>
  );
}
