import { SectionHeader } from "../components/SectionHeader";

export function AboutPage() {
  return (
    <>
      <SectionHeader
        eyebrow="PROJECT NOTES"
        title="About & methodology"
        description="A presentation and API layer around the project’s existing Android analysis pipelines."
      />
      <div className="method-grid">
        <section className="panel method-panel">
          <p className="eyebrow">STATIC PIPELINE</p>
          <h2>Drebin-215 feature model</h2>
          <p>The existing static engine reads APK manifest and DEX structures, builds the trained 215-feature vector, averages saved Random Forest and XGBoost malware probabilities, and returns local SHAP evidence.</p>
          <p>Optional embedded-IP reputation lookups use AbuseIPDB only when a backend key is configured. Domain resolution is separately user-controlled.</p>
        </section>
        <section className="panel method-panel">
          <p className="eyebrow">DYNAMIC PIPELINE</p>
          <h2>Emulator system-call capture</h2>
          <p>The existing Phase 5 workflow uses ADB, the emulator, monkey, and strace, then maps observed calls into the saved CICMalDroid-derived vocabulary and model features.</p>
          <p>Dynamic predictions are experimental when the live emulator differs from the model’s training platform. SHAP explains the model output; it is not proof of behavior.</p>
        </section>
        <section className="panel method-panel method-wide">
          <p className="eyebrow">EVALUATION CONTEXT</p>
          <h2>Historical research is separate from live analysis</h2>
          <p>Research tables and figures are served only from an explicit allowlist of existing artifacts in <code>static_outputs</code> and <code>dynamic_outputs_v2</code>. Missing files are reported as unavailable; the interface does not invent benchmark values or live activity.</p>
          <p>The original Streamlit dashboard remains available as a fallback. This React client and FastAPI backend are additional entry points to the existing Python analysis engine.</p>
        </section>
      </div>
    </>
  );
}
