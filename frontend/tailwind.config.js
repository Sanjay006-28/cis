/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        canvas: "#09111d",
        panel: "#111c2b",
        raised: "#172438",
        line: "#26364a",
        ink: "#e7edf5",
        muted: "#98a9bd",
        accent: "#4cc4c5",
        "accent-glow": "rgba(76, 196, 197, 0.15)",
        danger: "#f87171",
        "danger-panel": "#2a151b",
        "danger-border": "#5c242a",
        good: "#34d399",
        "good-panel": "#0f2b23",
        "good-border": "#1b5442",
      },
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', "Inter", "Segoe UI", "sans-serif"],
        mono: ['"JetBrains Mono"', "Consolas", "Courier New", "monospace"],
      },
      boxShadow: {
        card: "0 4px 20px -2px rgba(0, 0, 0, 0.5), 0 0 1px 1px rgba(255, 255, 255, 0.05)",
        "card-hover": "0 8px 30px -4px rgba(0, 0, 0, 0.6), 0 0 1px 1px rgba(76, 196, 197, 0.2)",
        "malware-glow": "0 0 35px -5px rgba(239, 68, 68, 0.25)",
        "benign-glow": "0 0 35px -5px rgba(52, 211, 153, 0.25)",
      },
    },
  },
  plugins: [],
};
