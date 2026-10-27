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
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "sans-serif"],
      },
    },
  },
  plugins: [],
};
