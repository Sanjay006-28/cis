import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { execFileSync } from "node:child_process";

function backendTarget() {
  const configuredTarget = process.env.VITE_API_PROXY_TARGET;
  if (configuredTarget) return configuredTarget;

  // Default to port 8001 (port 8000 is reserved/occupied by Splunk service)
  return "http://127.0.0.1:8001";
}

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: backendTarget(),
        changeOrigin: true,
      },
    },
  },
});
