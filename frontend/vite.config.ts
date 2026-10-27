import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { execFileSync } from "node:child_process";

function backendTarget() {
  const configuredTarget = process.env.VITE_API_PROXY_TARGET;
  if (configuredTarget) return configuredTarget;

  if (process.platform === "win32") {
    try {
      const addresses = execFileSync(
        "wsl.exe",
        ["-e", "bash", "-lc", "hostname -I"],
        { encoding: "utf8", timeout: 5000 },
      );
      const wslAddress = addresses.trim().split(/\s+/).find((address) =>
        /^\d{1,3}(?:\.\d{1,3}){3}$/.test(address),
      );
      if (wslAddress) return `http://${wslAddress}:8000`;
    } catch {
      console.warn("Could not discover the WSL address; set VITE_API_PROXY_TARGET explicitly.");
    }
  }

  return "http://localhost:8000";
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
