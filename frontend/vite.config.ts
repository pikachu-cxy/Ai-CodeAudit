import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import { writeFileSync } from "fs";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const apiTarget = env.VITE_API_PROXY_TARGET || `http://127.0.0.1:${env.VITE_API_PORT || "8787"}`;

  return {
    plugins: [
      react(),
      {
        name: "write-build-id",
        closeBundle() {
          writeFileSync("dist/build-id.txt", new Date().toISOString());
        },
      },
    ],
    server: {
      host: env.VITE_DEV_HOST === "0.0.0.0" ? "0.0.0.0" : undefined,
      port: 5173,
      proxy: {
        "/api": apiTarget,
      },
    },
  };
});
