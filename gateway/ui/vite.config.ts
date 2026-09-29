import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The console is served by the gateway under /ui. Build output is placed inside
// the Python package so a wheel/sdist ships the prebuilt assets.
export default defineConfig({
  base: "/ui/",
  plugins: [react()],
  build: {
    outDir: "../src/lono_gateway/ui/dist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/audit": "http://127.0.0.1:4000",
      "/healthz": "http://127.0.0.1:4000",
    },
  },
});