import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    manifest: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules/@azure/msal-")) {
            return "auth-vendor";
          }
          return undefined;
        }
      }
    }
  },
  test: {
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
    globals: true,
    testTimeout: 30000,
    hookTimeout: 30000
  }
});
