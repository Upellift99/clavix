import { svelteTesting } from "@testing-library/svelte/vite";
import { defineConfig, mergeConfig } from "vitest/config";
import viteConfig from "./vite.config.js";

// Test-only setup lives here so that `vite build` (used by distribution
// packagers, who don't install test dependencies) needs nothing beyond what
// production needs. Vitest picks this file over vite.config.js.
export default defineConfig(async (env) =>
  mergeConfig(await viteConfig(env), {
    plugins: [
      // Enables client-mode Svelte compilation for *.svelte.test.ts files that
      // opt into the jsdom environment; node-env tests are unaffected.
      svelteTesting(),
    ],
    test: {
      include: ["src/**/*.test.ts"],
      environment: "node",
    },
  }),
);
