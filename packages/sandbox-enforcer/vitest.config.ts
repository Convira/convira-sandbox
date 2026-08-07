import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"],
      include: ["src/**/*.ts"],
      exclude: ["src/profiles/**"],
      thresholds: {
        // Ratchet: measured 100/92.85/100/98.30 minus 2% safety margin
        lines: 98,
        branches: 90,
        functions: 98,
        statements: 96,
      },
    },
  },
});
