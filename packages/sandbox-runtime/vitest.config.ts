import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"],
      include: ["src/**/*.ts"],
      exclude: ["**/__tests__/**", "**/*.test.ts", "**/*.d.ts"],
      thresholds: {
        lines: 61,
        branches: 34,
        functions: 82,
        statements: 60,
      },
    },
  },
});
