import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ---------------------------------------------------------------------------
// We need fresh module imports per test because both landlock.ts and seccomp.ts
// cache native binding attempts at module scope.
// ---------------------------------------------------------------------------

function freshImport() {
  return import("../src/enforcer.js");
}

describe("enforcer", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // =========================================================================
  // isKernelHardeningAvailable
  // =========================================================================
  describe("isKernelHardeningAvailable", () => {
    it("returns false on non-linux platforms", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      expect(mod.isKernelHardeningAvailable()).toBe(false);
    });

    it("returns false on windows", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
      const mod = await freshImport();
      expect(mod.isKernelHardeningAvailable()).toBe(false);
    });

    it("returns a boolean", async () => {
      const mod = await freshImport();
      expect(typeof mod.isKernelHardeningAvailable()).toBe("boolean");
    });
  });

  // =========================================================================
  // applyKernelHardening — result structure
  // =========================================================================
  describe("applyKernelHardening result structure", () => {
    it("returns correctly shaped result with empty config", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      const result = mod.applyKernelHardening({});

      expect(result).toHaveProperty("landlock");
      expect(result).toHaveProperty("seccomp");
      expect(result.landlock).toHaveProperty("applied");
      expect(result.landlock).toHaveProperty("supported");
      expect(result.landlock).toHaveProperty("abiVersion");
      expect(result.seccomp).toHaveProperty("applied");
      expect(result.seccomp).toHaveProperty("supported");
    });

    it("landlock and seccomp are not applied with empty config", async () => {
      const mod = await freshImport();
      const result = mod.applyKernelHardening({});

      expect(result.landlock.applied).toBe(false);
      expect(result.seccomp.applied).toBe(false);
    });

    it("does not have error fields when nothing is requested", async () => {
      const mod = await freshImport();
      const result = mod.applyKernelHardening({});

      expect(result.landlock.error).toBeUndefined();
      expect(result.seccomp.error).toBeUndefined();
    });
  });

  // =========================================================================
  // applyKernelHardening — graceful degradation
  // =========================================================================
  describe("graceful degradation", () => {
    it("does not apply landlock when unsupported even if config requests it", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      const result = mod.applyKernelHardening({
        landlock: { readOnly: ["/usr"], readWrite: ["/tmp"] },
      });

      expect(result.landlock.applied).toBe(false);
      expect(result.landlock.supported).toBe(false);
      expect(result.landlock.error).toBeUndefined();
    });

    it("does not apply seccomp when unsupported even if config requests it", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      const result = mod.applyKernelHardening({
        seccompProfile: "gateway",
      });

      expect(result.seccomp.applied).toBe(false);
      expect(result.seccomp.supported).toBe(false);
      expect(result.seccomp.error).toBeUndefined();
    });

    it("reports supported=false on non-linux for both mechanisms", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      const result = mod.applyKernelHardening({
        landlock: { readOnly: [], readWrite: [] },
        seccompProfile: "gateway",
      });

      expect(result.landlock.supported).toBe(false);
      expect(result.seccomp.supported).toBe(false);
    });

    it("returns abiVersion -1 when landlock is unsupported", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      const result = mod.applyKernelHardening({});

      expect(result.landlock.abiVersion).toBe(-1);
    });
  });

  // =========================================================================
  // applyKernelHardening — with both configs
  // =========================================================================
  describe("combined config handling", () => {
    it("handles config with both landlock and seccomp on unsupported platform", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      const result = mod.applyKernelHardening({
        landlock: { readOnly: ["/usr", "/lib"], readWrite: ["/tmp"] },
        seccompProfile: "execute-code",
      });

      expect(result.landlock.applied).toBe(false);
      expect(result.seccomp.applied).toBe(false);
      expect(result.seccomp.fd).toBeUndefined();
    });

    it("handles config with only landlock specified", async () => {
      // Platform stub is load-bearing, not decoration: applyKernelHardening
      // applies a Landlock ruleset to the CURRENT process, irrevocably. Without
      // the stub this test confined the vitest worker on any Linux host with the
      // native binding built, and still reported green.
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      const result = mod.applyKernelHardening({
        landlock: { readOnly: ["/usr"], readWrite: [] },
      });

      // Nothing was applied to this process, on any host.
      expect(result.landlock.supported).toBe(false);
      expect(result.landlock.applied).toBe(false);
      // On non-linux it won't be applied, but the seccomp section should still exist
      expect(result.seccomp).toBeDefined();
      expect(result.seccomp.applied).toBe(false);
    });

    it("handles config with only seccompProfile specified", async () => {
      const mod = await freshImport();
      const result = mod.applyKernelHardening({
        seccompProfile: "gateway",
      });

      expect(result.landlock).toBeDefined();
      expect(result.landlock.applied).toBe(false);
    });
  });

  // =========================================================================
  // Config validation (type-level contracts)
  // =========================================================================
  describe("config validation", () => {
    it("accepts empty config object", async () => {
      const mod = await freshImport();
      expect(() => mod.applyKernelHardening({})).not.toThrow();
    });

    it("accepts config with undefined fields", async () => {
      const mod = await freshImport();
      expect(() =>
        mod.applyKernelHardening({
          landlock: undefined,
          seccompProfile: undefined,
        }),
      ).not.toThrow();
    });

    it("result types are correct", async () => {
      const mod = await freshImport();
      const result = mod.applyKernelHardening({});

      expect(typeof result.landlock.applied).toBe("boolean");
      expect(typeof result.landlock.supported).toBe("boolean");
      expect(typeof result.landlock.abiVersion).toBe("number");
      expect(typeof result.seccomp.applied).toBe("boolean");
      expect(typeof result.seccomp.supported).toBe("boolean");
    });
  });

  // =========================================================================
  // EnforcementResult shape
  // =========================================================================
  describe("EnforcementResult shape", () => {
    it("fd is undefined when seccomp is not applied", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      const result = mod.applyKernelHardening({ seccompProfile: "gateway" });
      expect(result.seccomp.fd).toBeUndefined();
    });

    it("error field is absent when no error occurs", async () => {
      const mod = await freshImport();
      const result = mod.applyKernelHardening({});
      expect("error" in result.landlock).toBe(false);
      expect("error" in result.seccomp).toBe(false);
    });
  });

  // =========================================================================
  // Orchestration of Landlock + seccomp
  // =========================================================================
  describe("orchestration", () => {
    it("processes landlock before seccomp", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();

      // Even though both are unsupported, the function should process both
      // sections without short-circuiting
      const result = mod.applyKernelHardening({
        landlock: { readOnly: ["/usr"], readWrite: ["/tmp"] },
        seccompProfile: "gateway",
      });

      // Both sections should be present and correctly populated
      expect(result.landlock).toBeDefined();
      expect(result.seccomp).toBeDefined();
    });

    it("each mechanism is independent - one failing does not affect the other", async () => {
      // Same reason as above: a real ruleset plus no platform stub Landlock-locks
      // the worker running this suite on Linux, and `typeof ... === "boolean"`
      // stays true either way, so the damage was invisible.
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      const result = mod.applyKernelHardening({
        landlock: { readOnly: ["/usr"], readWrite: ["/tmp"] },
        seccompProfile: "execute-code",
      });

      // Both should independently report their status
      expect(typeof result.landlock.applied).toBe("boolean");
      expect(typeof result.seccomp.applied).toBe("boolean");
      expect(result.landlock.applied).toBe(false);
      expect(result.seccomp.applied).toBe(false);
    });
  });
});
