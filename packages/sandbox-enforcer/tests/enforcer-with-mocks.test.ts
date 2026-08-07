/**
 * Tests for enforcer.ts with mocked landlock and seccomp modules.
 * This covers the success and error paths in applyKernelHardening
 * that require both mechanisms to be "supported".
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Mock landlock and seccomp modules
// ---------------------------------------------------------------------------

const mockIsLandlockSupported = vi.fn();
const mockApplyLandlockRuleset = vi.fn();
const mockGetLandlockAbiVersion = vi.fn();
const mockIsSeccompSupported = vi.fn();
const mockGetSeccompFd = vi.fn();

vi.mock("../src/landlock.js", () => ({
  isLandlockSupported: (...args: unknown[]) => mockIsLandlockSupported(...args),
  applyLandlockRuleset: (...args: unknown[]) => mockApplyLandlockRuleset(...args),
  getLandlockAbiVersion: (...args: unknown[]) => mockGetLandlockAbiVersion(...args),
}));

vi.mock("../src/seccomp.js", () => ({
  isSeccompSupported: (...args: unknown[]) => mockIsSeccompSupported(...args),
  getSeccompFd: (...args: unknown[]) => mockGetSeccompFd(...args),
}));

function freshImport() {
  return import("../src/enforcer.js");
}

describe("enforcer with mocked dependencies", () => {
  beforeEach(() => {
    vi.resetModules();
    mockIsLandlockSupported.mockReset();
    mockApplyLandlockRuleset.mockReset();
    mockGetLandlockAbiVersion.mockReset();
    mockIsSeccompSupported.mockReset();
    mockGetSeccompFd.mockReset();
  });

  // =========================================================================
  // isKernelHardeningAvailable
  // =========================================================================
  describe("isKernelHardeningAvailable", () => {
    it("returns true when landlock is supported", async () => {
      mockIsLandlockSupported.mockReturnValue(true);
      mockIsSeccompSupported.mockReturnValue(false);
      const mod = await freshImport();
      expect(mod.isKernelHardeningAvailable()).toBe(true);
    });

    it("returns true when seccomp is supported", async () => {
      mockIsLandlockSupported.mockReturnValue(false);
      mockIsSeccompSupported.mockReturnValue(true);
      const mod = await freshImport();
      expect(mod.isKernelHardeningAvailable()).toBe(true);
    });

    it("returns true when both are supported", async () => {
      mockIsLandlockSupported.mockReturnValue(true);
      mockIsSeccompSupported.mockReturnValue(true);
      const mod = await freshImport();
      expect(mod.isKernelHardeningAvailable()).toBe(true);
    });

    it("returns false when neither is supported", async () => {
      mockIsLandlockSupported.mockReturnValue(false);
      mockIsSeccompSupported.mockReturnValue(false);
      const mod = await freshImport();
      expect(mod.isKernelHardeningAvailable()).toBe(false);
    });
  });

  // =========================================================================
  // applyKernelHardening — successful landlock application
  // =========================================================================
  describe("applyKernelHardening with landlock success", () => {
    it("applies landlock when supported and config provided", async () => {
      mockIsLandlockSupported.mockReturnValue(true);
      mockGetLandlockAbiVersion.mockReturnValue(3);
      mockIsSeccompSupported.mockReturnValue(false);
      mockApplyLandlockRuleset.mockImplementation(() => {});

      const mod = await freshImport();
      const result = mod.applyKernelHardening({
        landlock: { readOnly: ["/usr"], readWrite: ["/tmp"] },
      });

      expect(result.landlock.applied).toBe(true);
      expect(result.landlock.supported).toBe(true);
      expect(result.landlock.abiVersion).toBe(3);
      expect(result.landlock.error).toBeUndefined();
      expect(mockApplyLandlockRuleset).toHaveBeenCalledOnce();
    });

    it("captures error when applyLandlockRuleset throws", async () => {
      mockIsLandlockSupported.mockReturnValue(true);
      mockGetLandlockAbiVersion.mockReturnValue(1);
      mockIsSeccompSupported.mockReturnValue(false);
      mockApplyLandlockRuleset.mockImplementation(() => {
        throw new Error("ABI version too low");
      });

      const mod = await freshImport();
      const result = mod.applyKernelHardening({
        landlock: { readOnly: ["/usr"], readWrite: [] },
      });

      expect(result.landlock.applied).toBe(false);
      expect(result.landlock.error).toBe("ABI version too low");
    });

    it("captures non-Error throws as strings", async () => {
      mockIsLandlockSupported.mockReturnValue(true);
      mockGetLandlockAbiVersion.mockReturnValue(2);
      mockIsSeccompSupported.mockReturnValue(false);
      mockApplyLandlockRuleset.mockImplementation(() => {
        throw "unexpected string error";
      });

      const mod = await freshImport();
      const result = mod.applyKernelHardening({
        landlock: { readOnly: [], readWrite: [] },
      });

      expect(result.landlock.applied).toBe(false);
      expect(result.landlock.error).toBe("unexpected string error");
    });
  });

  // =========================================================================
  // applyKernelHardening — successful seccomp application
  // =========================================================================
  describe("applyKernelHardening with seccomp success", () => {
    it("applies seccomp when supported and profile provided", async () => {
      mockIsLandlockSupported.mockReturnValue(false);
      mockGetLandlockAbiVersion.mockReturnValue(-1);
      mockIsSeccompSupported.mockReturnValue(true);
      mockGetSeccompFd.mockReturnValue(7);

      const mod = await freshImport();
      const result = mod.applyKernelHardening({
        seccompProfile: "gateway",
      });

      expect(result.seccomp.applied).toBe(true);
      expect(result.seccomp.supported).toBe(true);
      expect(result.seccomp.fd).toBe(7);
      expect(result.seccomp.error).toBeUndefined();
      expect(mockGetSeccompFd).toHaveBeenCalledWith("gateway");
    });

    it("applies seccomp with execute-code profile", async () => {
      mockIsLandlockSupported.mockReturnValue(false);
      mockGetLandlockAbiVersion.mockReturnValue(-1);
      mockIsSeccompSupported.mockReturnValue(true);
      mockGetSeccompFd.mockReturnValue(12);

      const mod = await freshImport();
      const result = mod.applyKernelHardening({
        seccompProfile: "execute-code",
      });

      expect(result.seccomp.fd).toBe(12);
      expect(mockGetSeccompFd).toHaveBeenCalledWith("execute-code");
    });

    it("captures error when getSeccompFd throws", async () => {
      mockIsLandlockSupported.mockReturnValue(false);
      mockGetLandlockAbiVersion.mockReturnValue(-1);
      mockIsSeccompSupported.mockReturnValue(true);
      mockGetSeccompFd.mockImplementation(() => {
        throw new Error("libseccomp compilation failed");
      });

      const mod = await freshImport();
      const result = mod.applyKernelHardening({
        seccompProfile: "gateway",
      });

      expect(result.seccomp.applied).toBe(false);
      expect(result.seccomp.error).toBe("libseccomp compilation failed");
      expect(result.seccomp.fd).toBeUndefined();
    });

    it("captures non-Error throws in seccomp", async () => {
      mockIsLandlockSupported.mockReturnValue(false);
      mockGetLandlockAbiVersion.mockReturnValue(-1);
      mockIsSeccompSupported.mockReturnValue(true);
      mockGetSeccompFd.mockImplementation(() => {
        throw 42;
      });

      const mod = await freshImport();
      const result = mod.applyKernelHardening({
        seccompProfile: "gateway",
      });

      expect(result.seccomp.applied).toBe(false);
      expect(result.seccomp.error).toBe("42");
    });
  });

  // =========================================================================
  // applyKernelHardening — both mechanisms
  // =========================================================================
  describe("applyKernelHardening with both mechanisms", () => {
    it("applies both when both are supported", async () => {
      mockIsLandlockSupported.mockReturnValue(true);
      mockGetLandlockAbiVersion.mockReturnValue(3);
      mockIsSeccompSupported.mockReturnValue(true);
      mockApplyLandlockRuleset.mockImplementation(() => {});
      mockGetSeccompFd.mockReturnValue(5);

      const mod = await freshImport();
      const result = mod.applyKernelHardening({
        landlock: { readOnly: ["/usr"], readWrite: ["/tmp"] },
        seccompProfile: "gateway",
      });

      expect(result.landlock.applied).toBe(true);
      expect(result.seccomp.applied).toBe(true);
      expect(result.seccomp.fd).toBe(5);
    });

    it("landlock failure does not prevent seccomp", async () => {
      mockIsLandlockSupported.mockReturnValue(true);
      mockGetLandlockAbiVersion.mockReturnValue(1);
      mockIsSeccompSupported.mockReturnValue(true);
      mockApplyLandlockRuleset.mockImplementation(() => {
        throw new Error("landlock failed");
      });
      mockGetSeccompFd.mockReturnValue(8);

      const mod = await freshImport();
      const result = mod.applyKernelHardening({
        landlock: { readOnly: ["/usr"], readWrite: [] },
        seccompProfile: "execute-code",
      });

      expect(result.landlock.applied).toBe(false);
      expect(result.landlock.error).toBe("landlock failed");
      expect(result.seccomp.applied).toBe(true);
      expect(result.seccomp.fd).toBe(8);
    });

    it("seccomp failure does not affect landlock result", async () => {
      mockIsLandlockSupported.mockReturnValue(true);
      mockGetLandlockAbiVersion.mockReturnValue(2);
      mockIsSeccompSupported.mockReturnValue(true);
      mockApplyLandlockRuleset.mockImplementation(() => {});
      mockGetSeccompFd.mockImplementation(() => {
        throw new Error("seccomp failed");
      });

      const mod = await freshImport();
      const result = mod.applyKernelHardening({
        landlock: { readOnly: ["/usr"], readWrite: [] },
        seccompProfile: "gateway",
      });

      expect(result.landlock.applied).toBe(true);
      expect(result.seccomp.applied).toBe(false);
      expect(result.seccomp.error).toBe("seccomp failed");
    });
  });
});
