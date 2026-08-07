/**
 * landlock.ts paths reachable WITHOUT the native binding: platform rejection,
 * the securityfs LSM probe, and the "binding unavailable" failure mode.
 *
 * Scope note (bug hunt W0-39): this file deliberately does not hook the native
 * require, so nothing here can reach `buildHandledAccessFlags`, the access-flag
 * masks, or `resolvePath`. Three describe blocks used to sit below - "path
 * resolution", "ABI version flag computation" and "LandlockRuleset type
 * contract" - whose thirteen tests asserted on mocks and object literals
 * declared in this file and never imported ../src/landlock.js at all. They
 * reported coverage of the confinement policy while a MAKE_* bit could be
 * dropped from the handled set, or a mutating bit added to the read-only mask,
 * with the whole package still green.
 *
 * Those behaviours belong in the files that drive real code through a mocked
 * binding: landlock-with-binding.test.ts (path resolution, symlinked parents)
 * and landlock-access-policy.test.ts (exact access masks per ABI). Do not add a
 * test here that does not call into ../src/landlock.js.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ---------------------------------------------------------------------------
// Mock node:fs so we can control readFileSync, realpathSync, existsSync
// inside landlock.ts.
// ---------------------------------------------------------------------------

const mockReadFileSync = vi.fn<(...args: unknown[]) => string>();
const mockRealpathSync = vi.fn<(...args: unknown[]) => string>();
const mockExistsSync = vi.fn<(...args: unknown[]) => boolean>();

vi.mock("node:fs", async (importOriginal) => {
  const actual = (await importOriginal()) as typeof import("node:fs");
  return {
    ...actual,
    readFileSync: (...args: unknown[]) => mockReadFileSync(...args),
    realpathSync: (...args: unknown[]) => mockRealpathSync(...args),
    existsSync: (...args: unknown[]) => mockExistsSync(...args),
    default: {
      ...actual,
      readFileSync: (...args: unknown[]) => mockReadFileSync(...args),
      realpathSync: (...args: unknown[]) => mockRealpathSync(...args),
      existsSync: (...args: unknown[]) => mockExistsSync(...args),
    },
  };
});

// ---------------------------------------------------------------------------
// Fresh module import (resets cached _binding / _loadAttempted)
// ---------------------------------------------------------------------------

function freshImport() {
  return import("../src/landlock.js");
}

// A 22-line `mockBinding` fixture used to live here, mirroring the
// NativeBinding interface. Nothing in this file hooks Module._resolveFilename,
// so it was never wired to anything - production could not observe it, and only
// the deleted flag-arithmetic block ever read it. The real fixture is in
// landlock-with-binding.test.ts and landlock-access-policy.test.ts.

describe("landlock", () => {
  beforeEach(() => {
    vi.resetModules();
    mockReadFileSync.mockReset();
    mockRealpathSync.mockReset();
    mockExistsSync.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // =========================================================================
  // isLandlockSupported
  // =========================================================================
  describe("isLandlockSupported", () => {
    it("returns false on non-linux platforms", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      expect(mod.isLandlockSupported()).toBe(false);
    });

    it("returns false on windows", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
      const mod = await freshImport();
      expect(mod.isLandlockSupported()).toBe(false);
    });

    it("returns false on freebsd", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("freebsd" as NodeJS.Platform);
      const mod = await freshImport();
      expect(mod.isLandlockSupported()).toBe(false);
    });

    it("returns false when /proc LSM list does not contain landlock", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("linux" as NodeJS.Platform);
      mockReadFileSync.mockReturnValue("apparmor,bpf");
      const mod = await freshImport();
      expect(mod.isLandlockSupported()).toBe(false);
    });

    it("returns false when reading /proc LSM list throws", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("linux" as NodeJS.Platform);
      mockReadFileSync.mockImplementation(() => {
        throw new Error("ENOENT");
      });
      const mod = await freshImport();
      expect(mod.isLandlockSupported()).toBe(false);
    });

    it("returns false when native binding cannot be loaded", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("linux" as NodeJS.Platform);
      mockReadFileSync.mockReturnValue("landlock,apparmor,bpf");
      // The native require will naturally fail — no .node file on this host
      const mod = await freshImport();
      expect(mod.isLandlockSupported()).toBe(false);
    });

    it("does not attempt /proc read on non-linux", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      mod.isLandlockSupported();
      expect(mockReadFileSync).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // getLandlockAbiVersion
  // =========================================================================
  describe("getLandlockAbiVersion", () => {
    it("returns -1 when native binding is not available (non-linux)", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      expect(mod.getLandlockAbiVersion()).toBe(-1);
    });

    it("returns -1 on windows", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
      const mod = await freshImport();
      expect(mod.getLandlockAbiVersion()).toBe(-1);
    });

    it("returns a number", async () => {
      const mod = await freshImport();
      const version = mod.getLandlockAbiVersion();
      expect(typeof version).toBe("number");
    });

    it("caches binding load attempt across calls", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      const v1 = mod.getLandlockAbiVersion();
      const v2 = mod.getLandlockAbiVersion();
      expect(v1).toBe(v2);
      expect(v1).toBe(-1);
    });
  });

  // =========================================================================
  // applyLandlockRuleset
  // =========================================================================
  describe("applyLandlockRuleset", () => {
    it("throws when native binding is not available", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      expect(() => mod.applyLandlockRuleset({ readOnly: [], readWrite: [] })).toThrow(
        "Landlock native binding not available",
      );
    });

    it("throws with descriptive message on windows", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
      const mod = await freshImport();
      expect(() =>
        mod.applyLandlockRuleset({ readOnly: ["/usr"], readWrite: ["/tmp"] }),
      ).toThrow("Landlock native binding not available");
    });

    it("error is an Error instance", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      try {
        mod.applyLandlockRuleset({ readOnly: [], readWrite: [] });
        expect.unreachable("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(Error);
        expect(typeof (err as Error).message).toBe("string");
      }
    });
  });
});
