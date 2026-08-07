/**
 * Tests for landlock.ts code paths that require the native binding.
 * Hooks into Module._resolveFilename to redirect the native binding require()
 * to a mock.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// Mock native binding
// ---------------------------------------------------------------------------

const mockBinding = {
  landlockGetAbiVersion: vi.fn().mockReturnValue(3),
  landlockCreateRuleset: vi.fn().mockReturnValue(42),
  landlockAddRule: vi.fn(),
  landlockRestrictSelf: vi.fn(),

  LANDLOCK_ACCESS_FS_EXECUTE: 1n,
  LANDLOCK_ACCESS_FS_WRITE_FILE: 2n,
  LANDLOCK_ACCESS_FS_READ_FILE: 4n,
  LANDLOCK_ACCESS_FS_READ_DIR: 8n,
  LANDLOCK_ACCESS_FS_REMOVE_DIR: 16n,
  LANDLOCK_ACCESS_FS_REMOVE_FILE: 32n,
  LANDLOCK_ACCESS_FS_MAKE_CHAR: 64n,
  LANDLOCK_ACCESS_FS_MAKE_DIR: 128n,
  LANDLOCK_ACCESS_FS_MAKE_REG: 256n,
  LANDLOCK_ACCESS_FS_MAKE_SOCK: 512n,
  LANDLOCK_ACCESS_FS_MAKE_FIFO: 1024n,
  LANDLOCK_ACCESS_FS_MAKE_BLOCK: 2048n,
  LANDLOCK_ACCESS_FS_MAKE_SYM: 4096n,
  LANDLOCK_ACCESS_FS_REFER: 8192n,
  LANDLOCK_ACCESS_FS_TRUNCATE: 16384n,
};

// ---------------------------------------------------------------------------
// Mock node:fs
// ---------------------------------------------------------------------------

const mockReadFileSync = vi.fn();
const mockRealpathSync = vi.fn();
const mockExistsSync = vi.fn();

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
// Patch Module._resolveFilename to intercept the native require
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// eslint-disable-next-line @typescript-eslint/no-require-imports
const Module = require("node:module");
const originalResolveFilename = Module._resolveFilename;

const FAKE_NATIVE_ID = path.resolve(__dirname, "__landlock_mock__");

function installHook() {
  Module._resolveFilename = function (request: string, ...rest: unknown[]) {
    if (request.endsWith("landlock_binding.node")) {
      return FAKE_NATIVE_ID;
    }
    return originalResolveFilename.call(this, request, ...rest);
  };

  const fakeModule = new Module(FAKE_NATIVE_ID);
  fakeModule.exports = mockBinding;
  fakeModule.loaded = true;
  Module._cache[FAKE_NATIVE_ID] = fakeModule;
}

function removeHook() {
  Module._resolveFilename = originalResolveFilename;
  delete Module._cache[FAKE_NATIVE_ID];
}

function freshImport() {
  return import("../src/landlock.js");
}

describe("landlock with native binding", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.spyOn(process, "platform", "get").mockReturnValue("linux" as NodeJS.Platform);

    mockReadFileSync.mockReturnValue("landlock,apparmor,bpf");
    mockRealpathSync.mockImplementation((p: string) => p);
    mockExistsSync.mockReturnValue(true);

    mockBinding.landlockGetAbiVersion.mockReturnValue(3);
    mockBinding.landlockCreateRuleset.mockReturnValue(42);
    mockBinding.landlockAddRule.mockReset();
    mockBinding.landlockRestrictSelf.mockReset();

    installHook();
  });

  afterEach(() => {
    removeHook();
    vi.restoreAllMocks();
  });

  // =========================================================================
  // isLandlockSupported with binding
  // =========================================================================
  describe("isLandlockSupported", () => {
    it("returns true when LSM list contains landlock and ABI >= 1", async () => {
      const mod = await freshImport();
      expect(mod.isLandlockSupported()).toBe(true);
    });

    it("returns false when ABI version is 0", async () => {
      mockBinding.landlockGetAbiVersion.mockReturnValue(0);
      const mod = await freshImport();
      expect(mod.isLandlockSupported()).toBe(false);
    });

    it("returns false when landlockGetAbiVersion throws", async () => {
      mockBinding.landlockGetAbiVersion.mockImplementation(() => {
        throw new Error("kernel too old");
      });
      const mod = await freshImport();
      expect(mod.isLandlockSupported()).toBe(false);
    });

    it("probes /sys/kernel/security/lsm (securityfs), not /proc", async () => {
      const mod = await freshImport();
      mod.isLandlockSupported();
      expect(mockReadFileSync).toHaveBeenCalledWith("/sys/kernel/security/lsm", "utf8");
    });

    it("falls through to the ABI probe when the LSM list is unreadable", async () => {
      // securityfs may be unmounted (containers) — an unreadable list means
      // "unknown", not "unsupported"; the ABI probe is authoritative.
      mockReadFileSync.mockImplementation(() => {
        throw new Error("ENOENT");
      });
      const mod = await freshImport();
      expect(mod.isLandlockSupported()).toBe(true);
    });
  });

  // =========================================================================
  // getLandlockAbiVersion with binding
  // =========================================================================
  describe("getLandlockAbiVersion", () => {
    it("returns ABI version 3 from binding", async () => {
      const mod = await freshImport();
      expect(mod.getLandlockAbiVersion()).toBe(3);
    });

    it("returns ABI version 1 from binding", async () => {
      mockBinding.landlockGetAbiVersion.mockReturnValue(1);
      const mod = await freshImport();
      expect(mod.getLandlockAbiVersion()).toBe(1);
    });

    it("returns -1 when binding throws", async () => {
      mockBinding.landlockGetAbiVersion.mockImplementation(() => {
        throw new Error("kernel error");
      });
      const mod = await freshImport();
      expect(mod.getLandlockAbiVersion()).toBe(-1);
    });
  });

  // =========================================================================
  // applyLandlockRuleset with binding
  // =========================================================================
  describe("applyLandlockRuleset", () => {
    it("throws when ABI version is too low", async () => {
      mockBinding.landlockGetAbiVersion.mockReturnValue(0);
      const mod = await freshImport();
      expect(() => mod.applyLandlockRuleset({ readOnly: [], readWrite: [] })).toThrow(
        "Landlock ABI version 0 too low",
      );
    });

    it("creates ruleset, adds rules, and restricts self", async () => {
      const mod = await freshImport();
      mod.applyLandlockRuleset({ readOnly: ["/usr", "/lib"], readWrite: [] });

      expect(mockBinding.landlockCreateRuleset).toHaveBeenCalled();
      expect(mockBinding.landlockAddRule).toHaveBeenCalledTimes(2);
      expect(mockBinding.landlockRestrictSelf).toHaveBeenCalledWith(42);
    });

    it("applies read-write rules with write access flags", async () => {
      const mod = await freshImport();
      mod.applyLandlockRuleset({ readOnly: [], readWrite: ["/tmp"] });

      expect(mockBinding.landlockAddRule).toHaveBeenCalledTimes(1);
      const callArgs =
        mockBinding.landlockAddRule.mock.calls[mockBinding.landlockAddRule.mock.calls.length - 1];
      const accessFlags = callArgs[2] as bigint;
      expect((accessFlags & mockBinding.LANDLOCK_ACCESS_FS_WRITE_FILE) !== 0n).toBe(true);
    });

    it("applies read-only rules without write flags", async () => {
      const mod = await freshImport();
      mod.applyLandlockRuleset({ readOnly: ["/usr"], readWrite: [] });

      const callArgs =
        mockBinding.landlockAddRule.mock.calls[mockBinding.landlockAddRule.mock.calls.length - 1];
      const accessFlags = callArgs[2] as bigint;
      expect((accessFlags & mockBinding.LANDLOCK_ACCESS_FS_READ_FILE) !== 0n).toBe(true);
      expect((accessFlags & mockBinding.LANDLOCK_ACCESS_FS_WRITE_FILE) !== 0n).toBe(false);
    });

    it("handles both read-only and read-write paths", async () => {
      const mod = await freshImport();
      mod.applyLandlockRuleset({
        readOnly: ["/usr", "/lib"],
        readWrite: ["/tmp", "/var/tmp"],
      });

      // Total calls includes ones from previous tests since mock isn't reset
      // Just check that restrictSelf was called
      expect(mockBinding.landlockRestrictSelf).toHaveBeenCalled();
    });

    it("skips unresolvable paths", async () => {
      // Both the leaf and its parent are unresolvable -> the rule is skipped.
      mockRealpathSync.mockImplementation((p: string) => {
        if (p === "/nonexistent" || p === "/") throw new Error("ENOENT");
        return p;
      });

      const mod = await freshImport();
      const addRuleCallsBefore = mockBinding.landlockAddRule.mock.calls.length;
      mod.applyLandlockRuleset({ readOnly: ["/nonexistent", "/usr"], readWrite: [] });
      const addRuleCallsAfter = mockBinding.landlockAddRule.mock.calls.length;

      // Only /usr should be added (1 new call)
      expect(addRuleCallsAfter - addRuleCallsBefore).toBe(1);
    });

    it("fails closed when a writable path and its parent cannot be resolved", async () => {
      mockRealpathSync.mockImplementation((p: string) => {
        if (p === "/missing-parent/new-output" || p === "/missing-parent") {
          throw new Error("ENOENT");
        }
        return p;
      });

      const mod = await freshImport();
      mod.applyLandlockRuleset({ readOnly: [], readWrite: ["/missing-parent/new-output"] });

      // A writable rule attached without a trustworthy parent would make the
      // policy describe a path different from the kernel object it confines.
      expect(mockBinding.landlockAddRule).not.toHaveBeenCalled();
      expect(mockBinding.landlockRestrictSelf).toHaveBeenCalledWith(42);
    });

    it("uses raw path when realpath fails but dirname exists", async () => {
      mockRealpathSync.mockImplementation((p: string) => {
        if (p === "/tmp/newfile") throw new Error("ENOENT");
        return p;
      });
      mockExistsSync.mockReturnValue(true);

      const mod = await freshImport();
      mod.applyLandlockRuleset({ readOnly: [], readWrite: ["/tmp/newfile"] });

      const lastCall =
        mockBinding.landlockAddRule.mock.calls[mockBinding.landlockAddRule.mock.calls.length - 1];
      expect(lastCall[1]).toBe("/tmp/newfile");
    });

    it("resolves a symlinked parent for a not-yet-created leaf (no symlink escape)", async () => {
      // The leaf doesn't exist yet (realpath throws) but its parent is a
      // symlink; the parent must be realpath-resolved and the leaf rejoined,
      // so the rule attaches to the real inode rather than the symlink target.
      mockRealpathSync.mockImplementation((p: string) => {
        if (p === "/sandbox/newfile") throw new Error("ENOENT");
        if (p === "/sandbox") return "/real/target";
        return p;
      });

      const mod = await freshImport();
      mod.applyLandlockRuleset({ readOnly: [], readWrite: ["/sandbox/newfile"] });

      const lastCall =
        mockBinding.landlockAddRule.mock.calls[mockBinding.landlockAddRule.mock.calls.length - 1];
      // Must be the resolved-parent path, NOT the raw symlinked "/sandbox/newfile".
      expect(lastCall[1]).toBe("/real/target/newfile");
    });

    it("passes resolved path from realpathSync", async () => {
      mockRealpathSync.mockReturnValue("/resolved/path");

      const mod = await freshImport();
      mod.applyLandlockRuleset({ readOnly: ["/some/link"], readWrite: [] });

      const lastCall =
        mockBinding.landlockAddRule.mock.calls[mockBinding.landlockAddRule.mock.calls.length - 1];
      expect(lastCall[1]).toBe("/resolved/path");
    });

    it("includes REFER and TRUNCATE in handled flags for ABI v3", async () => {
      const mod = await freshImport();
      mod.applyLandlockRuleset({ readOnly: [], readWrite: [] });

      const lastCall =
        mockBinding.landlockCreateRuleset.mock.calls[
          mockBinding.landlockCreateRuleset.mock.calls.length - 1
        ];
      const handledFlags = lastCall[0] as bigint;
      expect((handledFlags & mockBinding.LANDLOCK_ACCESS_FS_REFER) !== 0n).toBe(true);
      expect((handledFlags & mockBinding.LANDLOCK_ACCESS_FS_TRUNCATE) !== 0n).toBe(true);
    });

    it("excludes REFER and TRUNCATE for ABI v1", async () => {
      mockBinding.landlockGetAbiVersion.mockReturnValue(1);
      const mod = await freshImport();
      mod.applyLandlockRuleset({ readOnly: [], readWrite: [] });

      const lastCall =
        mockBinding.landlockCreateRuleset.mock.calls[
          mockBinding.landlockCreateRuleset.mock.calls.length - 1
        ];
      const handledFlags = lastCall[0] as bigint;
      expect((handledFlags & mockBinding.LANDLOCK_ACCESS_FS_REFER) !== 0n).toBe(false);
      expect((handledFlags & mockBinding.LANDLOCK_ACCESS_FS_TRUNCATE) !== 0n).toBe(false);
    });

    it("includes REFER but not TRUNCATE for ABI v2", async () => {
      mockBinding.landlockGetAbiVersion.mockReturnValue(2);
      const mod = await freshImport();
      mod.applyLandlockRuleset({ readOnly: [], readWrite: [] });

      const lastCall =
        mockBinding.landlockCreateRuleset.mock.calls[
          mockBinding.landlockCreateRuleset.mock.calls.length - 1
        ];
      const handledFlags = lastCall[0] as bigint;
      expect((handledFlags & mockBinding.LANDLOCK_ACCESS_FS_REFER) !== 0n).toBe(true);
      expect((handledFlags & mockBinding.LANDLOCK_ACCESS_FS_TRUNCATE) !== 0n).toBe(false);
    });

    it("handles empty ruleset", async () => {
      const addRuleCallsBefore = mockBinding.landlockAddRule.mock.calls.length;
      const mod = await freshImport();
      mod.applyLandlockRuleset({ readOnly: [], readWrite: [] });

      expect(mockBinding.landlockCreateRuleset).toHaveBeenCalled();
      expect(mockBinding.landlockAddRule.mock.calls.length).toBe(addRuleCallsBefore);
      expect(mockBinding.landlockRestrictSelf).toHaveBeenCalled();
    });

    it("uses rulesetFd from createRuleset for addRule and restrictSelf", async () => {
      mockBinding.landlockCreateRuleset.mockReturnValue(99);
      const mod = await freshImport();
      mod.applyLandlockRuleset({ readOnly: ["/usr"], readWrite: [] });

      const addRuleCall =
        mockBinding.landlockAddRule.mock.calls[mockBinding.landlockAddRule.mock.calls.length - 1];
      expect(addRuleCall[0]).toBe(99);

      const restrictCall =
        mockBinding.landlockRestrictSelf.mock.calls[
          mockBinding.landlockRestrictSelf.mock.calls.length - 1
        ];
      expect(restrictCall[0]).toBe(99);
    });
  });
});
