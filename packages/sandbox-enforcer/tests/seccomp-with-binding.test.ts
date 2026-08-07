/**
 * Tests for seccomp.ts code paths that require the native binding.
 * Hooks into Module._resolveFilename to redirect the native binding require()
 * to a mock, since the actual .node file doesn't exist on macOS.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// Mock native binding
// ---------------------------------------------------------------------------

const mockSeccompBinding = {
  compileSeccompToFd: vi.fn().mockReturnValue(10),
  isSeccompSupported: vi.fn().mockReturnValue(true),
};

// ---------------------------------------------------------------------------
// Patch Module._resolveFilename to intercept the native require
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// eslint-disable-next-line @typescript-eslint/no-require-imports
const Module = require("node:module");
const originalResolveFilename = Module._resolveFilename;

// Temp file that we'll use as the "resolved" path for the native binding
const FAKE_NATIVE_ID = path.resolve(__dirname, "__seccomp_mock__");

function installHook() {
  Module._resolveFilename = function (request: string, ...rest: unknown[]) {
    if (request.endsWith("seccomp_compile.node")) {
      return FAKE_NATIVE_ID;
    }
    return originalResolveFilename.call(this, request, ...rest);
  };

  // Place the mock in the cache under our fake ID
  const fakeModule = new Module(FAKE_NATIVE_ID);
  fakeModule.exports = mockSeccompBinding;
  fakeModule.loaded = true;
  Module._cache[FAKE_NATIVE_ID] = fakeModule;
}

function removeHook() {
  Module._resolveFilename = originalResolveFilename;
  delete Module._cache[FAKE_NATIVE_ID];
}

function freshImport() {
  return import("../src/seccomp.js");
}

describe("seccomp with native binding", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.spyOn(process, "platform", "get").mockReturnValue("linux" as NodeJS.Platform);
    mockSeccompBinding.compileSeccompToFd.mockReturnValue(10);
    mockSeccompBinding.isSeccompSupported.mockReturnValue(true);
    installHook();
  });

  afterEach(() => {
    removeHook();
    vi.restoreAllMocks();
  });

  describe("isSeccompSupported", () => {
    it("returns true when binding reports support", async () => {
      const mod = await freshImport();
      expect(mod.isSeccompSupported()).toBe(true);
    });

    it("returns false when binding reports no support", async () => {
      mockSeccompBinding.isSeccompSupported.mockReturnValue(false);
      const mod = await freshImport();
      expect(mod.isSeccompSupported()).toBe(false);
    });

    it("returns false when binding throws", async () => {
      mockSeccompBinding.isSeccompSupported.mockImplementation(() => {
        throw new Error("seccomp check failed");
      });
      const mod = await freshImport();
      expect(mod.isSeccompSupported()).toBe(false);
    });
  });

  describe("compileSeccompProfile", () => {
    it("compiles gateway profile and returns fd", async () => {
      const mod = await freshImport();
      const profilePath = path.resolve(__dirname, "../src/profiles/gateway.seccomp.json");
      const fd = mod.compileSeccompProfile(profilePath);
      expect(fd).toBe(10);
      expect(mockSeccompBinding.compileSeccompToFd).toHaveBeenCalledOnce();
    });

    it("passes allowed syscalls and default action to native binding", async () => {
      const mod = await freshImport();
      const profilePath = path.resolve(__dirname, "../src/profiles/gateway.seccomp.json");
      mod.compileSeccompProfile(profilePath);

      const [syscalls, defaultAction] = mockSeccompBinding.compileSeccompToFd.mock.calls[0];
      expect(Array.isArray(syscalls)).toBe(true);
      expect(syscalls.length).toBeGreaterThan(0);
      expect(syscalls).toContain("read");
      expect(syscalls).toContain("write");
      expect(syscalls).toContain("socket");
      expect(defaultAction).toBe("SCMP_ACT_ERRNO");
    });

    it("compiles execute-code profile and returns fd", async () => {
      mockSeccompBinding.compileSeccompToFd.mockReturnValue(15);
      const mod = await freshImport();
      const profilePath = path.resolve(
        __dirname,
        "../src/profiles/execute-code.seccomp.json",
      );
      const fd = mod.compileSeccompProfile(profilePath);
      expect(fd).toBe(15);
      expect(mockSeccompBinding.compileSeccompToFd).toHaveBeenCalled();
    });
  });

  describe("getSeccompFd", () => {
    it("returns fd for gateway profile", async () => {
      const mod = await freshImport();
      const fd = mod.getSeccompFd("gateway");
      expect(fd).toBe(10);
    });

    it("returns fd for execute-code profile", async () => {
      mockSeccompBinding.compileSeccompToFd.mockReturnValue(20);
      const mod = await freshImport();
      const fd = mod.getSeccompFd("execute-code");
      expect(fd).toBe(20);
    });
  });
});
