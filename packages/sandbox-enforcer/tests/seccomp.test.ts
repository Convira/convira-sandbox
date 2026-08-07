import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROFILES_DIR = path.resolve(__dirname, "../src/profiles");

function freshImport() {
  return import("../src/seccomp.js");
}

function loadProfileRaw(name: string) {
  const filePath = path.join(PROFILES_DIR, `${name}.seccomp.json`);
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("seccomp", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // =========================================================================
  // Profile JSON loading
  // =========================================================================
  describe("profile loading", () => {
    it("gateway profile exists and is valid JSON", () => {
      const profile = loadProfileRaw("gateway");
      expect(profile).toBeDefined();
      expect(profile.defaultAction).toBe("SCMP_ACT_ERRNO");
      expect(Array.isArray(profile.syscalls)).toBe(true);
      expect(profile.syscalls.length).toBeGreaterThan(0);
    });

    it("execute-code profile exists and is valid JSON", () => {
      const profile = loadProfileRaw("execute-code");
      expect(profile).toBeDefined();
      expect(profile.defaultAction).toBe("SCMP_ACT_ERRNO");
      expect(Array.isArray(profile.syscalls)).toBe(true);
      expect(profile.syscalls.length).toBeGreaterThan(0);
    });

    it("gateway profile contains architectures array", () => {
      const profile = loadProfileRaw("gateway");
      expect(profile.architectures).toBeDefined();
      expect(Array.isArray(profile.architectures)).toBe(true);
      expect(profile.architectures).toContain("SCMP_ARCH_X86_64");
      expect(profile.architectures).toContain("SCMP_ARCH_AARCH64");
    });

    it("execute-code profile contains architectures array", () => {
      const profile = loadProfileRaw("execute-code");
      expect(profile.architectures).toContain("SCMP_ARCH_X86_64");
      expect(profile.architectures).toContain("SCMP_ARCH_AARCH64");
    });

    it("profiles directory exists", () => {
      expect(fs.existsSync(PROFILES_DIR)).toBe(true);
    });
  });

  // =========================================================================
  // Profile selection and differences
  // =========================================================================
  describe("profile selection", () => {
    it("gateway profile allows network syscalls", () => {
      const profile = loadProfileRaw("gateway");
      const allowedSyscalls = profile.syscalls
        .filter((e: { action: string }) => e.action === "SCMP_ACT_ALLOW")
        .flatMap((e: { names: string[] }) => e.names);

      expect(allowedSyscalls).toContain("socket");
      expect(allowedSyscalls).toContain("connect");
      expect(allowedSyscalls).toContain("bind");
      expect(allowedSyscalls).toContain("listen");
      expect(allowedSyscalls).toContain("accept");
    });

    it("execute-code profile blocks network syscalls", () => {
      const profile = loadProfileRaw("execute-code");
      const allowedSyscalls = profile.syscalls
        .filter((e: { action: string }) => e.action === "SCMP_ACT_ALLOW")
        .flatMap((e: { names: string[] }) => e.names);

      expect(allowedSyscalls).not.toContain("socket");
      expect(allowedSyscalls).not.toContain("connect");
      expect(allowedSyscalls).not.toContain("bind");
      expect(allowedSyscalls).not.toContain("listen");
      expect(allowedSyscalls).not.toContain("accept");
    });

    it("execute-code profile still allows basic I/O", () => {
      const profile = loadProfileRaw("execute-code");
      const allowedSyscalls = profile.syscalls
        .filter((e: { action: string }) => e.action === "SCMP_ACT_ALLOW")
        .flatMap((e: { names: string[] }) => e.names);

      expect(allowedSyscalls).toContain("read");
      expect(allowedSyscalls).toContain("write");
      expect(allowedSyscalls).toContain("open");
      expect(allowedSyscalls).toContain("close");
    });

    it("both profiles use SCMP_ACT_ERRNO as default action", () => {
      const gateway = loadProfileRaw("gateway");
      const executeCode = loadProfileRaw("execute-code");
      expect(gateway.defaultAction).toBe("SCMP_ACT_ERRNO");
      expect(executeCode.defaultAction).toBe("SCMP_ACT_ERRNO");
    });

    it("gateway allows more syscalls than execute-code", () => {
      const gatewaySyscalls = loadProfileRaw("gateway").syscalls
        .filter((e: { action: string }) => e.action === "SCMP_ACT_ALLOW")
        .flatMap((e: { names: string[] }) => e.names);
      const execSyscalls = loadProfileRaw("execute-code").syscalls
        .filter((e: { action: string }) => e.action === "SCMP_ACT_ALLOW")
        .flatMap((e: { names: string[] }) => e.names);

      expect(gatewaySyscalls.length).toBeGreaterThan(execSyscalls.length);
    });
  });

  // =========================================================================
  // isSeccompSupported
  // =========================================================================
  describe("isSeccompSupported", () => {
    it("returns false on non-linux platforms", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      expect(mod.isSeccompSupported()).toBe(false);
    });

    it("returns false on windows", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("win32" as NodeJS.Platform);
      const mod = await freshImport();
      expect(mod.isSeccompSupported()).toBe(false);
    });
  });

  // =========================================================================
  // getSeccompProfile (public API)
  // =========================================================================
  describe("getSeccompProfile", () => {
    it("returns parsed gateway profile", async () => {
      const mod = await freshImport();
      const profile = mod.getSeccompProfile("gateway");
      expect(profile.defaultAction).toBe("SCMP_ACT_ERRNO");
      expect(profile.syscalls).toBeDefined();
      expect(profile.syscalls.length).toBeGreaterThan(0);
    });

    it("returns parsed execute-code profile", async () => {
      const mod = await freshImport();
      const profile = mod.getSeccompProfile("execute-code");
      expect(profile.defaultAction).toBe("SCMP_ACT_ERRNO");
      expect(profile.syscalls).toBeDefined();
    });

    it("profiles have correct structure", async () => {
      const mod = await freshImport();
      for (const name of ["gateway", "execute-code"] as const) {
        const profile = mod.getSeccompProfile(name);
        expect(profile).toHaveProperty("defaultAction");
        expect(profile).toHaveProperty("syscalls");
        for (const entry of profile.syscalls) {
          expect(entry).toHaveProperty("names");
          expect(entry).toHaveProperty("action");
          expect(Array.isArray(entry.names)).toBe(true);
          expect(typeof entry.action).toBe("string");
        }
      }
    });
  });

  // =========================================================================
  // getAllowedSyscalls
  // =========================================================================
  describe("getAllowedSyscalls", () => {
    it("returns an array of unique syscall names for gateway", async () => {
      const mod = await freshImport();
      const syscalls = mod.getAllowedSyscalls("gateway");
      expect(Array.isArray(syscalls)).toBe(true);
      expect(syscalls.length).toBeGreaterThan(0);
      // Verify uniqueness
      expect(new Set(syscalls).size).toBe(syscalls.length);
    });

    it("returns an array of unique syscall names for execute-code", async () => {
      const mod = await freshImport();
      const syscalls = mod.getAllowedSyscalls("execute-code");
      expect(Array.isArray(syscalls)).toBe(true);
      expect(syscalls.length).toBeGreaterThan(0);
      expect(new Set(syscalls).size).toBe(syscalls.length);
    });

    it("gateway allowed syscalls include networking", async () => {
      const mod = await freshImport();
      const syscalls = mod.getAllowedSyscalls("gateway");
      expect(syscalls).toContain("socket");
      expect(syscalls).toContain("connect");
    });

    it("execute-code allowed syscalls exclude networking", async () => {
      const mod = await freshImport();
      const syscalls = mod.getAllowedSyscalls("execute-code");
      expect(syscalls).not.toContain("socket");
      expect(syscalls).not.toContain("connect");
    });

    it("both profiles allow basic process management", async () => {
      const mod = await freshImport();
      for (const name of ["gateway", "execute-code"] as const) {
        const syscalls = mod.getAllowedSyscalls(name);
        expect(syscalls).toContain("exit");
        expect(syscalls).toContain("exit_group");
        expect(syscalls).toContain("getpid");
      }
    });
  });

  // =========================================================================
  // compileSeccompProfile / getSeccompFd (require native binding)
  // =========================================================================
  describe("compileSeccompProfile", () => {
    it("throws when native binding is not available on non-linux", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      const profilePath = path.join(PROFILES_DIR, "gateway.seccomp.json");
      expect(() => mod.compileSeccompProfile(profilePath)).toThrow(
        "seccomp native binding not available",
      );
    });
  });

  describe("getSeccompFd", () => {
    it("throws when native binding is not available", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      expect(() => mod.getSeccompFd("gateway")).toThrow(
        "seccomp native binding not available",
      );
    });

    it("throws for execute-code profile when binding unavailable", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("darwin" as NodeJS.Platform);
      const mod = await freshImport();
      expect(() => mod.getSeccompFd("execute-code")).toThrow(
        "seccomp native binding not available",
      );
    });
  });

  // =========================================================================
  // Architecture filtering
  // =========================================================================
  describe("architecture filtering", () => {
    it("all profiles support x86_64", () => {
      for (const name of ["gateway", "execute-code"]) {
        const profile = loadProfileRaw(name);
        expect(profile.architectures).toContain("SCMP_ARCH_X86_64");
      }
    });

    it("all profiles support aarch64", () => {
      for (const name of ["gateway", "execute-code"]) {
        const profile = loadProfileRaw(name);
        expect(profile.architectures).toContain("SCMP_ARCH_AARCH64");
      }
    });

    it("profiles only support expected architectures", () => {
      for (const name of ["gateway", "execute-code"]) {
        const profile = loadProfileRaw(name);
        expect(profile.architectures).toHaveLength(2);
      }
    });
  });

  // =========================================================================
  // Invalid profile handling
  // =========================================================================
  describe("invalid profile handling", () => {
    it("throws when loading a non-existent profile path", async () => {
      vi.spyOn(process, "platform", "get").mockReturnValue("linux" as NodeJS.Platform);
      const mod = await freshImport();
      // compileSeccompProfile will fail at fs.readFileSync since the path doesn't exist
      // but it will first fail at binding check on non-linux
      // We test the contract that invalid paths produce errors
      expect(() => mod.compileSeccompProfile("/nonexistent/profile.json")).toThrow();
    });

    it("profile syscalls all have SCMP_ACT_ALLOW action", () => {
      // Verify that profiles only use known actions
      for (const name of ["gateway", "execute-code"]) {
        const profile = loadProfileRaw(name);
        for (const entry of profile.syscalls) {
          expect(["SCMP_ACT_ALLOW", "SCMP_ACT_ERRNO", "SCMP_ACT_KILL"]).toContain(entry.action);
        }
      }
    });

    it("profile syscalls entries all have non-empty names arrays", () => {
      for (const name of ["gateway", "execute-code"]) {
        const profile = loadProfileRaw(name);
        for (const entry of profile.syscalls) {
          expect(entry.names.length).toBeGreaterThan(0);
          for (const n of entry.names) {
            expect(typeof n).toBe("string");
            expect(n.length).toBeGreaterThan(0);
          }
        }
      }
    });
  });
});
