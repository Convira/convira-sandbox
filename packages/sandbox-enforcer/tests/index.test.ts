import { describe, it, expect, vi, beforeEach } from "vitest";

function freshImport() {
  return import("../src/index.js");
}

describe("index (barrel exports)", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it("exports isLandlockSupported as a function", async () => {
    const mod = await freshImport();
    expect(typeof mod.isLandlockSupported).toBe("function");
  });

  it("exports getLandlockAbiVersion as a function", async () => {
    const mod = await freshImport();
    expect(typeof mod.getLandlockAbiVersion).toBe("function");
  });

  it("exports applyLandlockRuleset as a function", async () => {
    const mod = await freshImport();
    expect(typeof mod.applyLandlockRuleset).toBe("function");
  });

  it("exports isSeccompSupported as a function", async () => {
    const mod = await freshImport();
    expect(typeof mod.isSeccompSupported).toBe("function");
  });

  it("exports compileSeccompProfile as a function", async () => {
    const mod = await freshImport();
    expect(typeof mod.compileSeccompProfile).toBe("function");
  });

  it("exports getSeccompFd as a function", async () => {
    const mod = await freshImport();
    expect(typeof mod.getSeccompFd).toBe("function");
  });

  it("exports getSeccompProfile as a function", async () => {
    const mod = await freshImport();
    expect(typeof mod.getSeccompProfile).toBe("function");
  });

  it("exports getAllowedSyscalls as a function", async () => {
    const mod = await freshImport();
    expect(typeof mod.getAllowedSyscalls).toBe("function");
  });

  it("exports applyKernelHardening as a function", async () => {
    const mod = await freshImport();
    expect(typeof mod.applyKernelHardening).toBe("function");
  });

  it("exports isKernelHardeningAvailable as a function", async () => {
    const mod = await freshImport();
    expect(typeof mod.isKernelHardeningAvailable).toBe("function");
  });

  it("isLandlockSupported returns boolean when called through index", async () => {
    const mod = await freshImport();
    expect(typeof mod.isLandlockSupported()).toBe("boolean");
  });

  it("getLandlockAbiVersion returns number when called through index", async () => {
    const mod = await freshImport();
    expect(typeof mod.getLandlockAbiVersion()).toBe("number");
  });

  it("isSeccompSupported returns boolean when called through index", async () => {
    const mod = await freshImport();
    expect(typeof mod.isSeccompSupported()).toBe("boolean");
  });

  it("isKernelHardeningAvailable returns boolean when called through index", async () => {
    const mod = await freshImport();
    expect(typeof mod.isKernelHardeningAvailable()).toBe("boolean");
  });

  it("applyKernelHardening returns result object through index", async () => {
    const mod = await freshImport();
    const result = mod.applyKernelHardening({});
    expect(result).toHaveProperty("landlock");
    expect(result).toHaveProperty("seccomp");
  });

  it("getSeccompProfile returns valid profile through index", async () => {
    const mod = await freshImport();
    const profile = mod.getSeccompProfile("gateway");
    expect(profile.defaultAction).toBe("SCMP_ACT_ERRNO");
  });

  it("getAllowedSyscalls returns array through index", async () => {
    const mod = await freshImport();
    const syscalls = mod.getAllowedSyscalls("execute-code");
    expect(Array.isArray(syscalls)).toBe(true);
    expect(syscalls.length).toBeGreaterThan(0);
  });
});
