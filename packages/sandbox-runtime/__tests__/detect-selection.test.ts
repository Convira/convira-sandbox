/**
 * Adapter SELECTION coverage for detect.ts.
 *
 * `detect.test.ts` drives the real adapters on whatever platform the suite
 * happens to run on, so each run leaves the other platforms' branches - and
 * the "native mode with nothing available" throw on those platforms - dark.
 * Here the three native adapters are mocked and `process.platform` is pinned
 * per case, so every arm of `selectNativeAdapter()` plus both `logMissing()`
 * shapes (with and without an install hint) execute everywhere.
 */
import { describe, it, expect, vi, beforeEach, afterEach, type MockInstance } from "vitest";

const mocks = vi.hoisted(() => ({
  linuxAvailable: vi.fn<() => Promise<boolean>>(),
  macosAvailable: vi.fn<() => Promise<boolean>>(),
  windowsAvailable: vi.fn<() => Promise<boolean>>(),
}));

vi.mock("../src/adapters/native-linux.js", () => ({
  linuxAdapter: { platform: "linux-bubblewrap", available: mocks.linuxAvailable },
  _resetLinuxAdapterCache: () => {},
}));
vi.mock("../src/adapters/native-macos.js", () => ({
  macosAdapter: { platform: "macos-sandbox-exec", available: mocks.macosAvailable },
}));
vi.mock("../src/adapters/native-windows.js", () => ({
  windowsAdapter: { platform: "windows-job-objects", available: mocks.windowsAvailable },
}));

const { detectAdapter } = await import("../src/detect.js");

const realPlatform = Object.getOwnPropertyDescriptor(process, "platform");

function pinPlatform(platform: NodeJS.Platform): void {
  Object.defineProperty(process, "platform", { value: platform, configurable: true });
}

let stderrSpy: MockInstance<typeof process.stderr.write>;

beforeEach(() => {
  mocks.linuxAvailable.mockResolvedValue(true);
  mocks.macosAvailable.mockResolvedValue(true);
  mocks.windowsAvailable.mockResolvedValue(true);
  stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
});

afterEach(() => {
  if (realPlatform) Object.defineProperty(process, "platform", realPlatform);
  stderrSpy.mockRestore();
  vi.clearAllMocks();
});

describe("selectNativeAdapter per platform", () => {
  it("picks bubblewrap on Linux when bwrap is present", async () => {
    pinPlatform("linux");
    expect((await detectAdapter("auto")).platform).toBe("linux-bubblewrap");
  });

  it("falls back on Linux with an install hint when bwrap is missing", async () => {
    pinPlatform("linux");
    mocks.linuxAvailable.mockResolvedValue(false);
    expect((await detectAdapter("auto")).platform).toBe("passthrough");
    const written = stderrSpy.mock.calls.map((c) => String(c[0])).join("");
    expect(written).toContain("bubblewrap (bwrap) not found");
    expect(written).toContain("apt install bubblewrap");
  });

  it("picks sandbox-exec on macOS", async () => {
    pinPlatform("darwin");
    expect((await detectAdapter("auto")).platform).toBe("macos-sandbox-exec");
  });

  it("falls back on macOS with no install hint when sandbox-exec is missing", async () => {
    pinPlatform("darwin");
    mocks.macosAvailable.mockResolvedValue(false);
    expect((await detectAdapter("auto")).platform).toBe("passthrough");
    const written = stderrSpy.mock.calls.map((c) => String(c[0])).join("");
    expect(written).toContain("sandbox-exec not found");
    // No hint exists for a built-in macOS tool, so none is printed.
    expect(written).not.toContain("Install with:");
  });

  it("picks the Windows adapter, and stays silent when the addon is absent", async () => {
    // Also runs the WSL sniff: on a non-WSL host /proc/version either is
    // missing (throws) or lacks the microsoft marker.
    pinPlatform("win32");
    expect((await detectAdapter("auto")).platform).toBe("windows-job-objects");
    mocks.windowsAvailable.mockResolvedValue(false);
    expect((await detectAdapter("auto")).platform).toBe("passthrough");
    // The Windows arm has no CLI to install, so it never writes a hint line.
    expect(stderrSpy.mock.calls.length).toBe(0);
  });

  it("returns passthrough on an unsupported platform", async () => {
    pinPlatform("freebsd");
    expect((await detectAdapter("auto")).platform).toBe("passthrough");
  });

  it('throws in "native" mode on an unsupported platform', async () => {
    pinPlatform("freebsd");
    await expect(detectAdapter("native")).rejects.toThrow(/isolation mode "native"/);
  });

  it('"off" never consults an adapter', async () => {
    pinPlatform("linux");
    expect((await detectAdapter("off")).platform).toBe("passthrough");
    expect(mocks.linuxAvailable).not.toHaveBeenCalled();
  });
});
