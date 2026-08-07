import { describe, it, expect, beforeEach, afterEach, vi, type MockInstance } from "vitest";
import { detectAdapter } from "../src/detect.js";
import { createSandboxedSpawn } from "../src/index.js";
import { passthroughAdapter } from "../src/adapters/passthrough.js";
import { _resetLinuxAdapterCache } from "../src/adapters/native-linux.js";

describe("detectAdapter", () => {
  it('returns passthrough when mode is "off"', async () => {
    const adapter = await detectAdapter("off");
    expect(adapter.platform).toBe("passthrough");
  });

  it('returns a non-passthrough adapter on macOS/Linux when mode is "auto"', async () => {
    const adapter = await detectAdapter("auto");
    if (process.platform === "darwin") {
      expect(adapter.platform).toBe("macos-sandbox-exec");
    } else if (process.platform === "linux") {
      // May or may not have bubblewrap installed in CI
      expect(["linux-bubblewrap", "passthrough"]).toContain(adapter.platform);
    } else if (process.platform === "win32") {
      expect(["windows-job-objects", "passthrough"]).toContain(adapter.platform);
    }
  });

  it('throws when mode is "native" and sandbox is unavailable', async () => {
    // Handles both: sandbox available (local dev) and unavailable (CI without bwrap).
    if (process.platform === "win32") return;
    try {
      const adapter = await detectAdapter("native");
      expect(adapter.platform).not.toBe("passthrough");
    } catch (err) {
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toContain('isolation mode "native"');
    }
  });

  it("all adapters satisfy the SandboxAdapter interface", async () => {
    const adapter = await detectAdapter("auto");
    expect(typeof adapter.platform).toBe("string");
    expect(typeof adapter.available).toBe("function");
    expect(typeof adapter.capabilities).toBe("function");
    expect(typeof adapter.wrapSpawn).toBe("function");

    const caps = adapter.capabilities();
    expect(typeof caps.filesystemIsolation).toBe("boolean");
    expect(typeof caps.networkIsolation).toBe("boolean");
    expect(typeof caps.resourceLimits).toBe("boolean");
    // 60s, not the 5s default: detectAdapter("auto") runs the live capability
    // probes, which spawn real processes and observe real outcomes. That is
    // the design (a capability is reported only once its own probe passes), so
    // it is inherently slow - measured at 10s+ on a Windows CI runner, where
    // the default timeout failed this test while the code was working fine.
  }, 60_000);

  it("passthrough adapter is always available", async () => {
    expect(await passthroughAdapter.available()).toBe(true);
  });

  it("createSandboxedSpawn defaults to auto mode when called without arguments", async () => {
    const adapter = await createSandboxedSpawn();
    expect(typeof adapter.platform).toBe("string");
    expect(typeof adapter.wrapSpawn).toBe("function");
    // "auto" never throws: it returns a native adapter or passthrough.
    expect(adapter.platform.length).toBeGreaterThan(0);
  });
});

// Force the Linux adapter to report unavailable via the confinement markers it
// honors (SNAP env), so the "native sandbox missing" fallback paths in
// detect.ts — including logMissing() — execute on Linux CI where bubblewrap is
// installed. The detectAdapter() calls below are made UNCONDITIONALLY on every
// platform; only the assertions branch on process.platform.
describe("detectAdapter fallback when the Linux sandbox is unavailable", () => {
  let stderrSpy: MockInstance<typeof process.stderr.write>;

  beforeEach(() => {
    stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    vi.stubEnv("SNAP", "/snap/convira/1");
    _resetLinuxAdapterCache();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    _resetLinuxAdapterCache();
    stderrSpy.mockRestore();
  });

  it('falls back to passthrough (and logs the missing tool) in "auto" mode', async () => {
    const adapter = await detectAdapter("auto");
    if (process.platform === "linux") {
      expect(adapter.platform).toBe("passthrough");
      const written = stderrSpy.mock.calls.map((c) => String(c[0])).join("");
      expect(written).toContain("bubblewrap");
      expect(written).toContain("Falling back to passthrough");
    } else {
      expect(typeof adapter.platform).toBe("string");
    }
  });

  it('throws in "native" mode instead of degrading silently', async () => {
    const result = await detectAdapter("native").then(
      (adapter) => ({ ok: true as const, adapter }),
      (err: unknown) => ({ ok: false as const, err }),
    );
    if (process.platform === "linux") {
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.err).toBeInstanceOf(Error);
        expect((result.err as Error).message).toContain('isolation mode "native"');
      }
    } else if (result.ok) {
      expect(result.adapter.platform).not.toBe("passthrough");
    } else {
      expect(result.err).toBeInstanceOf(Error);
    }
  });
});
