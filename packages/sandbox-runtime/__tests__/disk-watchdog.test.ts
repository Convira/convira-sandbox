/**
 * Workspace disk-write watchdog tests (HARDENING batch 5).
 *
 * The watchdog is the Windows analog of the macOS RSS memory watchdog: there
 * is no RLIMIT_FSIZE on Windows, so a sampled granted-dir byte budget backed
 * by a real kill is the honest best-effort file-size control. The sampler and
 * breach logic are unit-tested everywhere with an injected sampler; the real
 * measure+kill probe runs only on the CI windows-2022 lane.
 */
import { describe, it, expect, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  sampleDirectoryBytes,
  startDiskWriteWatchdog,
  _runDiskWatchdogProbe,
  probeDiskWatchdogSupport,
  _setDiskWatchdogProbeForTests,
  _resetDiskWatchdogProbeCache,
} from "../src/disk-watchdog.js";

const onWindows = process.platform === "win32";

afterEach(() => {
  _resetDiskWatchdogProbeCache();
  vi.useRealTimers();
});

describe("sampleDirectoryBytes", () => {
  it("sums nested file sizes recursively", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-diskwd-sample-"));
    try {
      fs.writeFileSync(path.join(dir, "a.bin"), Buffer.alloc(1000));
      fs.mkdirSync(path.join(dir, "nested"));
      fs.writeFileSync(path.join(dir, "nested", "b.bin"), Buffer.alloc(500));
      expect(sampleDirectoryBytes(dir)).toBe(1500);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("returns null (not 0) when the root cannot be read", () => {
    // A transient read failure must never look like an over/under-budget
    // sample - the watchdog only acts on positive over-budget measurements.
    expect(sampleDirectoryBytes(path.join(os.tmpdir(), "sbx-diskwd-missing-xyz"))).toBeNull();
  });
});

describe("startDiskWriteWatchdog", () => {
  it("fires onBreach once when a sample exceeds the budget, then stops sampling", () => {
    vi.useFakeTimers();
    let breaches = 0;
    let sampleCalls = 0;
    const handle = startDiskWriteWatchdog({
      dir: "/anywhere",
      limitMb: 1,
      intervalMs: 100,
      sampler: () => {
        sampleCalls += 1;
        return 2 * 1024 * 1024;
      },
      onBreach: () => {
        breaches += 1;
      },
    });
    vi.advanceTimersByTime(350);
    expect(breaches).toBe(1);
    const callsAtBreach = sampleCalls;
    vi.advanceTimersByTime(500);
    expect(sampleCalls).toBe(callsAtBreach);
    handle.stop();
  });

  it("never fires under budget and ignores null samples", () => {
    vi.useFakeTimers();
    let breaches = 0;
    const samples: Array<number | null> = [null, 100, null, 512 * 1024];
    const handle = startDiskWriteWatchdog({
      dir: "/anywhere",
      limitMb: 1,
      intervalMs: 50,
      sampler: () => samples.shift() ?? 100,
      onBreach: () => {
        breaches += 1;
      },
    });
    vi.advanceTimersByTime(1000);
    expect(breaches).toBe(0);
    handle.stop();
  });

  it("stop() halts sampling and is idempotent", () => {
    vi.useFakeTimers();
    let sampleCalls = 0;
    const handle = startDiskWriteWatchdog({
      dir: "/anywhere",
      limitMb: 1,
      intervalMs: 50,
      sampler: () => {
        sampleCalls += 1;
        return 1;
      },
      onBreach: () => {},
    });
    vi.advanceTimersByTime(120);
    handle.stop();
    handle.stop();
    const after = sampleCalls;
    vi.advanceTimersByTime(500);
    expect(sampleCalls).toBe(after);
  });

  it("a sampler throw is treated as a null sample, not a breach", () => {
    vi.useFakeTimers();
    let breaches = 0;
    const handle = startDiskWriteWatchdog({
      dir: "/anywhere",
      limitMb: 1,
      intervalMs: 50,
      sampler: () => {
        throw new Error("transient");
      },
      onBreach: () => {
        breaches += 1;
      },
    });
    vi.advanceTimersByTime(300);
    expect(breaches).toBe(0);
    handle.stop();
  });
});

describe("probe gates + cache/override contract", () => {
  it("the probe is false off-win32", () => {
    expect(_runDiskWatchdogProbe("darwin")).toBe(false);
    expect(_runDiskWatchdogProbe("linux")).toBe(false);
  });

  it("honors + clears the test override", () => {
    _setDiskWatchdogProbeForTests(true);
    expect(probeDiskWatchdogSupport()).toBe(true);
    _setDiskWatchdogProbeForTests(false);
    expect(probeDiskWatchdogSupport()).toBe(false);
    _setDiskWatchdogProbeForTests(null);
    expect(typeof probeDiskWatchdogSupport()).toBe("boolean");
    if (!onWindows) expect(probeDiskWatchdogSupport()).toBe(false);
  });
});

// Real measure+kill proof - CI windows-2022 lane only (mirrors the Job Object
// and AppContainer suites: assert, never skip, on Windows).
describe("real win32 disk-write watchdog (CI windows-2022 lane)", () => {
  it("kills a real over-budget writer", { timeout: 120_000 }, () => {
    if (!onWindows) return;
    expect(_runDiskWatchdogProbe("win32")).toBe(true);
  });
});
