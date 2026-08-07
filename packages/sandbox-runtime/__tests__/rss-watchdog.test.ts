import { describe, it, expect, afterEach, vi } from "vitest";
import { spawn } from "node:child_process";
import {
  startRssGroupWatchdog,
  sampleProcessGroupRssKb,
  _runRssWatchdogProbe,
  probeRssWatchdogSupport,
  _setRssWatchdogProbeForTests,
  _resetRssWatchdogProbeCache,
} from "../src/rss-watchdog.js";

const isPosix = process.platform === "darwin" || process.platform === "linux";

afterEach(() => {
  _resetRssWatchdogProbeCache();
  vi.useRealTimers();
});

describe("startRssGroupWatchdog (injected sampler — deterministic)", () => {
  it("SIGKILLs (calls onBreach) once the sampled group RSS exceeds the budget", async () => {
    let breached = false;
    let sample = 10 * 1024; // 10 MiB, under budget
    const handle = startRssGroupWatchdog({
      pgid: 4242,
      limitMb: 64,
      intervalMs: 5,
      sampler: () => sample,
      onBreach: () => {
        breached = true;
      },
    });
    await new Promise((r) => setTimeout(r, 30));
    expect(breached).toBe(false);
    sample = 200 * 1024; // 200 MiB, over the 64 MiB budget
    await new Promise((r) => setTimeout(r, 40));
    expect(breached).toBe(true);
    handle.stop();
  });

  it("never breaches an under-budget process and stop() halts sampling", async () => {
    let calls = 0;
    const handle = startRssGroupWatchdog({
      pgid: 4242,
      limitMb: 64,
      intervalMs: 5,
      sampler: () => {
        calls += 1;
        return 1024; // 1 MiB
      },
      onBreach: () => {
        throw new Error("must not breach");
      },
    });
    await new Promise((r) => setTimeout(r, 30));
    handle.stop();
    const frozen = calls;
    await new Promise((r) => setTimeout(r, 20));
    expect(calls).toBe(frozen);
  });

  it("ignores a null sample (measurement unavailable) without breaching", async () => {
    const handle = startRssGroupWatchdog({
      pgid: 4242,
      limitMb: 1,
      intervalMs: 5,
      sampler: () => null,
      onBreach: () => {
        throw new Error("must not breach on null sample");
      },
    });
    await new Promise((r) => setTimeout(r, 30));
    handle.stop();
  });
});

describe("sampleProcessGroupRssKb (real ps) + probe", () => {
  it("measures a live process group's RSS as a positive number on posix", async () => {
    if (!isPosix) return;
    const child = spawn("/bin/sh", ["-c", "sleep 3"], { detached: true });
    child.on("error", () => {});
    try {
      await new Promise((r) => setTimeout(r, 250));
      const kb = sampleProcessGroupRssKb(child.pid!);
      expect(kb).not.toBeNull();
      expect(kb!).toBeGreaterThan(0);
    } finally {
      try {
        process.kill(-child.pid!, "SIGKILL");
      } catch {
        /* already gone */
      }
    }
  });

  it("real boot probe measures + kills a group on posix", () => {
    if (!isPosix) return;
    expect(_runRssWatchdogProbe()).toBe(true);
  });

  it("is false on a non-posix platform", () => {
    expect(_runRssWatchdogProbe("win32")).toBe(false);
  });

  it("caches per process and honors + clears the override", () => {
    _setRssWatchdogProbeForTests(true);
    expect(probeRssWatchdogSupport()).toBe(true);
    _setRssWatchdogProbeForTests(false);
    expect(probeRssWatchdogSupport()).toBe(false);
    _setRssWatchdogProbeForTests(null);
    expect(typeof probeRssWatchdogSupport()).toBe("boolean");
  });
});
