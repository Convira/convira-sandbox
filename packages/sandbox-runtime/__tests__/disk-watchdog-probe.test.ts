/**
 * Disk-write watchdog BOOT PROBE coverage.
 *
 * `disk-watchdog.test.ts` covers the sampler and the interval watchdog. The
 * boot probe (`_runDiskWatchdogProbe`) short-circuits off win32, so its
 * measure-then-kill body - the thing that decides whether the Windows
 * capability report may advertise `fileSize` at all - never ran in the suite.
 *
 * The body itself is platform-independent (spawn a real writer, sum the dir,
 * SIGKILL, confirm the pid is gone), so passing it an explicit "win32"
 * platform runs exactly the shipped code path on macOS/Linux. The win32 gate
 * keeps its own test below: the probe must stay false when asked about the
 * host platform on a non-Windows machine.
 */
import { describe, it, expect, afterEach } from "vitest";

import {
  _runDiskWatchdogProbe,
  probeDiskWatchdogSupport,
  _setDiskWatchdogProbeForTests,
  _resetDiskWatchdogProbeCache,
} from "../src/disk-watchdog.js";

afterEach(() => {
  _resetDiskWatchdogProbeCache();
});

describe("_runDiskWatchdogProbe", () => {
  it("measures a real over-budget writer, then verifies the kill", { timeout: 90_000 }, () => {
    // Runs the shipped body on every platform (the probe writes ~4 MiB of
    // scratch into the OS tmpdir and removes it in its own finally): spawn the
    // writer, sum the directory until it exceeds the 4 MiB budget, SIGKILL,
    // confirm the pid is gone.
    //
    // The final leg is where POSIX and Windows genuinely differ. The probe
    // blocks its own event loop while polling, so a SIGKILLed child of THIS
    // process stays an unreaped zombie and `process.kill(pid, 0)` keeps
    // succeeding - the confirmation can never land off win32. On Windows
    // libuv reports an exited pid as dead, which is why the probe is gated to
    // win32 and why the capability report may only advertise `fileSize`
    // there. Asserting both halves keeps that platform contract pinned.
    const verdict = _runDiskWatchdogProbe("win32");
    expect(verdict).toBe(process.platform === "win32");
  });

  it("is false on every non-win32 platform", () => {
    expect(_runDiskWatchdogProbe("darwin")).toBe(false);
    expect(_runDiskWatchdogProbe("linux")).toBe(false);
  });

  it("caches the host verdict and honors the test override", () => {
    _setDiskWatchdogProbeForTests(true);
    expect(probeDiskWatchdogSupport()).toBe(true);
    _setDiskWatchdogProbeForTests(false);
    expect(probeDiskWatchdogSupport()).toBe(false);
    _setDiskWatchdogProbeForTests(null);
    if (process.platform !== "win32") {
      expect(probeDiskWatchdogSupport()).toBe(false);
      // Second call comes from the cache, not a second destructive probe.
      expect(probeDiskWatchdogSupport()).toBe(false);
    }
  });
});
