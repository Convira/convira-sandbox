/**
 * Workspace disk-write watchdog (HARDENING batch 5 / Windows AppContainer
 * increment).
 *
 * Windows has no RLIMIT_FSIZE analog: neither Job Objects nor AppContainer
 * offer an output-file-size ceiling, which is why the legacy `resourceLimits`
 * tri-boolean is pinned false there. This watchdog is the honest best-effort
 * substitute - the exact pattern of the macOS RSS memory watchdog
 * (`rss-watchdog.ts`): it periodically sums the byte size of the granted
 * workspace directory and terminates the spawn's tree once the total exceeds
 * the budget. It is NOT a kernel cap - a fast writer can overshoot by up to
 * one sampling interval before the kill lands - so the capability report
 * advertises `fileSize` on Windows only while this watchdog's own
 * measure+kill probe passes, and consumers see it as a best-effort tier.
 *
 * The desktop runner starts one watchdog per Windows spawn when the adapter's
 * granular report says `fileSize` is enforced by this tier; macOS/Linux use
 * the kernel `ulimit -f` cap and never attach one.
 */

import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { probePayloadArgv, resolveProbePayloadHost } from "./probe-payload.js";

/** Sums a directory's recursive file bytes, or null when it cannot be read. */
export type DirectoryBytesSampler = (dir: string) => number | null;

export interface DiskWriteWatchdogHandle {
  /** Stop sampling. Idempotent. */
  stop(): void;
}

export interface StartDiskWriteWatchdogOptions {
  /** Granted (writable) directory whose recursive byte size is budgeted. */
  dir: string;
  /** Write budget in MiB. A summed size above this triggers onBreach. */
  limitMb: number;
  /** Called once, when the directory exceeds the budget. Sampling then stops. */
  onBreach: () => void;
  /** Sampling interval in ms (default 500). */
  intervalMs?: number;
  /** Injectable sampler (tests). Defaults to {@link sampleDirectoryBytes}. */
  sampler?: DirectoryBytesSampler;
}

/**
 * Default sampler: recursive synchronous walk summing regular-file sizes.
 * Returns null when the ROOT cannot be read (a transient failure must not be
 * treated as 0 or as over-budget); unreadable children are skipped so a file
 * deleted mid-walk cannot abort the sample.
 */
export function sampleDirectoryBytes(dir: string): number | null {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return null;
  }
  let total = 0;
  for (const entry of entries) {
    const target = path.join(dir, entry.name);
    try {
      if (entry.isDirectory()) {
        total += sampleDirectoryBytes(target) ?? 0;
      } else if (entry.isFile()) {
        total += fs.statSync(target).size;
      }
    } catch {
      /* entry vanished mid-walk - skip */
    }
  }
  return total;
}

/**
 * Start a granted-dir disk-write watchdog. Returns a handle whose `stop()`
 * halts sampling (the runner calls it on process close). The interval is
 * `unref`'d so it never keeps the event loop alive on its own.
 */
export function startDiskWriteWatchdog(
  opts: StartDiskWriteWatchdogOptions,
): DiskWriteWatchdogHandle {
  const intervalMs = opts.intervalMs ?? 500;
  const limitBytes = opts.limitMb * 1024 * 1024;
  const sampler = opts.sampler ?? sampleDirectoryBytes;
  let stopped = false;

  const timer: ReturnType<typeof setInterval> = setInterval(() => {
    if (stopped) return;
    let bytes: number | null;
    try {
      bytes = sampler(opts.dir);
    } catch {
      bytes = null;
    }
    if (bytes !== null && bytes > limitBytes) {
      stop();
      try {
        opts.onBreach();
      } catch {
        /* the runner's kill path owns errors */
      }
    }
  }, intervalMs);
  if (typeof timer.unref === "function") timer.unref();

  function stop(): void {
    if (stopped) return;
    stopped = true;
    clearInterval(timer);
  }

  return { stop };
}

// ─── boot probe ──────────────────────────────────────────────────────────────

function syncSleep(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.max(0, ms));
}

/**
 * Prove the watchdog primitive works on this host: spawn a REAL writer child
 * that appends 1 MiB chunks inside a scratch dir, watch the dir with a small
 * budget, and require the breach to fire AND the writer to be killable. This
 * backs the `fileSize` field of the WINDOWS capability report only - macOS and
 * Linux enforce file size with the kernel `ulimit -f` cap and never advertise
 * through this probe, so it returns false off win32.
 */
export function _runDiskWatchdogProbe(platform: NodeJS.Platform = process.platform): boolean {
  if (platform !== "win32") return false;
  let dir: string | null = null;
  let childPid: number | null = null;
  try {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-diskwd-probe-"));
    const host = resolveProbePayloadHost();
    if (host === null) return false;
    const marker = path.join(dir, "marker");
    const child = spawn(
      host.command,
      probePayloadArgv(host, "fill", ["--dir", dir, "--marker", marker]),
      { stdio: "ignore" },
    );
    child.on("error", () => {});
    child.unref();
    if (typeof child.pid !== "number") return false;
    childPid = child.pid;
    // Require the writer to announce itself before entering the breach loop.
    // Without this, "the child never started" and "the child is slow" are the
    // same 30s timeout, and the probe reports the same false for both.
    let started = false;
    for (let waited = 0; waited < 10_000; waited += 50) {
      try {
        if (fs.readFileSync(marker, "utf-8").trim() === "spinning") {
          started = true;
          break;
        }
      } catch {
        /* not yet */
      }
      syncSleep(50);
    }
    if (!started) return false;

    // Sample synchronously (the watchdog interval itself needs a live event
    // loop, which a one-shot boot probe does not have): poll for a positive
    // over-budget measurement, then kill and verify the writer is gone -
    // exactly the measure+kill pair `startDiskWriteWatchdog` wires at runtime.
    const limitBytes = 4 * 1024 * 1024;
    let breached = false;
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
      const bytes = sampleDirectoryBytes(dir);
      if (bytes !== null && bytes > limitBytes) {
        breached = true;
        break;
      }
      syncSleep(50);
    }
    if (!breached) return false;
    try {
      process.kill(childPid, "SIGKILL");
    } catch {
      return false;
    }
    const killDeadline = Date.now() + 10_000;
    while (Date.now() < killDeadline) {
      try {
        process.kill(childPid, 0);
      } catch {
        return true;
      }
      syncSleep(20);
    }
    return false;
  } catch {
    return false;
  } finally {
    if (childPid !== null) {
      try {
        process.kill(childPid, "SIGKILL");
      } catch {
        /* already gone */
      }
    }
    if (dir) {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
    }
  }
}

let _probeCache: boolean | null = null;
let _probeOverride: boolean | null = null;

export function probeDiskWatchdogSupport(): boolean {
  if (_probeOverride !== null) return _probeOverride;
  if (_probeCache === null) _probeCache = _runDiskWatchdogProbe();
  return _probeCache;
}

export function _setDiskWatchdogProbeForTests(result: boolean | null): void {
  _probeOverride = result;
}

export function _resetDiskWatchdogProbeCache(): void {
  _probeCache = null;
  _probeOverride = null;
}
