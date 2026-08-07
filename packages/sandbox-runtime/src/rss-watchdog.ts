/**
 * Resident-set (RSS) process-group memory watchdog (HARDENING_MASTER_PLAN_V5 / A2).
 *
 * macOS `ulimit` cannot set RLIMIT_AS, so there is no HARD address-space cap for
 * a sandboxed tool on Darwin. This watchdog is the honest best-effort
 * substitute: it periodically sums the resident set of every process in the
 * tool's process group and SIGKILLs the group once the total exceeds the
 * budget. It is NOT a kernel cap — a very fast allocator can overshoot by up to
 * one sampling interval before the kill lands — which is exactly why the
 * capability report tags this tier `"rss-watchdog"` rather than
 * `"hard-address-space"`.
 *
 * The runner starts one watchdog per spawned group when the adapter's granular
 * report says memory is enforced by this tier (macOS). Linux uses the hard
 * RLIMIT_AS cap and needs no watchdog.
 */

import { execFileSync, spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/** Sums a process group's RSS in KiB, or null when it cannot be measured. */
export type RssGroupSampler = (pgid: number) => number | null;

export interface RssGroupWatchdogHandle {
  /** Stop sampling. Idempotent. */
  stop(): void;
}

export interface StartRssGroupWatchdogOptions {
  /** Process-group id (the detached leader's pid). */
  pgid: number;
  /** Memory budget in MiB. A summed group RSS above this triggers onBreach. */
  limitMb: number;
  /** Called once, when the group exceeds the budget. Sampling then stops. */
  onBreach: () => void;
  /** Sampling interval in ms (default 500). */
  intervalMs?: number;
  /** Injectable sampler (tests). Defaults to {@link sampleProcessGroupRssKb}. */
  sampler?: RssGroupSampler;
}

/**
 * Default sampler: `ps -axo pgid=,rss=` sums the RSS (KiB on macOS + Linux) of
 * every process whose group id matches `pgid`. Returns null when `ps` fails or
 * no member is found (a transient read must not be treated as 0 and provoke a
 * spurious kill — the watchdog only acts on a positive over-budget sample).
 */
export function sampleProcessGroupRssKb(pgid: number): number | null {
  let out: string;
  try {
    out = execFileSync("ps", ["-axo", "pgid=,rss="], {
      encoding: "utf-8",
      timeout: 4_000,
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    return null;
  }
  let total = 0;
  let matched = false;
  for (const line of out.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length < 2) continue;
    const group = Number(parts[0]);
    const rss = Number(parts[1]);
    if (group === pgid && Number.isFinite(rss)) {
      total += rss;
      matched = true;
    }
  }
  return matched ? total : null;
}

/**
 * Start a group RSS watchdog. Returns a handle whose `stop()` halts sampling
 * (the runner calls it on process close). The interval is `unref`'d so it never
 * keeps the event loop alive on its own.
 */
export function startRssGroupWatchdog(
  opts: StartRssGroupWatchdogOptions,
): RssGroupWatchdogHandle {
  const intervalMs = opts.intervalMs ?? 500;
  const limitKb = opts.limitMb * 1024;
  const sampler = opts.sampler ?? sampleProcessGroupRssKb;
  let stopped = false;

  const timer: ReturnType<typeof setInterval> = setInterval(() => {
    if (stopped) return;
    let kb: number | null;
    try {
      kb = sampler(opts.pgid);
    } catch {
      kb = null;
    }
    if (kb !== null && kb > limitKb) {
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
 * Prove the watchdog primitive works on this host: spawn a real detached group
 * (a leader that forks a `sleep` descendant and `wait`s), measure the group's
 * summed RSS as a positive number (the sampler works), then SIGKILL the group
 * and confirm the descendant is gone. macOS/Linux only.
 *
 * Kill verification targets the DESCENDANT, not the leader: the leader is
 * Node's direct child and becomes an unreaped zombie while this synchronous
 * probe blocks the event loop, whereas the descendant is reparented to init
 * and truly reaped, so its ESRCH is a reliable signal.
 */
export function _runRssWatchdogProbe(platform: NodeJS.Platform = process.platform): boolean {
  if (platform !== "darwin" && platform !== "linux") return false;
  let dir: string | null = null;
  let leaderPid: number | null = null;
  try {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-rssprobe-"));
    const pidFile = path.join(dir, "descendant.pid");
    const quotedPidFile = `'${pidFile.replace(/'/g, "'\\''")}'`;
    const child = spawn(
      "/bin/sh",
      ["-c", `sleep 30 & echo $! > ${quotedPidFile}; wait`],
      { detached: true, stdio: "ignore" },
    );
    child.on("error", () => {});
    child.unref();
    leaderPid = typeof child.pid === "number" ? child.pid : null;
    if (leaderPid === null) return false;

    // Wait for the descendant to be recorded AND for the group RSS to measure.
    let descPid: number | null = null;
    let measured = false;
    for (let i = 0; i < 100 && !(descPid !== null && measured); i += 1) {
      syncSleep(20);
      if (descPid === null) {
        try {
          const raw = fs.readFileSync(pidFile, "utf-8").trim();
          if (/^\d+$/.test(raw)) descPid = Number(raw);
        } catch {
          /* not written yet */
        }
      }
      const kb = sampleProcessGroupRssKb(leaderPid);
      if (kb !== null && kb > 0) measured = true;
    }
    if (descPid === null || descPid <= 0 || !measured) return false;

    try {
      process.kill(-leaderPid, "SIGKILL");
    } catch {
      return false;
    }
    for (let i = 0; i < 50; i += 1) {
      syncSleep(20);
      try {
        process.kill(descPid, 0);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ESRCH") return true;
      }
    }
    return false;
  } catch {
    return false;
  } finally {
    if (leaderPid !== null) {
      try {
        process.kill(-leaderPid, "SIGKILL");
      } catch {
        /* already reaped */
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

let _watchdogCache: boolean | null = null;
let _watchdogOverride: boolean | null = null;

export function probeRssWatchdogSupport(): boolean {
  if (_watchdogOverride !== null) return _watchdogOverride;
  if (_watchdogCache === null) _watchdogCache = _runRssWatchdogProbe();
  return _watchdogCache;
}

export function _setRssWatchdogProbeForTests(result: boolean | null): void {
  _watchdogOverride = result;
}

export function _resetRssWatchdogProbeCache(): void {
  _watchdogCache = null;
  _watchdogOverride = null;
}
