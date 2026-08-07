/**
 * Active OS-control boot probes (HARDENING_MASTER_PLAN_V5 / A2).
 *
 * The rlimit probe in `rlimit.ts` verifies limit INHERITANCE via a
 * set-then-readback. These probes go further: they spawn REAL processes and
 * observe destructive behavior, so a granular capability report can flip a
 * field on ONLY when the control it names actually works on this host.
 *
 *   - descendant-kill: a group SIGKILL reaps a backgrounded descendant (backs
 *     `killTree` / `wallClockKill`).
 *   - memory hard-cap (Linux): a large allocation FAILS under a tight RLIMIT_AS
 *     and succeeds under a generous one (backs `memory: "hard-address-space"`).
 *
 * Each result is cached once per process (destructive probes are not free) and
 * carries a test override, mirroring `probeRlimitSupport()`.
 */

import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  RLIMIT_SHELL_PATH,
  probeRlimitSupport,
  wrapWithRlimit,
  RLIMIT_NPROC_HEADROOM,
  type RlimitValues,
} from "./rlimit.js";

/**
 * Synchronous pause without a busy-loop, so a one-shot boot probe can let a
 * just-spawned child start / fork before it inspects or kills it. Uses
 * `Atomics.wait` on a throwaway SharedArrayBuffer (blocks the current thread
 * for `ms`, never spins the CPU).
 */
function syncSleep(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.max(0, ms));
}

/** True iff `pid` (or the process group `-pid`) still exists. */
function isAlive(pidOrGroup: number): boolean {
  try {
    process.kill(pidOrGroup, 0);
    return true;
  } catch (err) {
    // EPERM means it exists but we may not signal it — still "alive".
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

// ─── descendant-kill probe ──────────────────────────────────────────────────

/**
 * Prove that SIGKILL to a detached process GROUP reaps a backgrounded
 * descendant — the exact primitive both runners use for timeout/abort kills.
 * Fully synchronous: spawns a detached group whose leader records a
 * backgrounded `sleep`'s pid to a temp file and then `wait`s (keeping the group
 * alive), SIGKILLs the group, and verifies the descendant pid is gone.
 */
export function _runDescendantKillProbe(platform: NodeJS.Platform = process.platform): boolean {
  if (platform !== "darwin" && platform !== "linux") return false;
  let dir: string | null = null;
  let leaderPid: number | null = null;
  try {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-desckill-"));
    const pidFile = path.join(dir, "descendant.pid");
    // Single-quote the (self-generated) temp path so a space in $TMPDIR cannot
    // break the redirection; the path never contains a single quote.
    const quotedPidFile = `'${pidFile.replace(/'/g, "'\\''")}'`;
    // The leader forks `sleep`, writes its pid, then `wait`s so the group stays
    // alive for us to kill. Detached => the leader is its own group leader.
    const child = spawn(
      RLIMIT_SHELL_PATH,
      ["-c", `sleep 30 & echo $! > ${quotedPidFile}; wait`],
      { detached: true, stdio: "ignore" },
    );
    child.on("error", () => {});
    child.unref();
    leaderPid = typeof child.pid === "number" ? child.pid : null;
    if (leaderPid === null) return false;

    // Wait (bounded) for the descendant pid to be recorded.
    let descPid: number | null = null;
    for (let i = 0; i < 100 && descPid === null; i += 1) {
      syncSleep(20);
      try {
        const raw = fs.readFileSync(pidFile, "utf-8").trim();
        if (/^\d+$/.test(raw)) descPid = Number(raw);
      } catch {
        /* not written yet */
      }
    }
    if (descPid === null || descPid <= 0) return false;
    if (!isAlive(descPid)) return false;

    // Kill the whole group; the descendant must not survive.
    try {
      process.kill(-leaderPid, "SIGKILL");
    } catch {
      return false;
    }
    for (let i = 0; i < 50; i += 1) {
      syncSleep(20);
      if (!isAlive(descPid)) return true;
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

let _descKillCache: boolean | null = null;
let _descKillOverride: boolean | null = null;

export function probeDescendantKill(): boolean {
  if (_descKillOverride !== null) return _descKillOverride;
  if (_descKillCache === null) _descKillCache = _runDescendantKillProbe();
  return _descKillCache;
}

export function _setDescendantKillProbeForTests(result: boolean | null): void {
  _descKillOverride = result;
}

export function _resetDescendantKillProbeCache(): void {
  _descKillCache = null;
  _descKillOverride = null;
}

// ─── memory hard-cap probe (Linux RLIMIT_AS) ────────────────────────────────

/** rlimit values sized for the probe, minus the address-space cap. */
function probeBaseValues(vmemKb: number): RlimitValues {
  return {
    cpuSeconds: 9,
    fileSizeBlocks: 8_388_608,
    openFiles: 256,
    processes: RLIMIT_NPROC_HEADROOM + 16,
    vmemKb,
  };
}

function runAllocation(vmemKb: number, allocMib: number): "ok" | "failed" | "error" {
  const probe = probeRlimitSupport();
  if (!probe.ok || !probe.procFlag) return "error";
  // A single `dd` buffer of `allocMib` MiB: dd allocates ONE buffer of size
  // `bs`, so bs=<allocMib>M count=1 tries to map that much at once.
  const wrapped = wrapWithRlimit(
    RLIMIT_SHELL_PATH,
    ["-c", `exec dd if=/dev/zero of=/dev/null bs=${allocMib}M count=1 2>/dev/null`],
    probeBaseValues(vmemKb),
    probe.procFlag,
  );
  const res = spawnSync(wrapped.command, wrapped.args, { timeout: 8_000, stdio: "ignore" });
  if (res.error) return "error";
  return res.status === 0 && res.signal === null ? "ok" : "failed";
}

/**
 * Prove RLIMIT_AS actually bounds memory on Linux: a 256 MiB allocation MUST
 * fail under a 64 MiB address-space cap, and a 64 MiB allocation MUST succeed
 * under a 1 GiB cap (the second leg rejects a cap so tight that nothing runs,
 * which would make the first leg a false positive). macOS `ulimit` rejects
 * `-v`, so this is Linux-only and returns false elsewhere — memory there is the
 * RSS-watchdog tier, never "hard-address-space".
 */
export function _runMemoryHardCapProbe(platform: NodeJS.Platform = process.platform): boolean {
  if (platform !== "linux") return false;
  const tight = runAllocation(65_536, 256); // 256 MiB under a 64 MiB cap
  if (tight !== "failed") return false;
  const loose = runAllocation(1_048_576, 64); // 64 MiB under a 1 GiB cap
  return loose === "ok";
}

let _memHardCapCache: boolean | null = null;
let _memHardCapOverride: boolean | null = null;

export function probeMemoryHardCap(): boolean {
  if (_memHardCapOverride !== null) return _memHardCapOverride;
  if (_memHardCapCache === null) _memHardCapCache = _runMemoryHardCapProbe();
  return _memHardCapCache;
}

export function _setMemoryHardCapProbeForTests(result: boolean | null): void {
  _memHardCapOverride = result;
}

export function _resetMemoryHardCapProbeCache(): void {
  _memHardCapCache = null;
  _memHardCapOverride = null;
}
