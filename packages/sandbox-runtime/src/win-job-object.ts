/**
 * Windows Job Object controller (HARDENING_MASTER_PLAN_V5 / A2 increment 2).
 *
 * Loads the optional `native/build/Release/win_job_object.node` addon (raw
 * N-API, compiled by `scripts/build-win-job-object-native.mjs` on win32 only)
 * and proves each Job Object control with its own destructive probe, in the
 * exact style of `probes.ts`: spawn REAL processes, observe enforcement, cache
 * once per process, carry a test override. A control without a passing probe
 * is reported false - a loaded binary proves compilation, not enforcement.
 *
 * Controls and their Win32 primitives:
 *   - killTree / wallClockKill — TerminateJobObject +
 *     JOB_OBJECT_EXTENDED_LIMIT_KILL_ON_JOB_CLOSE (reaps every member).
 *   - memory — JOB_OBJECT_LIMIT_PROCESS_MEMORY (+ JOB_MEMORY aggregate): a
 *     hard kernel commit-charge cap, the Windows analog of RLIMIT_AS.
 *   - pids — JOB_OBJECT_LIMIT_ACTIVE_PROCESS. Unlike RLIMIT_NPROC (per-uid),
 *     this counts ONLY processes in the job, so no headroom is needed.
 *   - cpu — JOB_OBJECT_LIMIT_JOB_TIME / PerJobUserTimeLimit: a cumulative
 *     user-CPU ceiling, the honest RLIMIT_CPU analog (a percent rate cap is
 *     not a budget and is deliberately NOT used for this claim).
 *
 * There is NO Windows primitive for an output-file-size ceiling (no
 * RLIMIT_FSIZE analog), so `fileSize` is never advertised from a Job Object
 * control; the honest Windows substitute is the sampled granted-dir
 * disk-write watchdog (`disk-watchdog.ts`, best-effort tier).
 *
 * HONEST LIMITATION of THIS module's post-spawn assignment: Node cannot spawn
 * CREATE_SUSPENDED, so a pid joins its job just after spawn; a hostile child
 * could fork in that microsecond window and the pre-assignment fork would
 * escape kill-on-close. Production Windows spawns therefore go through the
 * AppContainer launcher (`win-appcontainer.ts` / convira_sbx_launch.exe),
 * which creates the child suspended, assigns it to its kill-on-close job, and
 * only then resumes - race-free from the first instruction, proven by the
 * spawn-caging probe. The post-spawn hook here remains the outer backstop on
 * the launcher process itself (trusted code, not the hostile child).
 */

import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import { createRequire } from "node:module";
import * as os from "node:os";
import * as path from "node:path";

import {
  probePayloadArgv,
  probeSelftestHandshake,
  resolveProbePayloadHost,
  type ProbeVerb,
} from "./probe-payload.js";

export interface WinJobObjectLimits {
  /** JOB_OBJECT_LIMIT_PROCESS_MEMORY (+ JOB_MEMORY aggregate), in MiB. */
  memoryLimitMb?: number;
  /** JOB_OBJECT_LIMIT_ACTIVE_PROCESS ceiling (the assigned process counts). */
  maxProcesses?: number;
  /** PerJobUserTimeLimit, cumulative user-CPU milliseconds. */
  cpuTimeMs?: number;
  /** JOB_OBJECT_EXTENDED_LIMIT_KILL_ON_JOB_CLOSE. */
  killOnClose: boolean;
}

export interface WinJobObjectInfo {
  abiVersion: number;
  platform: string;
  primitives: {
    processMemory: boolean;
    jobMemory: boolean;
    activeProcess: boolean;
    jobUserTime: boolean;
    killOnClose: boolean;
    cpuRateControl: boolean;
    // ABI 2+ (AppContainer extension, `win-appcontainer.ts`). Absent on an
    // ABI 1 binary; runtime-detected, never assumed from compilation.
    appContainer?: boolean;
    securityCapabilitiesSpawn?: boolean;
    directorySidAcl?: boolean;
    networkCapabilitySids?: boolean;
  };
}

export interface WinJobObjectBindings {
  getInfo(): WinJobObjectInfo;
  createJob(limits: WinJobObjectLimits): number;
  assignProcess(jobId: number, pid: number): void;
  terminateJob(jobId: number, exitCode: number): void;
  closeJob(jobId: number): void;
}

// ─── addon loading ──────────────────────────────────────────────────────────

const requireAddon = createRequire(import.meta.url);

let _bindingsCache: WinJobObjectBindings | null | undefined;
let _bindingsOverride: WinJobObjectBindings | null | undefined;

/**
 * Load the Job Object addon. Null on every non-win32 platform (the addon is
 * never compiled there) and on win32 when the binary is missing or broken.
 * The path resolves to the package-root `native/` from both `src/` and
 * `dist/`, mirroring runtime-core's safe_workspace_fs layout.
 */
export function loadWinJobObjectBindings(
  platform: NodeJS.Platform = process.platform,
): WinJobObjectBindings | null {
  // Override first so off-win32 tests can exercise the win32 code paths;
  // a REAL load still requires win32.
  if (_bindingsOverride !== undefined) return _bindingsOverride;
  if (platform !== "win32") return null;
  if (_bindingsCache !== undefined) return _bindingsCache;
  try {
    _bindingsCache = requireAddon(
      "../native/build/Release/win_job_object.node",
    ) as WinJobObjectBindings;
  } catch {
    _bindingsCache = null;
  }
  return _bindingsCache;
}

/** Pin the bindings (tests only). Null simulates an absent addon. */
export function _setWinJobObjectBindingsForTests(bindings: WinJobObjectBindings | null): void {
  _bindingsOverride = bindings;
}

/** Clear the bindings cache and override (tests only). */
export function _resetWinJobObjectBindingsCache(): void {
  _bindingsCache = undefined;
  _bindingsOverride = undefined;
}

// ─── shared probe helpers ───────────────────────────────────────────────────

/**
 * Synchronous pause without a busy-loop (Atomics.wait on a throwaway
 * SharedArrayBuffer), mirroring `probes.ts` — one-shot boot probes stay fully
 * synchronous so their result can gate a capability report at first read.
 */
function syncSleep(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.max(0, ms));
}

/** True iff `pid` still exists (EPERM means alive but not signalable). */
function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
  if (process.platform === "win32") return true;
  // POSIX only (the fake-bindings test harness): a dead-but-unreaped DIRECT
  // child (zombie) still accepts signal 0, and the probe's blocked event loop
  // cannot reap it mid-poll, so ask ps for its state. On win32 libuv reports
  // exited processes dead through kill(0), making this branch unnecessary.
  const res = spawnSync("ps", ["-o", "state=", "-p", String(pid)], {
    encoding: "utf-8",
    timeout: 5_000,
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (res.error || res.status !== 0) return false;
  return !res.stdout.trim().toUpperCase().startsWith("Z");
}

function killBestEffort(pid: number | null): void {
  if (pid === null || pid <= 0) return;
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    /* already reaped */
  }
}

/** Poll until `condition` or `timeoutMs` elapses; true iff it became true. */
function pollUntil(condition: () => boolean, timeoutMs: number, stepMs = 20): boolean {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (condition()) return true;
    if (Date.now() >= deadline) return false;
    syncSleep(stepMs);
  }
}

function readFileTrimmed(file: string): string | null {
  try {
    return fs.readFileSync(file, "utf-8").trim();
  } catch {
    return null;
  }
}

interface SpawnedProbeChild {
  pid: number;
  jobId: number;
}

/**
 * Create a job, spawn `node -e script args...`, and assign the fresh pid to
 * the job. Assignment happens synchronously right after spawn() returns —
 * before the child's JS starts under any realistic scheduler (see the header
 * for the honest pre-assignment window). Returns null when anything fails;
 * a created job is closed on failure.
 */
function spawnIntoJob(
  bindings: WinJobObjectBindings,
  limits: WinJobObjectLimits,
  verb: ProbeVerb,
  verbArgs: string[],
): SpawnedProbeChild | null {
  const host = resolveProbePayloadHost();
  if (host === null) return null;
  let jobId: number | null = null;
  try {
    jobId = bindings.createJob(limits);
    const child = spawn(host.command, probePayloadArgv(host, verb, verbArgs), {
      stdio: "ignore",
    });
    child.on("error", () => {});
    child.unref();
    if (typeof child.pid !== "number") {
      bindings.closeJob(jobId);
      return null;
    }
    try {
      bindings.assignProcess(jobId, child.pid);
    } catch {
      killBestEffort(child.pid);
      bindings.closeJob(jobId);
      return null;
    }
    return { pid: child.pid, jobId };
  } catch {
    if (jobId !== null) {
      try {
        bindings.closeJob(jobId);
      } catch {
        /* best-effort */
      }
    }
    return null;
  }
}

function closeJobBestEffort(bindings: WinJobObjectBindings, jobId: number): void {
  try {
    bindings.closeJob(jobId);
  } catch {
    /* best-effort */
  }
}

// ─── kill-tree probe (TerminateJobObject reaps descendants) ────────────────

/**
 * Which stage of the kill-tree probe decided its verdict. The probe is a
 * boolean, and on Windows that boolean alone gates the whole deny-default
 * sandbox - so a false collapses "the addon is missing", "this host will not
 * let us assign a job", "the child never ran", and "Terminate did not reap"
 * into one indistinguishable refusal. Every value is a STATIC classification:
 * no paths, no pids, no argv.
 */
export type JobKillTreeProbeStage =
  | "not-run"
  | "ok"
  | "addon-absent"
  | "selftest-host-unavailable"
  | "job-create-or-assign-failed"
  | "probe-child-never-reported"
  | "probe-tree-died-before-terminate"
  | "terminate-job-threw"
  | "descendants-survived-terminate"
  | "probe-threw";

let _killTreeStage: JobKillTreeProbeStage = "not-run";

/** The stage that decided the last kill-tree probe run. */
export function jobKillTreeProbeStage(): JobKillTreeProbeStage {
  return _killTreeStage;
}

/**
 * Prove TerminateJobObject reaps a REAL child and its grandchild. The child
 * spawns a long-lived grandchild (which inherits job membership because it is
 * created after assignment), records its pid, and stays alive; the probe then
 * terminates the job and requires BOTH pids gone. Backs `killTree` AND
 * `wallClockKill` — a deadline kill calls exactly this terminate.
 */
export function _runJobKillTreeProbe(platform: NodeJS.Platform = process.platform): boolean {
  if (platform !== "win32") return false;
  const bindings = loadWinJobObjectBindings(platform);
  if (bindings === null) {
    _killTreeStage = "addon-absent";
    return false;
  }
  if (!probeSelftestHandshake()) {
    _killTreeStage = "selftest-host-unavailable";
    return false;
  }
  let dir: string | null = null;
  let child: SpawnedProbeChild | null = null;
  let grandchildPid: number | null = null;
  try {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-winjob-kill-"));
    const pidFile = path.join(dir, "grandchild.pid");
    // The gate file closes the pre-assignment window. `spawnIntoJob` assigns
    // AFTER spawn (Node cannot spawn CREATE_SUSPENDED), so a payload fast
    // enough to fork before the assign returns would produce a grandchild
    // outside the job - and the probe would report kill-tree false for a
    // control that works. The child waits for this file; we create it only
    // once the assignment has returned.
    const gate = path.join(dir, "assigned");
    child = spawnIntoJob(bindings, { killOnClose: true }, "spawn-child", [
      "--pid-file",
      pidFile,
      "--wait-for",
      gate,
    ]);
    if (child === null) {
      _killTreeStage = "job-create-or-assign-failed";
      return false;
    }
    fs.writeFileSync(gate, "go");

    const sawPid = pollUntil(() => {
      const raw = readFileTrimmed(pidFile);
      if (raw !== null && /^\d+$/.test(raw)) {
        grandchildPid = Number(raw);
        return true;
      }
      return false;
    }, 10_000);
    // The probe child never reported. Either it could not start, or it started
    // as something other than Node - which is exactly what a packaged Electron
    // `process.execPath` does when it is not told to run as Node.
    if (!sawPid || grandchildPid === null || grandchildPid <= 0) {
      _killTreeStage = "probe-child-never-reported";
      return false;
    }
    const gPid: number = grandchildPid;
    if (!isAlive(child.pid) || !isAlive(gPid)) {
      _killTreeStage = "probe-tree-died-before-terminate";
      return false;
    }

    try {
      bindings.terminateJob(child.jobId, 1);
    } catch {
      _killTreeStage = "terminate-job-threw";
      return false;
    }
    const childPid = child.pid;
    const reaped = pollUntil(() => !isAlive(childPid) && !isAlive(gPid), 10_000);
    _killTreeStage = reaped ? "ok" : "descendants-survived-terminate";
    return reaped;
  } catch {
    _killTreeStage = "probe-threw";
    return false;
  } finally {
    if (child !== null) {
      closeJobBestEffort(bindings, child.jobId);
      killBestEffort(child.pid);
    }
    killBestEffort(grandchildPid);
    if (dir) {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
    }
  }
}

let _killTreeCache: boolean | null = null;
let _killTreeOverride: boolean | null = null;

export function probeJobKillTree(): boolean {
  if (_killTreeOverride !== null) return _killTreeOverride;
  if (_killTreeCache === null) _killTreeCache = _runJobKillTreeProbe();
  return _killTreeCache;
}

export function _setJobKillTreeProbeForTests(result: boolean | null): void {
  _killTreeOverride = result;
}

export function _resetJobKillTreeProbeCache(): void {
  _killTreeCache = null;
  _killTreeOverride = null;
  _killTreeStage = "not-run";
}

// ─── memory probe (JOB_OBJECT_LIMIT_PROCESS_MEMORY) ─────────────────────────

/**
 * Run one allocation leg: a child that allocates `allocMib` and writes "ok"
 * only on success, inside a job capped at `memoryLimitMb`. Returns what the
 * cap did to the allocation.
 */
function runJobAllocation(
  bindings: WinJobObjectBindings,
  memoryLimitMb: number,
  allocMib: number,
): "ok" | "failed" | "error" {
  let dir: string | null = null;
  let child: SpawnedProbeChild | null = null;
  try {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-winjob-mem-"));
    const resultFile = path.join(dir, "result");
    child = spawnIntoJob(bindings, { memoryLimitMb, killOnClose: true }, "alloc", [
      "--mib",
      String(allocMib),
      "--out",
      resultFile,
    ]);
    if (child === null) return "error";
    const childPid = child.pid;
    // The child either writes its outcome or dies at the cap (commit denied
    // can abort the process before the catch runs — that still counts as the
    // cap enforcing).
    const settled = pollUntil(
      () => readFileTrimmed(resultFile) !== null || !isAlive(childPid),
      30_000,
    );
    if (!settled) return "error";
    // A just-dead child may have written the file moments before dying.
    syncSleep(50);
    return readFileTrimmed(resultFile) === "ok" ? "ok" : "failed";
  } catch {
    return "error";
  } finally {
    if (child !== null) {
      closeJobBestEffort(bindings, child.jobId);
      killBestEffort(child.pid);
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

/**
 * Prove JOB_OBJECT_LIMIT_PROCESS_MEMORY actually bounds committed memory:
 * a 256 MiB allocation MUST fail under a 64 MiB cap, and a 64 MiB allocation
 * MUST succeed under a 1 GiB cap (the loose leg rejects a cap so tight that
 * nothing runs, which would make the tight leg a false positive) — the same
 * two-leg design as `_runMemoryHardCapProbe`. Backs `memory:
 * "hard-address-space"` on Windows.
 */
export function _runJobMemoryProbe(platform: NodeJS.Platform = process.platform): boolean {
  if (platform !== "win32") return false;
  const bindings = loadWinJobObjectBindings(platform);
  if (bindings === null) return false;
  if (!probeSelftestHandshake()) return false;
  // LOOSE LEG FIRST, and it is not merely an ordering preference. The tight
  // leg settles on "the child died or wrote something other than ok", which a
  // payload that never ran satisfies for free - so with the tight leg first, a
  // completely dead probe subject scored half a pass. Requiring the loose leg
  // to come back "ok" first means every later verdict is spoken by a child we
  // have watched succeed.
  const loose = runJobAllocation(bindings, 1024, 64);
  if (loose !== "ok") return false;
  const tight = runJobAllocation(bindings, 64, 256);
  return tight === "failed";
}

let _memoryCache: boolean | null = null;
let _memoryOverride: boolean | null = null;

export function probeJobMemory(): boolean {
  if (_memoryOverride !== null) return _memoryOverride;
  if (_memoryCache === null) _memoryCache = _runJobMemoryProbe();
  return _memoryCache;
}

export function _setJobMemoryProbeForTests(result: boolean | null): void {
  _memoryOverride = result;
}

export function _resetJobMemoryProbeCache(): void {
  _memoryCache = null;
  _memoryOverride = null;
}

// ─── pids probe (JOB_OBJECT_LIMIT_ACTIVE_PROCESS) ───────────────────────────

/**
 * Run one `try-spawn` leg and report what the child said about its own spawn
 * attempt. Identical argv in both legs; only `maxProcesses` differs.
 */
function runJobSpawnAttempt(
  bindings: WinJobObjectBindings,
  maxProcesses: number,
): "spawned" | "denied" | "error" {
  let dir: string | null = null;
  let child: SpawnedProbeChild | null = null;
  try {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-winjob-pids-"));
    const resultFile = path.join(dir, "result");
    child = spawnIntoJob(bindings, { maxProcesses, killOnClose: true }, "try-spawn", [
      "--out",
      resultFile,
    ]);
    if (child === null) return "error";
    if (!pollUntil(() => readFileTrimmed(resultFile) !== null, 30_000)) return "error";
    const verdict = readFileTrimmed(resultFile);
    return verdict === "spawned" ? "spawned" : verdict === "denied" ? "denied" : "error";
  } catch {
    return "error";
  } finally {
    if (child !== null) {
      closeJobBestEffort(bindings, child.jobId);
      killBestEffort(child.pid);
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

/**
 * Prove ActiveProcessLimit actually denies a descendant spawn, in two legs.
 *
 * The single-leg version this replaces asked only "did the capped child report
 * denied?" - and the child writes "denied" whenever its spawn fails FOR ANY
 * REASON: antivirus, a bad self path, a transient failure. Any of those forged
 * proof of a process-count limit that was never applied, and
 * `granularResourceLimitsSatisfied()` then admits a profile requiring resource
 * limits onto a host that does not enforce them.
 *
 * The control leg (a generous cap, identical argv) must come back "spawned",
 * so the claim leg's "denied" can only mean the limit acted.
 */
export function _runJobPidsProbe(platform: NodeJS.Platform = process.platform): boolean {
  if (platform !== "win32") return false;
  const bindings = loadWinJobObjectBindings(platform);
  if (bindings === null) return false;
  if (!probeSelftestHandshake()) return false;
  if (runJobSpawnAttempt(bindings, 4) !== "spawned") return false;
  return runJobSpawnAttempt(bindings, 1) === "denied";
}

let _pidsCache: boolean | null = null;
let _pidsOverride: boolean | null = null;

export function probeJobPids(): boolean {
  if (_pidsOverride !== null) return _pidsOverride;
  if (_pidsCache === null) _pidsCache = _runJobPidsProbe();
  return _pidsCache;
}

export function _setJobPidsProbeForTests(result: boolean | null): void {
  _pidsOverride = result;
}

export function _resetJobPidsProbeCache(): void {
  _pidsCache = null;
  _pidsOverride = null;
}

// ─── cpu-time probe (PerJobUserTimeLimit) ───────────────────────────────────

/**
 * Run one busy-loop leg. Returns whether the spinner ever STARTED (its marker
 * landed) and whether it was still alive after a dwell / died inside the
 * deadline.
 */
function runJobCpuLeg(
  bindings: WinJobObjectBindings,
  cpuTimeMs: number | undefined,
): { started: boolean; diedFast: boolean } {
  let dir: string | null = null;
  let child: SpawnedProbeChild | null = null;
  try {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-winjob-cpu-"));
    const marker = path.join(dir, "marker");
    child = spawnIntoJob(
      bindings,
      cpuTimeMs === undefined ? { killOnClose: true } : { cpuTimeMs, killOnClose: true },
      "burn-cpu",
      ["--marker", marker],
    );
    if (child === null) return { started: false, diedFast: false };
    const childPid = child.pid;
    // The capped leg deliberately does NOT require the marker: a real
    // PerJobUserTimeLimit may reap the spinner at any point, including before
    // it publishes. Only the control leg - where nothing is supposed to kill
    // anything - has to prove the subject started.
    if (cpuTimeMs !== undefined) {
      return { started: true, diedFast: pollUntil(() => !isAlive(childPid), 10_000, 50) };
    }
    const started = pollUntil(() => readFileTrimmed(marker) === "spinning", 10_000, 50);
    if (!started) return { started: false, diedFast: false };
    // Short dwell: the control leg only needs to show the spinner OUTLIVES the
    // window in which the capped leg dies, not that it runs forever.
    return { started: true, diedFast: pollUntil(() => !isAlive(childPid), 1_500, 50) };
  } catch {
    return { started: false, diedFast: false };
  } finally {
    if (child !== null) {
      closeJobBestEffort(bindings, child.jobId);
      killBestEffort(child.pid);
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

/**
 * Prove PerJobUserTimeLimit terminates a busy-loop, in two legs. Backs `cpu`.
 *
 * The single-leg version this replaces wrote NO result file: it asked only
 * whether the child's pid vanished within 10s. Any child that exits on its own
 * satisfies that - and in a packaged build the old probe subject did exactly
 * that, quitting immediately on losing the single-instance lock. So the probe
 * would have reported a hard CPU cap that had never acted. A probe whose pass
 * condition is "the process is gone" cannot tell enforcement from a child that
 * simply left.
 *
 * The control leg runs the SAME spinner with no cap: it must start and must
 * still be running afterwards. Only then does a death under the cap mean the
 * cap killed it.
 */
export function _runJobCpuTimeProbe(platform: NodeJS.Platform = process.platform): boolean {
  if (platform !== "win32") return false;
  const bindings = loadWinJobObjectBindings(platform);
  if (bindings === null) return false;
  if (!probeSelftestHandshake()) return false;
  const control = runJobCpuLeg(bindings, undefined);
  if (!control.started || control.diedFast) return false;
  return runJobCpuLeg(bindings, 200).diedFast;
}

let _cpuTimeCache: boolean | null = null;
let _cpuTimeOverride: boolean | null = null;

export function probeJobCpuTime(): boolean {
  if (_cpuTimeOverride !== null) return _cpuTimeOverride;
  if (_cpuTimeCache === null) _cpuTimeCache = _runJobCpuTimeProbe();
  return _cpuTimeCache;
}

export function _setJobCpuTimeProbeForTests(result: boolean | null): void {
  _cpuTimeOverride = result;
}

export function _resetJobCpuTimeProbeCache(): void {
  _cpuTimeCache = null;
  _cpuTimeOverride = null;
}

// ─── aggregate report ───────────────────────────────────────────────────────

export interface WinJobObjectProbeReport {
  killTree: boolean;
  wallClockKill: boolean;
  memory: boolean;
  pids: boolean;
  cpu: boolean;
}

/** One-stop probe summary for the adapter's capability report. */
export function probeWinJobObjectReport(): WinJobObjectProbeReport {
  const killTree = probeJobKillTree();
  return {
    killTree,
    // A wall-clock deadline kill calls TerminateJobObject — the same
    // enforcement the kill-tree probe proves.
    wallClockKill: killTree,
    memory: probeJobMemory(),
    pids: probeJobPids(),
    cpu: probeJobCpuTime(),
  };
}

// ─── pid → job registry (wrapSpawn wiring surface) ──────────────────────────

const _jobsByPid = new Map<number, number>();

/**
 * Create a kill-on-close job with `limits`, assign `pid`, and register it so
 * a runner can later terminate or release the tree. Throws when the addon is
 * absent or a native call fails — the caller must treat a spawn it cannot
 * confine as a refusal, never as an unlimited process (fail closed).
 */
export function attachPidToJob(pid: number, limits: WinJobObjectLimits): void {
  const bindings = loadWinJobObjectBindings();
  if (bindings === null) {
    throw new Error(
      "[sandbox-runtime] Windows Job Object addon is not available; refusing to run an unconfined process",
    );
  }
  const jobId = bindings.createJob(limits);
  try {
    bindings.assignProcess(jobId, pid);
  } catch (err) {
    closeJobBestEffort(bindings, jobId);
    throw err;
  }
  _jobsByPid.set(pid, jobId);
}

/** TerminateJobObject the registered job for `pid` (kills the whole tree). */
export function terminateWinJob(pid: number, exitCode = 1): boolean {
  const bindings = loadWinJobObjectBindings();
  const jobId = _jobsByPid.get(pid);
  if (bindings === null || jobId === undefined) return false;
  _jobsByPid.delete(pid);
  try {
    bindings.terminateJob(jobId, exitCode);
  } finally {
    closeJobBestEffort(bindings, jobId);
  }
  return true;
}

/** Close the registered job for `pid`; kill-on-close reaps any survivors. */
export function releaseWinJob(pid: number): boolean {
  const bindings = loadWinJobObjectBindings();
  const jobId = _jobsByPid.get(pid);
  if (bindings === null || jobId === undefined) return false;
  _jobsByPid.delete(pid);
  closeJobBestEffort(bindings, jobId);
  return true;
}

/** Close every registered job and clear the registry (tests only). */
export function _resetWinJobRegistryForTests(): void {
  const bindings = loadWinJobObjectBindings();
  if (bindings !== null) {
    for (const jobId of _jobsByPid.values()) {
      closeJobBestEffort(bindings, jobId);
    }
  }
  _jobsByPid.clear();
}
