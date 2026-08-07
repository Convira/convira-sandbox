/**
 * POSIX rlimit launcher (HARDENING_MASTER_PLAN_V5 P0-6 / A2).
 *
 * Composes a portable /bin/sh wrapper that applies resource limits via the
 * shell built-in `ulimit` and then exec's the target binary in place, so the
 * limits bind the actual tool process (and, via inheritance, its
 * descendants). The wrapper is inserted at the INNERMOST layer of each
 * platform sandbox (inside bwrap on Linux, inside sandbox-exec on macOS) by
 * the native adapters.
 *
 * Enforced limits:
 *   -t  RLIMIT_CPU     (seconds; derived from the wall-clock timeout)
 *   -f  RLIMIT_FSIZE   (shell block units: 512 bytes on Linux dash,
 *                       1024 bytes on macOS bash - so the effective ceiling
 *                       is the block count times the host shell's unit)
 *   -n  RLIMIT_NOFILE  (descriptors)
 *   -u / -p  RLIMIT_NPROC (bash spells it -u, dash spells it -p; the probe
 *            discovers which one this host's /bin/sh understands)
 *   -v  RLIMIT_AS      (KiB) - Linux ONLY. macOS /bin/sh cannot reliably
 *            enforce RLIMIT_AS, so memory is enforced on Linux and
 *            best-effort-absent on macOS; we never fake it there.
 *
 * Both the hard and soft limits are set (no -S/-H flag), so the confined
 * process cannot raise them back. Each requested value is clamped to the
 * host's current hard limit inside the script; if a limit still cannot be
 * applied the `&&` chain fails BEFORE `exec`, so the tool never runs
 * unconfined (fail closed).
 *
 * A declared capability without a passing probe is false: adapters report
 * `resourceLimits: true` only while `probeRlimitSupport()` has functionally
 * proven - once per process, against the real /bin/sh - that this exact
 * wrapper applies and propagates limits on this host.
 */

import { execFileSync } from "node:child_process";
import type { SandboxSpawnConfig } from "./types.js";

/** POSIX shell used for the wrapper and the probe. Present on macOS + Linux. */
export const RLIMIT_SHELL_PATH = "/bin/sh";

/** RLIMIT_NPROC spelling: bash-style -u or dash-style -p. */
export type ProcLimitFlag = "-u" | "-p";

export interface RlimitValues {
  /**
   * RLIMIT_CPU in seconds (hard + soft). Omitted for long-lived processes
   * (e.g. STDIO MCP servers) that must not be SIGKILLed at a cumulative
   * CPU-seconds ceiling; when undefined, no `-t` limit is applied.
   */
  cpuSeconds?: number;
  /** RLIMIT_FSIZE in shell block units (512B Linux dash, 1024B macOS bash). */
  fileSizeBlocks: number;
  /** RLIMIT_NOFILE descriptor ceiling. */
  openFiles: number;
  /** RLIMIT_NPROC target, headroom included (per-uid semantics, see below). */
  processes: number;
  /** RLIMIT_AS in KiB. Omitted on macOS where -v is unenforceable. */
  vmemKb?: number;
}

export interface RlimitProbeResult {
  /** True only when the wrapper functionally applied limits on this host. */
  ok: boolean;
  /** The RLIMIT_NPROC flag this host's /bin/sh accepted; null when !ok. */
  procFlag: ProcLimitFlag | null;
}

/** CPU budget when the spawn spec carries no wall-clock timeout. */
export const DEFAULT_CPU_SECONDS = 600;
/**
 * CPU-seconds granted per wall-clock second: a legitimately multi-threaded
 * tool (LibreOffice render threads, OCR workers) burns CPU faster than wall
 * time, so a 1:1 mapping would kill it early.
 */
const CPU_SECONDS_PER_WALL_SECOND = 4;
/** Floor so sub-second timeouts still leave room for interpreter startup. */
const MIN_CPU_SECONDS = 4;
/**
 * S2-08 — ceiling for a timeout-derived CPU budget. Scaled by the same
 * headroom multiplier so a long wall-clock timeout keeps its 4x allowance
 * rather than collapsing onto the no-timeout default.
 */
export const MAX_CPU_SECONDS = DEFAULT_CPU_SECONDS * CPU_SECONDS_PER_WALL_SECOND;
/**
 * Output-size ceiling as a block count. The byte ceiling is shell-dependent
 * because the block unit is: ~4 GiB on 512-byte-block shells (Linux dash),
 * ~8 GiB on 1024-byte-block shells (macOS bash). A deliberately generous
 * bounded ceiling - document conversions run large - never unbounded.
 */
export const DEFAULT_FILE_SIZE_BLOCKS = 8_388_608;
export const DEFAULT_OPEN_FILES = 1024;
/**
 * RLIMIT_NPROC counts every process of the real uid, not just this spawn's
 * tree. On a desktop the user's other processes share the budget, so the
 * spec's per-tree `maxProcesses` cannot be applied literally - it would make
 * every fork fail immediately. The headroom keeps legitimate spawns working
 * while still stopping a fork bomb (which needs thousands of processes) well
 * before it exhausts the host.
 */
export const RLIMIT_NPROC_HEADROOM = 1024;

const PROBE_TIMEOUT_MS = 5_000;
const PROBE_PROC_LIMIT = RLIMIT_NPROC_HEADROOM + 16;

/**
 * Shell function applying one limit, clamped to the host's current hard
 * ceiling: `l <flag> <value>`. Lowering (or matching) the hard limit always
 * succeeds for an unprivileged process, so clamping is what keeps the
 * fail-closed `&&` chain from refusing spawns on hosts whose hard limits sit
 * below our defaults. An empty/`unlimited` hard readback keeps the requested
 * value. Runs only Node-validated integers and fixed flags - never user data.
 */
const CLAMP_HELPER =
  'l() { v=$2; h=$(ulimit -H "$1" 2>/dev/null); ' +
  'case "$h" in ""|unlimited) ;; *) if [ "$h" -lt "$v" ]; then v="$h"; fi ;; esac; ' +
  'ulimit "$1" "$v"; };';

function assertLimitValue(flag: string, value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`[sandbox-runtime] invalid rlimit value for ${flag}: ${value}`);
  }
}

/**
 * Derive concrete wrapper values from the spawn spec's resource block.
 * `enforceMemory` is a per-adapter constant (Linux true, macOS false), not a
 * runtime toggle.
 */
export function rlimitValuesFromResources(
  resources: SandboxSpawnConfig["resources"],
  opts: { enforceMemory: boolean },
): RlimitValues {
  const timeoutMs = resources.timeoutMs;
  // S2-08 — the ceiling used to be DEFAULT_CPU_SECONDS, the value for a spawn
  // with NO timeout at all. Because CPU_SECONDS_PER_WALL_SECOND is 4, every
  // timeout above 150 s collapsed onto that same 600 s cap, silently throwing
  // away the documented 4x headroom: a 10-minute tool got 600 CPU-seconds
  // instead of 2400, so a legitimately parallel or CPU-dense job was SIGKILLed
  // by RLIMIT_CPU well before its wall-clock deadline — and RLIMIT_CPU death
  // looks like a crash, not a timeout. Clamp against the headroom-scaled
  // maximum instead; the wall-clock kill still bounds the run.
  const cpuSeconds =
    typeof timeoutMs === "number" && timeoutMs > 0
      ? Math.min(
          MAX_CPU_SECONDS,
          Math.max(MIN_CPU_SECONDS, Math.ceil(timeoutMs / 1000) * CPU_SECONDS_PER_WALL_SECOND),
        )
      : DEFAULT_CPU_SECONDS;
  const maxProcesses = Math.max(1, Math.floor(resources.maxProcesses));
  const memoryMb = Math.floor(resources.memoryMb);
  return {
    // Long-lived servers get NO CPU-seconds cap so the kernel never kills them
    // after DEFAULT_CPU_SECONDS of cumulative CPU; every other rlimit still binds.
    ...(resources.longLived ? {} : { cpuSeconds }),
    fileSizeBlocks: DEFAULT_FILE_SIZE_BLOCKS,
    openFiles: DEFAULT_OPEN_FILES,
    processes: RLIMIT_NPROC_HEADROOM + maxProcesses,
    ...(opts.enforceMemory && memoryMb > 0 ? { vmemKb: memoryMb * 1024 } : {}),
  };
}

/**
 * Render the `-c` script: apply every limit (clamped, hard + soft), then
 * `exec "$0" "$@"` so the target replaces the shell with limits already
 * bound. RLIMIT_NPROC goes LAST: the clamp helper's `$(ulimit -H ...)`
 * readbacks fork subshells, and every fork must happen before the process
 * budget tightens.
 */
export function buildRlimitScript(values: RlimitValues, procFlag: ProcLimitFlag): string {
  const entries: Array<[string, number]> = [
    ["-f", values.fileSizeBlocks],
    ["-n", values.openFiles],
  ];
  if (values.cpuSeconds !== undefined) {
    // -t goes first when present; omitted entirely for long-lived processes.
    entries.unshift(["-t", values.cpuSeconds]);
  }
  if (values.vmemKb !== undefined) {
    entries.push(["-v", values.vmemKb]);
  }
  entries.push([procFlag, values.processes]);
  for (const [flag, value] of entries) {
    assertLimitValue(flag, value);
  }
  const sets = entries.map(([flag, value]) => `l ${flag} ${value}`).join(" && ");
  return `${CLAMP_HELPER} ${sets} && exec "$0" "$@"`;
}

/**
 * Wrap `command args...` in the rlimit shell. The command and every user arg
 * are delivered as positional parameters (`"$0" "$@"`), NEVER interpolated
 * into the `-c` script, so the shell cannot expand, split, or execute any of
 * their bytes.
 */
export function wrapWithRlimit(
  command: string,
  args: readonly string[],
  values: RlimitValues,
  procFlag: ProcLimitFlag,
  shellPath: string = RLIMIT_SHELL_PATH,
): { command: string; args: string[] } {
  return {
    command: shellPath,
    args: ["-c", buildRlimitScript(values, procFlag), command, ...args],
  };
}

function runProbeShell(command: string, args: string[]): string | null {
  try {
    return execFileSync(command, args, {
      timeout: PROBE_TIMEOUT_MS,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch {
    return null;
  }
}

/**
 * Discover which RLIMIT_NPROC spelling this shell accepts by actually
 * setting it (clamped to the hard ceiling) and reading it back. A read-only
 * check is not enough: bash's `-p` READS fine (pipe size) but cannot be set,
 * so only a successful set-then-readback qualifies. The readback runs
 * builtins only - no fork happens after the process budget tightens.
 */
function discoverProcFlag(shellPath: string): ProcLimitFlag | null {
  for (const flag of ["-u", "-p"] as const) {
    const script =
      `h=$(ulimit -H ${flag} 2>/dev/null); v=${PROBE_PROC_LIMIT}; ` +
      'case "$h" in ""|unlimited) ;; *) if [ "$h" -lt "$v" ]; then v="$h"; fi ;; esac; ' +
      `ulimit ${flag} "$v" && ulimit ${flag}`;
    const out = runProbeShell(shellPath, ["-c", script]);
    if (out !== null && /^\d+$/.test(out) && Number(out) > 0 && Number(out) <= PROBE_PROC_LIMIT) {
      return flag;
    }
  }
  return null;
}

/**
 * Functional probe: build the REAL wrapper with known small limits and exec
 * a readback shell through it, verifying the exec'd child inherited exactly
 * those values. Exported uncached for tests; product code goes through the
 * cached `probeRlimitSupport()`.
 */
export function _runRlimitProbe(
  shellPath: string = RLIMIT_SHELL_PATH,
  platform: NodeJS.Platform = process.platform,
): RlimitProbeResult {
  const procFlag = discoverProcFlag(shellPath);
  if (!procFlag) {
    return { ok: false, procFlag: null };
  }
  const enforceMemory = platform === "linux";
  const values: RlimitValues = {
    cpuSeconds: 9,
    fileSizeBlocks: 8,
    openFiles: 256,
    processes: PROBE_PROC_LIMIT,
    ...(enforceMemory ? { vmemKb: 1_048_576 } : {}),
  };
  const readback = "ulimit -t && ulimit -f && ulimit -n" + (enforceMemory ? " && ulimit -v" : "");
  const wrapped = wrapWithRlimit(shellPath, ["-c", readback], values, procFlag, shellPath);
  const out = runProbeShell(wrapped.command, wrapped.args);
  if (out === null) {
    return { ok: false, procFlag: null };
  }
  const expected = ["9", "8", "256", ...(enforceMemory ? ["1048576"] : [])].join("\n");
  const normalized = out
    .split(/\r?\n/)
    .map((line) => line.trim())
    .join("\n");
  return normalized === expected ? { ok: true, procFlag } : { ok: false, procFlag: null };
}

let _probeCache: RlimitProbeResult | null = null;
let _probeOverride: RlimitProbeResult | null = null;

/**
 * Cached-per-process probe result. Adapters consult this BOTH for their
 * capability report and for whether wrapSpawn applies the wrapper, so a
 * reported `resourceLimits: true` always corresponds to a wrapped spawn.
 */
export function probeRlimitSupport(): RlimitProbeResult {
  if (_probeOverride !== null) {
    return _probeOverride;
  }
  if (_probeCache === null) {
    _probeCache = _runRlimitProbe();
  }
  return _probeCache;
}

/** Pin the probe result (tests only). Pass null to restore real probing. */
export function _setRlimitProbeForTests(result: RlimitProbeResult | null): void {
  _probeOverride = result;
}

/** Reset cached state (for tests). Mirrors `_resetLinuxAdapterCache`. */
export function _resetRlimitProbeCache(): void {
  _probeCache = null;
  _probeOverride = null;
}
