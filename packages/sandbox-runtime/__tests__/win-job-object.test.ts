import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

import { shimPayloadHost } from "./fixtures/selftest-host.js";
import {
  _resetProbePayloadHostCache,
  _setProbePayloadHostForTests,
} from "../src/probe-payload.js";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, it, expect, afterEach, beforeEach } from "vitest";
import {
  loadWinJobObjectBindings,
  _setWinJobObjectBindingsForTests,
  _resetWinJobObjectBindingsCache,
  _runJobKillTreeProbe,
  jobKillTreeProbeStage,
  probeJobKillTree,
  _setJobKillTreeProbeForTests,
  _resetJobKillTreeProbeCache,
  _runJobMemoryProbe,
  probeJobMemory,
  _setJobMemoryProbeForTests,
  _resetJobMemoryProbeCache,
  _runJobPidsProbe,
  probeJobPids,
  _setJobPidsProbeForTests,
  _resetJobPidsProbeCache,
  _runJobCpuTimeProbe,
  probeJobCpuTime,
  _setJobCpuTimeProbeForTests,
  _resetJobCpuTimeProbeCache,
  probeWinJobObjectReport,
  attachPidToJob,
  terminateWinJob,
  releaseWinJob,
  _resetWinJobRegistryForTests,
  type WinJobObjectBindings,
  type WinJobObjectLimits,
} from "../src/win-job-object.js";

const onWindows = process.platform === "win32";
const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

afterEach(() => {
  _resetProbePayloadHostCache();
  _resetWinJobRegistryForTests();
  _resetWinJobObjectBindingsCache();
  _resetJobKillTreeProbeCache();
  _resetJobMemoryProbeCache();
  _resetJobPidsProbeCache();
  _resetJobCpuTimeProbeCache();
});

/**
 * Recording fake for the native bindings. `onAssign` lets a test simulate the
 * kernel-side enforcement (e.g. killing the assigned pid the way a Job Object
 * limit would) so probe decision logic is exercisable off-win32; the REAL
 * enforcement is proven by the win32 CI lane below.
 */
function makeFakeBindings(opts: {
  onAssign?: (jobId: number, pid: number, limits: WinJobObjectLimits) => void;
  onTerminate?: (jobId: number, pid: number | null) => void;
}): WinJobObjectBindings & {
  calls: Array<{ fn: string; args: unknown[] }>;
  jobs: Map<number, { limits: WinJobObjectLimits; pid: number | null }>;
} {
  let nextId = 1;
  const jobs = new Map<number, { limits: WinJobObjectLimits; pid: number | null }>();
  const calls: Array<{ fn: string; args: unknown[] }> = [];
  return {
    calls,
    jobs,
    getInfo() {
      calls.push({ fn: "getInfo", args: [] });
      return {
        abiVersion: 1,
        platform: "win32",
        primitives: {
          processMemory: true,
          jobMemory: true,
          activeProcess: true,
          jobUserTime: true,
          killOnClose: true,
          cpuRateControl: true,
        },
      };
    },
    createJob(limits) {
      calls.push({ fn: "createJob", args: [limits] });
      const id = nextId;
      nextId += 1;
      jobs.set(id, { limits, pid: null });
      return id;
    },
    assignProcess(jobId, pid) {
      calls.push({ fn: "assignProcess", args: [jobId, pid] });
      const job = jobs.get(jobId);
      if (!job) throw new Error(`unknown job ${jobId}`);
      job.pid = pid;
      opts.onAssign?.(jobId, pid, job.limits);
    },
    terminateJob(jobId, exitCode) {
      calls.push({ fn: "terminateJob", args: [jobId, exitCode] });
      const job = jobs.get(jobId);
      if (!job) throw new Error(`unknown job ${jobId}`);
      opts.onTerminate?.(jobId, job.pid);
    },
    closeJob(jobId) {
      calls.push({ fn: "closeJob", args: [jobId] });
      jobs.delete(jobId);
    },
  };
}

function killIfAlive(pid: number): void {
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    /* already gone */
  }
}

/**
 * Mirrors the probe's own liveness rule, zombie branch included. EPERM means
 * alive but not signalable; and on POSIX a killed DIRECT child stays a zombie
 * that still accepts signal 0 until reaped - which the blocking poll below
 * cannot do, because reaping needs the event loop it is holding. Asking `ps`
 * for the state is how win-job-object's own isAlive settles it, and skipping
 * that here made this control leg wait out its full budget on a process that
 * had already died.
 */
function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
  if (process.platform === "win32") return true;
  const res = spawnSync("ps", ["-o", "state=", "-p", String(pid)], {
    encoding: "utf-8",
    timeout: 5_000,
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (res.error || res.status !== 0) return false;
  return !res.stdout.trim().toUpperCase().startsWith("Z");
}

/** Blocking poll - the probe under test is synchronous, so this must be too. */
function blockUntil(done: () => boolean, budgetMs: number): boolean {
  const idle = new Int32Array(new SharedArrayBuffer(4));
  const deadline = Date.now() + budgetMs;
  for (;;) {
    if (done()) return true;
    if (Date.now() >= deadline) return false;
    Atomics.wait(idle, 0, 0, 20);
  }
}

/**
 * Can a shim grandchild outlive its parent on THIS platform?
 *
 * The refusal test below simulates "terminateJob reaped only the direct
 * child", which is constructible only if the grandchild survives that. Where
 * it does not, the probe is handed a tree that reaps itself, correctly
 * observes nothing left alive, and returns true - and reporting that as "the
 * probe trusted terminateJob" blames the subject for the harness's own
 * failure to pose the question. That is not hypothetical: it is what the
 * bare `expected true to be false` on windows-2022 actually meant.
 */
function grandchildOutlivesItsParent(): boolean {
  const dir = mkdtempSync(join(tmpdir(), "sbx-killtree-control-"));
  let parentPid: number | null = null;
  let grandchildPid: number | null = null;
  try {
    const pidFile = join(dir, "grandchild.pid");
    const host = shimPayloadHost();
    const parent = spawn(host.command, [...host.prefixArgs, "spawn-child", "--pid-file", pidFile], {
      stdio: "ignore",
    });
    parent.unref();
    parentPid = parent.pid ?? null;
    if (parentPid === null) return false;

    const readPid = (): number | null => {
      try {
        const raw = readFileSync(pidFile, "utf-8").trim();
        return /^\d+$/.test(raw) ? Number(raw) : null;
      } catch {
        return null;
      }
    };
    if (!blockUntil(() => readPid() !== null, 10_000)) return false;
    grandchildPid = readPid();
    if (grandchildPid === null || !pidAlive(grandchildPid)) return false;

    killIfAlive(parentPid);
    if (!blockUntil(() => !pidAlive(parentPid as number), 10_000)) return false;
    // Survives iff it is STILL alive after the same grace the probe allows.
    return !blockUntil(() => !pidAlive(grandchildPid as number), 2_000);
  } finally {
    if (grandchildPid !== null) killIfAlive(grandchildPid);
    if (parentPid !== null) killIfAlive(parentPid);
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("loadWinJobObjectBindings", () => {
  it("is null on every non-win32 platform", () => {
    expect(loadWinJobObjectBindings("darwin")).toBeNull();
    expect(loadWinJobObjectBindings("linux")).toBeNull();
  });

  it("honors and clears the test override", () => {
    const fake = makeFakeBindings({});
    _setWinJobObjectBindingsForTests(fake);
    expect(loadWinJobObjectBindings("win32")).toBe(fake);
    _setWinJobObjectBindingsForTests(null);
    expect(loadWinJobObjectBindings("win32")).toBeNull();
    _resetWinJobObjectBindingsCache();
    // Real load path: null everywhere the addon is not built.
    if (!onWindows) expect(loadWinJobObjectBindings()).toBeNull();
  });
});

describe("probe platform + bindings gates", () => {
  it("every probe is false off-win32", () => {
    for (const platform of ["darwin", "linux"] as const) {
      expect(_runJobKillTreeProbe(platform)).toBe(false);
      expect(_runJobMemoryProbe(platform)).toBe(false);
      expect(_runJobPidsProbe(platform)).toBe(false);
      expect(_runJobCpuTimeProbe(platform)).toBe(false);
    }
  });

  it("every probe is false on win32 when the addon is absent", () => {
    _setWinJobObjectBindingsForTests(null);
    expect(_runJobKillTreeProbe("win32")).toBe(false);
    expect(_runJobMemoryProbe("win32")).toBe(false);
    expect(_runJobPidsProbe("win32")).toBe(false);
    expect(_runJobCpuTimeProbe("win32")).toBe(false);
  });
});

describe("probe cache/override contract", () => {
  it("kill-tree: caches per process and honors + clears the test override", () => {
    _setJobKillTreeProbeForTests(true);
    expect(probeJobKillTree()).toBe(true);
    _setJobKillTreeProbeForTests(false);
    expect(probeJobKillTree()).toBe(false);
    _setJobKillTreeProbeForTests(null);
    expect(typeof probeJobKillTree()).toBe("boolean");
  });

  it("memory: caches per process and honors + clears the test override", () => {
    _setJobMemoryProbeForTests(true);
    expect(probeJobMemory()).toBe(true);
    _setJobMemoryProbeForTests(false);
    expect(probeJobMemory()).toBe(false);
    _setJobMemoryProbeForTests(null);
    expect(typeof probeJobMemory()).toBe("boolean");
  });

  it("pids: caches per process and honors + clears the test override", () => {
    _setJobPidsProbeForTests(true);
    expect(probeJobPids()).toBe(true);
    _setJobPidsProbeForTests(false);
    expect(probeJobPids()).toBe(false);
    _setJobPidsProbeForTests(null);
    expect(typeof probeJobPids()).toBe("boolean");
  });

  // 30s, unlike its three siblings, because clearing the override to null runs
  // the REAL probe - and on win32 that one has to let a busy-loop burn enough
  // user time for PerJobUserTimeLimit to fire. The real probe alone measures
  // ~3.7s on the CI box against vitest's 5s default, so this timed out where
  // kill-tree (78ms), memory (233ms) and pids (93ms) had headroom to spare.
  it("cpu-time: caches per process and honors + clears the test override", { timeout: 30_000 }, () => {
    _setJobCpuTimeProbeForTests(true);
    expect(probeJobCpuTime()).toBe(true);
    _setJobCpuTimeProbeForTests(false);
    expect(probeJobCpuTime()).toBe(false);
    _setJobCpuTimeProbeForTests(null);
    expect(typeof probeJobCpuTime()).toBe("boolean");
  });

  it("aggregate report mirrors the four probes, wallClockKill = killTree", () => {
    _setJobKillTreeProbeForTests(true);
    _setJobMemoryProbeForTests(true);
    _setJobPidsProbeForTests(false);
    _setJobCpuTimeProbeForTests(false);
    expect(probeWinJobObjectReport()).toEqual({
      killTree: true,
      wallClockKill: true,
      memory: true,
      pids: false,
      cpu: false,
    });
  });
});

describe("probe decision logic (fake bindings, platform forced to win32)", () => {
  // The shipped probe subject is a C++ verb table inside the signed Windows
  // launcher. Pinning the Node shim keeps the DECISION logic exercisable on
  // every platform - without it every probe below short-circuits to false
  // off-win32 and this whole suite would pass while proving nothing.
  beforeEach(() => {
    _setProbePayloadHostForTests(shimPayloadHost());
  });

  it("kill-tree probe refuses a terminateJob that reaps only the direct child", { timeout: 30_000 }, () => {
    // Control leg first: without it a self-reaping tree makes this assertion
    // fail against a probe that did nothing wrong.
    expect(
      grandchildOutlivesItsParent(),
      "a shim grandchild did not outlive its parent here, so 'terminateJob reaped only the direct child' is not constructible on this platform - fix the harness, not the probe",
    ).toBe(true);

    const fake = makeFakeBindings({
      onTerminate(_jobId, pid) {
        // Reap only the direct child - a real Job Object would also reap the
        // grandchild. The probe must observe the surviving grandchild and
        // return false, proving it never trusts terminateJob's own success.
        if (pid !== null) killIfAlive(pid);
      },
    });
    _setWinJobObjectBindingsForTests(fake);
    expect(
      _runJobKillTreeProbe("win32"),
      `probe stage=${jobKillTreeProbeStage()}`,
    ).toBe(false);
  });

  it("kill-tree probe fails when terminateJob does nothing", { timeout: 30_000 }, () => {
    const fake = makeFakeBindings({});
    _setWinJobObjectBindingsForTests(fake);
    expect(_runJobKillTreeProbe("win32")).toBe(false);
    expect(fake.calls.some((c) => c.fn === "createJob")).toBe(true);
    // The job is always closed, even on a failed probe.
    expect(fake.calls.some((c) => c.fn === "closeJob")).toBe(true);
  });

  it("memory probe passes only when the tight cap kills and the loose cap does not", { timeout: 60_000 }, () => {
    const fake = makeFakeBindings({
      onAssign(_jobId, pid, limits) {
        // Simulate JOB_OBJECT_LIMIT_PROCESS_MEMORY: an over-budget allocator
        // (256 MiB under a 64 MiB cap) is killed; the loose leg is left alone.
        if ((limits.memoryLimitMb ?? 0) < 256) killIfAlive(pid);
      },
    });
    _setWinJobObjectBindingsForTests(fake);
    expect(_runJobMemoryProbe("win32")).toBe(true);
  });

  it("memory probe fails when the cap enforces nothing (both legs succeed)", { timeout: 60_000 }, () => {
    const fake = makeFakeBindings({});
    _setWinJobObjectBindingsForTests(fake);
    expect(_runJobMemoryProbe("win32")).toBe(false);
  });

  it("cpu-time probe passes when the job terminates the busy-loop", { timeout: 30_000 }, () => {
    // The probe is fully synchronous (Atomics.wait), so a timer would never
    // fire; the fake simulates PerJobUserTimeLimit expiry by killing at
    // assignment time, which the probe observes as an enforced CPU ceiling.
    const fake = makeFakeBindings({
      onAssign(_jobId, pid, limits) {
        if (limits.cpuTimeMs !== undefined) killIfAlive(pid);
      },
    });
    _setWinJobObjectBindingsForTests(fake);
    expect(_runJobCpuTimeProbe("win32")).toBe(true);
  });

  it("cpu-time probe fails when the busy-loop survives", { timeout: 30_000 }, () => {
    const fake = makeFakeBindings({});
    _setWinJobObjectBindingsForTests(fake);
    expect(_runJobCpuTimeProbe("win32")).toBe(false);
  });

  it("pids probe fails when process creation is not denied", { timeout: 30_000 }, () => {
    const fake = makeFakeBindings({});
    _setWinJobObjectBindingsForTests(fake);
    expect(_runJobPidsProbe("win32")).toBe(false);
  });
});

describe("job registry (wrapSpawn wiring surface)", () => {
  it("attachPidToJob creates, assigns, and registers; terminateWinJob kills and closes", () => {
    const fake = makeFakeBindings({});
    _setWinJobObjectBindingsForTests(fake);
    attachPidToJob(4242, { memoryLimitMb: 512, maxProcesses: 8, killOnClose: true });
    expect(fake.calls.map((c) => c.fn)).toEqual(["createJob", "assignProcess"]);
    expect(fake.calls[1]!.args[1]).toBe(4242);
    expect(terminateWinJob(4242)).toBe(true);
    expect(fake.calls.map((c) => c.fn)).toEqual([
      "createJob",
      "assignProcess",
      "terminateJob",
      "closeJob",
    ]);
    expect(terminateWinJob(4242)).toBe(false);
  });

  it("releaseWinJob closes without terminating; unknown pid is false", () => {
    const fake = makeFakeBindings({});
    _setWinJobObjectBindingsForTests(fake);
    attachPidToJob(777, { killOnClose: true });
    expect(releaseWinJob(777)).toBe(true);
    expect(fake.calls.map((c) => c.fn)).toEqual(["createJob", "assignProcess", "closeJob"]);
    expect(releaseWinJob(777)).toBe(false);
  });

  it("attachPidToJob closes the job and rethrows when assignment fails (fail closed)", () => {
    const fake = makeFakeBindings({
      onAssign() {
        throw new Error("AssignProcessToJobObject failed: 5");
      },
    });
    _setWinJobObjectBindingsForTests(fake);
    expect(() => attachPidToJob(31337, { killOnClose: true })).toThrow(/AssignProcessToJobObject/);
    expect(fake.calls.map((c) => c.fn)).toEqual(["createJob", "assignProcess", "closeJob"]);
    expect(terminateWinJob(31337)).toBe(false);
  });

  it("attachPidToJob throws when the addon is absent (never silently unlimited)", () => {
    _setWinJobObjectBindingsForTests(null);
    expect(() => attachPidToJob(1, { killOnClose: true })).toThrow(/addon/i);
  });
});

describe("build/check scripts no-op off-win32", () => {
  it("build script exits 0 with the skip message", () => {
    if (onWindows) return;
    const res = spawnSync(
      process.execPath,
      [join(packageRoot, "scripts", "build-win-job-object-native.mjs")],
      { encoding: "utf-8", timeout: 30_000 },
    );
    expect(res.status).toBe(0);
    expect(res.stdout).toMatch(/Windows-only; skipping/);
  });

  it("check script exits 0 with the skip message", () => {
    if (onWindows) return;
    const res = spawnSync(
      process.execPath,
      [join(packageRoot, "scripts", "check-win-job-object-native.mjs")],
      { encoding: "utf-8", timeout: 30_000 },
    );
    expect(res.status).toBe(0);
    expect(res.stdout).toMatch(/Windows-only; skipping/);
  });
});

// ---------------------------------------------------------------------------
// Real win32 probes - the CI proof lane (desktop-e2e-smoke, windows-2022).
// The addon is compiled by `pnpm --filter @convira/sandbox-runtime build:native`
// immediately before this suite runs there, so these tests ASSERT the addon
// loads instead of skipping on null - a broken build must fail, not skip.
// On every other platform they are no-ops.
// ---------------------------------------------------------------------------

describe("real win32 Job Object enforcement (CI windows-2022 lane)", () => {
  it("addon loads and reports its authority via getInfo", () => {
    if (!onWindows) return;
    const bindings = loadWinJobObjectBindings();
    expect(bindings).not.toBeNull();
    const info = bindings!.getInfo();
    // ABI 2 = the AppContainer extension (profile lifecycle + launcher).
    expect(info.abiVersion).toBe(2);
    expect(info.platform).toBe("win32");
    expect(info.primitives.killOnClose).toBe(true);
    expect(info.primitives.processMemory).toBe(true);
    expect(info.primitives.activeProcess).toBe(true);
    expect(info.primitives.jobUserTime).toBe(true);
  });

  it("kill-tree: TerminateJobObject reaps a real child AND grandchild", { timeout: 60_000 }, () => {
    if (!onWindows) return;
    expect(loadWinJobObjectBindings()).not.toBeNull();
    expect(_runJobKillTreeProbe("win32")).toBe(true);
  });

  it("memory: an over-budget allocation dies under the cap, a modest one survives", { timeout: 120_000 }, () => {
    if (!onWindows) return;
    expect(loadWinJobObjectBindings()).not.toBeNull();
    expect(_runJobMemoryProbe("win32")).toBe(true);
  });

  it("pids: ActiveProcessLimit=1 denies a descendant spawn", { timeout: 60_000 }, () => {
    if (!onWindows) return;
    expect(loadWinJobObjectBindings()).not.toBeNull();
    expect(_runJobPidsProbe("win32")).toBe(true);
  });

  it("cpu-time: PerJobUserTimeLimit terminates a busy-loop", { timeout: 60_000 }, () => {
    if (!onWindows) return;
    expect(loadWinJobObjectBindings()).not.toBeNull();
    expect(_runJobCpuTimeProbe("win32")).toBe(true);
  });
});
