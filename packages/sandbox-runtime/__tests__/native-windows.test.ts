import { describe, it, expect, afterEach } from "vitest";
import { shimPayloadHost } from "./fixtures/selftest-host.js";
import { _resetProbePayloadHostCache, _setProbePayloadHostForTests } from "../src/probe-payload.js";
import { windowsAdapter, _windowsSandboxAvailable } from "../src/adapters/native-windows.js";
import {
  _setWinJobObjectBindingsForTests,
  _resetWinJobObjectBindingsCache,
  _setJobKillTreeProbeForTests,
  _resetJobKillTreeProbeCache,
  _setJobMemoryProbeForTests,
  _resetJobMemoryProbeCache,
  _setJobPidsProbeForTests,
  _resetJobPidsProbeCache,
  _setJobCpuTimeProbeForTests,
  _resetJobCpuTimeProbeCache,
  _resetWinJobRegistryForTests,
  terminateWinJob,
  type WinJobObjectBindings,
  type WinJobObjectLimits,
} from "../src/win-job-object.js";
import {
  WIN_APPCONTAINER_PROFILE_PREFIX,
  _setWinAppContainerLauncherForTests,
  _setGrantPathExistsForTests,
  _setWinAppContainerLedgerDirForTests,
  _setAppContainerFilesystemProbeForTests,
  _resetAppContainerFilesystemProbeCache,
  _setAppContainerNetworkProbeForTests,
  _resetAppContainerNetworkProbeCache,
  _setAppContainerSpawnCagingProbeForTests,
  _resetAppContainerSpawnCagingProbeCache,
} from "../src/win-appcontainer.js";
import {
  _setDiskWatchdogProbeForTests,
  _resetDiskWatchdogProbeCache,
} from "../src/disk-watchdog.js";
import { DEFAULT_CPU_SECONDS } from "../src/rlimit.js";
import type { SandboxSpawnConfig } from "../src/types.js";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

function makeConfig(overrides: Partial<SandboxSpawnConfig> = {}): SandboxSpawnConfig {
  return {
    command: "node",
    args: ["gateway.js"],
    cwd: "C:\\Users\\dev\\project",
    env: { PATH: "C:\\Windows\\System32", USERPROFILE: "C:\\Users\\dev" },
    filesystem: {
      readPaths: ["C:\\Users\\dev\\project"],
      writePaths: ["C:\\Users\\dev\\.convira"],
    },
    network: {
      enabled: true,
      allowLoopback: true,
    },
    resources: {
      memoryMb: 2048,
      maxProcesses: 64,
    },
    ...overrides,
  };
}

function makeRecordingBindings(): WinJobObjectBindings & {
  calls: Array<{ fn: string; args: unknown[] }>;
} {
  let nextId = 1;
  const calls: Array<{ fn: string; args: unknown[] }> = [];
  return {
    calls,
    getInfo() {
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
    createJob(limits: WinJobObjectLimits) {
      calls.push({ fn: "createJob", args: [limits] });
      const id = nextId;
      nextId += 1;
      return id;
    },
    assignProcess(jobId: number, pid: number) {
      calls.push({ fn: "assignProcess", args: [jobId, pid] });
    },
    terminateJob(jobId: number, exitCode: number) {
      calls.push({ fn: "terminateJob", args: [jobId, exitCode] });
    },
    closeJob(jobId: number) {
      calls.push({ fn: "closeJob", args: [jobId] });
    },
  };
}

function pinWinProbes(opts: {
  killTree: boolean;
  memory: boolean;
  pids: boolean;
  cpu: boolean;
}): void {
  _setJobKillTreeProbeForTests(opts.killTree);
  _setJobMemoryProbeForTests(opts.memory);
  _setJobPidsProbeForTests(opts.pids);
  _setJobCpuTimeProbeForTests(opts.cpu);
}

function pinAcProbes(opts: { filesystem: boolean; network: boolean; caging: boolean }): void {
  _setAppContainerFilesystemProbeForTests(opts.filesystem);
  _setAppContainerNetworkProbeForTests(opts.network);
  _setAppContainerSpawnCagingProbeForTests(opts.caging);
}

afterEach(() => {
  _resetProbePayloadHostCache();
  _resetWinJobRegistryForTests();
  _resetWinJobObjectBindingsCache();
  _resetJobKillTreeProbeCache();
  _resetJobMemoryProbeCache();
  _resetJobPidsProbeCache();
  _resetJobCpuTimeProbeCache();
  _resetAppContainerFilesystemProbeCache();
  _resetAppContainerNetworkProbeCache();
  _resetAppContainerSpawnCagingProbeCache();
  _resetDiskWatchdogProbeCache();
  _setWinAppContainerLauncherForTests(undefined);
  _setWinAppContainerLedgerDirForTests(null);
  _setGrantPathExistsForTests(null);
});

describe("windowsAdapter", () => {
  it("has the correct platform identifier", () => {
    expect(windowsAdapter.platform).toBe("windows-job-objects");
  });

  it("reports no filesystem or network isolation while the AppContainer probes fail", () => {
    // Job Object probes alone must never imply isolation: fs/net key on the
    // AppContainer probes exclusively.
    _setWinJobObjectBindingsForTests(makeRecordingBindings());
    pinWinProbes({ killTree: true, memory: true, pids: true, cpu: true });
    pinAcProbes({ filesystem: false, network: false, caging: false });
    const caps = windowsAdapter.capabilities();
    expect(caps.filesystemIsolation).toBe(false);
    expect(caps.networkIsolation).toBe(false);
    const v2 = windowsAdapter.capabilitiesV2!();
    expect(v2.filesystemIsolation).toBe(false);
    expect(v2.networkIsolation).toBe(false);
  });

  it("filesystem/network isolation flip ONLY on their own AppContainer probes", () => {
    _setWinJobObjectBindingsForTests(makeRecordingBindings());
    pinWinProbes({ killTree: false, memory: false, pids: false, cpu: false });
    pinAcProbes({ filesystem: true, network: false, caging: false });
    let caps = windowsAdapter.capabilities();
    expect(caps.filesystemIsolation).toBe(true);
    expect(caps.networkIsolation).toBe(false);
    let v2 = windowsAdapter.capabilitiesV2!();
    expect(v2.filesystemIsolation).toBe(true);
    expect(v2.networkIsolation).toBe(false);

    pinAcProbes({ filesystem: false, network: true, caging: true });
    caps = windowsAdapter.capabilities();
    expect(caps.filesystemIsolation).toBe(false);
    expect(caps.networkIsolation).toBe(true);
    v2 = windowsAdapter.capabilitiesV2!();
    expect(v2.filesystemIsolation).toBe(false);
    expect(v2.networkIsolation).toBe(true);
  });

  it("legacy resourceLimits stays false PERMANENTLY, even with passing probes", () => {
    // The legacy boolean's contract (types.ts) is the POSIX ulimit bundle,
    // which Windows cannot provide (no RLIMIT_FSIZE/descriptor rlimits). The
    // granular truth lives in capabilitiesV2 and resource-requiring profiles
    // are admitted through the runner's granular basis
    // (granularResourceLimitsSatisfied), never by flipping this flag.
    _setWinJobObjectBindingsForTests(makeRecordingBindings());
    pinWinProbes({ killTree: true, memory: true, pids: true, cpu: true });
    pinAcProbes({ filesystem: true, network: true, caging: true });
    _setDiskWatchdogProbeForTests(true);
    expect(windowsAdapter.capabilities().resourceLimits).toBe(false);
  });

  it("capabilitiesV2 stays all-none/false on a loaded addon whose probes fail", () => {
    // Probe-gated advertising: a loaded binary proves compilation, not
    // enforcement. Every field must key on its own probe.
    _setWinJobObjectBindingsForTests(makeRecordingBindings());
    pinWinProbes({ killTree: false, memory: false, pids: false, cpu: false });
    pinAcProbes({ filesystem: false, network: false, caging: false });
    _setDiskWatchdogProbeForTests(false);
    const v2 = windowsAdapter.capabilitiesV2!();
    expect(v2.adapter).toBe("windows-job-objects");
    expect(v2.memory).toBe("none");
    expect(v2.cpu).toBe(false);
    expect(v2.pids).toBe(false);
    expect(v2.fileSize).toBe(false);
    expect(v2.wallClockKill).toBe(false);
    expect(v2.killTree).toBe(false);
  });

  it("fileSize flips ONLY on the disk-write watchdog probe", () => {
    // Job Objects have no RLIMIT_FSIZE analog; the honest Windows file-size
    // control is the sampled granted-dir disk-write watchdog (best-effort
    // tier, mirroring the macOS RSS memory watchdog). Advertised only while
    // its own measure+kill probe passes on this host.
    _setWinJobObjectBindingsForTests(makeRecordingBindings());
    pinWinProbes({ killTree: true, memory: true, pids: true, cpu: true });
    _setDiskWatchdogProbeForTests(false);
    expect(windowsAdapter.capabilitiesV2!().fileSize).toBe(false);
    _setDiskWatchdogProbeForTests(true);
    expect(windowsAdapter.capabilitiesV2!().fileSize).toBe(true);
  });

  it("flips each capabilitiesV2 field only on its own probe", () => {
    _setWinJobObjectBindingsForTests(makeRecordingBindings());
    pinWinProbes({ killTree: false, memory: true, pids: false, cpu: false });
    let v2 = windowsAdapter.capabilitiesV2!();
    expect(v2.memory).toBe("hard-address-space");
    expect(v2.cpu).toBe(false);
    expect(v2.pids).toBe(false);
    expect(v2.killTree).toBe(false);
    expect(v2.wallClockKill).toBe(false);

    pinWinProbes({ killTree: true, memory: false, pids: false, cpu: true });
    v2 = windowsAdapter.capabilitiesV2!();
    expect(v2.memory).toBe("none");
    expect(v2.cpu).toBe(true);
    expect(v2.pids).toBe(false);
    expect(v2.killTree).toBe(true);
    expect(v2.wallClockKill).toBe(true);
  });

  it("availability is probe-gated on win32 and always false elsewhere", async () => {
    _setProbePayloadHostForTests(shimPayloadHost());
    _setWinJobObjectBindingsForTests(makeRecordingBindings());
    pinWinProbes({ killTree: true, memory: true, pids: true, cpu: true });
    // Off-win32 the adapter is never available, no matter what is pinned.
    expect(_windowsSandboxAvailable("darwin")).toBe(false);
    expect(_windowsSandboxAvailable("linux")).toBe(false);
    // On win32 availability keys on the kill-tree probe (minimum real
    // enforcement), not on the addon merely loading.
    expect(_windowsSandboxAvailable("win32")).toBe(true);
    pinWinProbes({ killTree: false, memory: true, pids: true, cpu: true });
    expect(_windowsSandboxAvailable("win32")).toBe(false);
    if (process.platform !== "win32") {
      expect(await windowsAdapter.available()).toBe(false);
    }
  });

  it("is not available when the addon is absent, even on win32", () => {
    _setWinJobObjectBindingsForTests(null);
    pinWinProbes({ killTree: true, memory: true, pids: true, cpu: true });
    expect(_windowsSandboxAvailable("win32")).toBe(false);
  });

  it("names WHICH leg refused, so a packaged build is diagnosable at all", () => {
    _setProbePayloadHostForTests(shimPayloadHost());
    // Availability is two legs and the second is a seven-stage probe. A bare
    // `false` reaches the user as "code execution refused" with no way to tell
    // a missing addon from a host that will not grant a Job Object - and on a
    // packaged Windows build there is no other observation available.
    _setWinJobObjectBindingsForTests(null);
    pinWinProbes({ killTree: true, memory: true, pids: true, cpu: true });
    _windowsSandboxAvailable("win32");
    expect(windowsAdapter.unavailableReason?.()).toBe("job-object-addon-did-not-load");

    _setWinJobObjectBindingsForTests(makeRecordingBindings());
    pinWinProbes({ killTree: false, memory: true, pids: true, cpu: true });
    _windowsSandboxAvailable("win32");
    expect(windowsAdapter.unavailableReason?.()).toMatch(/^kill-tree-probe-failed:/);

    _windowsSandboxAvailable("darwin");
    expect(windowsAdapter.unavailableReason?.()).toBe("not-win32");
  });

  it("reports no reason once the adapter is actually available", () => {
    _setProbePayloadHostForTests(shimPayloadHost());
    _setWinJobObjectBindingsForTests(makeRecordingBindings());
    pinWinProbes({ killTree: true, memory: true, pids: true, cpu: true });
    expect(_windowsSandboxAvailable("win32")).toBe(true);
    expect(windowsAdapter.unavailableReason?.()).toBeUndefined();
  });

  it("keeps every refusal reason a static classification, never host data", () => {
    // These strings reach an application log. A path, pid, or argv here would
    // turn a diagnostic into an exfiltration channel.
    _setWinJobObjectBindingsForTests(null);
    _windowsSandboxAvailable("win32");
    const reason = windowsAdapter.unavailableReason?.() ?? "";
    expect(reason).toMatch(/^[a-z0-9-]+(:[a-z0-9-]+)?$/);
  });

  it("REFUSES to spawn while AppContainer is not proven, instead of unwrapping", () => {
    // This used to return the command UNCONFINED and rely on the caller to
    // notice. Every caller does refuse first today, which is exactly what made
    // it a latent trapdoor: an adapter whose one job is confinement must not
    // be able to hand back an unconfined command at all.
    pinAcProbes({ filesystem: false, network: false, caging: false });
    // wrapSpawn is synchronous on this adapter, so the refusal is a throw and
    // not a rejected promise.
    expect(() => windowsAdapter.wrapSpawn(makeConfig())).toThrow(
      /refusing to spawn an unconfined process/i,
    );
  });

  it("wraps the spawn with the AppContainer launcher when the probes pass", async () => {
    const ledger = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-ac-wrap-"));
    _setWinAppContainerLedgerDirForTests(ledger);
    _setWinAppContainerLauncherForTests("C:\\app\\convira_sbx_launch.exe");
    // Synthetic C:\ paths never exist on this host; the subject here is which
    // grants are composed, not the existence filter (covered in its own suite).
    _setGrantPathExistsForTests(() => true);
    pinAcProbes({ filesystem: true, network: true, caging: true });
    _setWinJobObjectBindingsForTests(makeRecordingBindings());
    try {
      const config = makeConfig({ network: { enabled: false, allowLoopback: false } });
      const spec = await windowsAdapter.wrapSpawn(config);
      expect(spec.command).toBe("C:\\app\\convira_sbx_launch.exe");
      const profileName = spec.args[0]!;
      expect(profileName.startsWith(`${WIN_APPCONTAINER_PROFILE_PREFIX}-`)).toBe(true);
      const grantsFile = spec.args[1]!;
      expect(fs.existsSync(grantsFile)).toBe(true);
      const grants = fs.readFileSync(grantsFile, "utf-8");
      expect(grants).toContain("read\tC:\\Users\\dev\\project\n");
      expect(grants).toContain("write\tC:\\Users\\dev\\.convira\n");
      // No --allow-network for a network-denied spawn (default-deny outbound:
      // the SECURITY_CAPABILITIES array stays empty).
      expect(spec.args).not.toContain("--allow-network");
      expect(spec.args.slice(2)).toEqual(["--", "node", "gateway.js"]);
      expect(spec.postSpawnHook).toBeDefined();
    } finally {
      fs.rmSync(ledger, { recursive: true, force: true });
    }
  });

  it("passes --allow-network (INTERNET_CLIENT capability SID) for network-enabled spawns", async () => {
    const ledger = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-ac-wrapnet-"));
    _setWinAppContainerLedgerDirForTests(ledger);
    _setWinAppContainerLauncherForTests("C:\\app\\convira_sbx_launch.exe");
    // Synthetic C:\ paths never exist on this host; the subject here is which
    // grants are composed, not the existence filter (covered in its own suite).
    _setGrantPathExistsForTests(() => true);
    pinAcProbes({ filesystem: true, network: true, caging: true });
    _setWinJobObjectBindingsForTests(makeRecordingBindings());
    try {
      const spec = await windowsAdapter.wrapSpawn(
        makeConfig({ network: { enabled: true, allowLoopback: false } }),
      );
      expect(spec.command).toBe("C:\\app\\convira_sbx_launch.exe");
      expect(spec.args).toContain("--allow-network");
      const sep = spec.args.indexOf("--");
      expect(spec.args.slice(sep)).toEqual(["--", "node", "gateway.js"]);
    } finally {
      fs.rmSync(ledger, { recursive: true, force: true });
    }
  });

  it("grants read on the command's own directory for absolute commands", async () => {
    const ledger = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-ac-wrapcmd-"));
    _setWinAppContainerLedgerDirForTests(ledger);
    _setWinAppContainerLauncherForTests("C:\\app\\convira_sbx_launch.exe");
    // Synthetic C:\ paths never exist on this host; the subject here is which
    // grants are composed, not the existence filter (covered in its own suite).
    _setGrantPathExistsForTests(() => true);
    pinAcProbes({ filesystem: true, network: true, caging: true });
    _setWinJobObjectBindingsForTests(makeRecordingBindings());
    try {
      const spec = await windowsAdapter.wrapSpawn(
        makeConfig({ command: "C:\\tools\\python\\python.exe" }),
      );
      const grants = fs.readFileSync(spec.args[1]!, "utf-8");
      // The AC child must be able to load its own interpreter image; user
      // tool dirs have no ALL APPLICATION PACKAGES ACE by default.
      expect(grants).toContain("read\tC:\\tools\\python\n");
    } finally {
      fs.rmSync(ledger, { recursive: true, force: true });
    }
  });

  it("refuses a loopback-only spawn on the AppContainer path (non-admin exemption impossible)", async () => {
    _setWinAppContainerLauncherForTests("C:\\app\\convira_sbx_launch.exe");
    // Synthetic C:\ paths never exist on this host; the subject here is which
    // grants are composed, not the existence filter (covered in its own suite).
    _setGrantPathExistsForTests(() => true);
    pinAcProbes({ filesystem: true, network: true, caging: true });
    _setWinJobObjectBindingsForTests(makeRecordingBindings());
    await expect(async () =>
      windowsAdapter.wrapSpawn(makeConfig({ network: { enabled: false, allowLoopback: true } })),
    ).rejects.toThrow(/loopback/i);
  });

  it("postSpawnHook warns without throwing when the addon is missing", async () => {
    pinAcProbes({ filesystem: true, network: true, caging: true });
    _setWinAppContainerLauncherForTests("C:\\fake\\convira_sbx_launch.exe");
    _setWinJobObjectBindingsForTests(null);
    const spec = await windowsAdapter.wrapSpawn(makeConfig());
    expect(spec.postSpawnHook).toBeDefined();
    expect(() => spec.postSpawnHook!(12345)).not.toThrow();
  });

  it("postSpawnHook attaches the pid to a kill-on-close job with derived limits", async () => {
    pinAcProbes({ filesystem: true, network: true, caging: true });
    _setWinAppContainerLauncherForTests("C:\\fake\\convira_sbx_launch.exe");
    const bindings = makeRecordingBindings();
    _setWinJobObjectBindingsForTests(bindings);
    const spec = await windowsAdapter.wrapSpawn(makeConfig());
    spec.postSpawnHook!(4242);
    expect(bindings.calls.map((c) => c.fn)).toEqual(["createJob", "assignProcess"]);
    expect(bindings.calls[0]!.args[0]).toEqual({
      memoryLimitMb: 2048,
      maxProcesses: 64,
      cpuTimeMs: DEFAULT_CPU_SECONDS * 1000,
      killOnClose: true,
    });
    expect(bindings.calls[1]!.args[1]).toBe(4242);
    // The registry retains the job so a runner can kill the tree later.
    expect(terminateWinJob(4242)).toBe(true);
  });

  it("omits the CPU budget for long-lived processes (STDIO MCP servers)", async () => {
    pinAcProbes({ filesystem: true, network: true, caging: true });
    _setWinAppContainerLauncherForTests("C:\\fake\\convira_sbx_launch.exe");
    const bindings = makeRecordingBindings();
    _setWinJobObjectBindingsForTests(bindings);
    const spec = await windowsAdapter.wrapSpawn(
      makeConfig({
        resources: { memoryMb: 1024, maxProcesses: 16, longLived: true },
      }),
    );
    spec.postSpawnHook!(555);
    expect(bindings.calls[0]!.args[0]).toEqual({
      memoryLimitMb: 1024,
      maxProcesses: 16,
      killOnClose: true,
    });
  });
});
