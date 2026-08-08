/**
 * Windows sandbox adapter — Job Objects for resource limits, AppContainer for
 * filesystem/network isolation.
 *
 * Windows lacks a CLI-level sandbox equivalent to bubblewrap or sandbox-exec.
 * Job Objects provide memory limits, process-count limits, a cumulative
 * user-CPU ceiling, and automatic cleanup of the entire process tree when the
 * job handle closes. AppContainer (batch 5) adds OS-level filesystem
 * confinement (deny-by-default: no ACE for the AC SID means no access) and
 * default-deny outbound network (no capability SIDs), applied at
 * CreateProcessW time by the `convira_sbx_launch.exe` wrapper — see
 * `win-appcontainer.ts` for why a post-spawn hook cannot do this.
 *
 * Every capability field keys on its own destructive probe
 * (`win-job-object.ts`, `win-appcontainer.ts`, `disk-watchdog.ts`) — a loaded
 * addon/launcher proves compilation, not enforcement. Absent or failed
 * probes keep the honest all-none report and spawns stay unwrapped, so the
 * runner's capability gates keep refusing exactly as before this existed.
 *
 * Loopback under AppContainer is honestly UNSUPPORTED: exempting a package
 * from loopback isolation requires an admin `CheckNetIsolation` registration,
 * which a non-admin per-user install cannot perform at runtime. A
 * loopback-only spawn request is therefore refused (fail closed), and
 * `--allow-network` grants INTERNET_CLIENT/PRIVATE_NETWORK_CLIENT_SERVER
 * capability SIDs that cover internet/LAN but never 127.0.0.1.
 */

import * as path from "node:path";

import type {
  ExecutionCapabilityReportV2,
  SandboxAdapter,
  SandboxCapabilities,
  SandboxSpawnConfig,
  SpawnSpec,
} from "../types.js";
import { rlimitValuesFromResources } from "../rlimit.js";
import {
  attachPidToJob,
  loadWinJobObjectBindings,
  jobKillTreeProbeStage,
  probeJobKillTree,
  probeWinJobObjectReport,
  type WinJobObjectLimits,
} from "../win-job-object.js";
import { probeSelftestHandshake, selftestHandshakeStage } from "../probe-payload.js";
import {
  prepareAppContainerSpawn,
  probeAppContainerFilesystem,
  probeAppContainerNetwork,
  resolveWinAppContainerLauncher,
} from "../win-appcontainer.js";
import { probeDiskWatchdogSupport } from "../disk-watchdog.js";

/**
 * Availability = real enforcement can be proven, matching the Linux (bwrap
 * binary) and macOS (sandbox-exec) adapters: win32 AND the addon loads AND
 * the kill-tree probe passed (the minimum control a runner relies on for
 * timeout/abort kills). A mere addon load never counts — otherwise
 * detectAdapter("native") would hand back a no-enforcement adapter instead of
 * throwing per its contract. Exported with a platform argument so the win32
 * true-path is unit-testable everywhere.
 */
export function _windowsSandboxAvailable(platform: NodeJS.Platform = process.platform): boolean {
  if (platform !== "win32") {
    _unavailableReason = "not-win32";
    return false;
  }
  if (loadWinJobObjectBindings(platform) === null) {
    // Compilation is proven at package time; this is a RESOLUTION failure -
    // the addon is absent from the shipped tree or unreachable from where the
    // dist ended up (asar / asarUnpack).
    _unavailableReason = "job-object-addon-did-not-load";
    return false;
  }
  // The payload host must be proven BEFORE any destructive probe runs. Without
  // it every probe below reports its control unavailable for the same reason,
  // and the refusal would name the last one to fail rather than the only one
  // that matters.
  if (!probeSelftestHandshake()) {
    _unavailableReason = `selftest-host-unavailable:${selftestHandshakeStage()}`;
    return false;
  }
  if (!probeJobKillTree()) {
    _unavailableReason = `kill-tree-probe-failed:${jobKillTreeProbeStage()}`;
    return false;
  }
  _unavailableReason = undefined;
  return true;
}

/**
 * Static classification of the last refusal. Windows availability is two legs
 * and the second is a seven-stage probe, so a bare `false` is unactionable -
 * and a packaged build offers no other way to tell a missing addon from a
 * host that will not grant a Job Object.
 */
let _unavailableReason: string | undefined;

/**
 * An AppContainer's per-profile directory lives under `%LOCALAPPDATA%\Packages`,
 * and `CreateProcessW` resolves it FROM THE ENVIRONMENT of the calling process.
 * Strip that one variable and the launch fails with `ERROR_ENVVAR_NOT_FOUND`
 * (203) - which names no variable, points at no file, and is indistinguishable
 * from a bad image path until you bisect the environment. It cost this repo an
 * issue and three wrong theories (#1).
 *
 * So the requirement belongs here rather than in every caller's env allowlist.
 * A caller building a deliberately minimal environment - which is the correct
 * instinct for a sandbox - has no way to know that this specific name is load
 * bearing for the Windows *host API*, as opposed to for the child.
 *
 * Only filled in when absent, so an explicit caller value still wins. The cost
 * is that the confined child also sees the variable: it names a directory the
 * child has no ACE for and therefore cannot read, and PATH already discloses
 * the same username, so this widens no boundary that was previously closed.
 */
function withAppContainerRequiredEnv(env: Record<string, string>): Record<string, string> {
  if (typeof env["LOCALAPPDATA"] === "string") return env;
  const inherited = process.env["LOCALAPPDATA"];
  if (typeof inherited !== "string" || inherited.length === 0) return env;
  return { ...env, LOCALAPPDATA: inherited };
}

export const windowsAdapter: SandboxAdapter = {
  platform: "windows-job-objects",

  async available(): Promise<boolean> {
    return _windowsSandboxAvailable();
  },

  unavailableReason(): string | undefined {
    return _unavailableReason;
  },

  capabilities(): SandboxCapabilities {
    return {
      // Probe-gated (batch 5): OS-enforced only through the AppContainer
      // launcher path, and each flag flips ONLY on its own destructive probe.
      filesystemIsolation: probeAppContainerFilesystem(),
      networkIsolation: probeAppContainerNetwork(),
      // PERMANENTLY false on Windows: the legacy boolean's contract is the
      // POSIX ulimit bundle (CPU/file-size/descriptor/process-count rlimits),
      // which Windows cannot provide. The granular truth — which controls DO
      // hold — lives in capabilitiesV2, and resource-requiring profiles are
      // admitted through the runner's granular basis
      // (runtime-core `granularResourceLimitsSatisfied`), never by faking
      // this flag.
      resourceLimits: false,
    };
  },

  capabilitiesV2(): ExecutionCapabilityReportV2 {
    // Each field states a fact proven by that control's own destructive probe
    // (win-job-object.ts / win-appcontainer.ts / disk-watchdog.ts); with the
    // addon or launcher absent every probe is false and the report is
    // honestly all-none.
    const probes = probeWinJobObjectReport();
    return {
      adapter: windowsAdapter.platform,
      // JOB_OBJECT_LIMIT_PROCESS_MEMORY is a hard kernel commit-charge cap —
      // the Windows analog of RLIMIT_AS.
      memory: probes.memory ? "hard-address-space" : "none",
      cpu: probes.cpu,
      pids: probes.pids,
      // No RLIMIT_FSIZE analog exists in Job Objects; the honest Windows
      // control is the sampled granted-dir disk-write watchdog — a
      // best-effort tier (like the macOS RSS memory watchdog), advertised
      // only while its own measure+kill probe passes.
      fileSize: probeDiskWatchdogSupport(),
      wallClockKill: probes.wallClockKill,
      killTree: probes.killTree,
      filesystemIsolation: probeAppContainerFilesystem(),
      networkIsolation: probeAppContainerNetwork(),
    };
  },

  wrapSpawn(config: SandboxSpawnConfig): SpawnSpec {
    const bindings = loadWinJobObjectBindings();

    const hook = bindings
      ? (pid: number) => {
          // Reuse the shared CPU-budget derivation (wall-clock timeout →
          // cpu-seconds, omitted for long-lived servers) so Windows and POSIX
          // spawns agree on the budget for the same resource spec.
          const rlimitValues = rlimitValuesFromResources(config.resources, {
            enforceMemory: false,
          });
          const limits: WinJobObjectLimits = {
            memoryLimitMb: Math.floor(config.resources.memoryMb),
            // ActiveProcessLimit counts only processes in the job (true
            // per-tree semantics), so the spec's maxProcesses maps directly —
            // no RLIMIT_NPROC-style per-uid headroom.
            maxProcesses: Math.max(1, Math.floor(config.resources.maxProcesses)),
            ...(rlimitValues.cpuSeconds !== undefined
              ? { cpuTimeMs: rlimitValues.cpuSeconds * 1000 }
              : {}),
            killOnClose: true,
          };
          // Throws on failure: a process this adapter cannot confine must be
          // treated as a refusal by the caller, never left running unlimited.
          attachPidToJob(pid, limits);
        }
      : (pid: number) => {
          if (typeof process !== "undefined" && process.stderr) {
            process.stderr.write(
              `[sandbox-runtime] Windows native addon not available; ` +
                `no resource limits applied to PID ${pid}\n`,
            );
          }
        };

    // AppContainer launcher path (batch 5): used only when the launcher is
    // built AND the isolation this spawn relies on is probe-proven —
    // filesystem always; the network deny probe additionally when this spawn
    // denies network. Anything less keeps the unwrapped spec below, whose
    // honest all-false capabilities make the runner's gates refuse.
    const launcher = resolveWinAppContainerLauncher();
    const appContainerReady =
      launcher !== null &&
      probeAppContainerFilesystem() &&
      (config.network.enabled || probeAppContainerNetwork());
    if (appContainerReady) {
      if (!config.network.enabled && config.network.allowLoopback) {
        // Loopback exemption requires an admin CheckNetIsolation registration
        // a non-admin install cannot perform; granting INTERNET_CLIENT
        // instead would over-grant. Refuse rather than silently under- or
        // over-isolate.
        throw new Error(
          "[sandbox-runtime] AppContainer cannot grant loopback-only network access " +
            "(a non-admin install cannot register a loopback exemption); refusing to spawn",
        );
      }
      const prepared = prepareAppContainerSpawn({
        readPaths: [
          ...config.filesystem.readPaths,
          // The AC child must be able to load its own interpreter image;
          // user-local tool dirs carry no ALL APPLICATION PACKAGES ACE.
          // path.win32 explicitly: this adapter always handles Windows paths,
          // even when its decision logic runs under tests on POSIX hosts.
          ...(path.win32.isAbsolute(config.command)
            ? [path.win32.dirname(config.command)]
            : []),
        ],
        writePaths: config.filesystem.writePaths,
        ...(config.filesystem.denyPaths ? { denyPaths: config.filesystem.denyPaths } : {}),
        // Lets a deny leaf that does not exist yet be materialized with the
        // right kind instead of refusing the spawn.
        ...(config.filesystem.denyPathKinds
          ? { denyPathKinds: config.filesystem.denyPathKinds }
          : {}),
      });
      return {
        command: launcher,
        args: [
          prepared.profileName,
          prepared.grantsFile,
          ...(config.network.enabled ? ["--allow-network"] : []),
          "--",
          config.command,
          ...config.args,
        ],
        env: withAppContainerRequiredEnv(config.env),
        cwd: config.cwd,
        // The Job Object attaches to the LAUNCHER pid; the AC child joins
        // that job automatically at CreateProcessW (it is created by a job
        // member with no breakaway flags), and the launcher's own internal
        // suspended-assign-resume job is the race-free cage regardless.
        postSpawnHook: hook,
      };
    }

    // No AppContainer, no spawn. This used to return the command UNWRAPPED,
    // i.e. an adapter whose entire purpose is confinement handing back an
    // unconfined command and letting the caller notice. It is unreachable in
    // production only because every caller refuses first - which makes it a
    // latent trapdoor, not a safe default. Refuse here too, in the same shape
    // as the loopback refusal above.
    throw new Error(
      "[sandbox-runtime] AppContainer filesystem/network isolation is not proven on this host; " +
        "refusing to spawn an unconfined process",
    );
  },
};
