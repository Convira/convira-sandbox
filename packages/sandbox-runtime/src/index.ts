/**
 * @convira/sandbox-runtime — platform-native process sandboxing.
 *
 * Wraps child_process.spawn() with OS-level isolation:
 *   - Linux:   bubblewrap (namespace-based)
 *   - macOS:   sandbox-exec (Seatbelt profiles)
 *   - Windows: Job Objects (resource limits)
 *   - Fallback: passthrough (no isolation, warning logged)
 *
 * Usage:
 *   import { createSandboxedSpawn } from "@convira/sandbox-runtime";
 *
 *   const adapter = await createSandboxedSpawn("auto");
 *   const spec = adapter.wrapSpawn({ command, args, ... });
 *   const child = spawn(spec.command, spec.args, { env: spec.env });
 *   if (spec.postSpawnHook) spec.postSpawnHook(child.pid);
 */

export type {
  SandboxAdapter,
  SandboxCapabilities,
  ExecutionCapabilityReportV2,
  MemoryEnforcementTier,
  SandboxSpawnConfig,
  SpawnSpec,
  IsolationMode,
} from "./types.js";

export { detectAdapter } from "./detect.js";
export { linuxAdapter, isLinuxSandboxAvailable } from "./adapters/native-linux.js";
export {
  macosAdapter,
  SANDBOX_EXEC_PATH,
  isSandboxExecAvailable,
  legacyMacosProfile,
  LEGACY_MACOS_SENSITIVE_HOME_DIRS,
  LEGACY_MACOS_CONVIRA_READ_FLOOR,
} from "./adapters/native-macos.js";
export { windowsAdapter } from "./adapters/native-windows.js";
export { passthroughAdapter } from "./adapters/passthrough.js";
export {
  RLIMIT_SHELL_PATH,
  probeRlimitSupport,
  rlimitValuesFromResources,
  buildRlimitScript,
  wrapWithRlimit,
} from "./rlimit.js";
export type { RlimitValues, RlimitProbeResult, ProcLimitFlag } from "./rlimit.js";
export { probeDescendantKill, probeMemoryHardCap } from "./probes.js";
export {
  loadWinJobObjectBindings,
  probeJobKillTree,
  probeJobMemory,
  probeJobPids,
  probeJobCpuTime,
  probeWinJobObjectReport,
  attachPidToJob,
  terminateWinJob,
  releaseWinJob,
} from "./win-job-object.js";
export type {
  WinJobObjectBindings,
  WinJobObjectInfo,
  WinJobObjectLimits,
  WinJobObjectProbeReport,
} from "./win-job-object.js";
export {
  startRssGroupWatchdog,
  sampleProcessGroupRssKb,
  probeRssWatchdogSupport,
} from "./rss-watchdog.js";
export type { RssGroupWatchdogHandle, RssGroupSampler } from "./rss-watchdog.js";
export {
  WIN_APPCONTAINER_PROFILE_PREFIX,
  loadWinAppContainerBindings,
  resolveWinAppContainerLauncher,
  formatAppContainerGrants,
  prepareAppContainerSpawn,
  winAppContainerLedgerDir,
  sweepOrphanedAppContainerProfiles,
  probeAppContainerFilesystem,
  probeAppContainerNetwork,
  probeAppContainerSpawnCaging,
  probeWinAppContainerReport,
} from "./win-appcontainer.js";
export type {
  WinAppContainerBindings,
  WinAppContainerGrants,
  PreparedAppContainerSpawn,
  WinAppContainerProbeReport,
} from "./win-appcontainer.js";
export {
  sampleDirectoryBytes,
  startDiskWriteWatchdog,
  probeDiskWatchdogSupport,
} from "./disk-watchdog.js";
export type {
  DirectoryBytesSampler,
  DiskWriteWatchdogHandle,
  StartDiskWriteWatchdogOptions,
} from "./disk-watchdog.js";

import { detectAdapter } from "./detect.js";
import type { IsolationMode, SandboxAdapter } from "./types.js";

/**
 * Convenience entry point: detect the platform and return the best
 * available sandbox adapter.
 */
export async function createSandboxedSpawn(mode?: IsolationMode): Promise<SandboxAdapter> {
  return detectAdapter(mode ?? "auto");
}

// Probe payload host: the subject of every destructive Windows capability
// probe. Exported so the desktop can prove it FIRST and report a named reason
// instead of chaining minutes of blocked probe deadlines behind a host that
// was never usable.
export {
  probeSelftestHandshake,
  selftestHandshakeStage,
  resolveProbePayloadHost,
  probePayloadArgv,
  _setProbePayloadHostForTests,
  _setSelftestHandshakeForTests,
  _resetProbePayloadHostCache,
  type ProbeVerb,
  type ProbePayloadHost,
  type SelftestHandshakeStage,
} from "./probe-payload.js";
export { _unpackedTwinPath } from "./win-appcontainer.js";
