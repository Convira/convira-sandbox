/**
 * Passthrough adapter — no OS-level isolation.
 *
 * Used when:
 *  - the host selects isolation mode "off" (deployment knob CONVIRA_SANDBOX_MODE)
 *  - No native sandbox is available on the platform
 *  - Development mode
 *
 * Returns the original spawn command unchanged.
 */

import type {
  ExecutionCapabilityReportV2,
  SandboxAdapter,
  SandboxCapabilities,
  SandboxSpawnConfig,
  SpawnSpec,
} from "../types.js";

let _warned = false;

export const passthroughAdapter: SandboxAdapter = {
  platform: "passthrough",

  async available(): Promise<boolean> {
    return true;
  },

  capabilities(): SandboxCapabilities {
    return {
      filesystemIsolation: false,
      networkIsolation: false,
      resourceLimits: false,
    };
  },

  capabilitiesV2(): ExecutionCapabilityReportV2 {
    // No isolation at all - every control honestly off/none.
    return {
      adapter: passthroughAdapter.platform,
      memory: "none",
      cpu: false,
      pids: false,
      fileSize: false,
      wallClockKill: false,
      killTree: false,
      filesystemIsolation: false,
      networkIsolation: false,
    };
  },

  wrapSpawn(config: SandboxSpawnConfig): SpawnSpec {
    if (!_warned) {
      _warned = true;
      if (typeof process !== "undefined" && process.stderr) {
        process.stderr.write(
          "[sandbox-runtime] No OS-level sandbox active; " +
            "gateway runs with full host privileges. " +
            'Select isolation mode "auto" or "native" (host knob CONVIRA_SANDBOX_MODE) ' +
            "to enable platform-native sandboxing.\n",
        );
      }
    }

    return {
      command: config.command,
      args: config.args,
      env: config.env,
      cwd: config.cwd,
    };
  },
};

/**
 * Reset the warning flag (test helper).
 */
export function _resetPassthroughWarning(): void {
  _warned = false;
}
