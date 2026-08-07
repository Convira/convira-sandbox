/**
 * Platform detection — selects the best available SandboxAdapter for the
 * current OS and verifies that the required tooling is present.
 */

import fs from "node:fs";
import type { IsolationMode, SandboxAdapter } from "./types.js";
import { linuxAdapter } from "./adapters/native-linux.js";
import { macosAdapter } from "./adapters/native-macos.js";
import { windowsAdapter } from "./adapters/native-windows.js";
import { passthroughAdapter } from "./adapters/passthrough.js";

function isWSL(): boolean {
  if (process.platform !== "win32") return false;
  try {
    const version = fs.readFileSync("/proc/version", "utf-8");
    return /microsoft/i.test(version);
  } catch {
    return false;
  }
}

/**
 * Detect and return the best sandbox adapter for the current platform.
 *
 * @param mode - "auto" tries native then passthrough;
 *               "native" requires native or throws;
 *               "off" always returns passthrough.
 */
export async function detectAdapter(mode: IsolationMode = "auto"): Promise<SandboxAdapter> {
  if (mode === "off") {
    return passthroughAdapter;
  }

  const adapter = await selectNativeAdapter();

  if (adapter) {
    return adapter;
  }

  if (mode === "native") {
    throw new Error(
      `[sandbox-runtime] isolation mode "native" was requested (host knob ` +
        `CONVIRA_SANDBOX_MODE) but no OS-level sandbox is available on ${process.platform}. ` +
        `Install bubblewrap (Linux) or verify sandbox-exec (macOS). On Windows, ensure the ` +
        `native addon compiled successfully.`,
    );
  }

  return passthroughAdapter;
}

async function selectNativeAdapter(): Promise<SandboxAdapter | null> {
  // WSL: prefer Linux bubblewrap even though process.platform is "win32"
  if (isWSL()) {
    if (await linuxAdapter.available()) return linuxAdapter;
  }

  switch (process.platform) {
    case "linux":
      if (await linuxAdapter.available()) return linuxAdapter;
      logMissing("bubblewrap (bwrap)", "apt install bubblewrap");
      return null;

    case "darwin":
      if (await macosAdapter.available()) return macosAdapter;
      logMissing("sandbox-exec", null);
      return null;

    case "win32":
      if (await windowsAdapter.available()) return windowsAdapter;
      return null;

    default:
      return null;
  }
}

function logMissing(tool: string, installHint: string | null): void {
  const hint = installHint ? ` Install with: ${installHint}` : "";
  if (typeof process !== "undefined" && process.stderr) {
    process.stderr.write(
      `[sandbox-runtime] ${tool} not found on this system.${hint} ` +
        `Falling back to passthrough (no OS-level sandbox).\n`,
    );
  }
}
