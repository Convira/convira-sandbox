import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { ProbePayloadHost } from "../../src/probe-payload.js";

const here = dirname(fileURLToPath(import.meta.url));

/**
 * Pin the probe payload host to the Node shim so probe DECISION logic can be
 * exercised on macOS and Linux. The shipped host is a C++ verb table inside
 * `convira_sbx_launch.exe`, which exists only on Windows; without this seam
 * every probe short-circuits to false off-win32 and the orchestration - the
 * part with the interesting bugs - is never executed anywhere.
 */
export function shimPayloadHost(extraArgs: string[] = []): ProbePayloadHost {
  return {
    command: process.execPath,
    prefixArgs: [join(here, "selftest-shim.mjs"), ...extraArgs],
    readGrants: [],
  };
}
