/**
 * Windows-only DIAGNOSTIC for issue #1, not a confinement gate.
 *
 * `integration.test.ts` is skipped on win32 because the AppContainer launcher
 * answers `CreateProcessW failed (code 203)` on GitHub-hosted runners. Three
 * plausible causes were argued from the log alone and each died against some
 * other fact in the same log, so this file stops arguing and runs the
 * experiment on the only Windows machine available: the CI runner.
 *
 * The one thing that separates the failing suite from every passing one is the
 * environment. `integration.test.ts` replaces the child environment wholesale
 * with `{ PATH, HOME }`; every suite that passes inherits the real one, and the
 * desktop runner that ships to users passes a named allowlist that includes
 * LOCALAPPDATA, APPDATA and USERPROFILE. So environment content is the variable
 * to isolate, and this bisects it: same spec, same child, one env block
 * changed at a time.
 *
 * It asserts only the control leg, and prints a table for the rest. A
 * diagnostic that gates would make the answer harder to read, not easier - the
 * point is to learn which variable moves the failure, then fix that in
 * `integration.test.ts` (or in the launcher) and let the real integration
 * cases do the gating.
 *
 * Delete this file once issue #1 closes.
 */

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createSandboxedSpawn, type SandboxAdapter } from "../src/index.js";

const describeWin = describe.skipIf(process.platform !== "win32");

/** Mirrors WINDOWS_ENV_ALLOWLIST in the desktop sandboxed-process-runner. */
const PRODUCTION_ALLOWLIST = [
  "SystemRoot",
  "SystemDrive",
  "windir",
  "COMSPEC",
  "PATHEXT",
  "NUMBER_OF_PROCESSORS",
  "PROCESSOR_ARCHITECTURE",
  "USERPROFILE",
  "LOCALAPPDATA",
  "APPDATA",
] as const;

function pick(keys: readonly string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of keys) {
    const v = process.env[k];
    if (typeof v === "string") out[k] = v;
  }
  return out;
}

describeWin("issue #1 - which environment variable does the AC child need", () => {
  it(
    "bisects the environment against a child that only has to start",
    async () => {
      const adapter: SandboxAdapter = await createSandboxedSpawn("auto");
      if (adapter.platform === "passthrough") {
        console.log("[issue-1] no AppContainer on this host; nothing to bisect");
        return;
      }

      const nodeDir = path.dirname(process.execPath);
      const minimal = { PATH: process.env.PATH || "" };

      const variants: Array<{ name: string; env: Record<string, string> }> = [
        { name: "full process.env (control)", env: { ...process.env } as Record<string, string> },
        { name: "PATH+HOME (what integration.test.ts sends)", env: { ...minimal, HOME: "" } },
        { name: "PATH only", env: { ...minimal } },
        { name: "PATH+LOCALAPPDATA", env: { ...minimal, ...pick(["LOCALAPPDATA"]) } },
        { name: "PATH+APPDATA", env: { ...minimal, ...pick(["APPDATA"]) } },
        { name: "PATH+USERPROFILE", env: { ...minimal, ...pick(["USERPROFILE"]) } },
        { name: "PATH+SystemRoot+SystemDrive", env: { ...minimal, ...pick(["SystemRoot", "SystemDrive"]) } },
        { name: "PATH+TEMP+TMP", env: { ...minimal, ...pick(["TEMP", "TMP"]) } },
        { name: "production allowlist", env: { ...pick(PRODUCTION_ALLOWLIST), PATH: process.env.PATH || "" } },
      ];

      const rows: string[] = [];
      for (const variant of variants) {
        // A fresh spec per variant is REQUIRED, not tidiness: the launcher
        // deletes its grants file in cleanup on both the success and the
        // failure path, so a reused spec would fail for a second, unrelated
        // reason and poison every row after the first.
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sb-envprobe-"));
        const spec = await adapter.wrapSpawn({
          command: process.execPath,
          // The child does nothing but exit 42. Anything else would let a
          // sandbox denial masquerade as a launch failure, which is the exact
          // confusion this test exists to remove.
          args: ["-e", "process.exit(42)"],
          cwd: tmpDir,
          env: variant.env,
          filesystem: { readPaths: [tmpDir, nodeDir], writePaths: [tmpDir] },
          network: { enabled: false, allowLoopback: false },
          resources: { memoryMb: 2048, maxProcesses: 8 },
        });

        const result = spawnSync(spec.command, spec.args, {
          cwd: spec.cwd,
          env: spec.env,
          timeout: 30_000,
          encoding: "utf-8",
        });

        const started = result.status === 42;
        const detail = started
          ? "child started and exited 42"
          : `status=${result.status} ${(result.stderr || "").trim().replace(/\s+/g, " ").slice(0, 200)}`;
        rows.push(`${started ? "PASS" : "FAIL"}  ${variant.name.padEnd(42)} ${detail}`);
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }

      console.log("\n[issue-1] environment bisection\n" + rows.join("\n") + "\n");

      // Only the control is asserted. If a child cannot start even with the
      // real environment then the launcher is broken independently of issue
      // #1, and that deserves a red run.
      expect(rows[0]).toMatch(/^PASS/);
    },
    240_000,
  );
});
