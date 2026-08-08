/**
 * Windows-only regression test for issue #1.
 *
 * This file began as an environment bisection: `integration.test.ts` failed on
 * win32 with `CreateProcessW failed (code 203)`, three readings of that code
 * were argued from the log and each died against another fact in the same log,
 * so the experiment ran on the CI runner instead - same spec, same child, one
 * environment block changed at a time. LOCALAPPDATA came back both necessary
 * and sufficient: every other candidate still failed, that one passed. An
 * AppContainer profile lives under `%LOCALAPPDATA%\Packages`, and
 * CreateProcessW resolves it from the caller's environment, so 203 was telling
 * the literal truth - it could not find an environment variable.
 *
 * Two things came out of that, and this pins the second:
 *   1. `withAppContainerRequiredEnv` in the adapter supplies the variable, so
 *      no caller has to know. Covered off-Windows in `native-windows.test.ts`.
 *   2. The launcher refuses up front, by name, if it is ever invoked without
 *      it - because a bare 203 is what made this expensive. That is what this
 *      file checks, and it can only be checked on Windows.
 *
 * The bisection itself is not kept: its answer is now load bearing in three
 * places, and re-running nine real AppContainer spawns every CI pass would cost
 * ~30s to re-derive a settled fact.
 */

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createSandboxedSpawn, type SandboxAdapter } from "../src/index.js";

const describeWin = describe.skipIf(process.platform !== "win32");

describeWin("issue #1 - the launcher names LOCALAPPDATA rather than answering 203", () => {
  it("refuses with a named message when the variable is absent", async () => {
    const adapter: SandboxAdapter = await createSandboxedSpawn("auto");
    if (adapter.platform === "passthrough") return;

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sb-lad-"));
    try {
      const spec = await adapter.wrapSpawn({
        command: process.execPath,
        args: ["-e", "process.exit(42)"],
        cwd: tmpDir,
        env: { PATH: process.env["PATH"] || "" },
        filesystem: { readPaths: [tmpDir, path.dirname(process.execPath)], writePaths: [tmpDir] },
        network: { enabled: false, allowLoopback: false },
        resources: { memoryMb: 2048, maxProcesses: 8 },
      });

      // The adapter just supplied it, which is the fix. Removing it here is the
      // only way to reach the launcher's backstop, and reaching it is the point:
      // this asserts what a caller OUTSIDE this adapter is told.
      expect(spec.env["LOCALAPPDATA"]).toBeTypeOf("string");
      const stripped = { ...spec.env };
      delete stripped["LOCALAPPDATA"];

      const result = spawnSync(spec.command, spec.args, {
        cwd: spec.cwd,
        env: stripped,
        timeout: 30_000,
        encoding: "utf-8",
      });

      expect(result.status).not.toBe(42);
      expect(result.stderr).toContain("LOCALAPPDATA");
      // The failure must be the early, explanatory one - not the bare code 203
      // three stages later that this whole exercise was about.
      expect(result.stderr).not.toContain("code 203");
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 60_000);
});
