/**
 * Integration tests for OS-level sandbox enforcement.
 *
 * These tests spawn real sandboxed processes and verify that:
 *   - Filesystem reads outside allowed paths are denied
 *   - Filesystem writes outside allowed paths are denied
 *   - Network access is blocked when disabled
 *   - Allowed reads/writes succeed
 *
 * Skipped on platforms where the native sandbox is unavailable.
 */

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createSandboxedSpawn, type SandboxAdapter } from "../src/index.js";

/**
 * S3-18 — resolved at MODULE scope, not in `beforeAll`.
 *
 * `it.skipIf(...)` is evaluated when the file is collected, which happens
 * before any hook runs. Reading a `beforeAll`-assigned flag there would see
 * `undefined` and skip every test unconditionally — the same "looks covered,
 * runs nothing" failure this finding is about, just moved.
 */
const adapter: SandboxAdapter = await createSandboxedSpawn("auto");
const hasNativeSandbox = adapter.platform !== "passthrough";

/**
 * System read paths that Node.js needs to boot.
 * The Seatbelt profile already grants /usr, /System, /Library/Frameworks,
 * /dev — but the node binary itself may live elsewhere.
 */
function nodeBootReadPaths(): string[] {
  const nodeBin = process.execPath;
  const nodeDir = path.dirname(nodeBin);
  const paths = [nodeDir];
  // Include the node prefix (e.g. /usr/local for brew-installed Node)
  const prefix = path.resolve(nodeDir, "..");
  if (fs.existsSync(prefix)) paths.push(prefix);
  return paths;
}

/**
 * S3-18 — a real skip, not a silent `return`.
 *
 * The old guard was a plain early return, which made the test REPORT AS PASSED
 * on a host with no native sandbox — so a CI leg without one looked like proof
 * of confinement. `it.skipIf` marks it skipped, which is the honest signal.
 *
 * win32 WAS excluded on top of that, because the AppContainer launcher answered
 * `CreateProcessW failed (code 203)` on GitHub-hosted runners. The cause was
 * this file, not the platform: it replaced the child environment with
 * `{ PATH, HOME }`, and an AppContainer profile lives under
 * `%LOCALAPPDATA%\Packages`, which CreateProcessW resolves from the
 * environment. An environment bisection on the CI runner showed LOCALAPPDATA
 * alone to be both necessary and sufficient - every other candidate still
 * failed, that one passed. The adapter now guarantees it
 * (`withAppContainerRequiredEnv`), so the requirement no longer rides on each
 * caller remembering it. See issue #1.
 *
 * The remaining skip is honest: a host with no native sandbox reports skipped,
 * never passed.
 */
const requiresSandbox = it.skipIf(!hasNativeSandbox);

describe("integration: filesystem isolation", () => {
  requiresSandbox("denies reading files outside allowed paths", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sb-int-"));
    // S3-18 — own the probe instead of depending on `~/.bashrc` existing. The
    // old test wrapped its only assertion in `if (fs.existsSync(sensitiveFile))`,
    // so on macOS — which ships no .bashrc — it ran the sandboxed spawn and
    // then asserted NOTHING AT ALL. The read-denial check was dead on a
    // platform it is meant to cover.
    const probeDir = fs.mkdtempSync(path.join(os.homedir(), ".sb-test-probe-"));
    const sensitiveFile = path.join(probeDir, "secret.txt");
    fs.writeFileSync(sensitiveFile, "top secret");

    const spec = await adapter.wrapSpawn({
      command: process.execPath,
      args: [
        "-e",
        `try { require('fs').readFileSync('${sensitiveFile}'); process.exit(0); } catch { process.exit(42); }`,
      ],
      cwd: tmpDir,
      env: { PATH: process.env.PATH || "", HOME: tmpDir },
      filesystem: {
        readPaths: [tmpDir, ...nodeBootReadPaths()],
        writePaths: [tmpDir],
      },
      network: { enabled: false, allowLoopback: false },
      // 2048 matches the production default: on Linux memoryMb now becomes a real
      // RLIMIT_AS cap and node needs well over 256 MiB of address space to boot.
      resources: { memoryMb: 2048, maxProcesses: 8 },
    });

    const result = spawnSync(spec.command, spec.args, {
      cwd: spec.cwd,
      env: spec.env,
      timeout: 15_000,
      encoding: "utf-8",
    });

    // S3-18 — assert the EXACT sentinel the injected script exits with when the
    // read throws. `not.toBe(0)` accepted any non-zero status, so a sandbox so
    // misconfigured that node could not even boot inside it counted as proof
    // of confinement.
    expect(result.status, result.stderr).toBe(42);

    fs.rmSync(probeDir, { recursive: true, force: true });
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  requiresSandbox("allows reading/writing within permitted paths", async () => {
    const tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sb-int-ok-")));
    const testFile = path.join(tmpDir, "test-input.txt");
    fs.writeFileSync(testFile, "hello sandbox");

    const spec = await adapter.wrapSpawn({
      command: process.execPath,
      args: [
        "-e",
        `const fs = require('fs'); ` +
          `const data = fs.readFileSync('${testFile}', 'utf-8'); ` +
          `fs.writeFileSync('${path.join(tmpDir, "output.txt")}', data.toUpperCase()); ` +
          `process.exit(0);`,
      ],
      cwd: tmpDir,
      env: { PATH: process.env.PATH || "", HOME: tmpDir },
      filesystem: {
        readPaths: [tmpDir, ...nodeBootReadPaths()],
        writePaths: [tmpDir],
      },
      network: { enabled: false, allowLoopback: false },
      // 2048 matches the production default: on Linux memoryMb now becomes a real
      // RLIMIT_AS cap and node needs well over 256 MiB of address space to boot.
      resources: { memoryMb: 2048, maxProcesses: 8 },
    });

    const result = spawnSync(spec.command, spec.args, {
      cwd: spec.cwd,
      env: spec.env,
      timeout: 15_000,
      encoding: "utf-8",
    });

    expect(result.status).toBe(0);
    const output = fs.readFileSync(path.join(tmpDir, "output.txt"), "utf-8");
    expect(output).toBe("HELLO SANDBOX");

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  requiresSandbox("denies writing outside allowed paths", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sb-int-deny-write-"));
    const forbiddenDir = fs.mkdtempSync(path.join(os.homedir(), ".sb-test-forbidden-"));
    const forbiddenPath = path.join(forbiddenDir, "should-not-exist.txt");

    const spec = await adapter.wrapSpawn({
      command: process.execPath,
      args: [
        "-e",
        `try { require('fs').writeFileSync('${forbiddenPath}', 'pwned'); process.exit(0); } catch { process.exit(42); }`,
      ],
      cwd: tmpDir,
      env: { PATH: process.env.PATH || "", HOME: tmpDir },
      filesystem: {
        readPaths: [tmpDir, ...nodeBootReadPaths()],
        writePaths: [tmpDir],
      },
      network: { enabled: false, allowLoopback: false },
      // 2048 matches the production default: on Linux memoryMb now becomes a real
      // RLIMIT_AS cap and node needs well over 256 MiB of address space to boot.
      resources: { memoryMb: 2048, maxProcesses: 8 },
    });

    const result = spawnSync(spec.command, spec.args, {
      cwd: spec.cwd,
      env: spec.env,
      timeout: 15_000,
      encoding: "utf-8",
    });

    const fileLanded = fs.existsSync(forbiddenPath);
    expect(fileLanded).toBe(false);
    // S3-18 — and the write must have been REFUSED, not merely absent because
    // the process never got far enough to attempt it.
    expect(result.status, result.stderr).toBe(42);

    fs.rmSync(tmpDir, { recursive: true, force: true });
    fs.rmSync(forbiddenDir, { recursive: true, force: true });
  });
});

describe("integration: network isolation", () => {
  requiresSandbox("blocks outbound network when disabled", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sb-int-net-"));

    const spec = await adapter.wrapSpawn({
      command: process.execPath,
      args: [
        "-e",
        `const http = require('http'); ` +
          `const req = http.get('http://1.1.1.1', { timeout: 3000 }, () => process.exit(0)); ` +
          `req.on('error', () => process.exit(42)); ` +
          `req.on('timeout', () => { req.destroy(); process.exit(42); });`,
      ],
      cwd: tmpDir,
      env: { PATH: process.env.PATH || "", HOME: tmpDir },
      filesystem: {
        readPaths: [tmpDir, ...nodeBootReadPaths()],
        writePaths: [tmpDir],
      },
      network: { enabled: false, allowLoopback: false },
      // 2048 matches the production default: on Linux memoryMb now becomes a real
      // RLIMIT_AS cap and node needs well over 256 MiB of address space to boot.
      resources: { memoryMb: 2048, maxProcesses: 8 },
    });

    const result = spawnSync(spec.command, spec.args, {
      cwd: spec.cwd,
      env: spec.env,
      timeout: 15_000,
      encoding: "utf-8",
    });

    // S3-18 — the script exits 42 on a connection error or timeout and 0 on a
    // successful response. `not.toBe(0)` also accepted "node failed to start",
    // which proves nothing about the network policy.
    expect(result.status, result.stderr).toBe(42);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});

describe("integration: adapter detection", () => {
  it("createSandboxedSpawn returns a valid adapter", async () => {
    const a = await createSandboxedSpawn("auto");
    expect(a.platform).toBeTruthy();
    expect(typeof a.wrapSpawn).toBe("function");
    expect(typeof a.available).toBe("function");
    expect(typeof a.capabilities).toBe("function");
  });

  it("off mode always returns passthrough", async () => {
    const a = await createSandboxedSpawn("off");
    expect(a.platform).toBe("passthrough");
  });
});
