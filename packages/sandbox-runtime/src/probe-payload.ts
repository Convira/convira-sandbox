/**
 * The subject of every destructive Windows capability probe.
 *
 * A probe proves an OS control by spawning a child that does one specific
 * thing and observing what the control did to it. Those children used to be
 * `process.execPath -e "<script>"`, which works under plain Node and is inert
 * in a packaged Electron build: the `runAsNode` fuse (deliberately disabled so
 * a signed application binary can never be reused as a general-purpose Node
 * interpreter) makes the app ignore `-e`, so the child booted the app, lost
 * the single-instance lock, exited 0, and every probe reported its control
 * unavailable. Re-enabling that fuse to make a self-test pass would trade a
 * real security control for a green check.
 *
 * The payload host is instead `convira_sbx_launch --selftest <verb>` - a
 * closed verb table inside the one binary the Windows sandbox already
 * requires, already ships, already gates at package time, and already signs.
 * It is not an interpreter: each verb is a fixed behavior with clamped
 * numeric arguments and no path from argv to code execution.
 */

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { resolveWinAppContainerLauncher } from "./win-appcontainer.js";

/** The closed set of behaviors the payload can be asked for. */
export type ProbeVerb =
  | "echo"
  | "idle"
  | "spawn-child"
  | "try-spawn"
  | "alloc"
  | "burn-cpu"
  | "fill"
  | "fs-check"
  | "listen"
  | "connect";

export interface ProbePayloadHost {
  /** Absolute path to the binary a probe spawns. */
  command: string;
  /** Argv that must precede the verb. */
  prefixArgs: string[];
  /**
   * Directories the payload needs to read to run at all. Granted to an
   * AppContainer child on top of whatever the probe itself declares - one
   * directory we own, rather than the whole Electron install root the old
   * `dirname(process.execPath)` grant handed over.
   */
  readGrants: string[];
}

let _hostOverride: ProbePayloadHost | null | undefined;

/**
 * The payload host for this platform, or null when no probe can run. Null is
 * a legitimate answer: it makes every Windows capability report false, which
 * is the correct fail-closed posture, and is preferable to a probe that
 * cannot distinguish "the control works" from "the child never started".
 */
export function resolveProbePayloadHost(
  platform: NodeJS.Platform = process.platform,
): ProbePayloadHost | null {
  if (_hostOverride !== undefined) return _hostOverride;
  if (platform !== "win32") return null;
  const launcher = resolveWinAppContainerLauncher(platform);
  if (launcher === null) return null;
  return { command: launcher, prefixArgs: ["--selftest"], readGrants: [path.dirname(launcher)] };
}

/** Full argv for one verb invocation. */
export function probePayloadArgv(
  host: ProbePayloadHost,
  verb: ProbeVerb,
  verbArgs: string[] = [],
): string[] {
  return [...host.prefixArgs, verb, ...verbArgs];
}

/**
 * Which stage of the handshake decided its verdict. `spawn-failed` is the one
 * that catches a launcher path resolved inside `app.asar`: `fs.existsSync` is
 * asar-patched and blesses it, `spawn` is not patched, and `CreateProcessW`
 * gets a path no kernel can open.
 */
export type SelftestHandshakeStage =
  | "not-run"
  | "ok"
  | "launcher-absent"
  | "spawn-failed"
  | "nonce-never-arrived"
  | "nonce-mismatch";

let _handshakeCache: boolean | null = null;
let _handshakeStage: SelftestHandshakeStage = "not-run";
let _handshakeOverride: boolean | null = null;

function syncSleep(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.max(0, ms));
}

function runHandshake(): boolean {
  const host = resolveProbePayloadHost();
  if (host === null) {
    _handshakeStage = "launcher-absent";
    return false;
  }
  let dir: string | null = null;
  try {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-selftest-"));
    const out = path.join(dir, "nonce");
    const nonce = randomBytes(16).toString("hex");
    const child = spawn(
      host.command,
      probePayloadArgv(host, "echo", ["--nonce", nonce, "--out", out]),
      {
        stdio: "ignore",
      },
    );
    child.on("error", () => {});
    child.unref();
    if (typeof child.pid !== "number") {
      _handshakeStage = "spawn-failed";
      return false;
    }
    // The EXIT CODE is deliberately ignored. A packaged Convira.exe that boots
    // and loses the single-instance lock also exits 0, so an exit status is
    // exactly the evidence that is worthless here. Only the nonce coming back
    // proves this binary ran THIS payload.
    for (let waited = 0; waited < 5_000; waited += 25) {
      let seen: string | null = null;
      try {
        seen = fs.readFileSync(out, "utf-8").trim();
      } catch {
        seen = null;
      }
      if (seen !== null && seen.length > 0) {
        if (seen === nonce) {
          _handshakeStage = "ok";
          return true;
        }
        _handshakeStage = "nonce-mismatch";
        return false;
      }
      syncSleep(25);
    }
    _handshakeStage = "nonce-never-arrived";
    return false;
  } catch {
    _handshakeStage = "spawn-failed";
    return false;
  } finally {
    if (dir !== null) {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
    }
  }
}

/**
 * True once this process has proven the payload host actually runs the verb
 * table. Cached: the handshake spawns a real process, and every probe asks.
 */
export function probeSelftestHandshake(): boolean {
  if (_handshakeOverride !== null) return _handshakeOverride;
  if (_handshakeCache === null) _handshakeCache = runHandshake();
  return _handshakeCache;
}

/** The stage that decided the last handshake run. */
export function selftestHandshakeStage(): SelftestHandshakeStage {
  return _handshakeStage;
}

/** Pin the payload host (tests only). `undefined` clears the override. */
export function _setProbePayloadHostForTests(host: ProbePayloadHost | null | undefined): void {
  _hostOverride = host;
}

/** Pin the handshake verdict (tests only). `null` clears the override. */
export function _setSelftestHandshakeForTests(result: boolean | null): void {
  _handshakeOverride = result;
}

/** Clear the payload-host override and the handshake cache (tests only). */
export function _resetProbePayloadHostCache(): void {
  _hostOverride = undefined;
  _handshakeCache = null;
  _handshakeOverride = null;
  _handshakeStage = "not-run";
}
