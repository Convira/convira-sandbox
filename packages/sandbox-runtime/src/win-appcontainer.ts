/**
 * Windows AppContainer isolation (HARDENING batch 5 - the second half of
 * Windows sandboxing, on top of the A2 inc2 Job Object resource controller).
 *
 * The `win_job_object.node` addon (ABI 2) adds the AppContainer profile
 * lifecycle (userenv: CreateAppContainerProfile / DeriveAppContainerSid /
 * DeleteAppContainerProfile) plus orphan-ACE removal, and the build produces a
 * companion launcher EXE (`convira_sbx_launch.exe`). The launcher is the spawn
 * primitive: SECURITY_CAPABILITIES must be present at CreateProcessW time, so
 * AppContainer can never be applied by a post-spawn hook the way Job Objects
 * are - the launcher is used AS the wrapper command (argv-level, exactly like
 * `sandbox-exec` / `bwrap` on the other adapters) and internally does
 * CreateProcessW(CREATE_SUSPENDED) + assign-to-job + ResumeThread, making job
 * caging race-free from the child's first instruction.
 *
 * Why AppContainer and not a restricted/low-integrity token: a restricted
 * token provides NO outbound-network deny and only integrity-level WRITE
 * blocking (no read confinement), so advertising isolation while enforcing
 * strictly less would be dishonest. AppContainer is the only Windows
 * primitive that gives default-deny outbound network (no capability SIDs)
 * plus deny-by-default filesystem (no ACE for the AC SID = no access), and it
 * composes with the inc2 Job Object on the same child (nested jobs, Win8+).
 * On any probe failure the tools stay hidden - there is no weaker fallback.
 *
 * Every capability claim keys on its own destructive probe in the exact
 * `probes.ts` idiom: spawn REAL processes through the REAL launcher, observe
 * enforcement, cache once per process, carry a test override. Off win32 every
 * probe is false immediately, so nothing is ever advertised from macOS/Linux.
 *
 * Known environmental interference (documented, not worked around): antivirus
 * software may block AppContainer process creation or scan-lock the granted
 * workspace. Both surface as a spawn failure or a failing probe, i.e. a
 * fail-closed refusal - never a silent degradation.
 */

import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import {
  probePayloadArgv,
  probeSelftestHandshake,
  resolveProbePayloadHost,
  type ProbeVerb,
} from "./probe-payload.js";
import { loadWinJobObjectBindings, type WinJobObjectBindings } from "./win-job-object.js";
import { resolveDenyLeafKind } from "./deny-leaf-kind.js";

/** Prefix of every ephemeral per-spawn AppContainer profile this package creates. */
export const WIN_APPCONTAINER_PROFILE_PREFIX = "ConviraSbx";

export interface WinAppContainerBindings extends WinJobObjectBindings {
  /** Create (or reuse) a per-user profile; returns the AppContainer SID string. */
  createAppContainerProfile(name: string): string;
  /** Deterministically derive the SID string for a profile name. */
  deriveAppContainerSid(name: string): string;
  /** Delete a profile. Idempotent: an already-deleted profile is a no-op. */
  deleteAppContainerProfile(name: string): void;
  /**
   * Remove every ACE for the profile's SID from a path's DACL (propagates to
   * descendants). Used by the boot janitor so crash-orphaned grants cannot
   * accumulate on user directories.
   */
  removeAppContainerAce(target: string, name: string): void;
}

// ─── bindings loading ───────────────────────────────────────────────────────

let _bindingsOverride: WinAppContainerBindings | null | undefined;

/**
 * Load the AppContainer surface of the unified addon. Null off win32, when
 * the addon is absent, or when the built binary predates ABI 2 (an old
 * Job-Object-only binary must never be treated as an AppContainer authority).
 */
export function loadWinAppContainerBindings(
  platform: NodeJS.Platform = process.platform,
): WinAppContainerBindings | null {
  if (_bindingsOverride !== undefined) return _bindingsOverride;
  if (platform !== "win32") return null;
  const base = loadWinJobObjectBindings(platform);
  if (base === null) return null;
  const candidate = base as WinAppContainerBindings;
  if (
    typeof candidate.createAppContainerProfile !== "function" ||
    typeof candidate.deriveAppContainerSid !== "function" ||
    typeof candidate.deleteAppContainerProfile !== "function" ||
    typeof candidate.removeAppContainerAce !== "function"
  ) {
    return null;
  }
  try {
    if (candidate.getInfo().abiVersion < 2) return null;
  } catch {
    return null;
  }
  return candidate;
}

/** Pin the AppContainer bindings (tests only). Null simulates an absent addon. */
export function _setWinAppContainerBindingsForTests(
  bindings: WinAppContainerBindings | null,
): void {
  _bindingsOverride = bindings;
}

/** Clear the AppContainer bindings override (tests only). */
export function _resetWinAppContainerBindingsCache(): void {
  _bindingsOverride = undefined;
}

// ─── launcher resolution ────────────────────────────────────────────────────

let _launcherPathCache: string | null | undefined;

// Resolves to the package-root `native/` from both `src/` and `dist/`,
// mirroring the addon path in win-job-object.ts. Lazy + guarded: under test
// bundlers `import.meta.url` may not be a file URL (the desktop vitest jsdom
// pipeline), and a probe module must degrade to "absent" there, never crash
// at import time.
function launcherCandidatePath(): string | null {
  if (_launcherPathCache !== undefined) return _launcherPathCache;
  try {
    const raw = fileURLToPath(
      new URL("../native/build/Release/convira_sbx_launch.exe", import.meta.url),
    );
    // In a packaged build this module lives inside `app.asar`, so `raw` names a
    // path INSIDE the archive. `fs.existsSync` is asar-patched and answers true
    // for it, but `spawn`/`spawnSync` are NOT patched (Electron hooks only
    // exec/execSync/execFile/execFileSync), so `CreateProcessW` gets a path no
    // kernel can open. Prefer the `app.asar.unpacked` twin, where `asarUnpack`
    // put the real bytes; that directory is not an archive boundary, so the
    // existence check on it is a genuine filesystem check.
    const twin = _unpackedTwinPath(raw);
    _launcherPathCache = twin !== raw && fs.existsSync(twin) ? twin : raw;
  } catch {
    _launcherPathCache = null;
  }
  return _launcherPathCache;
}

/**
 * Map a path inside `app.asar` to its `app.asar.unpacked` twin. Returns the
 * input unchanged when it is not inside an archive (dev, tests, the API
 * server). Both separators are handled: the URL round-trip can yield either.
 */
export function _unpackedTwinPath(target: string): string {
  for (const sep of ["\\", "/"]) {
    const marker = `app.asar${sep}`;
    const at = target.indexOf(marker);
    if (at !== -1) {
      return target.slice(0, at) + `app.asar.unpacked${sep}` + target.slice(at + marker.length);
    }
  }
  return target;
}

let _launcherOverride: string | null | undefined;

/** Absolute launcher path when built and present on win32; null otherwise. */
export function resolveWinAppContainerLauncher(
  platform: NodeJS.Platform = process.platform,
): string | null {
  if (_launcherOverride !== undefined) return _launcherOverride;
  if (platform !== "win32") return null;
  const candidate = launcherCandidatePath();
  return candidate !== null && fs.existsSync(candidate) ? candidate : null;
}

/** Pin the launcher path (tests only). `undefined` clears the override. */
export function _setWinAppContainerLauncherForTests(
  launcher: string | null | undefined,
): void {
  _launcherOverride = launcher;
}

// ─── grants file + orphaned-profile ledger ──────────────────────────────────

export interface WinAppContainerGrants {
  /** Directories/files the AC child may read (GENERIC_READ|EXECUTE ACE). */
  readPaths: string[];
  /** Directories the AC child may read and write. */
  writePaths: string[];
  /** Explicit DENY ACEs carved out of broader grants (deny wins). */
  denyPaths?: string[];
  /** Leaf kind for deny paths that may still need to be materialized. */
  denyPathKinds?: Record<string, "file" | "dir">;
}

/**
 * Deny-leaf kinds moved to `../deny-leaf-kind.js` so Linux shares ONE table
 * with Windows. Both platforms materialize a missing deny path, and both are
 * broken in the same unrecoverable way by guessing the kind wrong, so the
 * authority may not be duplicated per adapter.
 */

let _ledgerDirOverride: string | null = null;

/**
 * On-disk ledger of live/orphaned AppContainer profiles: one grants file per
 * profile, named `<profileName>.grants`. The launcher deletes the profile and
 * revokes its ACEs in its own `finally`; a crash/kill before that leaves the
 * ledger entry behind for {@link sweepOrphanedAppContainerProfiles} at next
 * boot. Kept under the OS tmpdir - losing it to a temp sweep only means the
 * janitor has nothing to do.
 */
export function winAppContainerLedgerDir(): string {
  return _ledgerDirOverride ?? path.join(os.tmpdir(), "convira-appcontainer-ledger");
}

/** Redirect the ledger dir (tests only). Null restores the default. */
export function _setWinAppContainerLedgerDirForTests(dir: string | null): void {
  _ledgerDirOverride = dir;
}

/**
 * Serialize grants as `deny|read|write<TAB>path` lines. Tab-separated is
 * parse-safe: tabs and newlines are illegal in Windows paths, so no quoting
 * layer (or hand-rolled JSON parser in the launcher) is needed.
 */
export function formatAppContainerGrants(grants: WinAppContainerGrants): string {
  const lines: string[] = [];
  for (const p of grants.denyPaths ?? []) lines.push(`deny\t${p}`);
  for (const p of grants.readPaths) lines.push(`read\t${p}`);
  for (const p of grants.writePaths) lines.push(`write\t${p}`);
  return lines.map((l) => `${l}\n`).join("");
}

export interface PreparedAppContainerSpawn {
  /** Ephemeral profile name (<= 64 chars, prefix {@link WIN_APPCONTAINER_PROFILE_PREFIX}). */
  profileName: string;
  /** Ledger-backed grants file consumed (and deleted) by the launcher. */
  grantsFile: string;
}

let _existsOverride: ((p: string) => boolean) | null = null;

/**
 * Existence predicate for grant paths. Injectable because the rest of this
 * suite deliberately exercises Windows decision logic on POSIX hosts with
 * synthetic `C:\...` paths; a hard-wired `fs.existsSync` would make every one
 * of those cases collapse to "nothing exists" and stop testing the logic.
 */
function _grantPathExists(p: string): boolean {
  return _existsOverride ? _existsOverride(p) : fs.existsSync(p);
}

/** Pin the grant-path existence predicate (tests only). Null restores fs. */
export function _setGrantPathExistsForTests(fn: ((p: string) => boolean) | null): void {
  _existsOverride = fn;
}

/**
 * Drop grant paths that do not exist.
 *
 * `GetNamedSecurityInfoW` answers ERROR_FILE_NOT_FOUND (2) for an absent path,
 * and the launcher treats any grant failure as fatal - so ONE missing optional
 * directory refused the whole spawn. That is not hypothetical: the desktop's
 * read floor includes `~/.convira/python-env`, a user venv that a packaged
 * install has never created (it ships its own interpreter), so on a clean
 * Windows machine every sandboxed code-execution spawn failed with
 * "granting directory access failed (code 2)".
 *
 * Skipping is correct rather than a workaround: an ACE on a path that does not
 * exist grants nothing, and AppContainer is deny-by-default, so a path with no
 * ACE is already unreachable.
 *
 * DENY paths are the one case that needs care. A missing deny is normally moot
 * for the same deny-by-default reason, but if it sits INSIDE a surviving grant
 * it would inherit that grant the moment something creates it. That is a real
 * hole, so it is refused rather than dropped.
 */
export function filterGrantsToExistingPaths(
  grants: WinAppContainerGrants,
  exists: (p: string) => boolean = _grantPathExists,
): {
  grants: WinAppContainerGrants;
  dropped: string[];
  materialize: Array<{ path: string; kind: "file" | "dir" }>;
} {
  const keep = (paths: string[]): string[] => paths.filter((p) => exists(p));
  const readPaths = keep(grants.readPaths);
  const writePaths = keep(grants.writePaths);
  const dropped = [...grants.readPaths, ...grants.writePaths].filter((p) => !exists(p));
  const materialize: Array<{ path: string; kind: "file" | "dir" }> = [];

  const denyPaths = grants.denyPaths?.filter((p) => {
    if (exists(p)) return true;
    const within = [...readPaths, ...writePaths].find((granted) => isPathWithin(p, granted));
    if (within === undefined) {
      // Unreachable through any surviving grant, and AppContainer is
      // deny-by-default, so there is nothing to carve out of.
      dropped.push(p);
      return false;
    }
    // Inside a surviving grant: it would inherit that grant the moment
    // anything created it. Refusing outright is what broke every Windows
    // STDIO MCP spawn - the shipped deny list is ~20 home-relative paths,
    // most of which cannot exist on Windows at all. Materialize instead, so
    // the DENY ace has a real object and the name is occupied.
    const kind = resolveDenyLeafKind(p, grants.denyPathKinds);
    if (kind === null) {
      // Still fail closed when the kind is genuinely unknown: creating a file
      // as a directory (or the reverse) is not recoverable for the user.
      throw new Error(
        `[sandbox-runtime] deny path ${p} does not exist, lies inside granted ${within}, and ` +
          "its leaf kind is unknown (supply filesystem.denyPathKinds); refusing to spawn " +
          "rather than let it inherit that grant if created",
      );
    }
    materialize.push({ path: p, kind });
    return true;
  });

  return {
    grants: {
      readPaths,
      writePaths,
      ...(denyPaths ? { denyPaths } : {}),
      ...(grants.denyPathKinds ? { denyPathKinds: grants.denyPathKinds } : {}),
    },
    dropped,
    materialize,
  };
}

/** Case-insensitive containment test on Windows path separators. */
function isPathWithin(candidate: string, parent: string): boolean {
  const norm = (p: string): string => p.replace(/[\\/]+$/u, "").toLowerCase();
  const c = norm(candidate);
  const p = norm(parent);
  return c === p || c.startsWith(`${p}\\`) || c.startsWith(`${p}/`);
}

/**
 * Allocate an ephemeral profile name and write its ledger-backed grants file.
 * Called by the Windows adapter's wrapSpawn immediately before handing the
 * launcher command to the runner.
 */
export function prepareAppContainerSpawn(
  grants: WinAppContainerGrants,
): PreparedAppContainerSpawn {
  const profileName = `${WIN_APPCONTAINER_PROFILE_PREFIX}-${randomBytes(8).toString("hex")}`;
  const dir = winAppContainerLedgerDir();
  fs.mkdirSync(dir, { recursive: true });
  const grantsFile = path.join(dir, `${profileName}.grants`);
  const filtered = filterGrantsToExistingPaths(grants);
  // Create the deny leaves the filter could not find, so their DENY aces land
  // on a real object. Best-effort per path, but a failure THROWS: silently
  // dropping the deny would leave the path writable through the broader grant,
  // which is the hole this whole branch exists to close.
  for (const entry of filtered.materialize) {
    try {
      if (entry.kind === "dir") {
        fs.mkdirSync(entry.path, { recursive: true });
      } else {
        fs.mkdirSync(path.dirname(entry.path), { recursive: true });
        try {
          fs.writeFileSync(entry.path, "", { flag: "wx" });
        } catch (err) {
          // Someone created it between the existence check and now - fine,
          // the ace still lands. Anything else is a real failure.
          if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
        }
      }
    } catch (err) {
      throw new Error(
        `[sandbox-runtime] could not materialize deny path ${entry.path} ` +
          `(${err instanceof Error ? err.message : String(err)}); refusing to spawn rather ` +
          "than leave it writable through a broader grant",
      );
    }
  }
  fs.writeFileSync(grantsFile, formatAppContainerGrants(filtered.grants));
  return { profileName, grantsFile };
}

/**
 * Boot janitor: delete profiles (and revoke their directory ACEs) that a
 * crash or hard kill orphaned. Idempotent - deleting an absent profile or
 * removing absent ACEs is a no-op - and scoped strictly to ledger entries
 * whose name carries this package's profile prefix, so it can never touch a
 * foreign AppContainer profile. Returns the number of entries swept.
 */
export function sweepOrphanedAppContainerProfiles(
  platform: NodeJS.Platform = process.platform,
): number {
  if (platform !== "win32") return 0;
  const bindings = loadWinAppContainerBindings(platform);
  if (bindings === null) return 0;
  const dir = winAppContainerLedgerDir();
  let entries: string[];
  try {
    entries = fs.readdirSync(dir);
  } catch {
    return 0;
  }
  let swept = 0;
  for (const entry of entries) {
    if (!entry.startsWith(WIN_APPCONTAINER_PROFILE_PREFIX) || !entry.endsWith(".grants")) {
      continue;
    }
    const profileName = entry.slice(0, -".grants".length);
    const grantsFile = path.join(dir, entry);
    try {
      const raw = fs.readFileSync(grantsFile, "utf-8");
      for (const line of raw.split("\n")) {
        const tab = line.indexOf("\t");
        if (tab <= 0) continue;
        const target = line.slice(tab + 1);
        try {
          bindings.removeAppContainerAce(target, profileName);
        } catch {
          /* best-effort per path; the profile delete below is the authority */
        }
      }
      bindings.deleteAppContainerProfile(profileName);
      fs.rmSync(grantsFile, { force: true });
      swept += 1;
    } catch {
      // Leave the entry for the next boot rather than dropping the record of
      // an undeleted profile.
    }
  }
  return swept;
}

// ─── shared probe helpers (probes.ts idiom) ─────────────────────────────────

function syncSleep(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.max(0, ms));
}

/** True iff `pid` still exists (win32: libuv reports exited pids dead). */
function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

function killBestEffort(pid: number | null): void {
  if (pid === null || pid <= 0) return;
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    /* already reaped */
  }
}

function pollUntil(condition: () => boolean, timeoutMs: number, stepMs = 20): boolean {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (condition()) return true;
    if (Date.now() >= deadline) return false;
    syncSleep(stepMs);
  }
}

function readFileTrimmed(file: string): string | null {
  try {
    return fs.readFileSync(file, "utf-8").trim();
  } catch {
    return null;
  }
}

function rmBestEffort(target: string | null): void {
  if (!target) return;
  try {
    fs.rmSync(target, { recursive: true, force: true });
  } catch {
    /* best-effort */
  }
}

interface LauncherSpawn {
  launcherPid: number;
  profileName: string;
  grantsFile: string;
}

/**
 * Spawn `node -e script args...` inside a fresh ephemeral AppContainer via
 * the real launcher. The grants always include the Node executable's own
 * directory (user-local tool dirs carry no ALL APPLICATION PACKAGES ACE, so
 * the AC child could not even load its interpreter without it). Returns null
 * when the spawn cannot start.
 */
function spawnViaLauncher(
  launcher: string,
  grants: WinAppContainerGrants,
  options: { allowNetwork?: boolean; probeReportFile?: string; cwd?: string },
  verb: ProbeVerb,
  verbArgs: string[],
): LauncherSpawn | null {
  const host = resolveProbePayloadHost();
  if (host === null) return null;
  try {
    const prepared = prepareAppContainerSpawn({
      // The payload's own directory, not the entire Electron install root that
      // `dirname(process.execPath)` used to hand over. It is one directory we
      // build and ship, and it matches production, where `wrapSpawn` already
      // grants `dirname(config.command)`.
      readPaths: [...grants.readPaths, ...host.readGrants],
      writePaths: grants.writePaths,
      ...(grants.denyPaths ? { denyPaths: grants.denyPaths } : {}),
    });
    const args = [
      prepared.profileName,
      prepared.grantsFile,
      ...(options.allowNetwork ? ["--allow-network"] : []),
      ...(options.probeReportFile ? ["--probe-report", options.probeReportFile] : []),
      "--",
      // The launcher spawns ITSELF as the confined payload. No interpreter is
      // involved, so nothing here depends on the `runAsNode` fuse.
      host.command,
      ...probePayloadArgv(host, verb, verbArgs),
    ];
    // cwd defaults to the granted dir so the AC child never starts inside a
    // directory its token cannot even stat.
    const child = spawn(launcher, args, {
      stdio: "ignore",
      ...(options.cwd ? { cwd: options.cwd } : {}),
    });
    child.on("error", () => {});
    child.unref();
    if (typeof child.pid !== "number") return null;
    return { launcherPid: child.pid, profileName: prepared.profileName, grantsFile: prepared.grantsFile };
  } catch {
    return null;
  }
}

function cleanupLauncherSpawn(
  bindings: WinAppContainerBindings,
  spawned: LauncherSpawn | null,
): void {
  if (spawned === null) return;
  killBestEffort(spawned.launcherPid);
  rmBestEffort(spawned.grantsFile);
  try {
    bindings.deleteAppContainerProfile(spawned.profileName);
  } catch {
    /* launcher already deleted it */
  }
}

// ─── filesystem isolation probe ─────────────────────────────────────────────

/**
 * Prove AppContainer filesystem confinement with three legs:
 *   1. control - a PLAIN child reads the outside file (the file is readable
 *      by this user, so leg 2 cannot pass vacuously);
 *   2. the AC child CANNOT read a file outside its grants (user temp carries
 *      no ALL APPLICATION PACKAGES ACE and the dir is not granted);
 *   3. the AC child CAN read + write inside the granted dir (which also
 *      proves the AC child runs at all - the anti-false-positive leg).
 * Backs `filesystemIsolation` on Windows.
 */
export function _runAppContainerFilesystemProbe(
  platform: NodeJS.Platform = process.platform,
): boolean {
  if (platform !== "win32") return false;
  const bindings = loadWinAppContainerBindings(platform);
  const launcher = resolveWinAppContainerLauncher(platform);
  if (bindings === null || launcher === null) return false;
  // No payload host means no probe subject at all. Reporting the control
  // unavailable is the correct fail-closed answer; guessing is not.
  if (!probeSelftestHandshake()) return false;
  let outsideDir: string | null = null;
  let grantedDir: string | null = null;
  let spawned: LauncherSpawn | null = null;
  try {
    outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-ac-outside-"));
    grantedDir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-ac-granted-"));
    const outsideFile = path.join(outsideDir, "secret.txt");
    fs.writeFileSync(outsideFile, "outside-secret");

    // Control leg: an UNCONFINED payload running the identical verb must read
    // the outside file and write inside its grant. Checking only the exit
    // status - what this did before - is satisfied by any child that exits 0
    // without doing the work, which is precisely how a packaged build's
    // quitting probe child defeated the anti-false-positive guard.
    const host = resolveProbePayloadHost();
    if (host === null) return false;
    const controlDir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-ac-control-"));
    try {
      spawnSync(
        host.command,
        probePayloadArgv(host, "fs-check", [
          "--outside",
          outsideFile,
          "--granted",
          controlDir,
        ]),
        { stdio: "ignore", timeout: 30_000 },
      );
      if (readFileTrimmed(path.join(controlDir, "result.txt")) !== "read:ok") return false;
    } finally {
      rmBestEffort(controlDir);
    }

    // IDENTICAL argv to the control leg above. The only difference is the
    // AppContainer token, which the child cannot see - so a divergence in the
    // verdict can only have come from the confinement.
    spawned = spawnViaLauncher(
      launcher,
      { readPaths: [], writePaths: [grantedDir] },
      { cwd: grantedDir },
      "fs-check",
      ["--outside", outsideFile, "--granted", grantedDir],
    );
    if (spawned === null) return false;
    const resultFile = path.join(grantedDir, "result.txt");
    if (!pollUntil(() => readFileTrimmed(resultFile) !== null, 60_000)) return false;
    return readFileTrimmed(resultFile) === "denied:ok";
  } catch {
    return false;
  } finally {
    if (bindings !== null) cleanupLauncherSpawn(bindings, spawned);
    rmBestEffort(outsideDir);
    rmBestEffort(grantedDir);
  }
}

let _fsCache: boolean | null = null;
let _fsOverride: boolean | null = null;

export function probeAppContainerFilesystem(): boolean {
  if (_fsOverride !== null) return _fsOverride;
  if (_fsCache === null) _fsCache = _runAppContainerFilesystemProbe();
  return _fsCache;
}

export function _setAppContainerFilesystemProbeForTests(result: boolean | null): void {
  _fsOverride = result;
}

export function _resetAppContainerFilesystemProbeCache(): void {
  _fsCache = null;
  _fsOverride = null;
}

// ─── network isolation probe ────────────────────────────────────────────────

/**
 * Prove default-deny outbound: a localhost TCP listener child accepts a
 * connection from a PLAIN control child (proving the stack + listener work,
 * so the denial leg cannot pass vacuously), while the AC child - spawned with
 * NO network capability SIDs - must fail the same connect. AppContainer
 * denies loopback and internet through the same capability check, and this
 * two-leg local design keeps the probe hermetic (no real egress from CI).
 * Backs `networkIsolation` on Windows.
 */
export function _runAppContainerNetworkProbe(
  platform: NodeJS.Platform = process.platform,
): boolean {
  if (platform !== "win32") return false;
  const bindings = loadWinAppContainerBindings(platform);
  const launcher = resolveWinAppContainerLauncher(platform);
  if (bindings === null || launcher === null) return false;
  // No payload host means no probe subject at all. Reporting the control
  // unavailable is the correct fail-closed answer; guessing is not.
  if (!probeSelftestHandshake()) return false;
  let scratch: string | null = null;
  let grantedDir: string | null = null;
  let listenerPid: number | null = null;
  let spawned: LauncherSpawn | null = null;
  try {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-ac-net-"));
    grantedDir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-ac-netgrant-"));
    const portFile = path.join(scratch, "port");
    const host = resolveProbePayloadHost();
    if (host === null) return false;
    const listener = spawn(
      host.command,
      probePayloadArgv(host, "listen", ["--port-file", portFile]),
      { stdio: "ignore" },
    );
    listener.on("error", () => {});
    listener.unref();
    if (typeof listener.pid !== "number") return false;
    listenerPid = listener.pid;

    let port: number | null = null;
    if (
      !pollUntil(() => {
        const raw = readFileTrimmed(portFile);
        if (raw !== null && /^\d+$/.test(raw)) {
          port = Number(raw);
          return true;
        }
        return false;
      }, 30_000)
    ) {
      return false;
    }

    // Control leg: the UNCONFINED payload must reach the listener, so the AC
    // leg's denial cannot be blamed on a listener that was never up.
    const controlResult = path.join(scratch, "control-result");
    const control = spawnSync(
      host.command,
      probePayloadArgv(host, "connect", ["--port", String(port), "--out", controlResult]),
      { stdio: "ignore", timeout: 30_000 },
    );
    if (control.error || readFileTrimmed(controlResult) !== "connected") return false;

    // AC leg: same connect, no capability SIDs - must be denied.
    const acResult = path.join(grantedDir, "result");
    spawned = spawnViaLauncher(
      launcher,
      { readPaths: [], writePaths: [grantedDir] },
      { cwd: grantedDir },
      "connect",
      ["--port", String(port), "--out", acResult],
    );
    if (spawned === null) return false;
    if (!pollUntil(() => readFileTrimmed(acResult) !== null, 60_000)) return false;
    const verdict = readFileTrimmed(acResult);
    return verdict === "denied" || verdict === "timeout";
  } catch {
    return false;
  } finally {
    if (bindings !== null) cleanupLauncherSpawn(bindings, spawned);
    killBestEffort(listenerPid);
    rmBestEffort(scratch);
    rmBestEffort(grantedDir);
  }
}

let _netCache: boolean | null = null;
let _netOverride: boolean | null = null;

export function probeAppContainerNetwork(): boolean {
  if (_netOverride !== null) return _netOverride;
  if (_netCache === null) _netCache = _runAppContainerNetworkProbe();
  return _netCache;
}

export function _setAppContainerNetworkProbeForTests(result: boolean | null): void {
  _netOverride = result;
}

export function _resetAppContainerNetworkProbeCache(): void {
  _netCache = null;
  _netOverride = null;
}

// ─── suspended-spawn job-caging probe ───────────────────────────────────────

/**
 * Prove the race-free spawn guarantee the inc2 addon could not give: the
 * launcher creates the child CREATE_SUSPENDED, assigns it to its
 * kill-on-close job, and only then resumes - so job caging holds from the
 * first instruction. `--probe-report` makes the launcher write the
 * IsProcessInJob verdict (taken while the child is STILL SUSPENDED) plus the
 * child pid; the AC child then forks a grandchild, and killing the launcher
 * must reap BOTH through the job's kill-on-close. Distinct from inc2's
 * kill-tree probe, which only covers post-spawn assignment.
 */
export function _runAppContainerSpawnCagingProbe(
  platform: NodeJS.Platform = process.platform,
): boolean {
  if (platform !== "win32") return false;
  const bindings = loadWinAppContainerBindings(platform);
  const launcher = resolveWinAppContainerLauncher(platform);
  if (bindings === null || launcher === null) return false;
  // No payload host means no probe subject at all. Reporting the control
  // unavailable is the correct fail-closed answer; guessing is not.
  if (!probeSelftestHandshake()) return false;
  let scratch: string | null = null;
  let grantedDir: string | null = null;
  let spawned: LauncherSpawn | null = null;
  let childPid: number | null = null;
  let grandchildPid: number | null = null;
  try {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-ac-cage-"));
    grantedDir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-ac-cagegrant-"));
    const reportFile = path.join(scratch, "report");
    const gpidFile = path.join(grantedDir, "gpid");
    // No `--wait-for` gate here: the launcher assigns the child to its job
    // BEFORE ResumeThread, so unlike the post-spawn Job Object path there is no
    // pre-assignment window for the grandchild to escape through. Proving that
    // is the entire point of this probe.
    spawned = spawnViaLauncher(
      launcher,
      { readPaths: [], writePaths: [grantedDir] },
      { probeReportFile: reportFile, cwd: grantedDir },
      "spawn-child",
      ["--pid-file", gpidFile],
    );
    if (spawned === null) return false;

    // The launcher reports caged=<IsProcessInJob> BEFORE ResumeThread.
    if (!pollUntil(() => readFileTrimmed(reportFile) !== null, 60_000)) return false;
    const report = readFileTrimmed(reportFile) ?? "";
    const caged = /(^|\n)caged=1(\n|$)/.test(report);
    const pidMatch = /(^|\n)pid=(\d+)(\n|$)/.exec(report);
    if (!caged || pidMatch === null) return false;
    childPid = Number(pidMatch[2]);

    if (
      !pollUntil(() => {
        const raw = readFileTrimmed(gpidFile);
        if (raw !== null && /^\d+$/.test(raw)) {
          grandchildPid = Number(raw);
          return true;
        }
        return false;
      }, 60_000)
    ) {
      return false;
    }
    const gPid: number = grandchildPid!;
    if (!isAlive(childPid) || !isAlive(gPid)) return false;

    // Kill the launcher: its internal job handle closes and kill-on-close
    // must reap the whole caged tree.
    killBestEffort(spawned.launcherPid);
    const cPid = childPid;
    return pollUntil(() => !isAlive(cPid) && !isAlive(gPid), 30_000);
  } catch {
    return false;
  } finally {
    if (bindings !== null) cleanupLauncherSpawn(bindings, spawned);
    killBestEffort(childPid);
    killBestEffort(grandchildPid);
    rmBestEffort(scratch);
    rmBestEffort(grantedDir);
  }
}

let _cagingCache: boolean | null = null;
let _cagingOverride: boolean | null = null;

export function probeAppContainerSpawnCaging(): boolean {
  if (_cagingOverride !== null) return _cagingOverride;
  if (_cagingCache === null) _cagingCache = _runAppContainerSpawnCagingProbe();
  return _cagingCache;
}

export function _setAppContainerSpawnCagingProbeForTests(result: boolean | null): void {
  _cagingOverride = result;
}

export function _resetAppContainerSpawnCagingProbeCache(): void {
  _cagingCache = null;
  _cagingOverride = null;
}

// ─── aggregate report ───────────────────────────────────────────────────────

export interface WinAppContainerProbeReport {
  filesystemIsolation: boolean;
  networkIsolation: boolean;
  spawnCaging: boolean;
}

/** One-stop probe summary for the adapter + the desktop boot warm gate. */
export function probeWinAppContainerReport(): WinAppContainerProbeReport {
  return {
    filesystemIsolation: probeAppContainerFilesystem(),
    networkIsolation: probeAppContainerNetwork(),
    spawnCaging: probeAppContainerSpawnCaging(),
  };
}
