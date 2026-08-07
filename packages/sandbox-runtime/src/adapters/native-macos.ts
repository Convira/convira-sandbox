/**
 * macOS sandbox adapter — uses sandbox-exec with dynamically generated
 * Seatbelt (.sb) profiles for filesystem and network isolation.
 *
 * sandbox-exec ships with macOS and applies the profile at process launch.
 * The profile uses a deny-default posture: only explicitly allowed
 * operations succeed.
 *
 * Note: Apple deprecated sandbox-exec in macOS 10.15 but it still works
 * through macOS 15 (Sequoia). There is no CLI-level replacement. If Apple
 * removes it, detect.ts falls back to passthrough with a warning.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import type {
  ExecutionCapabilityReportV2,
  SandboxAdapter,
  SandboxCapabilities,
  SandboxSpawnConfig,
  SpawnSpec,
} from "../types.js";
import { probeRlimitSupport, rlimitValuesFromResources, wrapWithRlimit } from "../rlimit.js";
import { probeDescendantKill } from "../probes.js";
import { probeRssWatchdogSupport } from "../rss-watchdog.js";

/**
 * Canonical absolute path of the macOS Seatbelt driver. It is a SIP-protected
 * system binary and cannot be relocated, so an absolute-path `existsSync` is
 * both simpler and less spoofable than a `PATH` walk. Exported so the desktop
 * catalog-gate probe (`checkSandboxAvailability`) and this adapter's
 * `available()` share ONE definition and can never disagree (9.2 B2).
 */
export const SANDBOX_EXEC_PATH = "/usr/bin/sandbox-exec";
const SANDBOX_EXEC_BIN = SANDBOX_EXEC_PATH;

/** Single source of truth for "can this host run sandbox-exec at all". */
export function isSandboxExecAvailable(): boolean {
  return fs.existsSync(SANDBOX_EXEC_PATH);
}

/**
 * Sensitive home-relative directories the legacy allow-default fallback must
 * never expose to a code-execution subprocess. Mirrors the desktop filesystem
 * denylist (apps/desktop CLAUDE.md — .ssh/.gnupg/.aws/.azure/.kube/.docker)
 * plus `~/.convira` (the secret store: browser-bridge bearer token, offline-
 * license token, encrypted convira-store DBs — the exact B17 class), denied via
 * last-match-wins rules appended after `(allow default)`.
 */
export const LEGACY_MACOS_SENSITIVE_HOME_DIRS: readonly string[] = [
  ".ssh",
  ".gnupg",
  ".aws",
  ".azure",
  ".kube",
  ".docker",
  ".convira",
];

/**
 * Interpreter read-floor under `~/.convira` re-allowed AFTER the `~/.convira`
 * deny (last-match-wins) so code execution still works: the bundled venv lives
 * under `python-env` and the exec script is staged under `exec-staging`.
 */
export const LEGACY_MACOS_CONVIRA_READ_FLOOR: readonly string[] = [
  ".convira/python-env",
  ".convira/exec-staging",
];

/**
 * Legacy allow-default + deny-network Seatbelt profile, hardened with a
 * home-derived deny FLOOR (9.2 B1; T0.3).
 *
 * This is the compatibility profile the desktop runner may use for narrowly
 * trusted git/archive/OCR commands when the shared adapter is unavailable.
 * Model-authored code execution fails closed in that situation; the profile is
 * available to execute_* only through the explicit development-only
 * `CONVIRA_FF_SANDBOX_DENY_DEFAULT=false` opt-out and is then reported as
 * unisolated. `allow default` avoids enumerating every dyld / mach / sysctl op
 * each interpreter needs; `(deny network*)` closes subprocess egress
 * (loopback included).
 *
 * T0.3: `(allow default)` on its own grants WHOLE-FILESYSTEM read (and write),
 * so on this fallback a subprocess could read `~/.ssh`, `~/.aws`, the browser
 * cookies, the offline-license token and the `~/.convira` secret store — and,
 * via the `/System/Volumes/Data` APFS data-volume alias, every home dir even
 * when addressed through that mount (B18). We keep allow-default for
 * interpreter compatibility but append last-match-wins denies for those
 * sensitive targets, then re-allow the interpreter read-floor so exec still
 * runs. Coarse FS confinement is still enforced upstream by the approved-roots
 * check; this deny-floor is the in-profile backstop.
 *
 * Home-parameterized (was a static string) so the sensitive denies resolve to
 * the running user's home. Source of truth lives HERE; the desktop
 * `macosProfile()` mirrors it synchronously (a static value import would hang
 * the runner's fallback on the dev pre-build race that the lazy adapter import
 * exists to avoid), and a desktop parity test locks the two together byte-for-
 * byte so they cannot drift.
 */
export function legacyMacosProfile(homeDir: string): string {
  const home = homeDir.replace(/\/+$/, "");
  const denyLines = LEGACY_MACOS_SENSITIVE_HOME_DIRS.map(
    (d) => `  (subpath "${escapeSeatbeltPath(`${home}/${d}`)}")`,
  );
  const floorLines = LEGACY_MACOS_CONVIRA_READ_FLOOR.map(
    (d) => `  (subpath "${escapeSeatbeltPath(`${home}/${d}`)}")`,
  );
  return [
    "(version 1)",
    "(allow default)",
    "(deny network*)",
    "(deny file-read* file-write*",
    ...denyLines,
    '  (subpath "/System/Volumes/Data"))',
    "(allow file-read* file-write*",
    ...floorLines,
    ")",
  ].join("\n");
}

let _available: boolean | null = null;

function escapeSeatbeltPath(p: string): string {
  return p.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

// Canonical hardened macOS profile (deny-default). This is the single source of
// truth for macOS sandboxing; the desktop's legacy allow-default profile in
// `apps/desktop/.../sandboxed-process-runner.ts` is a flag-OFF fallback that
// delegates here via `buildDenyDefaultSpec` when CONVIRA_FF_SANDBOX_DENY_DEFAULT
// is on.
function generateSeatbeltProfile(config: SandboxSpawnConfig): string {
  const lines: string[] = [
    "(version 1)",
    "(deny default)",
    "",
    ";; System paths (read-only)",
    "(allow file-read*",
    '  (literal "/")',
    '  (subpath "/usr")',
    '  (subpath "/Library")',
    '  (subpath "/System")',
    '  (subpath "/private/var")',
    '  (subpath "/private/etc")',
    '  (subpath "/dev")',
    '  (subpath "/bin")',
    '  (subpath "/sbin")',
    '  (subpath "/opt")',
    '  (subpath "/etc")',
    ")",
    "",
    ";; Root symlinks (/var -> /private/var, /tmp -> /private/tmp, /etc ->",
    ";; /private/etc). Path resolution reads the symlink VNODE ITSELF before",
    ";; any subpath rule on the target can apply — without these literals a",
    ";; (deny default) profile fails traversal of e.g. /var/folders/... with",
    ';; EPERM ("can\'t open file"), even though /private/var/folders is allowed.',
    "(allow file-read*",
    '  (literal "/var")',
    '  (literal "/tmp")',
    '  (literal "/etc")',
    ")",
    "",
    ";; Metadata (lstat/exists) is allowed everywhere: interpreters realpath",
    ";; every component of a script path (node lstat's /private, /Users, ...)",
    ";; and fail hard on EPERM. Metadata leaks existence/permissions only —",
    ";; file CONTENTS stay deny-default via the read rules above. This is the",
    ";; standard Seatbelt concession (Apple's own profiles do the same).",
    "(allow file-read-metadata)",
    "",
  ];

  // Read paths
  if (config.filesystem.readPaths.length > 0) {
    lines.push(";; User-specified read paths");
    lines.push("(allow file-read*");
    for (const p of config.filesystem.readPaths) {
      lines.push(`  (subpath "${escapeSeatbeltPath(p)}")`);
    }
    lines.push(")");
    lines.push("");
  }

  // Write paths
  if (config.filesystem.writePaths.length > 0) {
    lines.push(";; User-specified write paths");
    lines.push("(allow file-read* file-write*");
    for (const p of config.filesystem.writePaths) {
      lines.push(`  (subpath "${escapeSeatbeltPath(p)}")`);
    }
    lines.push(")");
    lines.push("");
  }

  // Temp directories — macOS has /tmp -> /private/tmp, /var -> /private/var
  lines.push(";; Temp directories");
  lines.push("(allow file-read* file-write*");
  lines.push('  (subpath "/private/tmp")');
  lines.push('  (subpath "/private/var/folders")');
  lines.push('  (subpath "/var/folders")');
  lines.push('  (subpath "/tmp"))');
  lines.push("");

  // Process execution and forking
  lines.push(";; Process execution");
  lines.push("(allow process-exec process-fork)");
  lines.push("");

  // Network
  // system-socket is always needed (Node.js libuv uses it internally)
  lines.push("(allow system-socket)");
  if (config.network.enabled) {
    lines.push(";; Network — outbound allowed");
    lines.push('(allow network-outbound (remote tcp "*:443"))');
    lines.push('(allow network-outbound (remote tcp "*:80"))');
    if (config.network.allowLoopback) {
      lines.push('(allow network-outbound (remote tcp "localhost:*"))');
      lines.push('(allow network-bind (local tcp "localhost:*"))');
    }
    lines.push(";; UDP is DNS-only (9.2 B3). getaddrinfo resolves via the");
    lines.push(";; mDNSResponder mach service (already allowed above); this rule");
    lines.push(";; covers c-ares-style resolvers that speak raw UDP :53. network*");
    lines.push(";; (not just -outbound) so the ephemeral-port reply leg works.");
    lines.push(";; Arbitrary UDP — QUIC, exfil side-channels, inbound binds —");
    lines.push(";; stays denied.");
    lines.push('(allow network* (remote udp "*:53"))');
  } else if (config.network.allowLoopback) {
    // Loopback-only. The dev-server profile: the process must bind a port so
    // the preview pane can reach it, and must be able to talk to itself (a
    // Vite dev server proxies its own HMR socket), but must NOT reach the
    // internet — no :443, no :80, and deliberately no DNS, so a name cannot
    // even be resolved. That makes this strictly narrower than `enabled:true`
    // rather than a variant of it.
    //
    // Known and accepted for v1: loopback also reaches OTHER services already
    // listening on this machine (a local Ollama on :11434, a database on
    // :5432). Closing that would need a per-port allowlist Seatbelt cannot
    // express against a dynamically-assigned port.
    lines.push(";; Network — loopback only (dev server); no DNS, no outbound internet");
    lines.push('(allow network-outbound (remote tcp "localhost:*"))');
    lines.push('(allow network-bind (local tcp "localhost:*"))');
  } else {
    lines.push(";; Network — outbound denied (system-socket allowed for libuv)");
  }
  lines.push("");

  // Mach IPC and system services (Node.js / libuv requirements)
  lines.push(";; Mach IPC and system services");
  lines.push("(allow mach-lookup)");
  lines.push("(allow ipc-posix-shm*)");
  lines.push("(allow sysctl-read)");
  lines.push("(allow signal)");
  lines.push("(allow process-info*)");
  lines.push("(allow file-ioctl)");
  lines.push("");

  // B18: /System/Volumes/Data is the APFS Data-volume mount root, so
  // /System/Volumes/Data/Users/<user>/... is an ALIAS reaching every home
  // directory (~/.ssh, ~/.aws, browser cookies, the offline-license token).
  // The broad `(subpath "/System")` read above would otherwise expose all of it
  // via that alias, defeating the deny-default read confinement. Deny it LAST so
  // it wins (SBPL v1 last-match). Legitimate reads use the firmlinked /Users,
  // /private and /System/Library paths — none of which are literally under this
  // mount — so this closes the alias without affecting real interpreter/file
  // access.
  lines.push(";; Close the data-volume home-directory alias (B18)");
  lines.push('(deny file-read* (subpath "/System/Volumes/Data"))');

  if ((config.filesystem.denyPaths?.length ?? 0) > 0) {
    lines.push("");
    lines.push(";; Explicit deny overlays (last-match-wins)");
    lines.push("(deny file-read* file-write*");
    for (const p of config.filesystem.denyPaths ?? []) {
      lines.push(`  (subpath "${escapeSeatbeltPath(p)}")`);
    }
    lines.push(")");
  }

  return lines.join("\n") + "\n";
}

const PROFILE_PREFIX = "convira-sb-";
// Private per-write dirs (TOCTOU-safe fallback) are named with this prefix so
// the stale sweep can reclaim ones a crashed process left behind.
const PROFILE_DIR_PREFIX = "convira-sbd-";
const PROFILE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
// Seatbelt profiles are a few KB. Above this we stop passing the profile inline
// on argv (`-p`) and fall back to a private-dir temp file (`-f`). macOS ARG_MAX
// is ~1 MiB, so this ceiling leaves ample headroom for the rest of argv/env.
const INLINE_PROFILE_MAX_BYTES = 200_000;
let sweptThisProcess = false;

// Private profile dirs generated by THIS process (fallback path only), removed
// on graceful exit. The common path passes the profile inline via `-p` and
// creates NO file, so this set is usually empty.
const createdProfileDirs = new Set<string>();
let exitCleanupRegistered = false;

/**
 * TOCTOU-safe profile temp file, used ONLY when a profile is too large to pass
 * inline. A predictable, content-addressed path in the shared tmpdir let a
 * local attacker pre-create or swap the `.sb` between our write and
 * sandbox-exec's read; instead we mint a private 0700 directory (mkdtemp) and
 * create the file with O_EXCL (`wx`) under an unpredictable name, so no other
 * user can have placed or can replace it.
 */
function writeProfileToPrivateTemp(profile: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), PROFILE_DIR_PREFIX));
  const profilePath = path.join(dir, `${crypto.randomBytes(12).toString("hex")}.sb`);
  const fd = fs.openSync(profilePath, "wx", 0o600);
  try {
    fs.writeFileSync(fd, profile, { encoding: "utf-8" });
  } finally {
    fs.closeSync(fd);
  }
  createdProfileDirs.add(dir);
  return profilePath;
}

/**
 * Remove every private profile dir this process generated (per-process
 * cleanup). Best-effort and idempotent; registered on `process.once("exit")`.
 * `sweepStaleProfiles` is the backstop for dirs crash-orphaned by a *prior*
 * process.
 */
function cleanupCreatedProfiles(): void {
  for (const dir of createdProfileDirs) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* best-effort — already gone, or raced by the stale sweep */
    }
  }
  createdProfileDirs.clear();
}

function registerExitCleanup(): void {
  if (exitCleanupRegistered) return;
  exitCleanupRegistered = true;
  process.once("exit", cleanupCreatedProfiles);
}

/**
 * Best-effort removal of stale generated profiles. Reclaims (a) private profile
 * dirs a crashed process left behind and (b) legacy predictable `.sb` files
 * written by an older version of this adapter — anything older than a week
 * cannot be referenced by an in-flight spawn (the inline `-p` path holds no
 * file open at all).
 */
function sweepStaleProfiles(now = Date.now()): void {
  const dir = os.tmpdir();
  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return;
  }
  for (const name of names) {
    const isLegacyFile = name.startsWith(PROFILE_PREFIX) && name.endsWith(".sb");
    const isPrivateDir = name.startsWith(PROFILE_DIR_PREFIX);
    if (!isLegacyFile && !isPrivateDir) continue;
    const full = path.join(dir, name);
    try {
      if (now - fs.statSync(full).mtimeMs > PROFILE_MAX_AGE_MS) {
        fs.rmSync(full, { recursive: true, force: true });
      }
    } catch {
      /* best-effort — another process may have raced the unlink */
    }
  }
}

export { generateSeatbeltProfile as _generateSeatbeltProfile };
export { writeProfileToPrivateTemp as _writeProfileToPrivateTemp };
export { sweepStaleProfiles as _sweepStaleProfiles };
export { cleanupCreatedProfiles as _cleanupCreatedProfiles };
export { INLINE_PROFILE_MAX_BYTES as _INLINE_PROFILE_MAX_BYTES };

/**
 * Resolve the absolute filesystem path of a command so the Seatbelt
 * profile can whitelist its parent directory for reads.  Falls back to
 * the original command string when resolution fails.
 */
function resolveCommandPath(command: string, env: Record<string, string>): string | null {
  if (path.isAbsolute(command) && fs.existsSync(command)) return command;
  try {
    const resolved = execFileSync("/usr/bin/which", [command], {
      env: { ...process.env, ...env },
      timeout: 3_000,
      encoding: "utf-8",
    }).trim();
    if (resolved && fs.existsSync(resolved)) return resolved;
  } catch {
    /* which failed — command not on PATH */
  }
  return null;
}

/**
 * Collect ancestor directories of a resolved binary that live outside
 * the default Seatbelt read allowlist so the sandbox can exec them.
 */
function commandReadPaths(absPath: string): string[] {
  const DEFAULT_READ_PREFIXES = ["/usr", "/Library", "/System", "/bin", "/sbin", "/opt", "/etc"];
  const dir = path.dirname(absPath);
  if (DEFAULT_READ_PREFIXES.some((p) => dir.startsWith(p))) return [];
  const extraPaths = [dir];
  const realDir = fs.realpathSync(dir);
  if (realDir !== dir) extraPaths.push(realDir);
  return extraPaths;
}

export const macosAdapter: SandboxAdapter = {
  platform: "macos-sandbox-exec",

  async available(): Promise<boolean> {
    if (_available === null) {
      _available = isSandboxExecAvailable();
    }
    return _available;
  },

  capabilities(): SandboxCapabilities {
    return {
      filesystemIsolation: true,
      networkIsolation: true,
      // True ONLY while the functional /bin/sh ulimit probe passed on this
      // host (cached per process). wrapSpawn applies the same wrapper under
      // the same condition, so a reported capability is never a declaration
      // without enforcement (P0-6/A2: a capability without a passing probe
      // is false). Note: this covers CPU/file-size/descriptor/process
      // rlimits; the RLIMIT_AS memory cap is Linux-only - macOS cannot
      // enforce it via ulimit and we do not fake it.
      resourceLimits: probeRlimitSupport().ok,
    };
  },

  capabilitiesV2(): ExecutionCapabilityReportV2 {
    // Each field flips on ONLY its own passing probe (A2: a declared capability
    // without a passing probe is false/none). CPU/file-size/descriptor/process
    // rlimits share the one ulimit probe. macOS cannot set RLIMIT_AS, so the
    // memory tier is the RSS process-group WATCHDOG (best-effort, sampled) when
    // its boot probe proves it can measure + kill a group here - NEVER the hard
    // address-space tier, which macOS ulimit cannot provide.
    const rlimit = probeRlimitSupport().ok;
    const killTree = probeDescendantKill();
    return {
      adapter: macosAdapter.platform,
      memory: probeRssWatchdogSupport() ? "rss-watchdog" : "none",
      cpu: rlimit,
      pids: rlimit,
      fileSize: rlimit,
      wallClockKill: killTree,
      killTree,
      filesystemIsolation: true,
      networkIsolation: true,
    };
  },

  wrapSpawn(config: SandboxSpawnConfig): SpawnSpec {
    // Opportunistic, once per process: reap week-old generated profiles so
    // long-lived installs don't accrete .sb files in tmp indefinitely.
    if (!sweptThisProcess) {
      sweptThisProcess = true;
      sweepStaleProfiles();
      registerExitCleanup();
    }

    const resolved = resolveCommandPath(config.command, config.env);
    const effectiveCommand = resolved ?? config.command;
    const augmentedConfig = { ...config };

    if (resolved) {
      const extraReads = commandReadPaths(resolved);
      if (extraReads.length > 0) {
        augmentedConfig.filesystem = {
          ...config.filesystem,
          readPaths: [...config.filesystem.readPaths, ...extraReads],
        };
      }
    }

    const profile = generateSeatbeltProfile(augmentedConfig);

    // TOCTOU-safe profile delivery: pass the profile INLINE via `-p` so there
    // is no on-disk file an attacker could swap between our write and
    // sandbox-exec's read. Only a pathologically large profile falls back to a
    // private-dir temp file (`-f`), created atomically with O_EXCL.
    const profileArgs =
      Buffer.byteLength(profile, "utf-8") <= INLINE_PROFILE_MAX_BYTES
        ? ["-p", profile]
        : ["-f", writeProfileToPrivateTemp(profile)];

    // Resource limits bind the INNERMOST layer: sandbox-exec applies the
    // Seatbelt profile, then /bin/sh (readable via the default `/bin`
    // allow, exec permitted by `process-exec`) sets the rlimits and execs
    // the tool in place, so the limits attach to the actual tool process.
    // Applied only when the per-process probe proved the wrapper works
    // here - the capability report flips on the identical condition.
    // `enforceMemory: false`: RLIMIT_AS is unenforceable via macOS ulimit;
    // memory is enforced on Linux and best-effort-absent here, never faked.
    const rlimitProbe = probeRlimitSupport();
    let entry: string[] = [effectiveCommand, ...config.args];
    if (rlimitProbe.ok && rlimitProbe.procFlag) {
      const wrapped = wrapWithRlimit(
        effectiveCommand,
        config.args,
        rlimitValuesFromResources(config.resources, { enforceMemory: false }),
        rlimitProbe.procFlag,
      );
      entry = [wrapped.command, ...wrapped.args];
    }

    return {
      command: SANDBOX_EXEC_BIN,
      args: [...profileArgs, ...entry],
      env: config.env,
      cwd: config.cwd,
    };
  },
};

/** Reset cached state (for tests). Mirrors `_resetLinuxAdapterCache`. */
export function _resetMacosAdapterCache(): void {
  _available = null;
}
