/**
 * Linux sandbox adapter — uses bubblewrap (bwrap) for namespace-based
 * filesystem and network isolation.
 *
 * bubblewrap is the same tool that powers Flatpak sandboxing. It creates
 * Linux namespaces (mount, PID, optionally network) without requiring
 * root privileges on most distributions.
 *
 * Resolution order for the bwrap binary:
 *   1. Bundled binary at process.resourcesPath (Electron packaged app)
 *   2. System-installed bwrap in PATH
 */

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type {
  ExecutionCapabilityReportV2,
  SandboxAdapter,
  SandboxCapabilities,
  SandboxSpawnConfig,
  SpawnSpec,
} from "../types.js";
import { resolveDenyLeafKind } from "../deny-leaf-kind.js";
import { probeRlimitSupport, rlimitValuesFromResources, wrapWithRlimit } from "../rlimit.js";
import { probeDescendantKill, probeMemoryHardCap } from "../probes.js";

const SYSTEM_READ_PATHS = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"];

/**
 * True for a character or block device. Devices need bwrap's `--dev-bind`;
 * every other bind flavor sets MS_NODEV on the mount, and a device node on a
 * nodev mount cannot be opened at all (EACCES).
 */
export function _isDeviceNode(target: string): boolean {
  try {
    const st = fs.statSync(target);
    return st.isCharacterDevice() || st.isBlockDevice();
  } catch {
    return false;
  }
}

/**
 * The deepest DIRECTORY that already exists on the host between `mount`
 * (inclusive) and `target` (exclusive). Sealing that directory is what lets a
 * deny path which does not exist yet be denied WITHOUT creating it.
 *
 * `null` when the chain runs into something that is not a directory: a file
 * cannot gain children, so the deny path is not creatable through it either.
 */
function deepestExistingDirBelow(mount: string, target: string): string | null {
  let current = path.dirname(target);
  for (;;) {
    if (fs.existsSync(current)) {
      try {
        return fs.statSync(current).isDirectory() ? current : null;
      } catch {
        return null;
      }
    }
    // `mount` was proven to exist before it was bound, so this only guards a
    // caller that passed a target outside it.
    if (current === mount) return null;
    const parent = path.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

/** A mount already emitted into argv, so a later seal can replay it verbatim. */
interface EmittedMount {
  flag: string;
  source: string;
  dest: string;
}

/**
 * True for the bind flavors that expose the host READ-WRITE. Only under one of
 * these can the sandboxed process create a deny path that does not exist yet;
 * `--ro-bind` refuses the mkdir itself.
 */
function isWritableBind(flag: string): boolean {
  return flag === "--bind" || flag === "--dev-bind";
}

/**
 * The mount that actually governs `p` in the sandbox: the LAST emitted mount
 * whose dest is `p` or an ancestor of it. bwrap applies operations in order, so
 * a later mount over an ancestor replaces an earlier, deeper one, and a later
 * deeper mount overlays an earlier ancestor - in both directions the last
 * containing entry is the one the sandboxed process sees.
 *
 * Asking only whether SOME read-write mount contains `p` is not the same
 * question: a narrower `--ro-bind` emitted afterwards is what the process
 * actually gets, and treating that subtree as writable seals it and hands its
 * children back at the wrong access level.
 */
function governingMount(emitted: readonly EmittedMount[], p: string): EmittedMount | undefined {
  for (let i = emitted.length - 1; i >= 0; i -= 1) {
    const m = emitted[i];
    if (p === m.dest || p.startsWith(m.dest + path.sep)) return m;
  }
  return undefined;
}

/**
 * Replace a host bind with an EMPTY tmpfs and hand back every child of it that
 * is not itself denied.
 *
 * This is how a deny path that does not exist yet gets denied without the
 * parent writing anything to the host: the sandbox sees the same directory
 * contents, but a name that is absent on the host is absent from the tmpfs too,
 * so creating it lands on the tmpfs and dies with the sandbox.
 *
 * bwrap applies operations IN ORDER, so a tmpfs here also hides every mount
 * already emitted below this directory. Those are replayed with their original
 * flag - never widened to a plain `--bind` - and children with no mount of
 * their own come back with `dirFlag`, the flag of the mount that governs `dir`.
 *
 * Where the read-only guarantee actually comes from: the CALLER, not `dirFlag`.
 * A directory is only sealed when `isWritableBind(mount.flag)` holds, so this
 * function is reachable only from an already-writable anchor and `dirFlag` is
 * in practice always `--bind`. Attributing the guarantee to `dirFlag` reads as
 * "a read-only parent would hand children back read-only", which is a branch
 * that never executes; the thing that keeps a read-only path read-only is that
 * it is never sealed in the first place.
 *
 * One narrow case where the seal does widen access, stated rather than implied:
 * a child that is a DEVICE NODE is handed back with `--dev-bind` regardless of
 * `dirFlag` (see below), and a device declared in `readPaths` is deliberately
 * never emitted as a mount, so it has no `buried` entry to replay its original
 * flag. It therefore comes back openable, where the underlying `--bind dir` set
 * MS_NODEV and made it unopenable. That is a real, if very small, privilege
 * widening introduced by sealing, and it is the price of not blinding a
 * sandboxed process that legitimately needs the device.
 */
function sealDirectory(
  args: string[],
  dir: string,
  dirFlag: string,
  deniedPaths: ReadonlySet<string>,
  emitted: readonly EmittedMount[],
): void {
  let entries: string[];
  try {
    entries = fs.readdirSync(dir);
  } catch (err) {
    // Handing back nothing would silently blind the sandboxed process, and
    // skipping the seal would leave the deny creatable. Fail closed.
    throw new Error(
      `[sandbox-runtime] cannot enumerate ${dir} to mask a deny path that does not exist ` +
        `yet (${err instanceof Error ? err.message : String(err)}); refusing to spawn`,
    );
  }
  const buried = emitted.filter(
    (m) => m.dest.startsWith(dir + path.sep) && !deniedPaths.has(m.dest),
  );

  args.push("--tmpfs", dir);
  for (const entry of entries) {
    const child = path.join(dir, entry);
    // A denied child is NOT handed back - the deny overlays run after this and
    // cover it on the tmpfs.
    if (deniedPaths.has(child)) continue;
    // Declared mounts are replayed below with the access level the caller asked
    // for; handing them back here first would only duplicate the argv.
    if (buried.some((m) => m.dest === child)) continue;
    // bwrap resolves the SOURCE on the host and aborts the whole spawn when it
    // cannot ("Can't find source path"), so a dangling symlink is skipped.
    if (!fs.existsSync(child)) continue;
    // A device node is unopenable on any bind that sets MS_NODEV, so it needs
    // bwrap's device-permitting variant; that is only ever reached from a
    // writable anchor, which is the only kind this adapter seals.
    args.push(_isDeviceNode(child) ? "--dev-bind" : dirFlag, child, child);
  }
  for (const m of buried) args.push(m.flag, m.source, m.dest);
}

let _bwrapPath: string | null | undefined;
let _available: boolean | null = null;

/**
 * A binary we are willing to exec as the sandbox launcher must be a regular
 * file that no unprivileged local user can have swapped: not group- or
 * world-writable, and owned by root or by us. This is the integrity gate that
 * makes pinning an ABSOLUTE bwrap path meaningful — otherwise a writable
 * `/usr/local/bin/bwrap` (or a PATH-injected one) could stand in for the real
 * namespace launcher and silently neuter the sandbox.
 */
function statTrusted(absPath: string): boolean {
  try {
    const st = fs.statSync(absPath);
    if (!st.isFile()) return false;
    // Reject group/world writable (0o022) — anyone but the owner could replace it.
    if ((st.mode & 0o022) !== 0) return false;
    const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
    // Owner must be root (0) or the current user.
    if (st.uid !== 0 && (uid === undefined || st.uid !== uid)) return false;
    return true;
  } catch {
    return false;
  }
}

function findBwrap(): string | null {
  if (_bwrapPath !== undefined) return _bwrapPath;

  // 1. Bundled binary (Electron apps set process.resourcesPath). Integrity-gated.
  const resourcesPath = (process as NodeJS.Process & { resourcesPath?: string }).resourcesPath;
  if (resourcesPath) {
    const bundled = path.join(resourcesPath, "bwrap");
    if (fs.existsSync(bundled) && statTrusted(bundled)) {
      _bwrapPath = bundled;
      return _bwrapPath;
    }
  }

  // 2. System bwrap: resolve `which bwrap` to an ABSOLUTE path and PIN it. We
  //    never store the bare name "bwrap" — a bare command re-resolves through
  //    PATH at spawn time, so a poisoned PATH entry could substitute the
  //    launcher. Require an absolute path and a trusted stat (fail closed).
  try {
    const resolved = execFileSync("which", ["bwrap"], {
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 5_000,
      encoding: "utf-8",
    })
      .split("\n")[0]
      .trim();
    if (resolved && path.isAbsolute(resolved) && statTrusted(resolved)) {
      _bwrapPath = resolved;
      return _bwrapPath;
    }
  } catch {
    /* not found / not resolvable — fall through to unavailable */
  }
  _bwrapPath = null;
  return null;
}

function canCreateUserNamespace(): boolean {
  try {
    const val = fs.readFileSync("/proc/sys/kernel/unprivileged_userns_clone", "utf-8").trim();
    return val === "1";
  } catch {
    // File may not exist on newer kernels where it's always enabled
    return true;
  }
}

function isConfined(): boolean {
  if (process.env.APPIMAGE) return true;
  if (process.env.SNAP) return true;
  if (process.env.FLATPAK_ID) return true;
  try {
    const cgroup = fs.readFileSync("/proc/1/cgroup", "utf-8");
    if (/flatpak|snap/i.test(cgroup)) return true;
  } catch {
    /* best-effort */
  }
  return false;
}

function checkAvailable(): boolean {
  const bwrap = findBwrap();
  if (!bwrap) return false;

  if (!canCreateUserNamespace()) {
    if (typeof process !== "undefined" && process.stderr) {
      process.stderr.write(
        "[sandbox-runtime] bubblewrap found but unprivileged user namespaces are disabled. " +
          "Enable with: sysctl kernel.unprivileged_userns_clone=1\n",
      );
    }
    return false;
  }

  if (isConfined()) {
    if (typeof process !== "undefined" && process.stderr) {
      process.stderr.write(
        "[sandbox-runtime] Running inside a confined environment (AppImage/Snap/Flatpak). " +
          "Nested bubblewrap sandboxing may not work. Falling back to passthrough.\n",
      );
    }
    return false;
  }

  return true;
}

/**
 * Sync counterpart of `linuxAdapter.available()` — shares the same cached
 * `_available` so they can never disagree. Exported so the cloud host can
 * report an availability-honest `isolationLevel` from a SYNCHRONOUS getter (and
 * so its fail-closed process runner and the getter agree on one source of
 * truth). Reset in tests via `_resetLinuxAdapterCache()`.
 */
export function isLinuxSandboxAvailable(): boolean {
  if (_available === null) {
    _available = checkAvailable();
  }
  return _available;
}

export const linuxAdapter: SandboxAdapter = {
  platform: "linux-bubblewrap",

  async available(): Promise<boolean> {
    return isLinuxSandboxAvailable();
  },

  capabilities(): SandboxCapabilities {
    return {
      filesystemIsolation: true,
      networkIsolation: true,
      // True ONLY while the functional /bin/sh ulimit probe passed on this
      // host (cached per process). wrapSpawn applies the same wrapper under
      // the same condition, so a reported capability is never a declaration
      // without enforcement (P0-6/A2: a capability without a passing probe
      // is false).
      resourceLimits: probeRlimitSupport().ok,
    };
  },

  capabilitiesV2(): ExecutionCapabilityReportV2 {
    // Each field flips on ONLY its own passing probe. CPU/file-size/descriptor/
    // process rlimits share the ulimit probe. Linux CAN set RLIMIT_AS, so the
    // memory tier is the HARD address-space cap - but only when the active
    // allocation probe proves a large allocation actually fails under a tight
    // cap here (stronger than a set-then-readback). Cgroups are deliberately
    // NOT used: unprivileged containers (Railway) get read-only /sys/fs/cgroup
    // with no delegation, so a cgroup controller is unavailable and never
    // assumed.
    const rlimit = probeRlimitSupport().ok;
    const killTree = probeDescendantKill();
    return {
      adapter: linuxAdapter.platform,
      memory: probeMemoryHardCap() ? "hard-address-space" : "none",
      cpu: rlimit,
      pids: rlimit,
      fileSize: rlimit,
      wallClockKill: killTree,
      killTree,
      filesystemIsolation: true,
      networkIsolation: true,
    };
  },

  async wrapSpawn(config: SandboxSpawnConfig): Promise<SpawnSpec> {
    const bwrap = findBwrap();
    if (!bwrap) throw new Error("[sandbox-runtime] bwrap not found");

    const args: string[] = [];

    for (const p of SYSTEM_READ_PATHS) {
      if (fs.existsSync(p)) {
        args.push("--ro-bind", p, p);
      }
    }

    args.push("--proc", "/proc");
    args.push("--dev", "/dev");

    // Establish an empty process-local /tmp first. Explicit scratch roots
    // declared below may then be bind-mounted on top of it. The previous order
    // mounted scratch paths and subsequently hid them behind the tmpfs, making
    // sandboxed document helpers unable to read their generated 0600 scripts.
    args.push("--tmpfs", "/tmp");

    const seen = new Set<string>();
    // Every host mount emitted below, in order, so a deny seal can replay the
    // ones it buries with the access level they were granted - and so the deny
    // logic can ask which mount actually governs a path. Only a mount that is
    // read-write makes a deny path that does not exist yet creatable by the
    // sandboxed process: `--ro-bind` refuses the mkdir itself, and the `/tmp`
    // tmpfs above is not host-backed at all.
    const emitted: EmittedMount[] = [];

    for (const p of config.filesystem.writePaths) {
      if (!seen.has(p) && fs.existsSync(p)) {
        // `--bind` mounts with MS_NODEV, which makes a device node on that
        // mount impossible to OPEN (EACCES) - so binding a device the normal
        // way REPLACES the working node `--dev /dev` just created with a dead
        // one. That is how an explicit `/dev/null` write grant turned into
        // `cannot create /dev/null: Permission denied` for every `2>/dev/null`
        // the rlimit wrapper and user scripts issue. `--dev-bind` is bwrap's
        // device-permitting variant and is the only correct bind for a device.
        const flag = _isDeviceNode(p) ? "--dev-bind" : "--bind";
        args.push(flag, p, p);
        emitted.push({ flag, source: p, dest: p });
        seen.add(p);
      }
    }

    for (const p of config.filesystem.readPaths) {
      if (!seen.has(p) && fs.existsSync(p)) {
        // Same MS_NODEV rule, and bwrap has no read-only device bind. A device
        // declared read-only therefore cannot be honored: `--ro-bind` would
        // shadow a functioning node with an unopenable one, and `--dev-bind`
        // would silently upgrade a read grant to read-write. Leave it to the
        // `--dev /dev` mount above, which already supplies the inert device
        // set (null, zero, full, random, urandom, tty) read-write.
        if (_isDeviceNode(p)) continue;
        args.push("--ro-bind", p, p);
        emitted.push({ flag: "--ro-bind", source: p, dest: p });
        seen.add(p);
      }
    }

    // Denies are overlays applied AFTER broad read/write mounts. This is
    // required for long-lived plugin processes such as MCP servers that need a
    // runtime under HOME but must never see credential/persistence paths.
    //
    // Each request is expanded to the literal path AND its realpath, so a
    // symlinked deny cannot be reached through the other name.
    const denyPaths: string[] = [];
    for (const requested of config.filesystem.denyPaths ?? []) {
      const candidates = [requested];
      try {
        candidates.push(fs.realpathSync(requested));
      } catch {
        // Not resolvable yet - it may not exist, which is handled below.
      }
      for (const p of candidates) if (!denyPaths.includes(p)) denyPaths.push(p);
    }
    const denySet = new Set(denyPaths);

    // A deny path that does not exist yet is NOT automatically safe. Sitting
    // inside a bind we just made read-write, the sandboxed process can create
    // it - `mkdir ~/.ssh && echo <key> > authorized_keys`, or a fresh
    // ~/.bashrc - and the write goes straight through to the host.
    //
    // The parent must NOT close that by creating the leaf itself. That runs on
    // the HOST filesystem, before bwrap exists, and nothing ever removes it: the
    // shipped MCP deny list alone leaves ~21 permanent objects in a fresh Linux
    // home on the first sandboxed spawn, among them an empty ~/.bash_profile -
    // which takes precedence over ~/.profile for bash login shells, so the
    // user's login environment silently stops being applied. Pointing a bwrap
    // mount at a missing path under a host bind has the same effect, because
    // bwrap creates its own mount points and the bind carries that through to
    // the host.
    //
    // So SEAL instead: cover the deepest directory that DOES exist between the
    // bind and the deny with an empty tmpfs, and hand back each of its existing,
    // non-denied children. The sandbox sees the same contents, but every name
    // that is absent on the host - the deny leaves included - now resolves on
    // the tmpfs and is discarded with the sandbox. The host is never written to.
    //
    // The cost is deliberate and bounded: an entry the sandbox NEWLY creates
    // directly in a sealed directory is ephemeral. Only a directory that is both
    // bound read-write and the anchor of a missing deny is ever sealed.
    const sealTargets: { dir: string; flag: string }[] = [];
    // Missing denies whose parent chain ends in a tmpfs, and which can therefore
    // carry an overlay of their own without bwrap creating a mount point on the
    // host (or dying because the chain runs through a regular file).
    const maskable = new Set<string>();
    for (const p of denyPaths) {
      if (fs.existsSync(p)) continue;
      const mount = governingMount(emitted, p);
      // Not exposed at all, or exposed only read-only: the sandboxed process
      // cannot create the leaf either way, so there is nothing to seal and no
      // overlay to emit.
      if (mount === undefined || !isWritableBind(mount.flag)) continue;
      const anchor = deepestExistingDirBelow(mount.dest, p);
      if (anchor === null) continue;
      // An anchor that is itself denied is covered by that deny's own overlay,
      // which is emitted from the same list and NOT guaranteed to come first.
      // Masking this leaf too would point bwrap at a mount point inside a
      // directory that is still the host's, and bwrap creates its own mount
      // points - the host write the seal exists to avoid. The ancestor's
      // overlay already hides every name beneath it.
      if (denyPaths.some((d) => anchor === d || anchor.startsWith(d + path.sep))) continue;
      maskable.add(p);
      if (sealTargets.some((t) => t.dir === anchor)) continue;
      // The anchor is the DEEPEST existing directory between the mount and the
      // deny, and a mount is only emitted for a path that exists, so no mount
      // sits between the two: the anchor is governed by this same mount, and
      // its children are handed back at exactly that access level.
      sealTargets.push({ dir: anchor, flag: mount.flag });
    }
    // Shallowest first: a nested seal re-covers a directory the outer seal has
    // just handed back, which only works once the outer one has been emitted.
    sealTargets.sort((a, b) => a.dir.split(path.sep).length - b.dir.split(path.sep).length);
    for (const t of sealTargets) sealDirectory(args, t.dir, t.flag, denySet, emitted);

    for (const p of denyPaths) {
      if (fs.existsSync(p)) {
        const stat = fs.statSync(p);
        if (stat.isDirectory()) args.push("--tmpfs", p);
        else args.push("--ro-bind", "/dev/null", p);
        continue;
      }

      // Missing and not maskable: nothing read-write exposes it (so the child
      // cannot create it), or it is not anchorable (the chain runs through a
      // regular file, which cannot gain children), or its anchor is itself
      // denied and that deny's own overlay already covers it. Emitting an
      // overlay for any of those would only ask bwrap to create a mount point
      // it must not.
      if (!maskable.has(p)) continue;

      // Missing but sealed above, so bwrap materializes this mount point on the
      // tmpfs rather than on the host. The overlay is emitted anyway - it keeps
      // the deny explicit in argv and holds even if the anchor is later covered
      // some other way. The leaf kind now only decides which inert object the
      // SANDBOX sees, so an unfamiliar name falls back to a tmpfs directory
      // instead of failing the spawn: nothing it can get wrong reaches the host.
      const kind = resolveDenyLeafKind(p, config.filesystem.denyPathKinds) ?? "dir";
      if (kind === "dir") args.push("--tmpfs", p);
      else args.push("--ro-bind", "/dev/null", p);
    }

    args.push("--unshare-pid");

    if (!config.network.enabled) {
      // `--unshare-net` gives the child a fresh network namespace with only a
      // loopback device, which IS loopback-only isolation — but the loopback
      // is the NAMESPACE's, not the host's, so a port bound inside is
      // unreachable from outside. `allowLoopback` is therefore deliberately
      // not consulted here: there is no bwrap flag that would make it mean
      // anything different.
      //
      // Consequence for callers that need a reachable bound port (the dev
      // server preview): on Linux they must pass `enabled: true` and accept
      // the host netns, and with it outbound access this platform cannot
      // narrow. See `dev-server-service.ts`, which makes that choice
      // explicitly per platform rather than letting it happen by accident.
      args.push("--unshare-net");
    }

    args.push("--die-with-parent");
    args.push("--new-session");

    if (config.kernelHardening?.seccompProfile) {
      try {
        const { getSeccompFd } = await import("@convira/sandbox-enforcer");
        const fd = getSeccompFd(config.kernelHardening.seccompProfile);
        args.push("--seccomp", String(fd));
      } catch {
        // seccomp native binding not available — degrade gracefully
      }
    }

    // Resource limits bind the INNERMOST layer: the ulimit wrapper runs
    // inside the bwrap namespaces so the rlimits attach to the actual tool
    // process (and its descendants), not to bwrap. Applied only when the
    // per-process probe proved the wrapper works here - the capability
    // report flips on the identical condition. On Linux this includes the
    // RLIMIT_AS memory cap (`-v`), which macOS cannot enforce.
    const rlimitProbe = probeRlimitSupport();
    let entry: string[] = [config.command, ...config.args];
    if (rlimitProbe.ok && rlimitProbe.procFlag) {
      const wrapped = wrapWithRlimit(
        config.command,
        config.args,
        rlimitValuesFromResources(config.resources, { enforceMemory: true }),
        rlimitProbe.procFlag,
      );
      entry = [wrapped.command, ...wrapped.args];
    }
    args.push("--", ...entry);

    return {
      command: bwrap,
      args,
      env: config.env,
      cwd: config.cwd,
    };
  },
};

/** Reset cached state (for tests). */
export function _resetLinuxAdapterCache(): void {
  _bwrapPath = undefined;
  _available = null;
}

export { statTrusted as _statTrusted };
export { findBwrap as _findBwrap };
