/**
 * Landlock LSM — kernel-level filesystem access control for Linux.
 *
 * Once applied, restrictions are irrevocable for the calling process
 * and all its descendants, even under root.
 */

import * as fs from "node:fs";
import { createRequire } from "node:module";
import * as path from "node:path";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface LandlockRuleset {
  /** Paths the process can read (but not write) */
  readOnly: string[];
  /** Paths the process can read, write, create, and delete */
  readWrite: string[];
}

interface NativeBinding {
  landlockGetAbiVersion(): number;
  landlockCreateRuleset(handledAccessFs: bigint): number;
  landlockAddRule(rulesetFd: number, path: string, allowedAccess: bigint): void;
  landlockRestrictSelf(rulesetFd: number): void;

  LANDLOCK_ACCESS_FS_EXECUTE: bigint;
  LANDLOCK_ACCESS_FS_WRITE_FILE: bigint;
  LANDLOCK_ACCESS_FS_READ_FILE: bigint;
  LANDLOCK_ACCESS_FS_READ_DIR: bigint;
  LANDLOCK_ACCESS_FS_REMOVE_DIR: bigint;
  LANDLOCK_ACCESS_FS_REMOVE_FILE: bigint;
  LANDLOCK_ACCESS_FS_MAKE_CHAR: bigint;
  LANDLOCK_ACCESS_FS_MAKE_DIR: bigint;
  LANDLOCK_ACCESS_FS_MAKE_REG: bigint;
  LANDLOCK_ACCESS_FS_MAKE_SOCK: bigint;
  LANDLOCK_ACCESS_FS_MAKE_FIFO: bigint;
  LANDLOCK_ACCESS_FS_MAKE_BLOCK: bigint;
  LANDLOCK_ACCESS_FS_MAKE_SYM: bigint;
  LANDLOCK_ACCESS_FS_REFER: bigint;
  LANDLOCK_ACCESS_FS_TRUNCATE: bigint;
}

// ---------------------------------------------------------------------------
// Native binding loader
// ---------------------------------------------------------------------------

let _binding: NativeBinding | null = null;
let _loadAttempted = false;

function getBinding(): NativeBinding | null {
  if (_loadAttempted) return _binding;
  _loadAttempted = true;

  if (process.platform !== "linux") return null;

  try {
    // This package is ESM — a bare `require` would be a ReferenceError at
    // runtime, so build one anchored to this file. Both src/ and dist/ sit
    // one level below the package root, where native/ lives.
    const requireNative = createRequire(import.meta.url);
    _binding = requireNative("../native/build/Release/landlock_binding.node") as NativeBinding;
  } catch {
    _binding = null;
  }
  return _binding;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Check whether Landlock LSM is available on the current kernel.
 * Returns false on non-Linux or if the kernel doesn't support Landlock.
 */
export function isLandlockSupported(): boolean {
  if (process.platform !== "linux") return false;

  // The active-LSM list lives in securityfs at /sys/kernel/security/lsm
  // (there is no /proc/sys/kernel/security). When it is readable and does
  // not mention landlock, the kernel definitively lacks it. When it cannot
  // be read (securityfs unmounted, restricted container), treat support as
  // unknown and fall through to the ABI probe, which is authoritative.
  try {
    const lsmList = fs.readFileSync("/sys/kernel/security/lsm", "utf8");
    if (!lsmList.includes("landlock")) return false;
  } catch {
    // unknown — fall through to the ABI probe
  }

  const binding = getBinding();
  if (!binding) return false;

  try {
    const abi = binding.landlockGetAbiVersion();
    return abi >= 1;
  } catch {
    return false;
  }
}

/**
 * Get the Landlock ABI version supported by the running kernel.
 * Returns -1 if Landlock is not supported.
 */
export function getLandlockAbiVersion(): number {
  const binding = getBinding();
  if (!binding) return -1;

  try {
    return binding.landlockGetAbiVersion();
  } catch {
    return -1;
  }
}

/**
 * Build the set of access flags handled by this ruleset, appropriate
 * for the detected ABI version.
 */
function buildHandledAccessFlags(binding: NativeBinding, abi: number): bigint {
  let flags =
    binding.LANDLOCK_ACCESS_FS_EXECUTE |
    binding.LANDLOCK_ACCESS_FS_WRITE_FILE |
    binding.LANDLOCK_ACCESS_FS_READ_FILE |
    binding.LANDLOCK_ACCESS_FS_READ_DIR |
    binding.LANDLOCK_ACCESS_FS_REMOVE_DIR |
    binding.LANDLOCK_ACCESS_FS_REMOVE_FILE |
    binding.LANDLOCK_ACCESS_FS_MAKE_CHAR |
    binding.LANDLOCK_ACCESS_FS_MAKE_DIR |
    binding.LANDLOCK_ACCESS_FS_MAKE_REG |
    binding.LANDLOCK_ACCESS_FS_MAKE_SOCK |
    binding.LANDLOCK_ACCESS_FS_MAKE_FIFO |
    binding.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
    binding.LANDLOCK_ACCESS_FS_MAKE_SYM;

  if (abi >= 2) flags |= binding.LANDLOCK_ACCESS_FS_REFER;
  if (abi >= 3) flags |= binding.LANDLOCK_ACCESS_FS_TRUNCATE;

  return flags;
}

/**
 * Apply Landlock filesystem restrictions to the current process.
 *
 * WARNING: This is irrevocable. Once applied, the process and all
 * children are permanently restricted. Any path not covered by
 * readOnly or readWrite rules becomes inaccessible.
 *
 * Paths are resolved to their real filesystem paths via realpathSync
 * to prevent symlink escapes.
 */
export function applyLandlockRuleset(ruleset: LandlockRuleset): void {
  const binding = getBinding();
  if (!binding) throw new Error("Landlock native binding not available");

  const abi = binding.landlockGetAbiVersion();
  if (abi < 1) throw new Error(`Landlock ABI version ${abi} too low (need >= 1)`);

  const handledFlags = buildHandledAccessFlags(binding, abi);
  const rulesetFd = binding.landlockCreateRuleset(handledFlags);

  const readAccess =
    binding.LANDLOCK_ACCESS_FS_EXECUTE |
    binding.LANDLOCK_ACCESS_FS_READ_FILE |
    binding.LANDLOCK_ACCESS_FS_READ_DIR;

  let writeAccess =
    binding.LANDLOCK_ACCESS_FS_READ_FILE |
    binding.LANDLOCK_ACCESS_FS_READ_DIR |
    binding.LANDLOCK_ACCESS_FS_WRITE_FILE |
    binding.LANDLOCK_ACCESS_FS_REMOVE_DIR |
    binding.LANDLOCK_ACCESS_FS_REMOVE_FILE |
    binding.LANDLOCK_ACCESS_FS_MAKE_CHAR |
    binding.LANDLOCK_ACCESS_FS_MAKE_DIR |
    binding.LANDLOCK_ACCESS_FS_MAKE_REG |
    binding.LANDLOCK_ACCESS_FS_MAKE_SOCK |
    binding.LANDLOCK_ACCESS_FS_MAKE_FIFO |
    binding.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
    binding.LANDLOCK_ACCESS_FS_MAKE_SYM |
    binding.LANDLOCK_ACCESS_FS_EXECUTE;

  if (abi >= 2) writeAccess |= binding.LANDLOCK_ACCESS_FS_REFER;
  if (abi >= 3) writeAccess |= binding.LANDLOCK_ACCESS_FS_TRUNCATE;

  const resolvePath = (p: string): string | null => {
    try {
      return fs.realpathSync(p);
    } catch {
      // The leaf may not exist yet (a legitimate not-yet-created path).
      // Resolve the PARENT's real path so any symlink components are
      // collapsed, then rejoin the leaf — otherwise a symlinked parent would
      // let the rule attach to the symlink target and escape the sandbox.
      // If the parent itself cannot be resolved, fail closed (skip the rule).
      try {
        return path.join(fs.realpathSync(path.dirname(p)), path.basename(p));
      } catch {
        return null;
      }
    }
  };

  for (const p of ruleset.readOnly) {
    const resolved = resolvePath(p);
    if (resolved) binding.landlockAddRule(rulesetFd, resolved, readAccess);
  }

  for (const p of ruleset.readWrite) {
    const resolved = resolvePath(p);
    if (resolved) binding.landlockAddRule(rulesetFd, resolved, writeAccess);
  }

  binding.landlockRestrictSelf(rulesetFd);
}
