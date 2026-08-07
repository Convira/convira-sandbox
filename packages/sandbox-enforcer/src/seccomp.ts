/**
 * seccomp-bpf — syscall filtering for Linux processes.
 *
 * Loads OCI-format JSON profiles, compiles them to BPF bytecode via
 * libseccomp, and returns a file descriptor suitable for bubblewrap's
 * --seccomp <fd> argument.
 */

import * as fs from "node:fs";
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SeccompProfile {
  defaultAction: string;
  architectures?: string[];
  syscalls: Array<{
    names: string[];
    action: string;
  }>;
}

export type SeccompProfileName = "gateway" | "execute-code";

interface SeccompNativeBinding {
  compileSeccompToFd(syscallNames: string[], defaultAction: string): number;
  isSeccompSupported(): boolean;
}

// ---------------------------------------------------------------------------
// Native binding loader
// ---------------------------------------------------------------------------

let _binding: SeccompNativeBinding | null = null;
let _loadAttempted = false;

function getBinding(): SeccompNativeBinding | null {
  if (_loadAttempted) return _binding;
  _loadAttempted = true;

  if (process.platform !== "linux") return null;

  try {
    // This package is ESM — a bare `require` would be a ReferenceError at
    // runtime, so build one anchored to this file. Both src/ and dist/ sit
    // one level below the package root, where native/ lives.
    const requireNative = createRequire(import.meta.url);
    _binding = requireNative(
      "../native/build/Release/seccomp_compile.node",
    ) as SeccompNativeBinding;
  } catch {
    _binding = null;
  }
  return _binding;
}

// ---------------------------------------------------------------------------
// Profile loading
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Anchor on the package root so the profiles resolve from BOTH execution
// homes: tsx runs this file from src/, the built package runs dist/ (the
// package exports point at dist, and tsc does not copy JSON into it). The
// profiles ship as src/profiles - see "files" in package.json.
const PROFILES_DIR = path.join(__dirname, "..", "src", "profiles");

function loadProfile(name: SeccompProfileName): SeccompProfile {
  const filePath = path.join(PROFILES_DIR, `${name}.seccomp.json`);
  const raw = fs.readFileSync(filePath, "utf8");
  return JSON.parse(raw) as SeccompProfile;
}

/**
 * Extract all allowed syscall names from a profile.
 */
function extractAllowedSyscalls(profile: SeccompProfile): string[] {
  const names: string[] = [];
  for (const entry of profile.syscalls) {
    if (entry.action === "SCMP_ACT_ALLOW") {
      names.push(...entry.names);
    }
  }
  return [...new Set(names)];
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Check whether seccomp-bpf compilation is available on this system.
 * Requires libseccomp and the native binding to be compiled.
 */
export function isSeccompSupported(): boolean {
  if (process.platform !== "linux") return false;
  const binding = getBinding();
  if (!binding) return false;
  try {
    return binding.isSeccompSupported();
  } catch {
    return false;
  }
}

/**
 * Compile a seccomp profile from JSON to BPF and return an fd to the
 * compiled program. The fd can be passed to bubblewrap's --seccomp.
 *
 * The fd must be closed by the caller after bubblewrap has read it.
 */
export function compileSeccompProfile(profilePath: string): number {
  const binding = getBinding();
  if (!binding)
    throw new Error("seccomp native binding not available — install libseccomp-dev and rebuild");

  const raw = fs.readFileSync(profilePath, "utf8");
  const profile = JSON.parse(raw) as SeccompProfile;
  const allowed = extractAllowedSyscalls(profile);

  return binding.compileSeccompToFd(allowed, profile.defaultAction);
}

/**
 * Get an fd for a built-in seccomp profile by name.
 *
 * @param profile - "gateway" for the gateway process or "execute-code" for
 *                  sandboxed code execution (blocks network syscalls)
 * @returns File descriptor to the compiled BPF program
 */
export function getSeccompFd(profile: SeccompProfileName): number {
  const profilePath = path.join(PROFILES_DIR, `${profile}.seccomp.json`);
  return compileSeccompProfile(profilePath);
}

/**
 * Load and return a parsed seccomp profile (for inspection/testing).
 */
export function getSeccompProfile(name: SeccompProfileName): SeccompProfile {
  return loadProfile(name);
}

/**
 * Get the list of syscalls allowed by a given profile.
 */
export function getAllowedSyscalls(name: SeccompProfileName): string[] {
  return extractAllowedSyscalls(loadProfile(name));
}
