/**
 * @convira/sandbox-enforcer
 *
 * Kernel-level sandboxing for Linux — Landlock LSM for filesystem access
 * control and seccomp-bpf for syscall filtering. Provides defense-in-depth
 * inside bubblewrap namespaces.
 *
 * Non-Linux platforms: all functions degrade gracefully (isSupported returns
 * false, apply functions are no-ops).
 */

export {
  isLandlockSupported,
  getLandlockAbiVersion,
  applyLandlockRuleset,
  type LandlockRuleset,
} from "./landlock.js";

export {
  isSeccompSupported,
  compileSeccompProfile,
  getSeccompFd,
  getSeccompProfile,
  getAllowedSyscalls,
  type SeccompProfile,
  type SeccompProfileName,
} from "./seccomp.js";

export {
  applyKernelHardening,
  isKernelHardeningAvailable,
  type KernelHardeningConfig,
  type EnforcementResult,
} from "./enforcer.js";
