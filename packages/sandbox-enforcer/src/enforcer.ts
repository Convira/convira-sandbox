/**
 * Combined enforcement entry point — applies both Landlock and seccomp
 * to the current process for defense-in-depth kernel hardening.
 */

import {
  isLandlockSupported,
  applyLandlockRuleset,
  getLandlockAbiVersion,
  type LandlockRuleset,
} from "./landlock.js";
import { isSeccompSupported, getSeccompFd, type SeccompProfileName } from "./seccomp.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface KernelHardeningConfig {
  /** Landlock filesystem ruleset — if omitted, Landlock is not applied */
  landlock?: LandlockRuleset;
  /** seccomp profile to compile and return as an fd for bubblewrap */
  seccompProfile?: SeccompProfileName;
}

export interface EnforcementResult {
  landlock: {
    applied: boolean;
    supported: boolean;
    abiVersion: number;
    error?: string;
  };
  seccomp: {
    applied: boolean;
    supported: boolean;
    fd?: number;
    error?: string;
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Apply kernel-level hardening to the current process.
 *
 * For Landlock: applies the ruleset immediately (irrevocable).
 * For seccomp: returns an fd suitable for bubblewrap --seccomp <fd>.
 *
 * Both degrade gracefully if the kernel or native bindings don't support them.
 */
export function applyKernelHardening(config: KernelHardeningConfig): EnforcementResult {
  const result: EnforcementResult = {
    landlock: {
      applied: false,
      supported: isLandlockSupported(),
      abiVersion: getLandlockAbiVersion(),
    },
    seccomp: {
      applied: false,
      supported: isSeccompSupported(),
    },
  };

  if (config.landlock && result.landlock.supported) {
    try {
      applyLandlockRuleset(config.landlock);
      result.landlock.applied = true;
    } catch (err) {
      result.landlock.error = err instanceof Error ? err.message : String(err);
    }
  }

  if (config.seccompProfile && result.seccomp.supported) {
    try {
      const fd = getSeccompFd(config.seccompProfile);
      result.seccomp.fd = fd;
      result.seccomp.applied = true;
    } catch (err) {
      result.seccomp.error = err instanceof Error ? err.message : String(err);
    }
  }

  return result;
}

/**
 * Check whether any kernel hardening is available on this platform.
 */
export function isKernelHardeningAvailable(): boolean {
  return isLandlockSupported() || isSeccompSupported();
}
