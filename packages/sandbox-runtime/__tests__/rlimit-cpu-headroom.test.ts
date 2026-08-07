/**
 * S2-08 — the documented 4x CPU-headroom multiplier.
 *
 * `rlimitValuesFromResources` scaled a spawn's wall-clock timeout by
 * CPU_SECONDS_PER_WALL_SECOND (4) and then clamped the result to
 * DEFAULT_CPU_SECONDS — the value used for a spawn with NO timeout at all.
 * Because 600 / 4 = 150, every timeout above 150 s collapsed onto that same
 * cap, silently discarding the headroom. A 10-minute tool got 600 CPU-seconds
 * instead of 2400, so a genuinely parallel or CPU-dense job was SIGKILLed by
 * RLIMIT_CPU well before its wall-clock deadline — and an RLIMIT_CPU death
 * presents as a crash, not as a timeout, so the failure was misdiagnosed.
 */

import { describe, expect, it } from "vitest";

import { DEFAULT_CPU_SECONDS, MAX_CPU_SECONDS, rlimitValuesFromResources } from "../src/rlimit.js";

const base = { memoryMb: 512, maxProcesses: 8 };
const cpuFor = (timeoutMs: number | undefined) =>
  rlimitValuesFromResources({ ...base, timeoutMs } as never, { enforceMemory: false }).cpuSeconds;

describe("timeout-derived CPU budget keeps its headroom (S2-08)", () => {
  it("scales past the no-timeout default instead of clamping to it", () => {
    // 10 minutes of wall clock -> 2400 CPU-seconds, not 600.
    expect(cpuFor(600_000)).toBe(2400);
    expect(cpuFor(600_000)).toBeGreaterThan(DEFAULT_CPU_SECONDS);
  });

  it("is monotonic across the old 150 s cliff", () => {
    const below = cpuFor(149_000)!;
    const above = cpuFor(151_000)!;
    expect(above).toBeGreaterThan(below);
    // Under the bug both sides of the cliff returned the same 600.
    expect(below).not.toBe(above);
  });

  it("still applies the 4x multiplier exactly", () => {
    expect(cpuFor(30_000)).toBe(120);
    expect(cpuFor(1_000)).toBe(4);
  });

  it("keeps a ceiling so a huge timeout cannot ask for an unbounded budget", () => {
    expect(cpuFor(10 * 60 * 60 * 1000)).toBe(MAX_CPU_SECONDS);
  });

  it("uses the no-timeout default when there is no timeout", () => {
    expect(cpuFor(undefined)).toBe(DEFAULT_CPU_SECONDS);
  });

  it("omits the cap entirely for long-lived servers", () => {
    const values = rlimitValuesFromResources(
      { ...base, timeoutMs: 600_000, longLived: true } as never,
      {
        enforceMemory: false,
      },
    );
    expect(values.cpuSeconds).toBeUndefined();
  });
});
