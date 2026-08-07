import { describe, it, expect } from "vitest";
import {
  rlimitValuesFromResources,
  buildRlimitScript,
  DEFAULT_CPU_SECONDS,
} from "../src/rlimit.js";

/**
 * A2 — long-lived subprocess CPU-budget fix. STDIO MCP servers run for the
 * whole session; the shared rlimit wrapper must NOT give them a finite
 * RLIMIT_CPU (`-t`) budget, or the kernel SIGKILLs them after
 * DEFAULT_CPU_SECONDS of cumulative CPU time.
 */
describe("rlimitValuesFromResources — longLived", () => {
  it("omits the CPU-seconds cap for a long-lived process", () => {
    const values = rlimitValuesFromResources(
      { memoryMb: 2048, maxProcesses: 32, longLived: true },
      { enforceMemory: true },
    );
    expect(values.cpuSeconds).toBeUndefined();
    // Every other rlimit still binds.
    expect(values.fileSizeBlocks).toBeGreaterThan(0);
    expect(values.openFiles).toBeGreaterThan(0);
    expect(values.processes).toBeGreaterThan(0);
    expect(values.vmemKb).toBe(2048 * 1024);
  });

  it("keeps the CPU-seconds cap for an ordinary (one-shot) process", () => {
    const values = rlimitValuesFromResources(
      { memoryMb: 2048, maxProcesses: 32 },
      { enforceMemory: true },
    );
    expect(values.cpuSeconds).toBe(DEFAULT_CPU_SECONDS);
  });
});

describe("buildRlimitScript — CPU cap presence", () => {
  it("emits NO `-t` when cpuSeconds is undefined (long-lived)", () => {
    const script = buildRlimitScript(
      { fileSizeBlocks: 8_388_608, openFiles: 1024, processes: 1040, vmemKb: 2_097_152 },
      "-u",
    );
    expect(script).not.toContain("-t");
    // The remaining limits are still present.
    expect(script).toContain("l -f 8388608");
    expect(script).toContain("l -n 1024");
    expect(script).toContain("l -u 1040");
    expect(script).toContain("l -v 2097152");
    expect(script.endsWith('exec "$0" "$@"')).toBe(true);
  });

  it("emits `-t` first when cpuSeconds is present (one-shot)", () => {
    const script = buildRlimitScript(
      { cpuSeconds: 600, fileSizeBlocks: 8, openFiles: 256, processes: 1040 },
      "-u",
    );
    expect(script).toContain("l -t 600");
    // -t precedes the other limits.
    expect(script.indexOf("l -t 600")).toBeLessThan(script.indexOf("l -f 8"));
  });
});
