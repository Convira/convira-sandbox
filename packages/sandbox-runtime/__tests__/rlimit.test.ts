import { describe, it, expect, afterEach } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  RLIMIT_SHELL_PATH,
  DEFAULT_CPU_SECONDS,
  DEFAULT_FILE_SIZE_BLOCKS,
  DEFAULT_OPEN_FILES,
  RLIMIT_NPROC_HEADROOM,
  rlimitValuesFromResources,
  buildRlimitScript,
  wrapWithRlimit,
  probeRlimitSupport,
  _runRlimitProbe,
  _setRlimitProbeForTests,
  _resetRlimitProbeCache,
  type RlimitValues,
} from "../src/rlimit.js";

const HOSTILE_ARGS = ["$(touch /tmp/rlimit-pwned)", "; touch /tmp/rlimit-pwned", "`id`", '"$HOME"'];

function baseValues(overrides: Partial<RlimitValues> = {}): RlimitValues {
  return {
    cpuSeconds: 600,
    fileSizeBlocks: 8_388_608,
    openFiles: 1024,
    processes: 1040,
    ...overrides,
  };
}

// The probe caches per process; every suite that touches it must leave the
// module in its pristine (uncached, no-override) state.
afterEach(() => {
  _resetRlimitProbeCache();
});

describe("rlimitValuesFromResources", () => {
  it("derives conservative defaults from a spec without a timeout", () => {
    const values = rlimitValuesFromResources(
      { memoryMb: 2048, maxProcesses: 16 },
      { enforceMemory: true },
    );
    expect(values.cpuSeconds).toBe(DEFAULT_CPU_SECONDS);
    expect(values.fileSizeBlocks).toBe(DEFAULT_FILE_SIZE_BLOCKS);
    expect(values.openFiles).toBe(DEFAULT_OPEN_FILES);
    expect(values.processes).toBe(RLIMIT_NPROC_HEADROOM + 16);
    expect(values.vmemKb).toBe(2048 * 1024);
  });

  it("omits the address-space cap when memory enforcement is off (macOS)", () => {
    const values = rlimitValuesFromResources(
      { memoryMb: 2048, maxProcesses: 16 },
      { enforceMemory: false },
    );
    expect(values.vmemKb).toBeUndefined();
  });

  it("derives CPU seconds from the wall-clock timeout with multi-core headroom", () => {
    const values = rlimitValuesFromResources(
      { memoryMb: 2048, maxProcesses: 16, timeoutMs: 5_000 },
      { enforceMemory: false },
    );
    // ceil(5s) * 4 CPU-seconds-per-wall-second
    expect(values.cpuSeconds).toBe(20);
  });

  it("floors the derived CPU budget for very short timeouts", () => {
    const values = rlimitValuesFromResources(
      { memoryMb: 2048, maxProcesses: 16, timeoutMs: 100 },
      { enforceMemory: false },
    );
    expect(values.cpuSeconds).toBeGreaterThanOrEqual(4);
    expect(values.cpuSeconds).toBeLessThanOrEqual(DEFAULT_CPU_SECONDS);
  });

  it("omits the address-space cap for a non-positive memoryMb", () => {
    const values = rlimitValuesFromResources(
      { memoryMb: 0, maxProcesses: 16 },
      { enforceMemory: true },
    );
    expect(values.vmemKb).toBeUndefined();
  });
});

describe("buildRlimitScript", () => {
  it("renders every limit and execs the target via positional params", () => {
    const script = buildRlimitScript(baseValues({ vmemKb: 2_097_152 }), "-u");
    expect(script).toContain("l -t 600");
    expect(script).toContain("l -f 8388608");
    expect(script).toContain("l -n 1024");
    expect(script).toContain("l -u 1040");
    expect(script).toContain("l -v 2097152");
    expect(script.endsWith('exec "$0" "$@"')).toBe(true);
  });

  it("uses the dash-style -p flag when discovered", () => {
    const script = buildRlimitScript(baseValues(), "-p");
    expect(script).toContain("l -p 1040");
    expect(script).not.toContain("l -u");
  });

  it("omits -v when no vmem cap is set", () => {
    const script = buildRlimitScript(baseValues(), "-u");
    expect(script).not.toContain("-v");
  });

  it("rejects non-integer, non-positive, and non-finite limit values", () => {
    expect(() => buildRlimitScript(baseValues({ cpuSeconds: 1.5 }), "-u")).toThrow(/rlimit/);
    expect(() => buildRlimitScript(baseValues({ openFiles: 0 }), "-u")).toThrow(/rlimit/);
    expect(() => buildRlimitScript(baseValues({ processes: -5 }), "-u")).toThrow(/rlimit/);
    expect(() => buildRlimitScript(baseValues({ fileSizeBlocks: Infinity }), "-u")).toThrow(
      /rlimit/,
    );
    expect(() => buildRlimitScript(baseValues({ vmemKb: NaN }), "-u")).toThrow(/rlimit/);
  });
});

describe("wrapWithRlimit argv composition", () => {
  it("passes the command and user args positionally, never inside the -c script", () => {
    const wrapped = wrapWithRlimit("/usr/bin/python3", HOSTILE_ARGS, baseValues(), "-u");
    expect(wrapped.command).toBe(RLIMIT_SHELL_PATH);
    expect(wrapped.args[0]).toBe("-c");
    const script = wrapped.args[1];
    expect(wrapped.args[2]).toBe("/usr/bin/python3");
    expect(wrapped.args.slice(3)).toEqual(HOSTILE_ARGS);
    // The script is built exclusively from validated integers and fixed
    // flags; no user-controlled byte may appear in it.
    for (const arg of HOSTILE_ARGS) {
      expect(script).not.toContain(arg);
    }
    expect(script).not.toContain("python3");
  });

  it("preserves empty args arrays", () => {
    const wrapped = wrapWithRlimit("/bin/echo", [], baseValues(), "-u");
    expect(wrapped.args.length).toBe(3);
    expect(wrapped.args[2]).toBe("/bin/echo");
  });
});

describe("probe", () => {
  it("passes against the real /bin/sh on macOS and Linux hosts", () => {
    if (process.platform !== "darwin" && process.platform !== "linux") return;
    const result = _runRlimitProbe();
    expect(result.ok).toBe(true);
    expect(result.procFlag === "-u" || result.procFlag === "-p").toBe(true);
  });

  it("fails closed when the shell is missing", () => {
    const result = _runRlimitProbe("/nonexistent/definitely-not-a-shell");
    expect(result).toEqual({ ok: false, procFlag: null });
  });

  it("fails closed when the shell cannot run the probe script", () => {
    if (!fs.existsSync("/usr/bin/false")) return;
    const result = _runRlimitProbe("/usr/bin/false");
    expect(result).toEqual({ ok: false, procFlag: null });
  });

  it("caches the probe result per process and resets on demand", () => {
    const first = probeRlimitSupport();
    const second = probeRlimitSupport();
    expect(second).toBe(first);
    _resetRlimitProbeCache();
    const third = probeRlimitSupport();
    expect(third).not.toBe(first);
    expect(third).toEqual(first);
  });

  it("honors the test override until cleared", () => {
    _setRlimitProbeForTests({ ok: false, procFlag: null });
    expect(probeRlimitSupport().ok).toBe(false);
    _setRlimitProbeForTests({ ok: true, procFlag: "-u" });
    expect(probeRlimitSupport()).toEqual({ ok: true, procFlag: "-u" });
    _setRlimitProbeForTests(null);
    expect(typeof probeRlimitSupport().ok).toBe("boolean");
  });
});

describe("wrapper enforcement (real /bin/sh)", () => {
  const supported = () => {
    if (process.platform !== "darwin" && process.platform !== "linux") return null;
    const probe = _runRlimitProbe();
    return probe.ok && probe.procFlag ? probe : null;
  };

  it("delivers hostile args literally to the target process", () => {
    const probe = supported();
    if (!probe) return;
    const marker = path.join(
      fs.mkdtempSync(path.join(os.tmpdir(), "rlimit-lit-")),
      "pwned-marker",
    );
    const hostile = [`$(touch ${marker})`, `; touch ${marker}`, "`id`"];
    const wrapped = wrapWithRlimit("/bin/echo", hostile, baseValues(), probe.procFlag!);
    const out = execFileSync(wrapped.command, wrapped.args, {
      encoding: "utf-8",
      timeout: 10_000,
    });
    expect(out.trim()).toBe(hostile.join(" "));
    expect(fs.existsSync(marker)).toBe(false);
    fs.rmSync(path.dirname(marker), { recursive: true, force: true });
  });

  it("kills a child that writes past a tiny file-size limit", () => {
    const probe = supported();
    if (!probe) return;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rlimit-fsz-"));
    const target = path.join(dir, "fsz.out");
    const wrapped = wrapWithRlimit(
      "/bin/sh",
      ["-c", `dd if=/dev/zero of=${target} bs=512 count=8 2>/dev/null`],
      baseValues({ fileSizeBlocks: 1 }),
      probe.procFlag!,
    );
    const result = spawnSync(wrapped.command, wrapped.args, {
      encoding: "utf-8",
      timeout: 10_000,
    });
    // Either dd dies on SIGXFSZ (128 + 25) or reports the write failure;
    // the file must never reach the full 4096 bytes.
    expect(result.status === 0 && result.signal === null).toBe(false);
    const written = fs.existsSync(target) ? fs.statSync(target).size : 0;
    expect(written).toBeLessThan(4096);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("the exec'd child inherits the exact configured limits", () => {
    const probe = supported();
    if (!probe) return;
    const wrapped = wrapWithRlimit(
      "/bin/sh",
      ["-c", "ulimit -t && ulimit -f && ulimit -n"],
      baseValues({ cpuSeconds: 9, fileSizeBlocks: 8, openFiles: 256 }),
      probe.procFlag!,
    );
    const out = execFileSync(wrapped.command, wrapped.args, {
      encoding: "utf-8",
      timeout: 10_000,
    });
    expect(out.trim().split(/\r?\n/)).toEqual(["9", "8", "256"]);
  });
});
