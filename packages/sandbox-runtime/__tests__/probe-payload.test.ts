import { describe, it, expect, afterEach, beforeEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { shimPayloadHost } from "./fixtures/selftest-host.js";
import {
  probePayloadArgv,
  probeSelftestHandshake,
  resolveProbePayloadHost,
  selftestHandshakeStage,
  _resetProbePayloadHostCache,
  _setProbePayloadHostForTests,
} from "../src/probe-payload.js";
import { _setWinAppContainerLauncherForTests } from "../src/win-appcontainer.js";
import {
  _runJobCpuTimeProbe,
  _runJobPidsProbe,
  jobKillTreeProbeStage,
  _runJobKillTreeProbe,
  _setWinJobObjectBindingsForTests,
  _resetWinJobObjectBindingsCache,
  type WinJobObjectBindings,
  type WinJobObjectLimits,
} from "../src/win-job-object.js";

afterEach(() => {
  _resetProbePayloadHostCache();
  _resetWinJobObjectBindingsCache();
  _setWinAppContainerLauncherForTests(undefined);
});

function inertBindings(): WinJobObjectBindings {
  let next = 1;
  return {
    getInfo: () => ({
      abiVersion: 2,
      platform: "win32",
      primitives: {
        processMemory: true,
        jobMemory: true,
        activeProcess: true,
        jobUserTime: true,
        killOnClose: true,
        cpuRateControl: true,
      },
    }),
    createJob: (_limits: WinJobObjectLimits) => next++,
    assignProcess: () => {},
    terminateJob: () => {},
    closeJob: () => {},
  };
}

describe("resolveProbePayloadHost", () => {
  it("is null off-win32, so no probe ever runs where it cannot be honest", () => {
    expect(resolveProbePayloadHost("darwin")).toBeNull();
    expect(resolveProbePayloadHost("linux")).toBeNull();
  });

  it("is null on win32 without the launcher, rather than falling back to an interpreter", () => {
    // Falling back to `process.execPath` is exactly what broke: in a packaged
    // build the `runAsNode` fuse makes it ignore `-e`, so the child boots the
    // app and never runs the payload. No host is the correct answer - it makes
    // every Windows capability report false, which is fail-closed.
    _setWinAppContainerLauncherForTests(null);
    expect(resolveProbePayloadHost("win32")).toBeNull();
  });

  it("uses the launcher's own self-test form, and grants only its directory", () => {
    const launcher = path.join(path.sep, "app", "native", "convira_sbx_launch.exe");
    _setWinAppContainerLauncherForTests(launcher);
    const host = resolveProbePayloadHost("win32");
    expect(host).not.toBeNull();
    expect(host!.command).toBe(launcher);
    expect(host!.prefixArgs).toEqual(["--selftest"]);
    // NOT dirname(process.execPath): that handed an AppContainer child the
    // entire Electron install root just to let it load an interpreter.
    expect(host!.readGrants).toEqual([path.dirname(launcher)]);
  });

  it("puts the verb after the prefix and the args after the verb", () => {
    const host = { command: "L.exe", prefixArgs: ["--selftest"], readGrants: [] };
    expect(probePayloadArgv(host, "alloc", ["--mib", "64"])).toEqual([
      "--selftest",
      "alloc",
      "--mib",
      "64",
    ]);
  });
});

describe("probeSelftestHandshake", () => {
  beforeEach(() => {
    _resetProbePayloadHostCache();
  });

  it("reports launcher-absent rather than guessing when there is no host", () => {
    _setProbePayloadHostForTests(null);
    expect(probeSelftestHandshake()).toBe(false);
    expect(selftestHandshakeStage()).toBe("launcher-absent");
  });

  it("passes only when the payload echoes the exact nonce back", () => {
    _setProbePayloadHostForTests(shimPayloadHost());
    expect(probeSelftestHandshake()).toBe(true);
    expect(selftestHandshakeStage()).toBe("ok");
  });

  it("fails when the host cannot be spawned at all", () => {
    // The packaged asar case: a path that `fs.existsSync` blesses and
    // `CreateProcessW` cannot open surfaces here, not three probes later.
    _setProbePayloadHostForTests({
      command: path.join(os.tmpdir(), "definitely-not-a-real-binary-xyz"),
      prefixArgs: [],
      readGrants: [],
    });
    expect(probeSelftestHandshake()).toBe(false);
    expect(["spawn-failed", "nonce-never-arrived"]).toContain(selftestHandshakeStage());
  });

  it(
    "ignores the exit code, because a child that merely exits 0 proves nothing",
    { timeout: 20_000 },
    () => {
      // This is the whole point of the nonce. The packaged probe child DID exit
      // 0 - it booted the app, lost the single-instance lock and quit - which is
      // why an exit status was worthless evidence and a round trip is not.
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-exit0-"));
      const script = path.join(dir, "exit0.mjs");
      fs.writeFileSync(script, "process.exit(0);\n");
      try {
        _setProbePayloadHostForTests({
          command: process.execPath,
          prefixArgs: [script],
          readGrants: [],
        });
        expect(probeSelftestHandshake()).toBe(false);
        expect(selftestHandshakeStage()).toBe("nonce-never-arrived");
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    },
  );
});

describe("probes refuse rather than lie when the payload host is unusable", () => {
  it("names the missing host in the kill-tree stage instead of blaming the child", () => {
    // Before the payload host existed this reported
    // `probe-child-never-reported`, which is true and misleading: the child
    // could not have reported, because it was never a payload at all.
    _setProbePayloadHostForTests(null);
    _setWinJobObjectBindingsForTests(inertBindings());
    expect(_runJobKillTreeProbe("win32")).toBe(false);
    expect(jobKillTreeProbeStage()).toBe("selftest-host-unavailable");
  });

  it("fails the CPU probe when the spinner never actually spins", { timeout: 60_000 }, () => {
    // The structural false positive this closes: the old probe's only pass
    // condition was "the pid is gone within 10s", and a child that quits on
    // its own satisfies that without any CPU cap acting. `--fail-marker` makes
    // the payload skip its start marker, so the control leg cannot confirm the
    // subject ran - and the probe must refuse.
    _setProbePayloadHostForTests(shimPayloadHost(["--fail-marker"]));
    _setWinJobObjectBindingsForTests(inertBindings());
    expect(_runJobCpuTimeProbe("win32")).toBe(false);
  });

  it("fails the pids probe when the control leg cannot even spawn", { timeout: 60_000 }, () => {
    // `denied` used to be accepted on its own, so ANY spawn failure - antivirus,
    // a bad path - forged proof of a process-count limit. With the control leg
    // reporting denied too, there is no enforcement to infer.
    _setProbePayloadHostForTests(shimPayloadHost(["--deny"]));
    _setWinJobObjectBindingsForTests(inertBindings());
    expect(_runJobPidsProbe("win32")).toBe(false);
  });
});
