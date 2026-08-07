import { describe, it, expect, afterEach } from "vitest";
import { macosAdapter } from "../src/adapters/native-macos.js";
import { linuxAdapter } from "../src/adapters/native-linux.js";
import { windowsAdapter } from "../src/adapters/native-windows.js";
import { passthroughAdapter } from "../src/adapters/passthrough.js";
import { _setRlimitProbeForTests, _resetRlimitProbeCache } from "../src/rlimit.js";
import {
  _setDescendantKillProbeForTests,
  _resetDescendantKillProbeCache,
  _setMemoryHardCapProbeForTests,
  _resetMemoryHardCapProbeCache,
} from "../src/probes.js";
import {
  _setRssWatchdogProbeForTests,
  _resetRssWatchdogProbeCache,
} from "../src/rss-watchdog.js";
import {
  _setJobKillTreeProbeForTests,
  _resetJobKillTreeProbeCache,
  _setJobMemoryProbeForTests,
  _resetJobMemoryProbeCache,
  _setJobPidsProbeForTests,
  _resetJobPidsProbeCache,
  _setJobCpuTimeProbeForTests,
  _resetJobCpuTimeProbeCache,
} from "../src/win-job-object.js";
import {
  _setAppContainerFilesystemProbeForTests,
  _resetAppContainerFilesystemProbeCache,
  _setAppContainerNetworkProbeForTests,
  _resetAppContainerNetworkProbeCache,
  _resetAppContainerSpawnCagingProbeCache,
} from "../src/win-appcontainer.js";
import {
  _setDiskWatchdogProbeForTests,
  _resetDiskWatchdogProbeCache,
} from "../src/disk-watchdog.js";

afterEach(() => {
  _resetRlimitProbeCache();
  _resetDescendantKillProbeCache();
  _resetMemoryHardCapProbeCache();
  _resetRssWatchdogProbeCache();
  _resetJobKillTreeProbeCache();
  _resetJobMemoryProbeCache();
  _resetJobPidsProbeCache();
  _resetJobCpuTimeProbeCache();
  _resetAppContainerFilesystemProbeCache();
  _resetAppContainerNetworkProbeCache();
  _resetAppContainerSpawnCagingProbeCache();
  _resetDiskWatchdogProbeCache();
});

function pinAllProbes(opts: {
  rlimit: boolean;
  descKill: boolean;
  memHardCap: boolean;
  watchdog: boolean;
}): void {
  _setRlimitProbeForTests(opts.rlimit ? { ok: true, procFlag: "-u" } : { ok: false, procFlag: null });
  _setDescendantKillProbeForTests(opts.descKill);
  _setMemoryHardCapProbeForTests(opts.memHardCap);
  _setRssWatchdogProbeForTests(opts.watchdog);
}

describe("macosAdapter.capabilitiesV2 — granular, honest", () => {
  it("reports memory 'rss-watchdog' (never 'hard-address-space') when the watchdog probe passes", () => {
    pinAllProbes({ rlimit: true, descKill: true, memHardCap: true, watchdog: true });
    const v2 = macosAdapter.capabilitiesV2!();
    expect(v2.adapter).toBe("macos-sandbox-exec");
    expect(v2.memory).toBe("rss-watchdog");
    expect(v2.cpu).toBe(true);
    expect(v2.pids).toBe(true);
    expect(v2.fileSize).toBe(true);
    expect(v2.killTree).toBe(true);
    expect(v2.wallClockKill).toBe(true);
    expect(v2.filesystemIsolation).toBe(true);
    expect(v2.networkIsolation).toBe(true);
  });

  it("reports memory 'none' when the RSS watchdog probe fails", () => {
    pinAllProbes({ rlimit: true, descKill: true, memHardCap: true, watchdog: false });
    expect(macosAdapter.capabilitiesV2!().memory).toBe("none");
  });

  it("flips cpu/pids/fileSize to false when the rlimit probe fails", () => {
    pinAllProbes({ rlimit: false, descKill: true, memHardCap: true, watchdog: true });
    const v2 = macosAdapter.capabilitiesV2!();
    expect(v2.cpu).toBe(false);
    expect(v2.pids).toBe(false);
    expect(v2.fileSize).toBe(false);
  });

  it("flips killTree/wallClockKill to false when the descendant-kill probe fails", () => {
    pinAllProbes({ rlimit: true, descKill: false, memHardCap: true, watchdog: true });
    const v2 = macosAdapter.capabilitiesV2!();
    expect(v2.killTree).toBe(false);
    expect(v2.wallClockKill).toBe(false);
  });

  it("keeps the legacy resourceLimits boolean = the rlimit probe result", () => {
    _setRlimitProbeForTests({ ok: true, procFlag: "-u" });
    expect(macosAdapter.capabilities().resourceLimits).toBe(true);
    _setRlimitProbeForTests({ ok: false, procFlag: null });
    expect(macosAdapter.capabilities().resourceLimits).toBe(false);
  });
});

describe("linuxAdapter.capabilitiesV2 — hard address-space", () => {
  it("reports memory 'hard-address-space' when the active-allocation probe passes", () => {
    pinAllProbes({ rlimit: true, descKill: true, memHardCap: true, watchdog: true });
    const v2 = linuxAdapter.capabilitiesV2!();
    expect(v2.adapter).toBe("linux-bubblewrap");
    expect(v2.memory).toBe("hard-address-space");
    expect(v2.cpu).toBe(true);
    expect(v2.killTree).toBe(true);
    expect(v2.filesystemIsolation).toBe(true);
    expect(v2.networkIsolation).toBe(true);
  });

  it("reports memory 'none' when the address-space probe fails", () => {
    pinAllProbes({ rlimit: true, descKill: true, memHardCap: false, watchdog: true });
    expect(linuxAdapter.capabilitiesV2!().memory).toBe("none");
  });
});

describe("windows + passthrough — honestly all-false/none", () => {
  it("windows reports memory 'none' and every control false when its probes fail", () => {
    // Pinned false so this stays green on the Windows CI lane, where the Job
    // Object addon + AppContainer launcher are built and the real probes pass.
    _setJobKillTreeProbeForTests(false);
    _setJobMemoryProbeForTests(false);
    _setJobPidsProbeForTests(false);
    _setJobCpuTimeProbeForTests(false);
    _setAppContainerFilesystemProbeForTests(false);
    _setAppContainerNetworkProbeForTests(false);
    _setDiskWatchdogProbeForTests(false);
    const v2 = windowsAdapter.capabilitiesV2!();
    expect(v2.adapter).toBe("windows-job-objects");
    expect(v2.memory).toBe("none");
    expect(v2.cpu).toBe(false);
    expect(v2.pids).toBe(false);
    expect(v2.fileSize).toBe(false);
    expect(v2.killTree).toBe(false);
    expect(v2.wallClockKill).toBe(false);
    expect(v2.filesystemIsolation).toBe(false);
    expect(v2.networkIsolation).toBe(false);
  });

  it("passthrough reports memory 'none' and every control false", () => {
    const v2 = passthroughAdapter.capabilitiesV2!();
    expect(v2.adapter).toBe("passthrough");
    expect(v2.memory).toBe("none");
    expect(v2.cpu).toBe(false);
    expect(v2.killTree).toBe(false);
    expect(v2.filesystemIsolation).toBe(false);
    expect(v2.networkIsolation).toBe(false);
  });
});
