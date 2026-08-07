import { describe, it, expect, afterEach } from "vitest";
import {
  _runDescendantKillProbe,
  probeDescendantKill,
  _setDescendantKillProbeForTests,
  _resetDescendantKillProbeCache,
  _runMemoryHardCapProbe,
  probeMemoryHardCap,
  _setMemoryHardCapProbeForTests,
  _resetMemoryHardCapProbeCache,
} from "../src/probes.js";

const isPosix = process.platform === "darwin" || process.platform === "linux";

afterEach(() => {
  _resetDescendantKillProbeCache();
  _resetMemoryHardCapProbeCache();
});

describe("descendant-kill probe (real process group)", () => {
  it("proves a group SIGKILL reaps a backgrounded descendant on posix", () => {
    if (!isPosix) return;
    expect(_runDescendantKillProbe()).toBe(true);
  });

  it("is false on a non-posix platform", () => {
    expect(_runDescendantKillProbe("win32")).toBe(false);
  });

  it("caches per process and honors + clears the test override", () => {
    _setDescendantKillProbeForTests(true);
    expect(probeDescendantKill()).toBe(true);
    _setDescendantKillProbeForTests(false);
    expect(probeDescendantKill()).toBe(false);
    _setDescendantKillProbeForTests(null);
    expect(typeof probeDescendantKill()).toBe("boolean");
  });
});

describe("memory hard-cap probe (Linux RLIMIT_AS active allocation)", () => {
  it("is false on macOS/non-linux (ulimit -v is unenforceable there)", () => {
    expect(_runMemoryHardCapProbe("darwin")).toBe(false);
    expect(_runMemoryHardCapProbe("win32")).toBe(false);
  });

  it("proves a tight address-space cap actually fails a large allocation on Linux", () => {
    if (process.platform !== "linux") return;
    // Real probe: a 256MiB buffer must fail under a 64MiB RLIMIT_AS, and a
    // modest buffer must succeed under a generous cap.
    expect(_runMemoryHardCapProbe("linux")).toBe(true);
  });

  it("caches per process and honors + clears the test override", () => {
    _setMemoryHardCapProbeForTests(true);
    expect(probeMemoryHardCap()).toBe(true);
    _setMemoryHardCapProbeForTests(false);
    expect(probeMemoryHardCap()).toBe(false);
    _setMemoryHardCapProbeForTests(null);
    expect(typeof probeMemoryHardCap()).toBe("boolean");
  });
});
