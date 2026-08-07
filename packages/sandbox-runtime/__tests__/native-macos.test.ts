import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  macosAdapter,
  SANDBOX_EXEC_PATH,
  isSandboxExecAvailable,
  _generateSeatbeltProfile,
  _writeProfileToPrivateTemp,
  _sweepStaleProfiles,
  _cleanupCreatedProfiles,
  _INLINE_PROFILE_MAX_BYTES,
  _resetMacosAdapterCache,
  legacyMacosProfile,
  LEGACY_MACOS_CONVIRA_READ_FLOOR,
  LEGACY_MACOS_SENSITIVE_HOME_DIRS,
} from "../src/adapters/native-macos.js";
import {
  probeRlimitSupport,
  rlimitValuesFromResources,
  _setRlimitProbeForTests,
  _resetRlimitProbeCache,
} from "../src/rlimit.js";
import type { SandboxSpawnConfig } from "../src/types.js";

// The rlimit probe passes on any host with a working /bin/sh, which would
// make the legacy argv/capability assertions below host-dependent. Pin it
// OFF by default; suites that exercise the wrapper pin it ON (or restore
// real probing) themselves.
beforeEach(() => {
  _setRlimitProbeForTests({ ok: false, procFlag: null });
});

afterEach(() => {
  _resetRlimitProbeCache();
});

function makeConfig(overrides: Partial<SandboxSpawnConfig> = {}): SandboxSpawnConfig {
  return {
    command: "python3",
    args: ["script.py"],
    cwd: "/Users/dev/project",
    env: { PATH: "/usr/bin", HOME: "/Users/dev" },
    filesystem: {
      readPaths: ["/Users/dev/project", "/Users/dev/.convira/python-env"],
      writePaths: ["/tmp/convira-exec-abc"],
    },
    network: {
      enabled: true,
      allowLoopback: true,
    },
    resources: {
      memoryMb: 512,
      maxProcesses: 16,
    },
    ...overrides,
  };
}

describe("macosAdapter", () => {
  it("has the correct platform identifier", () => {
    expect(macosAdapter.platform).toBe("macos-sandbox-exec");
  });

  it("reports filesystem and network isolation capabilities", () => {
    const caps = macosAdapter.capabilities();
    expect(caps.filesystemIsolation).toBe(true);
    expect(caps.networkIsolation).toBe(true);
  });

  it("reports resourceLimits false while the rlimit probe fails", () => {
    _setRlimitProbeForTests({ ok: false, procFlag: null });
    expect(macosAdapter.capabilities().resourceLimits).toBe(false);
  });

  it("reports resourceLimits true only when the rlimit probe passed", () => {
    _setRlimitProbeForTests({ ok: true, procFlag: "-u" });
    expect(macosAdapter.capabilities().resourceLimits).toBe(true);
  });

  it("reports resourceLimits from the REAL probe on this host (P0-6 outage fix)", () => {
    _resetRlimitProbeCache();
    const caps = macosAdapter.capabilities();
    // Definition of done: on a macOS or Linux dev/CI host the capability is
    // now genuinely true, backed by a functional /bin/sh probe.
    if (process.platform === "darwin" || process.platform === "linux") {
      expect(caps.resourceLimits).toBe(true);
    }
    expect(caps.resourceLimits).toBe(probeRlimitSupport().ok);
  });
});

// Availability probing is a plain fs.existsSync on the SIP-protected binary
// path, so it executes (and counts as covered) on every platform: true on
// macOS hosts, false elsewhere.
describe("macosAdapter availability", () => {
  afterEach(() => {
    _resetMacosAdapterCache();
  });

  it("isSandboxExecAvailable reflects the presence of the sandbox-exec binary", () => {
    const result = isSandboxExecAvailable();
    expect(result).toBe(fs.existsSync(SANDBOX_EXEC_PATH));
    if (process.platform === "darwin") {
      expect(result).toBe(true);
    }
  });

  it("available() matches isSandboxExecAvailable() and caches across calls", async () => {
    _resetMacosAdapterCache();
    const first = await macosAdapter.available();
    const second = await macosAdapter.available();
    expect(first).toBe(isSandboxExecAvailable());
    expect(second).toBe(first);
  });

  it("re-evaluates after _resetMacosAdapterCache()", async () => {
    const before = await macosAdapter.available();
    _resetMacosAdapterCache();
    const after = await macosAdapter.available();
    expect(after).toBe(before);
  });
});

// wrapSpawn assembles a Seatbelt profile and returns the sandbox-exec command
// line — nothing in it requires darwin. It is invoked unconditionally here so
// the command-resolution helpers (resolveCommandPath, commandReadPaths) execute
// on Linux CI as well. The common path passes the profile INLINE via `-p`, so
// there is no temp file to clean up.
describe("macosAdapter.wrapSpawn (profile assembly is platform-independent)", () => {
  it("wraps an absolute command with sandbox-exec -p <profile> inline and whitelists its dir", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sb-macos-cmd-"));
    const fakeBin = path.join(dir, "fake-tool");
    fs.writeFileSync(fakeBin, "#!/bin/sh\n", { mode: 0o755 });
    const sbFiles = (): string[] =>
      fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith("convira-sb") && n.endsWith(".sb"));
    try {
      const before = new Set(sbFiles());
      const config = makeConfig({ command: fakeBin });
      const spec = await macosAdapter.wrapSpawn(config);

      expect(spec.command).toBe(SANDBOX_EXEC_PATH);
      // TOCTOU-safe: the profile rides on argv, not a temp file.
      expect(spec.args[0]).toBe("-p");
      const profile = spec.args[1];
      expect(spec.args[2]).toBe(fakeBin);
      expect(spec.args.slice(3)).toEqual(config.args);
      expect(spec.env).toEqual(config.env);
      expect(spec.cwd).toBe(config.cwd);

      // The resolved binary lives outside the default read prefixes, so its
      // parent directory must be added to the profile's read allowlist.
      expect(profile).toContain(`(subpath "${dir}")`);
      // The inline path creates NO new .sb temp file (diffed against before).
      const created = sbFiles().filter((n) => !before.has(n));
      expect(created).toEqual([]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("falls back to the original command string when PATH resolution fails", async () => {
    const spec = await macosAdapter.wrapSpawn(
      makeConfig({ command: "definitely-not-a-real-command-xyz" }),
    );
    expect(spec.command).toBe(SANDBOX_EXEC_PATH);
    expect(spec.args[0]).toBe("-p");
    expect(spec.args[2]).toBe("definitely-not-a-real-command-xyz");
  });

  it("resolves a bare command through `which` when possible", async () => {
    const spec = await macosAdapter.wrapSpawn(makeConfig({ command: "sh" }));
    expect(spec.command).toBe(SANDBOX_EXEC_PATH);
    expect(spec.args[0]).toBe("-p");
    // On macOS/Linux `which sh` resolves to an absolute path under a default
    // read prefix (/bin or /usr/bin); on hosts without /usr/bin/which the
    // original command string is preserved. Either way it stays "sh"-shaped.
    expect(spec.args[2].endsWith("sh")).toBe(true);
  });

  it("falls back to a private-dir temp file (-f) for a pathologically large profile", async () => {
    // Force the profile past the inline ceiling with many write paths.
    const writePaths = Array.from({ length: 8000 }, (_v, i) => `/tmp/convira-huge/${i}`);
    const spec = await macosAdapter.wrapSpawn(
      makeConfig({ filesystem: { readPaths: [], writePaths } }),
    );
    try {
      expect(spec.command).toBe(SANDBOX_EXEC_PATH);
      expect(spec.args[0]).toBe("-f");
      const profilePath = spec.args[1];
      // Lives inside a private per-write dir (convira-sbd-*), not directly in
      // the shared tmp root.
      expect(path.basename(path.dirname(profilePath))).toMatch(/^convira-sbd-/);
      expect(profilePath.startsWith(os.tmpdir())).toBe(true);
      expect(fs.statSync(profilePath).mode & 0o777).toBe(0o600);
      expect(fs.statSync(path.dirname(profilePath)).mode & 0o777).toBe(0o700);
      expect(fs.readFileSync(profilePath, "utf-8").length).toBeGreaterThan(
        _INLINE_PROFILE_MAX_BYTES,
      );
    } finally {
      _cleanupCreatedProfiles();
    }
  });
});

describe("macosAdapter.wrapSpawn rlimit wrapper (probe-gated, innermost layer)", () => {
  it("inserts the ulimit shell INSIDE sandbox-exec when the probe passed", async () => {
    _setRlimitProbeForTests({ ok: true, procFlag: "-u" });
    const hostile = ["$(touch /tmp/rlimit-macos-pwned)", "; touch /tmp/x", "`id`"];
    const spec = await macosAdapter.wrapSpawn(makeConfig({ command: "/bin/echo", args: hostile }));

    // sandbox-exec stays the outermost layer with the profile passed inline.
    expect(spec.command).toBe(SANDBOX_EXEC_PATH);
    expect(spec.args[0]).toBe("-p");
    // The rlimit shell wraps the tool INSIDE the Seatbelt boundary.
    expect(spec.args[2]).toBe("/bin/sh");
    expect(spec.args[3]).toBe("-c");
    const script = spec.args[4];
    expect(script).toContain("ulimit");
    expect(script).toContain("l -u 1040");
    expect(script.endsWith('exec "$0" "$@"')).toBe(true);
    // macOS never renders the Linux-only RLIMIT_AS cap.
    expect(script).not.toContain("-v");
    // Command + user args ride as positional params, byte-for-byte literal.
    expect(spec.args[5]).toBe("/bin/echo");
    expect(spec.args.slice(6)).toEqual(hostile);
    for (const arg of hostile) {
      expect(script).not.toContain(arg);
    }
  });

  it("keeps the unwrapped argv when the probe failed (fail-closed downstream)", async () => {
    _setRlimitProbeForTests({ ok: false, procFlag: null });
    const spec = await macosAdapter.wrapSpawn(makeConfig({ command: "/bin/echo" }));
    expect(spec.args[2]).toBe("/bin/echo");
    expect(spec.args).not.toContain("-c");
  });

  it("enforces the derived limits through the REAL sandbox on this host", async () => {
    // Restore real probing: this is the end-to-end definition-of-done check.
    _setRlimitProbeForTests(null);
    _resetRlimitProbeCache();
    if (process.platform !== "darwin" || !isSandboxExecAvailable()) return;
    if (!probeRlimitSupport().ok) return;

    const tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sb-rlimit-e2e-")));
    const resources = { memoryMb: 2048, maxProcesses: 16, timeoutMs: 5_000 };
    const expected = rlimitValuesFromResources(resources, { enforceMemory: false });
    const spec = await macosAdapter.wrapSpawn(
      makeConfig({
        command: "/bin/sh",
        args: ["-c", "ulimit -t && ulimit -n"],
        cwd: tmpDir,
        env: { PATH: "/usr/bin:/bin", HOME: tmpDir },
        filesystem: { readPaths: [tmpDir], writePaths: [tmpDir] },
        network: { enabled: false, allowLoopback: false },
        resources,
      }),
    );
    const result = spawnSync(spec.command, spec.args, {
      cwd: spec.cwd,
      env: spec.env,
      timeout: 15_000,
      encoding: "utf-8",
    });
    expect(result.status).toBe(0);
    expect(result.stdout.trim().split(/\r?\n/)).toEqual([
      String(expected.cpuSeconds),
      String(expected.openFiles),
    ]);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});

describe("generateSeatbeltProfile", () => {
  it("starts with deny default", () => {
    const profile = _generateSeatbeltProfile(makeConfig());
    expect(profile).toContain("(version 1)");
    expect(profile).toContain("(deny default)");
  });

  it("includes system read paths and root literal", () => {
    const profile = _generateSeatbeltProfile(makeConfig());
    expect(profile).toContain('(literal "/")');
    expect(profile).toContain('(subpath "/usr")');
    expect(profile).toContain('(subpath "/System")');
    expect(profile).toContain('(subpath "/dev")');
  });

  it("includes user-specified read paths", () => {
    const profile = _generateSeatbeltProfile(makeConfig());
    expect(profile).toContain('(subpath "/Users/dev/project")');
    expect(profile).toContain('(subpath "/Users/dev/.convira/python-env")');
  });

  it("does not expose the data-volume alias to home dirs (B18)", () => {
    const profile = _generateSeatbeltProfile(makeConfig());
    // The ONLY mention of /System/Volumes/Data is the trailing deny — the
    // redundant read-allow form for it is gone.
    const occurrences = profile.split("/System/Volumes/Data").length - 1;
    expect(occurrences).toBe(1);
    expect(profile).toContain('(deny file-read* (subpath "/System/Volumes/Data"))');
    // Last-match-wins: the deny must appear AFTER the broad (subpath "/System")
    // read allow, or it would not override the alias exposure.
    const denyIdx = profile.indexOf('(deny file-read* (subpath "/System/Volumes/Data"))');
    const systemAllowIdx = profile.indexOf('(subpath "/System")');
    expect(systemAllowIdx).toBeGreaterThan(-1);
    expect(denyIdx).toBeGreaterThan(systemAllowIdx);
  });

  it("includes user-specified write paths with file-write*", () => {
    const profile = _generateSeatbeltProfile(makeConfig());
    expect(profile).toMatch(/file-write\*.*\/tmp\/convira-exec-abc/s);
  });

  it("applies explicit deny overlays after broader writable paths", () => {
    const profile = _generateSeatbeltProfile(
      makeConfig({
        filesystem: {
          readPaths: [],
          writePaths: ["/Users/dev"],
          denyPaths: ["/Users/dev/.ssh"],
        },
      }),
    );
    const writableIndex = profile.indexOf('(subpath "/Users/dev")');
    const denyIndex = profile.indexOf('(subpath "/Users/dev/.ssh")');
    expect(writableIndex).toBeGreaterThan(-1);
    expect(profile).toContain("(deny file-read* file-write*");
    expect(denyIndex).toBeGreaterThan(writableIndex);
  });

  it("includes temp directory access", () => {
    const profile = _generateSeatbeltProfile(makeConfig());
    expect(profile).toContain('(subpath "/private/tmp")');
    expect(profile).toContain('(subpath "/private/var/folders")');
    expect(profile).toContain('(subpath "/var/folders")');
  });

  it("allows process execution", () => {
    const profile = _generateSeatbeltProfile(makeConfig());
    expect(profile).toContain("(allow process-exec process-fork)");
  });

  it("allows outbound network when enabled", () => {
    const profile = _generateSeatbeltProfile(
      makeConfig({ network: { enabled: true, allowLoopback: true } }),
    );
    expect(profile).toContain('(allow network-outbound (remote tcp "*:443"))');
    expect(profile).toContain('(allow network-outbound (remote tcp "localhost:*"))');
  });

  it("uses localhost-only loopback rules that sandbox-exec accepts", () => {
    const profile = _generateSeatbeltProfile(
      makeConfig({ network: { enabled: true, allowLoopback: true } }),
    );
    expect(profile).not.toContain("127.0.0.1");
    expect(profile).toContain('(allow network-outbound (remote tcp "localhost:*"))');
    expect(profile).toContain('(allow network-bind (local tcp "localhost:*"))');
  });

  it("denies network outbound when disabled", () => {
    const profile = _generateSeatbeltProfile(
      makeConfig({ network: { enabled: false, allowLoopback: false } }),
    );
    expect(profile).toContain(";; Network — outbound denied");
    expect(profile).not.toContain("network-outbound");
    // No UDP of any kind on a no-network profile (9.2 B3).
    expect(profile).not.toContain("udp");
    // system-socket is still allowed for libuv
    expect(profile).toContain("(allow system-socket)");
  });

  it("scopes UDP to DNS (:53) only when network is enabled (9.2 B3)", () => {
    const profile = _generateSeatbeltProfile(
      makeConfig({ network: { enabled: true, allowLoopback: false } }),
    );
    expect(profile).toContain('(allow network* (remote udp "*:53"))');
    // The old blanket grant (any local/remote UDP — QUIC, exfil channels,
    // inbound binds) must never come back.
    expect(profile).not.toContain("(allow network* (local udp) (remote udp))");
    expect(profile).not.toContain("(local udp)");
  });

  it("includes loopback binding when allowLoopback is true", () => {
    const profile = _generateSeatbeltProfile(
      makeConfig({ network: { enabled: true, allowLoopback: true } }),
    );
    expect(profile).toContain('(allow network-bind (local tcp "localhost:*"))');
  });

  it("omits loopback binding when allowLoopback is false", () => {
    const profile = _generateSeatbeltProfile(
      makeConfig({ network: { enabled: true, allowLoopback: false } }),
    );
    expect(profile).not.toContain("network-bind");
  });

  describe("loopback-only profile (dev server preview)", () => {
    const loopbackOnly = () =>
      _generateSeatbeltProfile(makeConfig({ network: { enabled: false, allowLoopback: true } }));

    it("lets the process bind and reach a local port", () => {
      // Before this state existed, `{enabled:false, allowLoopback:true}` fell
      // into the deny branch and emitted nothing — a dev server could not
      // bind at all.
      const profile = loopbackOnly();
      expect(profile).toContain('(allow network-bind (local tcp "localhost:*"))');
      expect(profile).toContain('(allow network-outbound (remote tcp "localhost:*"))');
    });

    it("is strictly narrower than the network-enabled profile", () => {
      // The whole point: a dev server may serve the preview and may not
      // reach the internet. If :443/:80 ever appear here, a build step could
      // quietly exfiltrate the project it is building.
      const profile = loopbackOnly();
      expect(profile).not.toContain('(remote tcp "*:443")');
      expect(profile).not.toContain('(remote tcp "*:80")');
    });

    it("grants no DNS at all, so a hostname cannot even be resolved", () => {
      expect(loopbackOnly()).not.toContain("udp");
    });

    it("still allows system-socket for libuv", () => {
      expect(loopbackOnly()).toContain("(allow system-socket)");
    });
  });

  describe("byte-identity for the states that existed before loopback-only", () => {
    // The new `else if` branch was added rather than hoisting the loopback
    // lines out of the enabled block precisely so these three stay unchanged.
    // Every production caller today is one of them (execute_* and the cloud
    // runner pass {false,false}; MCP passes {n,n} / {true,false} on win32),
    // so a diff here is a live behaviour change, not a refactor.
    const NETWORK_SECTION = /\(allow system-socket\)[\s\S]*?\n\n/;

    function networkSection(enabled: boolean, allowLoopback: boolean): string {
      const profile = _generateSeatbeltProfile(makeConfig({ network: { enabled, allowLoopback } }));
      return NETWORK_SECTION.exec(profile)?.[0] ?? "";
    }

    it("deny-all is unchanged", () => {
      expect(networkSection(false, false)).toBe(
        "(allow system-socket)\n;; Network — outbound denied (system-socket allowed for libuv)\n\n",
      );
    });

    it("network-enabled without loopback is unchanged", () => {
      expect(networkSection(true, false)).toBe(
        [
          "(allow system-socket)",
          ";; Network — outbound allowed",
          '(allow network-outbound (remote tcp "*:443"))',
          '(allow network-outbound (remote tcp "*:80"))',
          ";; UDP is DNS-only (9.2 B3). getaddrinfo resolves via the",
          ";; mDNSResponder mach service (already allowed above); this rule",
          ";; covers c-ares-style resolvers that speak raw UDP :53. network*",
          ";; (not just -outbound) so the ephemeral-port reply leg works.",
          ";; Arbitrary UDP — QUIC, exfil side-channels, inbound binds —",
          ";; stays denied.",
          '(allow network* (remote udp "*:53"))',
          "",
          "",
        ].join("\n"),
      );
    });

    it("network-enabled with loopback is unchanged, loopback still inside the block", () => {
      expect(networkSection(true, true)).toBe(
        [
          "(allow system-socket)",
          ";; Network — outbound allowed",
          '(allow network-outbound (remote tcp "*:443"))',
          '(allow network-outbound (remote tcp "*:80"))',
          '(allow network-outbound (remote tcp "localhost:*"))',
          '(allow network-bind (local tcp "localhost:*"))',
          ";; UDP is DNS-only (9.2 B3). getaddrinfo resolves via the",
          ";; mDNSResponder mach service (already allowed above); this rule",
          ";; covers c-ares-style resolvers that speak raw UDP :53. network*",
          ";; (not just -outbound) so the ephemeral-port reply leg works.",
          ";; Arbitrary UDP — QUIC, exfil side-channels, inbound binds —",
          ";; stays denied.",
          '(allow network* (remote udp "*:53"))',
          "",
          "",
        ].join("\n"),
      );
    });
  });

  it("includes Mach IPC, sysctl, and process-info for Node.js", () => {
    const profile = _generateSeatbeltProfile(makeConfig());
    expect(profile).toContain("(allow mach-lookup)");
    expect(profile).toContain("(allow sysctl-read)");
    expect(profile).toContain("(allow process-info*)");
  });

  it("escapes special characters in paths", () => {
    const profile = _generateSeatbeltProfile(
      makeConfig({
        filesystem: {
          readPaths: ['/Users/dev/project "with quotes"'],
          writePaths: [],
        },
      }),
    );
    expect(profile).toContain('\\"with quotes\\"');
  });
});

describe("legacyMacosProfile", () => {
  it("denies every sensitive home subtree while preserving only the interpreter floor", () => {
    const profile = legacyMacosProfile('/Users/dev-user/with "quotes"///');

    for (const directory of LEGACY_MACOS_SENSITIVE_HOME_DIRS) {
      expect(profile).toContain(`with \\"quotes\\"/${directory}`);
    }
    for (const directory of LEGACY_MACOS_CONVIRA_READ_FLOOR) {
      expect(profile).toContain(`with \\"quotes\\"/${directory}`);
    }
    expect(profile).toContain("(deny network*)");
    expect(profile).toContain('(subpath "/System/Volumes/Data")');
    expect(profile).not.toContain("quotes///");
  });
});

describe("private profile temp-file lifecycle (TOCTOU fallback)", () => {
  afterEach(() => {
    _cleanupCreatedProfiles();
  });

  it("writes the profile 0600 inside a private 0700 dir with an unpredictable name", () => {
    const p = _writeProfileToPrivateTemp("(version 1)\n(deny default)\n");
    const dir = path.dirname(p);
    expect(path.basename(dir)).toMatch(/^convira-sbd-/);
    // Unpredictable random file name (not content-addressed).
    expect(path.basename(p)).toMatch(/^[0-9a-f]{24}\.sb$/);
    expect(fs.statSync(p).mode & 0o777).toBe(0o600);
    expect(fs.statSync(dir).mode & 0o777).toBe(0o700);
    expect(fs.readFileSync(p, "utf-8")).toBe("(version 1)\n(deny default)\n");
  });

  it("mints a DISTINCT private path even for identical content (O_EXCL, no reuse)", () => {
    const content = "(version 1)\n;; same\n";
    const a = _writeProfileToPrivateTemp(content);
    const b = _writeProfileToPrivateTemp(content);
    expect(a).not.toBe(b);
    expect(path.dirname(a)).not.toBe(path.dirname(b));
  });

  it("sweeps week-old private dirs and legacy .sb files but keeps fresh ones", () => {
    const fresh = _writeProfileToPrivateTemp("(version 1)\n;; fresh\n");
    const freshDir = path.dirname(fresh);
    // A crash-orphaned private dir from a prior process.
    const staleDir = fs.mkdtempSync(path.join(os.tmpdir(), "convira-sbd-"));
    fs.writeFileSync(path.join(staleDir, "old.sb"), "x", { mode: 0o600 });
    // A legacy predictable file left by an older adapter version.
    const legacy = path.join(os.tmpdir(), "convira-sb-000000000000.sb");
    fs.writeFileSync(legacy, "(version 1)\n;; legacy\n", { mode: 0o600 });
    const eightDaysMs = 8 * 24 * 60 * 60 * 1000;
    const old = new Date(Date.now() - eightDaysMs);
    fs.utimesSync(staleDir, old, old);
    fs.utimesSync(legacy, old, old);

    _sweepStaleProfiles();

    expect(fs.existsSync(staleDir)).toBe(false);
    expect(fs.existsSync(legacy)).toBe(false);
    expect(fs.existsSync(freshDir)).toBe(true);
  });

  it("cleanupCreatedProfiles removes every private dir generated this process", () => {
    const a = _writeProfileToPrivateTemp("(version 1)\n;; exit-a\n");
    const b = _writeProfileToPrivateTemp("(version 1)\n;; exit-b\n");
    expect(fs.existsSync(a)).toBe(true);
    expect(fs.existsSync(b)).toBe(true);

    _cleanupCreatedProfiles();

    expect(fs.existsSync(path.dirname(a))).toBe(false);
    expect(fs.existsSync(path.dirname(b))).toBe(false);
  });
});
