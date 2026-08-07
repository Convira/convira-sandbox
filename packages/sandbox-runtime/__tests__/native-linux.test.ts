import {
  describe,
  it,
  expect,
  beforeAll,
  beforeEach,
  afterEach,
  vi,
  type MockInstance,
} from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  linuxAdapter,
  isLinuxSandboxAvailable,
  _resetLinuxAdapterCache,
  _statTrusted,
  _findBwrap,
  _isDeviceNode,
} from "../src/adapters/native-linux.js";
import { _setRlimitProbeForTests, _resetRlimitProbeCache } from "../src/rlimit.js";
import type { SandboxSpawnConfig } from "../src/types.js";

// These suites model a POSIX host. They assert on absolute POSIX paths, on
// bwrap/sandbox-exec argv, and on 0600/0700 file modes - primitives Windows
// does not have, which is why they report 438 (0666) where 384 (0600) is
// expected. The adapter under test cannot run on Windows either, so executing
// them there measures the host, not the code. Windows confinement is covered
// by native-windows / win-job-object / win-appcontainer, which do run there.
const describePosix = describe.skipIf(process.platform === "win32");

// The rlimit probe passes on any host with a working /bin/sh, which would
// make the legacy argv/capability assertions below host-dependent. Pin it
// OFF by default; the wrapper suite pins it ON itself.
beforeEach(() => {
  _setRlimitProbeForTests({ ok: false, procFlag: null });
});

afterEach(() => {
  _resetRlimitProbeCache();
});

// Mock the OPTIONAL kernel-hardening enforcer so the seccomp import path in
// wrapSpawn is exercised deterministically regardless of whether the native
// binding is installed or which platform the test runs on.
const { getSeccompFd } = vi.hoisted(() => ({ getSeccompFd: vi.fn() }));
vi.mock("@convira/sandbox-enforcer", () => ({ getSeccompFd }));

let testReadDir: string;
let testWriteDir: string;

beforeAll(() => {
  testReadDir = fs.mkdtempSync(path.join(os.tmpdir(), "sb-test-read-"));
  testWriteDir = fs.mkdtempSync(path.join(os.tmpdir(), "sb-test-write-"));
});

function makeConfig(overrides: Partial<SandboxSpawnConfig> = {}): SandboxSpawnConfig {
  return {
    command: "python3",
    args: ["script.py"],
    cwd: "/home/user/project",
    env: { PATH: "/usr/bin", HOME: "/home/user" },
    filesystem: {
      readPaths: [testReadDir],
      writePaths: [testWriteDir],
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

describePosix("linuxAdapter", () => {
  it("has the correct platform identifier", () => {
    expect(linuxAdapter.platform).toBe("linux-bubblewrap");
  });

  it("reports filesystem and network isolation capabilities", () => {
    const caps = linuxAdapter.capabilities();
    expect(caps.filesystemIsolation).toBe(true);
    expect(caps.networkIsolation).toBe(true);
  });

  it("reports resourceLimits false while the rlimit probe fails", () => {
    _setRlimitProbeForTests({ ok: false, procFlag: null });
    expect(linuxAdapter.capabilities().resourceLimits).toBe(false);
  });

  it("reports resourceLimits true only when the rlimit probe passed", () => {
    _setRlimitProbeForTests({ ok: true, procFlag: "-p" });
    expect(linuxAdapter.capabilities().resourceLimits).toBe(true);
  });

  it("wraps the command with bwrap (or throws if unavailable)", async () => {
    const available = await linuxAdapter.available();
    if (!available) {
      await expect(linuxAdapter.wrapSpawn(makeConfig())).rejects.toThrow("bwrap not found");
      return;
    }
    const spec = await linuxAdapter.wrapSpawn(makeConfig());
    expect(spec.command).toMatch(/bwrap/);
    expect(spec.env).toEqual({ PATH: "/usr/bin", HOME: "/home/user" });
  });

  it("includes system read-only binds for paths that exist", async () => {
    if (!(await linuxAdapter.available())) return;
    const spec = await linuxAdapter.wrapSpawn(makeConfig());
    expect(spec.args).toContain("--ro-bind");
    if (fs.existsSync("/usr")) {
      const idx = spec.args.indexOf("/usr");
      expect(idx).toBeGreaterThan(-1);
      expect(spec.args[idx - 1]).toBe("--ro-bind");
      expect(spec.args[idx + 1]).toBe("/usr");
    }
  });

  it("adds --proc /proc and --dev /dev", async () => {
    if (!(await linuxAdapter.available())) return;
    const spec = await linuxAdapter.wrapSpawn(makeConfig());
    expect(spec.args).toContain("--proc");
    expect(spec.args).toContain("--dev");
  });

  it("mounts user read paths as --ro-bind", async () => {
    if (!(await linuxAdapter.available())) return;
    const spec = await linuxAdapter.wrapSpawn(makeConfig());
    const args = spec.args;
    const idx = args.indexOf(testReadDir);
    expect(idx).toBeGreaterThan(-1);
    expect(args[idx - 1]).toBe("--ro-bind");
    expect(args[idx + 1]).toBe(testReadDir);
  });

  it("mounts user write paths as --bind", async () => {
    if (!(await linuxAdapter.available())) return;
    const spec = await linuxAdapter.wrapSpawn(makeConfig());
    const args = spec.args;
    const idx = args.indexOf(testWriteDir);
    expect(idx).toBeGreaterThan(-1);
    expect(args[idx - 1]).toBe("--bind");
    expect(args[idx + 1]).toBe(testWriteDir);
  });

  it("includes --tmpfs /tmp", async () => {
    if (!(await linuxAdapter.available())) return;
    const spec = await linuxAdapter.wrapSpawn(makeConfig());
    const idx = spec.args.indexOf("/tmp");
    expect(idx).toBeGreaterThan(-1);
    expect(spec.args[idx - 1]).toBe("--tmpfs");
  });

  it("includes --unshare-pid and --die-with-parent", async () => {
    if (!(await linuxAdapter.available())) return;
    const spec = await linuxAdapter.wrapSpawn(makeConfig());
    expect(spec.args).toContain("--unshare-pid");
    expect(spec.args).toContain("--die-with-parent");
    expect(spec.args).toContain("--new-session");
  });

  it("does NOT unshare network when network.enabled is true", async () => {
    if (!(await linuxAdapter.available())) return;
    const spec = await linuxAdapter.wrapSpawn(
      makeConfig({ network: { enabled: true, allowLoopback: true } }),
    );
    expect(spec.args).not.toContain("--unshare-net");
  });

  it("unshares network when network.enabled is false", async () => {
    if (!(await linuxAdapter.available())) return;
    const spec = await linuxAdapter.wrapSpawn(
      makeConfig({ network: { enabled: false, allowLoopback: false } }),
    );
    expect(spec.args).toContain("--unshare-net");
  });

  it("appends -- separator followed by the original command and args", async () => {
    if (!(await linuxAdapter.available())) return;
    const spec = await linuxAdapter.wrapSpawn(makeConfig());
    const sepIdx = spec.args.indexOf("--");
    expect(sepIdx).toBeGreaterThan(-1);
    expect(spec.args[sepIdx + 1]).toBe("python3");
    expect(spec.args[sepIdx + 2]).toBe("script.py");
  });

  it("does not duplicate paths present in both readPaths and writePaths", async () => {
    if (!(await linuxAdapter.available())) return;
    const spec = await linuxAdapter.wrapSpawn(
      makeConfig({
        filesystem: {
          readPaths: [testWriteDir, testReadDir],
          writePaths: [testWriteDir],
        },
      }),
    );
    const occurrences = spec.args.filter((a: string) => a === testWriteDir).length;
    expect(occurrences).toBe(2);
  });
});

describePosix("linuxAdapter cache reset", () => {
  beforeEach(() => {
    _resetLinuxAdapterCache();
  });

  it("exposes a cache reset function for testing", () => {
    expect(typeof _resetLinuxAdapterCache).toBe("function");
  });

  it("re-evaluates availability after cache reset", async () => {
    const first = await linuxAdapter.available();
    _resetLinuxAdapterCache();
    const second = await linuxAdapter.available();
    expect(typeof first).toBe("boolean");
    expect(typeof second).toBe("boolean");
  });

  it("sync isLinuxSandboxAvailable() agrees with async available() (shared cache)", async () => {
    _resetLinuxAdapterCache();
    const sync = isLinuxSandboxAvailable();
    const async_ = await linuxAdapter.available();
    expect(async_).toBe(sync);
  });
});

// Confinement markers force checkAvailable() to report false even where bwrap
// is installed, exercising isConfined()'s env branches and the confined-env
// stderr warning on Linux CI. On hosts without bwrap the probe short-circuits
// earlier but still returns false, so the assertion is unconditional.
describePosix("linuxAdapter confinement detection", () => {
  let stderrSpy: MockInstance<typeof process.stderr.write>;

  beforeEach(() => {
    stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    _resetLinuxAdapterCache();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    _resetLinuxAdapterCache();
    stderrSpy.mockRestore();
  });

  it.each(["APPIMAGE", "SNAP", "FLATPAK_ID"])(
    "reports unavailable when %s marks a confined environment",
    async (envVar) => {
      vi.stubEnv(envVar, "/confined/marker");
      _resetLinuxAdapterCache();
      expect(await linuxAdapter.available()).toBe(false);
      expect(isLinuxSandboxAvailable()).toBe(false);
    },
  );
});

// Kernel-hardening seccomp wiring. wrapSpawn only needs a discoverable bwrap
// (not full `available()`), so we inject a fake bundled binary via
// process.resourcesPath to drive the seccomp branch deterministically on any
// host — closing the gap where the existing tests never exercise --seccomp.
describePosix("linuxAdapter seccomp profile", () => {
  let fakeResources: string;
  let prevResourcesPath: string | undefined;

  beforeEach(() => {
    getSeccompFd.mockReset();
    fakeResources = fs.mkdtempSync(path.join(os.tmpdir(), "sb-resources-"));
    // findBwrap() returns the bundled binary when it exists under resourcesPath
    // AND passes the integrity gate. Force a non-group/world-writable mode
    // (0755) so statTrusted accepts it regardless of the CI umask.
    const bundled = path.join(fakeResources, "bwrap");
    fs.writeFileSync(bundled, "#!/bin/sh\n");
    fs.chmodSync(bundled, 0o755);
    const proc = process as NodeJS.Process & { resourcesPath?: string };
    prevResourcesPath = proc.resourcesPath;
    proc.resourcesPath = fakeResources;
    _resetLinuxAdapterCache();
  });

  afterEach(() => {
    const proc = process as NodeJS.Process & { resourcesPath?: string };
    if (prevResourcesPath === undefined) delete proc.resourcesPath;
    else proc.resourcesPath = prevResourcesPath;
    _resetLinuxAdapterCache();
    fs.rmSync(fakeResources, { recursive: true, force: true });
  });

  it("appends --seccomp <fd> when a seccompProfile is set and the enforcer loads", async () => {
    getSeccompFd.mockReturnValue(7);
    const spec = await linuxAdapter.wrapSpawn(
      makeConfig({ kernelHardening: { seccompProfile: "gateway" } }),
    );
    const idx = spec.args.indexOf("--seccomp");
    expect(idx).toBeGreaterThan(-1);
    expect(spec.args[idx + 1]).toBe("7");
    expect(getSeccompFd).toHaveBeenCalledWith("gateway");
  });

  it("degrades gracefully (no --seccomp) when the enforcer import/binding fails", async () => {
    getSeccompFd.mockImplementation(() => {
      throw new Error("native seccomp binding unavailable");
    });
    const spec = await linuxAdapter.wrapSpawn(
      makeConfig({ kernelHardening: { seccompProfile: "gateway" } }),
    );
    expect(spec.args).not.toContain("--seccomp");
    // Spec still builds and runs the original command.
    const sepIdx = spec.args.indexOf("--");
    expect(spec.args[sepIdx + 1]).toBe("python3");
  });

  it("does not add --seccomp when no seccompProfile is requested", async () => {
    const spec = await linuxAdapter.wrapSpawn(makeConfig());
    expect(spec.args).not.toContain("--seccomp");
    expect(getSeccompFd).not.toHaveBeenCalled();
  });

  it("inserts the ulimit shell INSIDE the bwrap argv when the probe passed", async () => {
    _setRlimitProbeForTests({ ok: true, procFlag: "-p" });
    const hostile = ["$(touch /tmp/rlimit-linux-pwned)", "; touch /tmp/x", "`id`"];
    const spec = await linuxAdapter.wrapSpawn(makeConfig({ args: hostile }));

    // No existing sandbox flag is weakened by the wrapper.
    expect(spec.args).toContain("--unshare-pid");
    expect(spec.args).toContain("--die-with-parent");
    expect(spec.args).toContain("--new-session");
    const tmpIdx = spec.args.indexOf("/tmp");
    expect(spec.args[tmpIdx - 1]).toBe("--tmpfs");

    // The rlimit shell wraps the tool INSIDE the namespaces, after `--`.
    const sepIdx = spec.args.indexOf("--");
    expect(spec.args[sepIdx + 1]).toBe("/bin/sh");
    expect(spec.args[sepIdx + 2]).toBe("-c");
    const script = spec.args[sepIdx + 3];
    expect(script).toContain("ulimit");
    expect(script).toContain("l -p 1040");
    // Linux enforces the RLIMIT_AS memory cap from resources.memoryMb (512 MiB).
    expect(script).toContain("l -v 524288");
    expect(script.endsWith('exec "$0" "$@"')).toBe(true);
    // Command + user args ride as positional params, byte-for-byte literal.
    expect(spec.args[sepIdx + 4]).toBe("python3");
    expect(spec.args.slice(sepIdx + 5)).toEqual(hostile);
    for (const arg of hostile) {
      expect(script).not.toContain(arg);
    }
  });

  it("keeps the unwrapped argv after -- when the probe failed", async () => {
    _setRlimitProbeForTests({ ok: false, procFlag: null });
    const spec = await linuxAdapter.wrapSpawn(makeConfig());
    const sepIdx = spec.args.indexOf("--");
    expect(spec.args[sepIdx + 1]).toBe("python3");
    expect(spec.args[sepIdx + 2]).toBe("script.py");
  });

  it("overlays deny paths after broader writable mounts", async () => {
    const broad = fs.mkdtempSync(path.join(os.tmpdir(), "sb-broad-home-"));
    const denied = path.join(broad, ".ssh");
    fs.mkdirSync(denied);
    try {
      const spec = await linuxAdapter.wrapSpawn(
        makeConfig({
          filesystem: {
            readPaths: [],
            writePaths: [broad],
            denyPaths: [denied],
          },
        }),
      );
      const broadIndex = spec.args.indexOf(broad);
      const deniedIndex = spec.args.indexOf(denied);
      expect(spec.args[broadIndex - 1]).toBe("--bind");
      expect(spec.args[deniedIndex - 1]).toBe("--tmpfs");
      expect(deniedIndex).toBeGreaterThan(broadIndex);
    } finally {
      fs.rmSync(broad, { recursive: true, force: true });
    }
  });

  /**
   * S0-53 - a deny path that did not exist yet was silently dropped.
   *
   * The loop gated on `fs.existsSync` and `continue`d, so no overlay was
   * emitted - while the parent stayed bound READ-WRITE. A user who has never
   * used ssh has no ~/.ssh, so an MCP server could run
   * `mkdir ~/.ssh && echo <key> > authorized_keys`, or drop a ~/.bashrc, and
   * the write went through the bind straight to the host home: persistent
   * remote access from inside a sandbox whose stated purpose is preventing
   * exactly that.
   *
   * The test directly above sets up this scenario and then calls mkdirSync on
   * the deny path, so it only ever exercised the existing-path branch. The
   * equivalent Windows behaviour IS covered, which made this a cross-adapter
   * asymmetry nothing guarded.
   */
  it("masks a deny path that does not exist yet inside a writable bind", async () => {
    const broad = fs.mkdtempSync(path.join(os.tmpdir(), "sb-missing-deny-"));
    const denied = path.join(broad, ".ssh");
    expect(fs.existsSync(denied)).toBe(false);
    try {
      const spec = await linuxAdapter.wrapSpawn(
        makeConfig({
          filesystem: { readPaths: [], writePaths: [broad], denyPaths: [denied] },
        }),
      );

      const broadIndex = spec.args.indexOf(broad);
      const deniedIndex = spec.args.indexOf(denied);
      expect(spec.args[broadIndex - 1]).toBe("--bind");
      // The mask must exist and must come AFTER the broad bind, or the bind
      // overlays it straight back.
      expect(deniedIndex).toBeGreaterThan(-1);
      expect(spec.args[deniedIndex - 1]).toBe("--tmpfs");
      expect(deniedIndex).toBeGreaterThan(broadIndex);
    } finally {
      fs.rmSync(broad, { recursive: true, force: true });
    }
  });

  it("leaves a missing deny alone when no emitted mount can reach it", async () => {
    // Nothing bound it, so the child cannot create it either. Materializing
    // would be a pointless write into the user's real filesystem.
    const outside = path.join(os.tmpdir(), `sb-unreachable-${process.pid}`, ".ssh");
    const spec = await linuxAdapter.wrapSpawn(
      makeConfig({
        filesystem: { readPaths: [], writePaths: [], denyPaths: [outside] },
      }),
    );

    expect(spec.args).not.toContain(outside);
    expect(fs.existsSync(outside)).toBe(false);
  });

  it("masks a missing deny nested several levels below the bind", async () => {
    // Containment is by path prefix, not by immediate parent.
    const broad = fs.mkdtempSync(path.join(os.tmpdir(), "sb-deep-deny-"));
    const denied = path.join(broad, "Library", "LaunchAgents");
    try {
      const spec = await linuxAdapter.wrapSpawn(
        makeConfig({
          filesystem: { readPaths: [], writePaths: [broad], denyPaths: [denied] },
        }),
      );

      const deniedIndex = spec.args.indexOf(denied);
      expect(spec.args[deniedIndex - 1]).toBe("--tmpfs");
    } finally {
      fs.rmSync(broad, { recursive: true, force: true });
    }
  });

  it("does not treat a sibling with a shared name prefix as contained", async () => {
    // `/home/user2` must not count as inside `/home/user`, which a bare
    // startsWith without the separator would get wrong.
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "sb-prefix-"));
    const bound = path.join(base, "user");
    const sibling = path.join(base, "user2", ".ssh");
    fs.mkdirSync(bound);
    try {
      const spec = await linuxAdapter.wrapSpawn(
        makeConfig({
          filesystem: { readPaths: [], writePaths: [bound], denyPaths: [sibling] },
        }),
      );

      expect(spec.args).not.toContain(sibling);
      expect(fs.existsSync(sibling)).toBe(false);
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });

  /**
   * D003 - the leaf kind must never be resolved by WRITING to the host.
   *
   * The first fix for the missing-deny hole above created the leaf in the
   * PARENT, on the host filesystem, before bwrap exists. With the shipped MCP
   * deny list that is ~21 permanent objects in a fresh Linux home on the first
   * sandboxed spawn, none of which anything ever removes - among them an empty
   * `~/.bash_profile`, which takes precedence over `~/.profile` for bash login
   * shells, so the user's login environment silently stops being applied
   * outside the app, with nothing in the app to undo it. Getting the KIND wrong
   * made it worse still (a `.gitconfig` directory breaks every later
   * `git config --global`), but the kind was never the real problem: the host
   * write was.
   *
   * So the adapter seals instead of materializing: the deepest directory that
   * already exists between the read-write bind and the deny is covered by an
   * empty tmpfs and its real, non-denied children handed back, which puts the
   * missing leaf's mount point on the tmpfs rather than on the host. The kind
   * now only selects which inert object the SANDBOX sees, so an unfamiliar name
   * is masked rather than refused - nothing it can get wrong reaches the host.
   *
   * Each test below therefore asserts BOTH halves: the host is untouched AND
   * the deny still holds, in the right argv order (bwrap applies mounts in
   * order, so bind -> seal -> mask is what makes the mask land on the tmpfs).
   */
  describe("masks a missing deny without materializing it on the host", () => {
    /** Index of the arg that follows `flag` at `value`, or -1. */
    const mountIndex = (args: string[], flag: string, value: string): number => {
      for (let i = 1; i < args.length; i += 1) {
        if (args[i] === value && args[i - 1] === flag) return i;
      }
      return -1;
    };

    it("masks a FILE-kind leaf with /dev/null and creates nothing on the host", async () => {
      const broad = fs.mkdtempSync(path.join(os.tmpdir(), "sb-file-deny-"));
      const denied = path.join(broad, ".gitconfig");
      expect(fs.existsSync(denied)).toBe(false);
      try {
        const spec = await linuxAdapter.wrapSpawn(
          makeConfig({
            filesystem: { readPaths: [], writePaths: [broad], denyPaths: [denied] },
          }),
        );

        // The host keeps the shape it had: no `.gitconfig` of EITHER kind.
        expect(fs.existsSync(denied)).toBe(false);
        expect(fs.readdirSync(broad)).toEqual([]);

        // The deny still holds, and lands on the seal rather than on the bind.
        const bindIndex = mountIndex(spec.args, "--bind", broad);
        const sealIndex = mountIndex(spec.args, "--tmpfs", broad);
        expect(bindIndex).toBeGreaterThan(-1);
        expect(sealIndex).toBeGreaterThan(bindIndex);
        const deniedIndex = spec.args.indexOf(denied);
        expect(deniedIndex).toBeGreaterThan(sealIndex);
        expect(spec.args[deniedIndex - 1]).toBe("/dev/null");
        expect(spec.args[deniedIndex - 2]).toBe("--ro-bind");
      } finally {
        fs.rmSync(broad, { recursive: true, force: true });
      }
    });

    it("masks a DIR-kind leaf with a tmpfs and creates nothing on the host", async () => {
      const broad = fs.mkdtempSync(path.join(os.tmpdir(), "sb-dir-deny-"));
      const denied = path.join(broad, ".ssh");
      try {
        const spec = await linuxAdapter.wrapSpawn(
          makeConfig({
            filesystem: { readPaths: [], writePaths: [broad], denyPaths: [denied] },
          }),
        );

        expect(fs.existsSync(denied)).toBe(false);
        expect(fs.readdirSync(broad)).toEqual([]);

        const sealIndex = mountIndex(spec.args, "--tmpfs", broad);
        const deniedIndex = mountIndex(spec.args, "--tmpfs", denied);
        expect(sealIndex).toBeGreaterThan(mountIndex(spec.args, "--bind", broad));
        expect(deniedIndex).toBeGreaterThan(sealIndex);
      } finally {
        fs.rmSync(broad, { recursive: true, force: true });
      }
    });

    it("honours caller-supplied denyPathKinds over the tmpfs fallback", async () => {
      // A name the well-known table has never heard of is masked as a FILE when
      // the caller declares it, not as the directory the fallback would pick.
      const broad = fs.mkdtempSync(path.join(os.tmpdir(), "sb-declared-deny-"));
      const denied = path.join(broad, "vendor-credentials.ini");
      try {
        const spec = await linuxAdapter.wrapSpawn(
          makeConfig({
            filesystem: {
              readPaths: [],
              writePaths: [broad],
              denyPaths: [denied],
              denyPathKinds: { [denied]: "file" },
            },
          }),
        );

        expect(fs.existsSync(denied)).toBe(false);
        expect(fs.readdirSync(broad)).toEqual([]);

        // Same bind -> seal -> mask order the siblings pin: the mask only lands
        // on the tmpfs while it follows the seal, and the seal only replaces the
        // bind while it follows the bind.
        const bindIndex = mountIndex(spec.args, "--bind", broad);
        const sealIndex = mountIndex(spec.args, "--tmpfs", broad);
        expect(bindIndex).toBeGreaterThan(-1);
        expect(sealIndex).toBeGreaterThan(bindIndex);
        const deniedIndex = mountIndex(spec.args, "/dev/null", denied);
        expect(deniedIndex).toBeGreaterThan(sealIndex);
        expect(spec.args[deniedIndex - 2]).toBe("--ro-bind");
        expect(mountIndex(spec.args, "--tmpfs", denied)).toBe(-1);
      } finally {
        fs.rmSync(broad, { recursive: true, force: true });
      }
    });

    it("falls back to a tmpfs mask for an unresolvable kind instead of refusing", async () => {
      // Refusing was only correct while the guess landed on the host. On a
      // sealed anchor it cannot, and a hard refusal would take the whole spawn
      // down for any caller whose deny list names something unfamiliar.
      const broad = fs.mkdtempSync(path.join(os.tmpdir(), "sb-unknown-deny-"));
      const denied = path.join(broad, "mystery-leaf");
      try {
        const spec = await linuxAdapter.wrapSpawn(
          makeConfig({
            filesystem: { readPaths: [], writePaths: [broad], denyPaths: [denied] },
          }),
        );

        expect(fs.existsSync(denied)).toBe(false);
        expect(fs.readdirSync(broad)).toEqual([]);

        const sealIndex = mountIndex(spec.args, "--tmpfs", broad);
        expect(sealIndex).toBeGreaterThan(-1);
        expect(mountIndex(spec.args, "--tmpfs", denied)).toBeGreaterThan(sealIndex);
      } finally {
        fs.rmSync(broad, { recursive: true, force: true });
      }
    });
  });
});

// bwrap binary integrity gate: the launcher we exec must be a non-writable
// regular file owned by root or us, and a system bwrap must be pinned by
// ABSOLUTE path (never the bare name that re-resolves through PATH).
describePosix("bwrap integrity gate (statTrusted / findBwrap)", () => {
  let dir: string;
  let prevResourcesPath: string | undefined;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sb-bwrap-gate-"));
    const proc = process as NodeJS.Process & { resourcesPath?: string };
    prevResourcesPath = proc.resourcesPath;
    _resetLinuxAdapterCache();
  });

  afterEach(() => {
    const proc = process as NodeJS.Process & { resourcesPath?: string };
    if (prevResourcesPath === undefined) delete proc.resourcesPath;
    else proc.resourcesPath = prevResourcesPath;
    _resetLinuxAdapterCache();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("statTrusted accepts a 0755 regular file owned by the current user", () => {
    const p = path.join(dir, "bwrap");
    fs.writeFileSync(p, "#!/bin/sh\n");
    fs.chmodSync(p, 0o755);
    expect(_statTrusted(p)).toBe(true);
  });

  it("statTrusted rejects group- or world-writable binaries", () => {
    const g = path.join(dir, "bwrap-group");
    fs.writeFileSync(g, "x");
    fs.chmodSync(g, 0o775);
    expect(_statTrusted(g)).toBe(false);

    const w = path.join(dir, "bwrap-world");
    fs.writeFileSync(w, "x");
    fs.chmodSync(w, 0o777);
    expect(_statTrusted(w)).toBe(false);
  });

  it("statTrusted rejects directories and missing paths", () => {
    const d = path.join(dir, "adir");
    fs.mkdirSync(d, { mode: 0o755 });
    expect(_statTrusted(d)).toBe(false);
    expect(_statTrusted(path.join(dir, "nope"))).toBe(false);
  });

  it("findBwrap returns the bundled ABSOLUTE path when it passes the gate", () => {
    const bundled = path.join(dir, "bwrap");
    fs.writeFileSync(bundled, "#!/bin/sh\n");
    fs.chmodSync(bundled, 0o755);
    (process as NodeJS.Process & { resourcesPath?: string }).resourcesPath = dir;
    _resetLinuxAdapterCache();
    const found = _findBwrap();
    expect(found).toBe(bundled);
    expect(path.isAbsolute(found as string)).toBe(true);
  });

  it("findBwrap refuses a group-writable bundled binary (never returns it)", () => {
    const bundled = path.join(dir, "bwrap");
    fs.writeFileSync(bundled, "#!/bin/sh\n");
    fs.chmodSync(bundled, 0o777);
    (process as NodeJS.Process & { resourcesPath?: string }).resourcesPath = dir;
    _resetLinuxAdapterCache();
    // On a host without a system bwrap this is null; on one with bwrap it is the
    // system ABSOLUTE path — either way it is NEVER the untrusted bundled file.
    expect(_findBwrap()).not.toBe(bundled);
  });
});

// Device binds, host-independently: the same stubbed-bwrap seam the seccomp
// suite uses lets wrapSpawn build real argv on any platform, so this runs (and
// can fail) off Linux too — unlike the availability-guarded tests above, which
// silently no-op wherever bwrap is absent. That is precisely the blind spot
// that let the /dev/null regression reach a packaged Linux build.
describePosix("linuxAdapter device binds", () => {
  let fakeResources: string;
  let prevResourcesPath: string | undefined;

  beforeEach(() => {
    fakeResources = fs.mkdtempSync(path.join(os.tmpdir(), "sb-devbind-"));
    const bundled = path.join(fakeResources, "bwrap");
    fs.writeFileSync(bundled, "#!/bin/sh\n");
    fs.chmodSync(bundled, 0o755);
    const proc = process as NodeJS.Process & { resourcesPath?: string };
    prevResourcesPath = proc.resourcesPath;
    proc.resourcesPath = fakeResources;
    _resetLinuxAdapterCache();
  });

  afterEach(() => {
    const proc = process as NodeJS.Process & { resourcesPath?: string };
    if (prevResourcesPath === undefined) delete proc.resourcesPath;
    else proc.resourcesPath = prevResourcesPath;
    _resetLinuxAdapterCache();
    fs.rmSync(fakeResources, { recursive: true, force: true });
  });

  it("classifies a character device, a directory and a missing path", () => {
    expect(_isDeviceNode("/dev/null")).toBe(true);
    expect(_isDeviceNode(fakeResources)).toBe(false);
    expect(_isDeviceNode(path.join(fakeResources, "absent"))).toBe(false);
  });

  it("grants a device write path with --dev-bind, never plain --bind", async () => {
    // Plain `--bind` mounts MS_NODEV, so it SHADOWS the working /dev/null that
    // `--dev /dev` just created with one nothing can open. The explicit write
    // grant was making the device unusable — every `2>/dev/null` under the
    // sandbox died with "cannot create /dev/null: Permission denied".
    const spec = await linuxAdapter.wrapSpawn(
      makeConfig({ filesystem: { readPaths: [], writePaths: ["/dev/null"] } }),
    );
    const idx = spec.args.indexOf("/dev/null");
    expect(idx).toBeGreaterThan(-1);
    expect(spec.args[idx - 1]).toBe("--dev-bind");
    expect(spec.args).not.toContain("--bind");
  });

  it("still uses plain --bind for an ordinary writable directory", async () => {
    const spec = await linuxAdapter.wrapSpawn(
      makeConfig({ filesystem: { readPaths: [], writePaths: [testWriteDir] } }),
    );
    const idx = spec.args.indexOf(testWriteDir);
    expect(idx).toBeGreaterThan(-1);
    expect(spec.args[idx - 1]).toBe("--bind");
  });

  it("leaves a read-only device to the --dev mount rather than shadowing it", async () => {
    // bwrap has no read-only device bind: `--ro-bind` would replace a working
    // node with an unopenable one, and `--dev-bind` would silently upgrade a
    // read grant to read-write. `--dev /dev` already supplies the inert set.
    const spec = await linuxAdapter.wrapSpawn(
      makeConfig({ filesystem: { readPaths: ["/dev/null"], writePaths: [] } }),
    );
    expect(spec.args).not.toContain("/dev/null");
    const devIdx = spec.args.indexOf("--dev");
    expect(devIdx).toBeGreaterThan(-1);
    expect(spec.args[devIdx + 1]).toBe("/dev");
  });
});
