/**
 * Windows AppContainer isolation tests (HARDENING batch 5).
 *
 * Everything here runs on macOS/Linux with honest-false results (the probes
 * take a platform argument and the decision logic is exercised through fake
 * bindings/launcher overrides); the TRUE paths - profile lifecycle, ACL
 * enforcement, default-deny network, suspended-spawn caging - are proven ONLY
 * by the `real win32` describe on the CI windows-2022 lane, exactly like the
 * Job Object suite.
 */
import { describe, it, expect, afterEach } from "vitest";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import { readFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  WIN_APPCONTAINER_PROFILE_PREFIX,
  filterGrantsToExistingPaths,
  loadWinAppContainerBindings,
  _setWinAppContainerBindingsForTests,
  _resetWinAppContainerBindingsCache,
  resolveWinAppContainerLauncher,
  _unpackedTwinPath,
  _setWinAppContainerLauncherForTests,
  formatAppContainerGrants,
  prepareAppContainerSpawn,
  winAppContainerLedgerDir,
  _setWinAppContainerLedgerDirForTests,
  sweepOrphanedAppContainerProfiles,
  _runAppContainerFilesystemProbe,
  probeAppContainerFilesystem,
  _setAppContainerFilesystemProbeForTests,
  _resetAppContainerFilesystemProbeCache,
  _runAppContainerNetworkProbe,
  probeAppContainerNetwork,
  _setAppContainerNetworkProbeForTests,
  _resetAppContainerNetworkProbeCache,
  _runAppContainerSpawnCagingProbe,
  probeAppContainerSpawnCaging,
  _setAppContainerSpawnCagingProbeForTests,
  _resetAppContainerSpawnCagingProbeCache,
  probeWinAppContainerReport,
  type WinAppContainerBindings,
} from "../src/win-appcontainer.js";
import {
  _setWinJobObjectBindingsForTests,
  _resetWinJobObjectBindingsCache,
} from "../src/win-job-object.js";

const onWindows = process.platform === "win32";
const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

function makeFakeAcBindings(overrides: Partial<WinAppContainerBindings> = {}): WinAppContainerBindings & {
  calls: Array<{ fn: string; args: unknown[] }>;
} {
  const calls: Array<{ fn: string; args: unknown[] }> = [];
  return {
    calls,
    getInfo() {
      return {
        abiVersion: 2,
        platform: "win32",
        primitives: {
          processMemory: true,
          jobMemory: true,
          activeProcess: true,
          jobUserTime: true,
          killOnClose: true,
          cpuRateControl: true,
          appContainer: true,
          securityCapabilitiesSpawn: true,
          directorySidAcl: true,
          networkCapabilitySids: true,
        },
      };
    },
    createJob() {
      return 1;
    },
    assignProcess() {},
    terminateJob() {},
    closeJob() {},
    createAppContainerProfile(name: string) {
      calls.push({ fn: "createAppContainerProfile", args: [name] });
      return "S-1-15-2-1111";
    },
    deriveAppContainerSid(name: string) {
      calls.push({ fn: "deriveAppContainerSid", args: [name] });
      return "S-1-15-2-1111";
    },
    deleteAppContainerProfile(name: string) {
      calls.push({ fn: "deleteAppContainerProfile", args: [name] });
    },
    removeAppContainerAce(target: string, name: string) {
      calls.push({ fn: "removeAppContainerAce", args: [target, name] });
    },
    ...overrides,
  };
}

afterEach(() => {
  _resetWinAppContainerBindingsCache();
  _resetWinJobObjectBindingsCache();
  _setWinAppContainerLauncherForTests(undefined);
  _setWinAppContainerLedgerDirForTests(null);
  _resetAppContainerFilesystemProbeCache();
  _resetAppContainerNetworkProbeCache();
  _resetAppContainerSpawnCagingProbeCache();
});

describe("loadWinAppContainerBindings", () => {
  it("is null on every non-win32 platform", () => {
    expect(loadWinAppContainerBindings("darwin")).toBeNull();
    expect(loadWinAppContainerBindings("linux")).toBeNull();
  });

  it("honors and clears the test override", () => {
    const fake = makeFakeAcBindings();
    _setWinAppContainerBindingsForTests(fake);
    expect(loadWinAppContainerBindings("win32")).toBe(fake);
    _setWinAppContainerBindingsForTests(null);
    expect(loadWinAppContainerBindings("win32")).toBeNull();
    _resetWinAppContainerBindingsCache();
    if (!onWindows) expect(loadWinAppContainerBindings()).toBeNull();
  });

  it("rejects an abi-1 addon that lacks the AppContainer surface", () => {
    // An old win_job_object.node (abiVersion 1) must never be treated as an
    // AppContainer authority: the loader requires abi >= 2 AND the profile
    // functions to be present.
    _setWinJobObjectBindingsForTests({
      getInfo: () => ({
        abiVersion: 1,
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
      createJob: () => 1,
      assignProcess: () => {},
      terminateJob: () => {},
      closeJob: () => {},
    });
    expect(loadWinAppContainerBindings("win32")).toBeNull();
  });
});

describe("launcher resolution", () => {
  it("is null off-win32 and honors the test override", () => {
    expect(resolveWinAppContainerLauncher("darwin")).toBeNull();
    expect(resolveWinAppContainerLauncher("linux")).toBeNull();
    _setWinAppContainerLauncherForTests("C:\\fake\\convira_sbx_launch.exe");
    expect(resolveWinAppContainerLauncher("win32")).toBe("C:\\fake\\convira_sbx_launch.exe");
    _setWinAppContainerLauncherForTests(null);
    expect(resolveWinAppContainerLauncher("win32")).toBeNull();
  });

  it("maps an asar-interior path to its app.asar.unpacked twin, on both separators", () => {
    // A packaged build resolves this module inside app.asar, so the launcher
    // path lands inside the archive. `fs.existsSync` is asar-patched and says
    // yes; `spawn` is NOT patched (Electron hooks only exec/execFile and their
    // sync forms), so CreateProcessW receives a path no kernel can open. The
    // real bytes are in the app.asar.unpacked twin.
    const win =
      "D:\\app\\resources\\app.asar\\node_modules\\@convira\\sandbox-runtime" +
      "\\native\\build\\Release\\convira_sbx_launch.exe";
    expect(_unpackedTwinPath(win)).toBe(
      "D:\\app\\resources\\app.asar.unpacked\\node_modules\\@convira\\sandbox-runtime" +
        "\\native\\build\\Release\\convira_sbx_launch.exe",
    );
    const posix =
      "/Applications/Convira.app/Contents/Resources/app.asar/node_modules/" +
      "@convira/sandbox-runtime/native/build/Release/convira_sbx_launch.exe";
    expect(_unpackedTwinPath(posix)).toBe(
      "/Applications/Convira.app/Contents/Resources/app.asar.unpacked/node_modules/" +
        "@convira/sandbox-runtime/native/build/Release/convira_sbx_launch.exe",
    );
  });

  it("leaves a path that is not inside an archive exactly as it is", () => {
    // Dev, tests and the API server all resolve to a real directory. Rewriting
    // those would break the common case to fix the packaged one.
    const plain = path.join(path.sep, "repo", "native", "build", "Release", "convira_sbx_launch.exe");
    expect(_unpackedTwinPath(plain)).toBe(plain);
    expect(_unpackedTwinPath("")).toBe("");
    // "app.asar.unpacked" must not be rewritten a second time: the marker is
    // `app.asar` + separator, and the twin has `.unpacked` before its separator.
    const already =
      "D:\\app\\resources\\app.asar.unpacked\\node_modules\\x\\convira_sbx_launch.exe";
    expect(_unpackedTwinPath(already)).toBe(already);
  });
});

describe("grants + ledger", () => {
  it("formats grants as tab-separated read/write/deny lines", () => {
    const text = formatAppContainerGrants({
      readPaths: ["C:\\Users\\dev\\project"],
      writePaths: ["C:\\Users\\dev\\scratch"],
      denyPaths: ["C:\\Users\\dev\\.ssh"],
    });
    expect(text).toBe(
      "deny\tC:\\Users\\dev\\.ssh\n" +
        "read\tC:\\Users\\dev\\project\n" +
        "write\tC:\\Users\\dev\\scratch\n",
    );
  });

  it("prepareAppContainerSpawn writes a ledger-backed grants file with a prefixed profile name", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-ac-ledger-"));
    _setWinAppContainerLedgerDirForTests(dir);
    try {
      // Real directories: prepareAppContainerSpawn drops grants whose path does
      // not exist, because the launcher treats a grant on an absent path as a
      // fatal ERROR_FILE_NOT_FOUND and refuses the whole spawn.
      const readDir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-ac-read-"));
      const writeDir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-ac-write-"));
      const prepared = prepareAppContainerSpawn({
        readPaths: [readDir],
        writePaths: [writeDir],
      });
      expect(prepared.profileName.startsWith(`${WIN_APPCONTAINER_PROFILE_PREFIX}-`)).toBe(true);
      // AppContainer profile names must stay under the 64-char OS ceiling.
      expect(prepared.profileName.length).toBeLessThanOrEqual(64);
      expect(prepared.grantsFile).toBe(path.join(dir, `${prepared.profileName}.grants`));
      expect(fs.readFileSync(prepared.grantsFile, "utf-8")).toContain(`read\t${readDir}\n`);
      expect(fs.readFileSync(prepared.grantsFile, "utf-8")).toContain(`write\t${writeDir}\n`);
      fs.rmSync(readDir, { recursive: true, force: true });
      fs.rmSync(writeDir, { recursive: true, force: true });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("ledger dir defaults under the OS tmpdir", () => {
    _setWinAppContainerLedgerDirForTests(null);
    expect(winAppContainerLedgerDir().startsWith(os.tmpdir())).toBe(true);
  });
});

describe("boot janitor (orphaned profile sweep)", () => {
  it("is a no-op off-win32 and when the addon is absent", () => {
    expect(sweepOrphanedAppContainerProfiles("darwin")).toBe(0);
    expect(sweepOrphanedAppContainerProfiles("linux")).toBe(0);
    _setWinAppContainerBindingsForTests(null);
    expect(sweepOrphanedAppContainerProfiles("win32")).toBe(0);
  });

  it("deletes ledgered profiles, revokes their ACEs, and removes the entries", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-ac-janitor-"));
    _setWinAppContainerLedgerDirForTests(dir);
    const fake = makeFakeAcBindings();
    _setWinAppContainerBindingsForTests(fake);
    try {
      const name = `${WIN_APPCONTAINER_PROFILE_PREFIX}-deadbeef`;
      fs.writeFileSync(path.join(dir, `${name}.grants`), "read\tC:\\r\nwrite\tC:\\w\n");
      // A non-prefixed entry must never be touched (the janitor only ever
      // deletes profiles this package created).
      fs.writeFileSync(path.join(dir, "unrelated.grants"), "read\tC:\\x\n");
      const swept = sweepOrphanedAppContainerProfiles("win32");
      expect(swept).toBe(1);
      expect(fake.calls.filter((c) => c.fn === "removeAppContainerAce").length).toBe(2);
      expect(fake.calls.some((c) => c.fn === "deleteAppContainerProfile" && c.args[0] === name)).toBe(
        true,
      );
      expect(fs.existsSync(path.join(dir, `${name}.grants`))).toBe(false);
      expect(fs.existsSync(path.join(dir, "unrelated.grants"))).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("keeps sweeping when a single delete throws (idempotent, best-effort)", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-ac-janitor2-"));
    _setWinAppContainerLedgerDirForTests(dir);
    const fake = makeFakeAcBindings({
      deleteAppContainerProfile(name: string) {
        if (name.endsWith("bad")) throw new Error("locked");
      },
    });
    _setWinAppContainerBindingsForTests(fake);
    try {
      fs.writeFileSync(
        path.join(dir, `${WIN_APPCONTAINER_PROFILE_PREFIX}-bad.grants`),
        "read\tC:\\r\n",
      );
      fs.writeFileSync(
        path.join(dir, `${WIN_APPCONTAINER_PROFILE_PREFIX}-good.grants`),
        "read\tC:\\r\n",
      );
      const swept = sweepOrphanedAppContainerProfiles("win32");
      // The good entry is swept; the failing one stays for the next boot.
      expect(swept).toBe(1);
      expect(fs.existsSync(path.join(dir, `${WIN_APPCONTAINER_PROFILE_PREFIX}-bad.grants`))).toBe(
        true,
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("probe platform + bindings/launcher gates", () => {
  it("every probe is false off-win32", () => {
    for (const platform of ["darwin", "linux"] as const) {
      expect(_runAppContainerFilesystemProbe(platform)).toBe(false);
      expect(_runAppContainerNetworkProbe(platform)).toBe(false);
      expect(_runAppContainerSpawnCagingProbe(platform)).toBe(false);
    }
  });

  it("every probe is false on win32 when the addon or launcher is absent", () => {
    _setWinAppContainerBindingsForTests(null);
    expect(_runAppContainerFilesystemProbe("win32")).toBe(false);
    expect(_runAppContainerNetworkProbe("win32")).toBe(false);
    expect(_runAppContainerSpawnCagingProbe("win32")).toBe(false);
    _setWinAppContainerBindingsForTests(makeFakeAcBindings());
    _setWinAppContainerLauncherForTests(null);
    expect(_runAppContainerFilesystemProbe("win32")).toBe(false);
    expect(_runAppContainerNetworkProbe("win32")).toBe(false);
    expect(_runAppContainerSpawnCagingProbe("win32")).toBe(false);
  });
});

describe("probe cache/override contract", () => {
  it("filesystem: honors + clears the test override", () => {
    _setAppContainerFilesystemProbeForTests(true);
    expect(probeAppContainerFilesystem()).toBe(true);
    _setAppContainerFilesystemProbeForTests(false);
    expect(probeAppContainerFilesystem()).toBe(false);
    _setAppContainerFilesystemProbeForTests(null);
    expect(typeof probeAppContainerFilesystem()).toBe("boolean");
    if (!onWindows) expect(probeAppContainerFilesystem()).toBe(false);
  });

  it("network: honors + clears the test override", () => {
    _setAppContainerNetworkProbeForTests(true);
    expect(probeAppContainerNetwork()).toBe(true);
    _setAppContainerNetworkProbeForTests(null);
    if (!onWindows) expect(probeAppContainerNetwork()).toBe(false);
  });

  it("spawn caging: honors + clears the test override", () => {
    _setAppContainerSpawnCagingProbeForTests(true);
    expect(probeAppContainerSpawnCaging()).toBe(true);
    _setAppContainerSpawnCagingProbeForTests(null);
    if (!onWindows) expect(probeAppContainerSpawnCaging()).toBe(false);
  });

  it("aggregate report mirrors the three probes", () => {
    _setAppContainerFilesystemProbeForTests(true);
    _setAppContainerNetworkProbeForTests(false);
    _setAppContainerSpawnCagingProbeForTests(true);
    expect(probeWinAppContainerReport()).toEqual({
      filesystemIsolation: true,
      networkIsolation: false,
      spawnCaging: true,
    });
  });
});

describe("build/check scripts still no-op off-win32", () => {
  it("build script exits 0 with the skip message", () => {
    if (onWindows) return;
    const res = spawnSync(
      process.execPath,
      [join(packageRoot, "scripts", "build-win-job-object-native.mjs")],
      { encoding: "utf-8", timeout: 30_000 },
    );
    expect(res.status).toBe(0);
    expect(res.stdout).toMatch(/Windows-only; skipping/);
  });

  it("check script exits 0 with the skip message", () => {
    if (onWindows) return;
    const res = spawnSync(
      process.execPath,
      [join(packageRoot, "scripts", "check-win-job-object-native.mjs")],
      { encoding: "utf-8", timeout: 30_000 },
    );
    expect(res.status).toBe(0);
    expect(res.stdout).toMatch(/Windows-only; skipping/);
  });
});

// ---------------------------------------------------------------------------
// Real win32 probes - the CI proof lane (desktop-e2e-smoke, windows-2022).
// The addon AND the launcher EXE are compiled by build:native immediately
// before this suite runs there, so these tests ASSERT both load instead of
// skipping on null - a broken build must fail, not skip. No-ops elsewhere.
// ---------------------------------------------------------------------------

describe("real win32 AppContainer enforcement (CI windows-2022 lane)", () => {
  it("addon exposes the AppContainer surface via getInfo", () => {
    if (!onWindows) return;
    const bindings = loadWinAppContainerBindings();
    expect(bindings).not.toBeNull();
    const info = bindings!.getInfo();
    expect(info.abiVersion).toBe(2);
    expect(info.primitives.appContainer).toBe(true);
    expect(info.primitives.securityCapabilitiesSpawn).toBe(true);
    expect(info.primitives.directorySidAcl).toBe(true);
    expect(info.primitives.networkCapabilitySids).toBe(true);
  });

  it("launcher EXE is built and resolvable", () => {
    if (!onWindows) return;
    const launcher = resolveWinAppContainerLauncher();
    expect(launcher).not.toBeNull();
    expect(fs.existsSync(launcher!)).toBe(true);
  });

  it("profile lifecycle: create → derive → delete round-trips", () => {
    if (!onWindows) return;
    const bindings = loadWinAppContainerBindings();
    expect(bindings).not.toBeNull();
    const name = `${WIN_APPCONTAINER_PROFILE_PREFIX}Test-${Date.now()}`;
    const sid = bindings!.createAppContainerProfile(name);
    try {
      expect(sid.startsWith("S-1-15-2-")).toBe(true);
      expect(bindings!.deriveAppContainerSid(name)).toBe(sid);
    } finally {
      bindings!.deleteAppContainerProfile(name);
    }
    // Deleting an already-deleted profile is idempotent (janitor contract).
    expect(() => bindings!.deleteAppContainerProfile(name)).not.toThrow();
  });

  it(
    "filesystem: AC child cannot read outside the grant but can read+write inside it",
    { timeout: 120_000 },
    () => {
      if (!onWindows) return;
      expect(loadWinAppContainerBindings()).not.toBeNull();
      expect(resolveWinAppContainerLauncher()).not.toBeNull();
      expect(_runAppContainerFilesystemProbe("win32")).toBe(true);
    },
  );

  it(
    "network: a plain child reaches a localhost listener, the AC child is denied",
    { timeout: 120_000 },
    () => {
      if (!onWindows) return;
      expect(loadWinAppContainerBindings()).not.toBeNull();
      expect(resolveWinAppContainerLauncher()).not.toBeNull();
      expect(_runAppContainerNetworkProbe("win32")).toBe(true);
    },
  );

  it(
    "spawn caging: the child is in the job while still suspended and descendants are reaped",
    { timeout: 120_000 },
    () => {
      if (!onWindows) return;
      expect(loadWinAppContainerBindings()).not.toBeNull();
      expect(resolveWinAppContainerLauncher()).not.toBeNull();
      expect(_runAppContainerSpawnCagingProbe("win32")).toBe(true);
    },
  );
});

describe("filterGrantsToExistingPaths", () => {
  // Shipped bug: GetNamedSecurityInfoW answers ERROR_FILE_NOT_FOUND (2) for an
  // absent path and the launcher treats any grant failure as fatal, so ONE
  // missing optional directory refused the whole spawn. The desktop read floor
  // includes ~/.convira/python-env, a user venv a packaged install never
  // creates, so on a clean Windows machine every sandboxed code-execution
  // spawn died with "granting directory access failed (code 2)".
  const present = new Set(["C:\\app\\python", "C:\\tmp\\work"]);
  const exists = (p: string): boolean => present.has(p);

  it("drops a missing read path instead of failing the whole spawn", () => {
    const out = filterGrantsToExistingPaths(
      {
        readPaths: ["C:\\app\\python", "C:\\Users\\me\\.convira\\python-env"],
        writePaths: ["C:\\tmp\\work"],
      },
      exists,
    );
    expect(out.grants.readPaths).toEqual(["C:\\app\\python"]);
    expect(out.grants.writePaths).toEqual(["C:\\tmp\\work"]);
    expect(out.dropped).toContain("C:\\Users\\me\\.convira\\python-env");
  });

  it("drops a missing write path too", () => {
    const out = filterGrantsToExistingPaths(
      { readPaths: [], writePaths: ["C:\\tmp\\work", "C:\\tmp\\gone"] },
      exists,
    );
    expect(out.grants.writePaths).toEqual(["C:\\tmp\\work"]);
    expect(out.dropped).toEqual(["C:\\tmp\\gone"]);
  });

  it("keeps a deny whose path exists", () => {
    const out = filterGrantsToExistingPaths(
      { readPaths: ["C:\\app\\python"], writePaths: [], denyPaths: ["C:\\tmp\\work"] },
      exists,
    );
    expect(out.grants.denyPaths).toEqual(["C:\\tmp\\work"]);
  });

  it("drops a missing deny that is outside every surviving grant", () => {
    // Nothing to weaken: AppContainer is deny-by-default, so a path carrying no
    // ACE is already unreachable.
    const out = filterGrantsToExistingPaths(
      { readPaths: ["C:\\app\\python"], writePaths: [], denyPaths: ["C:\\Users\\me\\.ssh"] },
      exists,
    );
    expect(out.grants.denyPaths).toEqual([]);
    expect(out.dropped).toContain("C:\\Users\\me\\.ssh");
  });

  it("REFUSES a missing deny that sits inside a surviving grant", () => {
    // Dropping this one would let the path inherit the surrounding grant the
    // moment anything creates it, turning a carve-out into an opening.
    expect(() =>
      filterGrantsToExistingPaths(
        {
          readPaths: ["C:\\app\\python"],
          writePaths: [],
          denyPaths: ["C:\\app\\python\\secrets"],
        },
        exists,
      ),
    ).toThrow(/refusing to spawn rather than let it inherit that grant/u);
  });

  it("matches containment case-insensitively, as Windows does", () => {
    // The grant survives (it exists), the deny does not, and only a
    // case-insensitive containment test sees that the deny is inside it.
    expect(() =>
      filterGrantsToExistingPaths(
        { readPaths: ["C:\\app\\python"], writePaths: [], denyPaths: ["C:\\App\\Python\\Keys"] },
        exists,
      ),
    ).toThrow(/refusing to spawn/u);
  });
});

/**
 * S0-43 - the shipped MCP deny list could never satisfy this filter on Windows.
 *
 * `resolveMcpSandboxSpawn` grants all of HOME read-write and denies ~20
 * home-relative paths, most of which cannot exist on Windows at all
 * (`Library/LaunchAgents`, `.zshrc`, `.bashrc`, `.profile`, `.gnupg`). The
 * filter threw on the first one and the error propagated out with no
 * try/catch, so STDIO MCP was deterministically broken on every Windows box.
 *
 * The suite above fixed `present` to two synthetic paths and only ever passed
 * single made-up deny entries; two of its cases actively ASSERT the throw, so
 * they locked the refusal in as desired behaviour without ever asking whether
 * a real shipped list could satisfy it. Those two cases stay green here - an
 * unknown leaf kind still fails closed - because guessing wrong is worse than
 * refusing.
 */
describe("filterGrantsToExistingPaths — shipped MCP deny list (S0-43)", () => {
  const HOME = "C:\\Users\\me";
  // Exactly the home-relative names the desktop MCP profile denies.
  const MCP_DENY_SUBPATHS = [
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".convira",
    ".config",
    "Library\\Keychains",
    "Library\\LaunchAgents",
    "Library\\LaunchDaemons",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".gitconfig",
  ];
  // A clean Windows box: HOME exists, none of the deny leaves do.
  const cleanBox = (p: string): boolean => p === HOME;

  it("survives the shipped MCP home-relative deny list against a whole-HOME grant on a clean Windows box", () => {
    const denyPaths = MCP_DENY_SUBPATHS.map((s) => `${HOME}\\${s}`);

    const out = filterGrantsToExistingPaths(
      { readPaths: [], writePaths: [HOME], denyPaths },
      cleanBox,
    );

    // Every deny survives as a deny - none dropped, none fatal.
    expect(out.grants.denyPaths).toEqual(denyPaths);
    expect(out.materialize.map((m) => m.path)).toEqual(denyPaths);
  });

  it("resolves each leaf to the right kind, because creating .gitconfig as a directory is unrecoverable", () => {
    const denyPaths = MCP_DENY_SUBPATHS.map((s) => `${HOME}\\${s}`);

    const out = filterGrantsToExistingPaths(
      { readPaths: [], writePaths: [HOME], denyPaths },
      cleanBox,
    );
    const kindOf = new Map(out.materialize.map((m) => [m.path, m.kind]));

    // path.extname reports "" for .zshrc, .gitconfig AND .ssh alike, so a
    // dot-suffix heuristic guesses wrong on exactly the names that matter.
    expect(kindOf.get(`${HOME}\\.ssh`)).toBe("dir");
    expect(kindOf.get(`${HOME}\\.gnupg`)).toBe("dir");
    expect(kindOf.get(`${HOME}\\Library\\LaunchAgents`)).toBe("dir");
    expect(kindOf.get(`${HOME}\\.gitconfig`)).toBe("file");
    expect(kindOf.get(`${HOME}\\.zshrc`)).toBe("file");
    expect(kindOf.get(`${HOME}\\.bashrc`)).toBe("file");
    expect(kindOf.get(`${HOME}\\.npmrc`)).toBe("file");
  });

  it("lets the caller's explicit kind override the built-in table", () => {
    const p = `${HOME}\\.config`;

    const out = filterGrantsToExistingPaths(
      {
        readPaths: [],
        writePaths: [HOME],
        denyPaths: [p],
        denyPathKinds: { [p]: "file" },
      },
      cleanBox,
    );

    expect(out.materialize).toEqual([{ path: p, kind: "file" }]);
  });

  it("still fails closed for a leaf whose kind nothing can resolve", () => {
    // The two assertions above this block depend on exactly this: an
    // unrecognised name with no caller-supplied kind must refuse, not guess.
    expect(() =>
      filterGrantsToExistingPaths(
        { readPaths: [], writePaths: [HOME], denyPaths: [`${HOME}\\mystery-leaf`] },
        cleanBox,
      ),
    ).toThrow(/leaf kind is unknown/u);
  });

  it("does not materialize a deny that already exists", () => {
    const p = `${HOME}\\.ssh`;

    const out = filterGrantsToExistingPaths(
      { readPaths: [], writePaths: [HOME], denyPaths: [p] },
      (candidate) => candidate === HOME || candidate === p,
    );

    expect(out.grants.denyPaths).toEqual([p]);
    expect(out.materialize).toEqual([]);
  });

  it("does not materialize a deny that no surviving grant can reach", () => {
    // Deny-by-default already covers it; creating it would be a pointless
    // write into the user's real home.
    const out = filterGrantsToExistingPaths(
      { readPaths: [], writePaths: ["C:\\app"], denyPaths: [`${HOME}\\.ssh`] },
      (p) => p === "C:\\app",
    );

    expect(out.materialize).toEqual([]);
    expect(out.dropped).toContain(`${HOME}\\.ssh`);
  });
});

/**
 * S0-52 - the DENY ace mask was derived from the grant flavor.
 *
 * The launcher passes write=false for every deny entry, so a deny ace carried
 * GENERIC_READ|GENERIC_EXECUTE only: a denyPaths carve-out nested inside a
 * granted write tree could not be READ but could still be overwritten or
 * DELETED. That is the encrypted convira-store, the offline-license token and
 * ~/.ssh/authorized_keys, inside a sandbox whose denyPaths contract says
 * "hidden" and whose other two adapters implement it as a full block.
 *
 * The mask lives in a C++ header, so this pins the source invariant. The addon
 * and launcher EXE must be rebuilt on Windows (`build:native`) for the change
 * to take effect - a stale prebuilt binary silently keeps the old mask.
 */
describe("AppContainer DENY ace mask (S0-52)", () => {
  const header = readFileSync(
    fileURLToPath(new URL("../native/win_appcontainer_common.h", import.meta.url)),
    "utf8",
  );

  function aceMaskForBody(): string {
    const start = header.indexOf("inline DWORD AceMaskFor(");
    expect(start).toBeGreaterThan(-1);
    const open = header.indexOf("{", start);
    let depth = 0;
    for (let i = open; i < header.length; i += 1) {
      if (header[i] === "{") depth += 1;
      else if (header[i] === "}") {
        depth -= 1;
        if (depth === 0) return header.slice(open, i + 1);
      }
    }
    throw new Error("AceMaskFor body not found");
  }

  it("the DENY ace mask includes write + delete regardless of the grant flavor", () => {
    const body = aceMaskForBody();
    const denyBranch = body.slice(0, body.indexOf("return write"));

    // The deny branch must be reached BEFORE the write ternary...
    expect(denyBranch).toMatch(/if\s*\(deny\)/u);
    // ...and must remove write and delete, not just read/execute.
    for (const right of ["GENERIC_READ", "GENERIC_WRITE", "GENERIC_EXECUTE", "DELETE"]) {
      expect(denyBranch).toContain(right);
    }
  });

  it("also denies DACL rewriting, so the child cannot re-grant itself", () => {
    const body = aceMaskForBody();
    const denyBranch = body.slice(0, body.indexOf("return write"));

    expect(denyBranch).toContain("WRITE_DAC");
    expect(denyBranch).toContain("WRITE_OWNER");
  });

  it("routes the ACE through the helper instead of an inline grant-flavor ternary", () => {
    // Vacuity guard: the helper could be correct and simply unused.
    expect(header).toContain("access.grfAccessPermissions = AceMaskFor(write, deny);");
    expect(header).not.toMatch(/grfAccessPermissions\s*=\s*\n?\s*write\s*\?/u);
  });

  it("leaves the GRANT masks exactly as they were", () => {
    // A read grant must not silently acquire write.
    const body = aceMaskForBody();
    expect(body).toMatch(
      /return write\s*\?\s*\(GENERIC_READ \| GENERIC_WRITE \| GENERIC_EXECUTE \| DELETE\)\s*:\s*\(GENERIC_READ \| GENERIC_EXECUTE\);/u,
    );
  });
});
