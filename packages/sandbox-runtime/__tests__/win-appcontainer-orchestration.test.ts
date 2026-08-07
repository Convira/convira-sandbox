/**
 * AppContainer probe ORCHESTRATION coverage (HARDENING batch 5).
 *
 * `win-appcontainer.test.ts` proves the platform gates (every probe is false
 * off-win32) and the real enforcement on the CI windows-2022 lane. Neither
 * exercises the probe BODIES anywhere else, so the spawn/poll/verdict/cleanup
 * orchestration - the part that is pure TypeScript and platform-independent -
 * shipped unverified on the two platforms that actually run the suite.
 *
 * These tests close that gap the same way the rest of the package fakes an
 * OS authority: the addon is a fake binding object and the launcher EXE is a
 * stub executable that emulates `convira_sbx_launch.exe`'s observable
 * contract (parse `<profile> <grants> [--probe-report F] -- <cmd...>`, produce
 * the verdict file, keep its process tree tied to its own lifetime). The
 * probes then run their REAL code paths - real child processes, real polling,
 * real cleanup - and return honest verdicts on macOS and Linux.
 *
 * What this deliberately does NOT claim: that AppContainer isolates anything.
 * Only the win32 lane can prove enforcement, and it still does.
 */
import { describe, it, expect, afterEach, beforeEach } from "vitest";
import { shimPayloadHost } from "./fixtures/selftest-host.js";
import { _resetProbePayloadHostCache, _setProbePayloadHostForTests } from "../src/probe-payload.js";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  _setWinAppContainerBindingsForTests,
  _resetWinAppContainerBindingsCache,
  _setWinAppContainerLauncherForTests,
  _setWinAppContainerLedgerDirForTests,
  _runAppContainerFilesystemProbe,
  _runAppContainerNetworkProbe,
  _runAppContainerSpawnCagingProbe,
  _resetAppContainerFilesystemProbeCache,
  _resetAppContainerNetworkProbeCache,
  _resetAppContainerSpawnCagingProbeCache,
  type WinAppContainerBindings,
} from "../src/win-appcontainer.js";
import { _resetWinJobObjectBindingsCache } from "../src/win-job-object.js";

// The stub launcher is a shebang script, so these run on macOS/Linux only.
// On win32 the REAL launcher + addon are built before the suite and the
// enforcement describe in win-appcontainer.test.ts covers the same functions.
const stubbable = process.platform !== "win32";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function fakeBindings(
  overrides: Partial<WinAppContainerBindings> = {},
): WinAppContainerBindings & { deleted: string[] } {
  const deleted: string[] = [];
  return {
    deleted,
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
    createJob: () => 1,
    assignProcess: () => {},
    terminateJob: () => {},
    closeJob: () => {},
    createAppContainerProfile: () => "S-1-15-2-2222",
    deriveAppContainerSid: () => "S-1-15-2-2222",
    deleteAppContainerProfile(name: string) {
      deleted.push(name);
    },
    removeAppContainerAce: () => {},
    ...overrides,
  };
}

/**
 * Write an executable stub standing in for `convira_sbx_launch.exe`. `body`
 * runs with `argv` (post-`node stub`) already split into the launcher's own
 * options and the inner command, mirroring how the real EXE parses them.
 */
function writeStubLauncher(dir: string, body: string): string {
  const file = path.join(dir, "stub-launch.mjs");
  fs.writeFileSync(
    file,
    `#!${process.execPath}\n` +
      'import * as fs from "node:fs";\n' +
      'import * as path from "node:path";\n' +
      'import { spawn } from "node:child_process";\n' +
      "const argv = process.argv.slice(2);\n" +
      'const sep = argv.indexOf("--");\n' +
      "const own = argv.slice(0, sep);\n" +
      "const inner = argv.slice(sep + 1);\n" +
      "const profileName = own[0];\n" +
      "const grantsFile = own[1];\n" +
      'const reportIdx = own.indexOf("--probe-report");\n' +
      "const reportFile = reportIdx === -1 ? null : own[reportIdx + 1];\n" +
      // Atomic publish: the probes poll these files, so a torn read must be
      // impossible or the verdict would be decided on a partial line.
      "const publish = (target, text) => {\n" +
      '  const tmp = target + ".tmp";\n' +
      "  fs.writeFileSync(tmp, text);\n" +
      "  fs.renameSync(tmp, target);\n" +
      "};\n" +
      "void profileName; void grantsFile; void spawn; void path;\n" +
      body,
    { mode: 0o755 },
  );
  return file;
}

/**
 * Children that exit as soon as their spawning stub launcher is gone, which
 * is what the real launcher's kill-on-close job does to its caged tree.
 *
 * Death is detected through an inherited stdin pipe (EOF when the launcher's
 * end closes), NOT by polling the launcher's pid: on POSIX the SIGKILLed
 * launcher stays a zombie until the vitest worker's event loop turns, and the
 * probe blocks that loop while polling, so a pid check would never see it die.
 */
const TIED_TO_LAUNCHER =
  "process.stdin.resume();" +
  'process.stdin.on("end",()=>process.exit(0));' +
  'process.stdin.on("close",()=>process.exit(0));' +
  "setInterval(()=>{},1000);";

afterEach(() => {
  _resetProbePayloadHostCache();
  _setWinAppContainerBindingsForTests(null);
  _resetWinAppContainerBindingsCache();
  _resetWinJobObjectBindingsCache();
  _setWinAppContainerLauncherForTests(undefined);
  _setWinAppContainerLedgerDirForTests(null);
  _resetAppContainerFilesystemProbeCache();
  _resetAppContainerNetworkProbeCache();
  _resetAppContainerSpawnCagingProbeCache();
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("filesystem probe orchestration", () => {
  // The shipped probe subject is a C++ verb table inside the signed launcher.
  // Pinning the Node shim keeps this orchestration exercisable off-win32.
  beforeEach(() => {
    _setProbePayloadHostForTests(shimPayloadHost());
  });

  it("passes when the AC child reports denied-outside + ok-inside", { timeout: 60_000 }, () => {
    if (!stubbable) return;
    const workspace = makeTempDir("sbx-ac-orch-fs-");
    _setWinAppContainerLedgerDirForTests(workspace);
    const bindings = fakeBindings();
    _setWinAppContainerBindingsForTests(bindings);
    _setWinAppContainerLauncherForTests(
      writeStubLauncher(
        workspace,
        // The probe hands the granted dir as the final inner argument and
        // then polls <grantedDir>/result.txt for the two-leg verdict.
        "const grantedDir = inner[inner.length - 1];\n" +
          'publish(path.join(grantedDir, "result.txt"), "denied:ok");\n',
      ),
    );

    expect(_runAppContainerFilesystemProbe("win32")).toBe(true);
    // Cleanup ran: the ephemeral profile was deleted even though the launcher
    // exited on its own (the real launcher deletes it in its finally).
    expect(bindings.deleted.length).toBe(1);
  });

  it("fails when the AC child could read outside its grant", { timeout: 60_000 }, () => {
    if (!stubbable) return;
    const workspace = makeTempDir("sbx-ac-orch-fs-leak-");
    _setWinAppContainerLedgerDirForTests(workspace);
    _setWinAppContainerBindingsForTests(fakeBindings());
    _setWinAppContainerLauncherForTests(
      writeStubLauncher(
        workspace,
        "const grantedDir = inner[inner.length - 1];\n" +
          // "read" on the outside leg is exactly the false-negative this probe
          // exists to catch: isolation claimed, confinement absent.
          'publish(path.join(grantedDir, "result.txt"), "read:ok");\n',
      ),
    );

    expect(_runAppContainerFilesystemProbe("win32")).toBe(false);
  });

  it("fails closed when the launcher cannot be spawned", { timeout: 60_000 }, () => {
    if (!stubbable) return;
    const workspace = makeTempDir("sbx-ac-orch-fs-nolaunch-");
    _setWinAppContainerLedgerDirForTests(workspace);
    _setWinAppContainerBindingsForTests(fakeBindings());
    _setWinAppContainerLauncherForTests(path.join(workspace, "does-not-exist"));

    expect(_runAppContainerFilesystemProbe("win32")).toBe(false);
  });

  it("survives a cleanup delete that throws", { timeout: 60_000 }, () => {
    if (!stubbable) return;
    const workspace = makeTempDir("sbx-ac-orch-fs-badclean-");
    _setWinAppContainerLedgerDirForTests(workspace);
    _setWinAppContainerBindingsForTests(
      fakeBindings({
        deleteAppContainerProfile() {
          throw new Error("profile locked by the OS");
        },
      }),
    );
    _setWinAppContainerLauncherForTests(
      writeStubLauncher(
        workspace,
        "const grantedDir = inner[inner.length - 1];\n" +
          'publish(path.join(grantedDir, "result.txt"), "denied:ok");\n',
      ),
    );

    // A failing profile delete is best-effort: the verdict still stands and
    // the boot janitor picks the profile up from the ledger.
    expect(_runAppContainerFilesystemProbe("win32")).toBe(true);
  });
});

describe("network probe orchestration", () => {
  // The shipped probe subject is a C++ verb table inside the signed launcher.
  // Pinning the Node shim keeps this orchestration exercisable off-win32.
  beforeEach(() => {
    _setProbePayloadHostForTests(shimPayloadHost());
  });

  it(
    "passes when the control child connects and the AC child is denied",
    { timeout: 60_000 },
    () => {
      if (!stubbable) return;
      const workspace = makeTempDir("sbx-ac-orch-net-");
      _setWinAppContainerLedgerDirForTests(workspace);
      _setWinAppContainerBindingsForTests(fakeBindings());
      _setWinAppContainerLauncherForTests(
        writeStubLauncher(
          workspace,
          // The AC leg's report file is the final inner argument.
          "const acResult = inner[inner.length - 1];\n" + 'publish(acResult, "denied");\n',
        ),
      );

      expect(_runAppContainerNetworkProbe("win32")).toBe(true);
    },
  );

  it("accepts a timeout verdict as denial", { timeout: 60_000 }, () => {
    if (!stubbable) return;
    const workspace = makeTempDir("sbx-ac-orch-net-timeout-");
    _setWinAppContainerLedgerDirForTests(workspace);
    _setWinAppContainerBindingsForTests(fakeBindings());
    _setWinAppContainerLauncherForTests(
      writeStubLauncher(
        workspace,
        "const acResult = inner[inner.length - 1];\n" + 'publish(acResult, "timeout");\n',
      ),
    );

    expect(_runAppContainerNetworkProbe("win32")).toBe(true);
  });

  it("fails when the AC child reached the listener", { timeout: 60_000 }, () => {
    if (!stubbable) return;
    const workspace = makeTempDir("sbx-ac-orch-net-open-");
    _setWinAppContainerLedgerDirForTests(workspace);
    _setWinAppContainerBindingsForTests(fakeBindings());
    _setWinAppContainerLauncherForTests(
      writeStubLauncher(
        workspace,
        "const acResult = inner[inner.length - 1];\n" + 'publish(acResult, "connected");\n',
      ),
    );

    expect(_runAppContainerNetworkProbe("win32")).toBe(false);
  });

  it("fails closed when the launcher cannot be spawned", { timeout: 60_000 }, () => {
    if (!stubbable) return;
    const workspace = makeTempDir("sbx-ac-orch-net-nolaunch-");
    _setWinAppContainerLedgerDirForTests(workspace);
    _setWinAppContainerBindingsForTests(fakeBindings());
    _setWinAppContainerLauncherForTests(path.join(workspace, "does-not-exist"));

    expect(_runAppContainerNetworkProbe("win32")).toBe(false);
  });
});

describe("spawn-caging probe orchestration", () => {
  // The shipped probe subject is a C++ verb table inside the signed launcher.
  // Pinning the Node shim keeps this orchestration exercisable off-win32.
  beforeEach(() => {
    _setProbePayloadHostForTests(shimPayloadHost());
  });

  it(
    "passes when the launcher reports a caged child and the tree dies with it",
    { timeout: 60_000 },
    () => {
      if (!stubbable) return;
      const workspace = makeTempDir("sbx-ac-orch-cage-");
      _setWinAppContainerLedgerDirForTests(workspace);
      _setWinAppContainerBindingsForTests(fakeBindings());
      _setWinAppContainerLauncherForTests(
        writeStubLauncher(
          workspace,
          "const gpidFile = inner[inner.length - 1];\n" +
            `const tied = ${JSON.stringify(TIED_TO_LAUNCHER)};\n` +
            'const tie = () => spawn(process.execPath, ["-e", tied], { stdio: ["pipe", "ignore", "ignore"] });\n' +
            "const child = tie();\n" +
            "const grand = tie();\n" +
            // caged=1 is taken while the child is still suspended by the real
            // launcher; the stub asserts the same shape the probe parses.
            "publish(reportFile, `caged=1\\npid=${child.pid}\\n`);\n" +
            "publish(gpidFile, String(grand.pid));\n" +
            "setInterval(() => {}, 1000);\n",
        ),
      );

      expect(_runAppContainerSpawnCagingProbe("win32")).toBe(true);
    },
  );

  it("fails when the launcher reports the child was NOT in the job", { timeout: 60_000 }, () => {
    if (!stubbable) return;
    const workspace = makeTempDir("sbx-ac-orch-cage-uncaged-");
    _setWinAppContainerLedgerDirForTests(workspace);
    _setWinAppContainerBindingsForTests(fakeBindings());
    _setWinAppContainerLauncherForTests(
      writeStubLauncher(
        workspace,
        "publish(reportFile, `caged=0\\npid=${process.pid}\\n`);\n" +
          "setInterval(() => {}, 1000);\n",
      ),
    );

    expect(_runAppContainerSpawnCagingProbe("win32")).toBe(false);
  });

  it("fails when the report carries no child pid", { timeout: 60_000 }, () => {
    if (!stubbable) return;
    const workspace = makeTempDir("sbx-ac-orch-cage-nopid-");
    _setWinAppContainerLedgerDirForTests(workspace);
    _setWinAppContainerBindingsForTests(fakeBindings());
    _setWinAppContainerLauncherForTests(
      writeStubLauncher(
        workspace,
        'publish(reportFile, "caged=1\\n");\n' + "setInterval(() => {}, 1000);\n",
      ),
    );

    expect(_runAppContainerSpawnCagingProbe("win32")).toBe(false);
  });

  it("fails closed when the launcher cannot be spawned", { timeout: 60_000 }, () => {
    if (!stubbable) return;
    const workspace = makeTempDir("sbx-ac-orch-cage-nolaunch-");
    _setWinAppContainerLedgerDirForTests(workspace);
    _setWinAppContainerBindingsForTests(fakeBindings());
    _setWinAppContainerLauncherForTests(path.join(workspace, "does-not-exist"));

    expect(_runAppContainerSpawnCagingProbe("win32")).toBe(false);
  });
});
