/**
 * D003 - the Linux deny path must never leave anything behind in the user's
 * real home.
 *
 * bwrap needs a mount point before it can place `--tmpfs` / `--ro-bind` over a
 * name, so the adapter used to CREATE every missing deny leaf on the host,
 * in the parent, before bwrap exists. With the shipped MCP deny list that is
 * ~21 permanent objects in a fresh Linux home on the FIRST sandboxed spawn,
 * none of which anything ever removes - including an empty `~/.bash_profile`,
 * which takes precedence over `~/.profile` for bash login shells, so the
 * user's login environment silently stops being applied outside the app.
 *
 * The deny itself is not optional (a missing deny inside a read-write bind is
 * creatable by the sandboxed process and the write reaches the host), so these
 * tests assert BOTH halves: the host is untouched AND the deny still holds.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { linuxAdapter, _resetLinuxAdapterCache } from "../src/adapters/native-linux.js";
import { _setRlimitProbeForTests, _resetRlimitProbeCache } from "../src/rlimit.js";
import type { SandboxSpawnConfig } from "../src/types.js";

// The optional kernel-hardening enforcer is never exercised here; stub it so
// the import in wrapSpawn cannot depend on whether the native binding exists.
const { getSeccompFd } = vi.hoisted(() => ({ getSeccompFd: vi.fn() }));
vi.mock("@convira/sandbox-enforcer", () => ({ getSeccompFd }));

function makeConfig(filesystem: SandboxSpawnConfig["filesystem"]): SandboxSpawnConfig {
  return {
    command: "node",
    args: ["server.js"],
    cwd: "/",
    env: {},
    filesystem,
    network: { enabled: true, allowLoopback: true },
    resources: { memoryMb: 512, maxProcesses: 16 },
  };
}

/** Index of the arg that follows `flag` at `value`, or -1. */
function mountIndex(args: string[], flag: string, value: string): number {
  for (let i = 1; i < args.length; i += 1) {
    if (args[i] === value && args[i - 1] === flag) return i;
  }
  return -1;
}

describe("linuxAdapter deny paths never mutate the host", () => {
  let fakeResources: string;
  let prevResourcesPath: string | undefined;
  let home: string;

  beforeEach(() => {
    // findBwrap() accepts a bundled binary under resourcesPath that passes the
    // integrity gate, which is what lets wrapSpawn run on a non-Linux host.
    fakeResources = fs.mkdtempSync(path.join(os.tmpdir(), "sb-deny-resources-"));
    const bundled = path.join(fakeResources, "bwrap");
    fs.writeFileSync(bundled, "#!/bin/sh\n");
    fs.chmodSync(bundled, 0o755);
    const proc = process as NodeJS.Process & { resourcesPath?: string };
    prevResourcesPath = proc.resourcesPath;
    proc.resourcesPath = fakeResources;
    _resetLinuxAdapterCache();
    // Pin the rlimit probe off so the argv tail stays host-independent.
    _setRlimitProbeForTests({ ok: false, procFlag: null });
    home = fs.mkdtempSync(path.join(os.tmpdir(), "sb-deny-home-"));
  });

  afterEach(() => {
    const proc = process as NodeJS.Process & { resourcesPath?: string };
    if (prevResourcesPath === undefined) delete proc.resourcesPath;
    else proc.resourcesPath = prevResourcesPath;
    _resetLinuxAdapterCache();
    _resetRlimitProbeCache();
    fs.rmSync(fakeResources, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("leaves a fresh home byte-for-byte untouched while masking every missing deny", async () => {
    // The shape a fresh Linux home actually has: some real content, and none of
    // the credential / shell-startup names the MCP cage denies.
    fs.mkdirSync(path.join(home, "Documents"));
    fs.writeFileSync(path.join(home, "notes.txt"), "keep me");
    const before = fs.readdirSync(home).sort();

    const denyPaths = [
      path.join(home, ".ssh"),
      path.join(home, ".gitconfig"),
      path.join(home, ".bash_profile"),
      path.join(home, ".profile"),
      path.join(home, "Library", "LaunchAgents"),
    ];

    const spec = await linuxAdapter.wrapSpawn(
      makeConfig({ readPaths: [], writePaths: [home], denyPaths }),
    );

    // Nothing was created, renamed or removed on the host.
    expect(fs.readdirSync(home).sort()).toEqual(before);
    for (const p of denyPaths) {
      expect(fs.existsSync(p), `${p} was materialized on the host`).toBe(false);
    }

    // …and the deny still holds: the bind is replaced by an empty tmpfs, so a
    // name that is absent on the host cannot be created through it.
    const bindIdx = mountIndex(spec.args, "--bind", home);
    const sealIdx = mountIndex(spec.args, "--tmpfs", home);
    expect(bindIdx).toBeGreaterThan(-1);
    expect(sealIdx).toBeGreaterThan(bindIdx);
  });

  it("re-binds the existing children of a sealed directory so the mount stays usable", async () => {
    fs.mkdirSync(path.join(home, "Documents"));
    fs.writeFileSync(path.join(home, "notes.txt"), "keep me");

    const spec = await linuxAdapter.wrapSpawn(
      makeConfig({ readPaths: [], writePaths: [home], denyPaths: [path.join(home, ".ssh")] }),
    );

    const sealIdx = mountIndex(spec.args, "--tmpfs", home);
    for (const child of ["Documents", "notes.txt"]) {
      const idx = mountIndex(spec.args, "--bind", path.join(home, child));
      expect(idx, `${child} was not handed back after the seal`).toBeGreaterThan(sealIdx);
    }
  });

  it("does not hand a denied child back through the seal", async () => {
    // ~/.ssh exists AND is denied; ~/.gitconfig does not exist and is denied.
    // The second forces the seal, and the seal must not re-bind the first.
    const existingDeny = path.join(home, ".ssh");
    fs.mkdirSync(existingDeny);
    fs.writeFileSync(path.join(existingDeny, "id_ed25519"), "PRIVATE KEY");

    const spec = await linuxAdapter.wrapSpawn(
      makeConfig({
        readPaths: [],
        writePaths: [home],
        denyPaths: [existingDeny, path.join(home, ".gitconfig")],
      }),
    );

    expect(mountIndex(spec.args, "--bind", existingDeny)).toBe(-1);
    const sealIdx = mountIndex(spec.args, "--tmpfs", home);
    expect(sealIdx).toBeGreaterThan(-1);
    expect(mountIndex(spec.args, "--tmpfs", existingDeny)).toBeGreaterThan(sealIdx);
    // The real key is still on disk - masking is not deletion.
    expect(fs.existsSync(path.join(existingDeny, "id_ed25519"))).toBe(true);
  });

  it("replays a buried read-only mount instead of handing it back writable", async () => {
    // The seal hides every mount already emitted below it. Re-binding those
    // children blindly would upgrade a path the caller declared READ-ONLY to
    // read-write, which is a widening the deny fix must not smuggle in.
    const readOnly = path.join(home, "reference");
    fs.mkdirSync(readOnly);

    const spec = await linuxAdapter.wrapSpawn(
      makeConfig({
        readPaths: [readOnly],
        writePaths: [home],
        denyPaths: [path.join(home, ".ssh")],
      }),
    );

    const sealIdx = mountIndex(spec.args, "--tmpfs", home);
    expect(sealIdx).toBeGreaterThan(-1);
    // The mount is re-emitted after the seal that buried it…
    const afterSeal = spec.args.slice(sealIdx);
    expect(mountIndex(afterSeal, "--ro-bind", readOnly)).toBeGreaterThan(-1);
    // …and nothing after the seal hands the same path back read-write.
    expect(mountIndex(afterSeal, "--bind", readOnly)).toBe(-1);
  });

  it("does not hand a read-only subtree back writable when it anchors a deny", async () => {
    // The deny sits inside a subtree the caller declared READ-ONLY, which is
    // itself inside a wider writable bind. Asking only whether SOME writable
    // mount contains the deny seals the read-only directory and re-binds its
    // children read-write, so `reference/a.txt` comes back writable even though
    // the caller granted read access only. Under the ro-bind the sandboxed
    // process cannot create the missing deny in the first place, so there is
    // nothing to seal.
    const readOnly = path.join(home, "reference");
    fs.mkdirSync(readOnly);
    fs.writeFileSync(path.join(readOnly, "a.txt"), "reference data");
    const child = path.join(readOnly, "a.txt");

    const spec = await linuxAdapter.wrapSpawn(
      makeConfig({
        readPaths: [readOnly],
        writePaths: [home],
        denyPaths: [path.join(readOnly, ".ssh")],
      }),
    );

    expect(mountIndex(spec.args, "--ro-bind", readOnly)).toBeGreaterThan(-1);
    expect(mountIndex(spec.args, "--tmpfs", readOnly)).toBe(-1);
    // Nothing hands a path under the read-only subtree back read-write.
    expect(mountIndex(spec.args, "--bind", child)).toBe(-1);
    expect(mountIndex(spec.args, "--dev-bind", child)).toBe(-1);
    expect(spec.args).not.toContain(path.join(readOnly, ".ssh"));
    expect(fs.existsSync(path.join(readOnly, ".ssh"))).toBe(false);
  });

  it("does not mask a deny whose parent is denied and still the host directory", async () => {
    // ~/.ssh exists and is denied, so its anchor is skipped and no seal is
    // emitted. The missing child is denied too and listed FIRST, so its overlay
    // would land while ~/.ssh is still the real directory reached through the
    // read-write bind - and bwrap creates its own mount points, which is the
    // host write the seal exists to prevent. The parent's own tmpfs already
    // covers every name inside it.
    const ssh = path.join(home, ".ssh");
    fs.mkdirSync(ssh);
    const child = path.join(ssh, "id_rsa");

    const spec = await linuxAdapter.wrapSpawn(
      makeConfig({ readPaths: [], writePaths: [home], denyPaths: [child, ssh] }),
    );

    expect(spec.args).not.toContain(child);
    expect(fs.existsSync(child)).toBe(false);
    expect(fs.readdirSync(ssh)).toEqual([]);
    // The parent deny still holds, after the bind that would otherwise expose it.
    expect(mountIndex(spec.args, "--tmpfs", ssh)).toBeGreaterThan(
      mountIndex(spec.args, "--bind", home),
    );
  });

  it("does not seal a read-only mount, where a missing deny is not creatable", async () => {
    // `--ro-bind` refuses the mkdir itself, so there is nothing to defend
    // against and no reason to make the whole mount ephemeral.
    const denied = path.join(home, ".ssh");
    const spec = await linuxAdapter.wrapSpawn(
      makeConfig({ readPaths: [home], writePaths: [], denyPaths: [denied] }),
    );

    expect(mountIndex(spec.args, "--tmpfs", home)).toBe(-1);
    expect(spec.args).not.toContain(denied);
    expect(fs.existsSync(denied)).toBe(false);
  });

  it("masks an unknown leaf name without creating it and without refusing the spawn", async () => {
    // Guessing the kind was only dangerous because the guess landed on the
    // host. On a sealed anchor it cannot, so an unfamiliar name is masked
    // rather than turned into a hard spawn refusal.
    const denied = path.join(home, "vendor-credentials.ini");
    const spec = await linuxAdapter.wrapSpawn(
      makeConfig({ readPaths: [], writePaths: [home], denyPaths: [denied] }),
    );

    expect(fs.existsSync(denied)).toBe(false);
    expect(spec.args).toContain(denied);
  });

  it("refuses the spawn when the anchor cannot be enumerated", async () => {
    // Failing to read the directory means we cannot hand its children back, and
    // handing back nothing would silently break the sandboxed process while
    // skipping the seal would leave the deny creatable. Fail closed.
    if (typeof process.getuid === "function" && process.getuid() === 0) return;
    const locked = path.join(home, "locked");
    fs.mkdirSync(locked);
    fs.chmodSync(locked, 0o000);
    try {
      await expect(
        linuxAdapter.wrapSpawn(
          makeConfig({
            readPaths: [],
            writePaths: [locked],
            denyPaths: [path.join(locked, ".ssh")],
          }),
        ),
      ).rejects.toThrow(/cannot enumerate/u);
    } finally {
      fs.chmodSync(locked, 0o700);
    }
  });
});
