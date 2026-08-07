#!/usr/bin/env node

// Windows-only clone of runtime-core's build-safe-workspace-native.mjs
// (exclusive dir-lock, source+platform+arch+ABI fingerprint stamp, compile in
// OS-private scratch via node-gyp's module API, atomic publish, --verify
// mode). The ONE divergence: the Job Object addon has no meaning off win32,
// so every other platform exits 0 without touching the toolchain.

import { createHash, randomBytes } from "node:crypto";
import {
  access,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { homedir, tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const scriptPath = fileURLToPath(import.meta.url);
const packageRoot = resolve(dirname(scriptPath), "..");
const nativeRoot = join(packageRoot, "native");
const buildRoot = join(nativeRoot, "build");
const binaryPath = join(buildRoot, "Release", "win_job_object.node");
// The AppContainer launcher EXE compiles from the same binding.gyp (second,
// executable target) and publishes next to the addon; both artifacts share
// one stamp so neither can be stale independently.
const launcherPath = join(buildRoot, "Release", "convira_sbx_launch.exe");
const stampPath = join(buildRoot, ".convira-win-job-object-native.json");
const lockPath = join(nativeRoot, ".win-job-object-native-build.lock");
const BUILD_STAMP_VERSION = 2;
const DEFAULT_LOCK_TIMEOUT_MS = 10 * 60_000;
const ORPHAN_GRACE_MS = 5_000;

const delay = (ms) => new Promise((resolveDelay) => setTimeout(resolveDelay, ms));

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function isProcessAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM means the process exists but is owned by another principal.
    return error?.code === "EPERM";
  }
}

async function readLockOwner(directory) {
  try {
    return JSON.parse(await readFile(join(directory, "owner.json"), "utf8"));
  } catch {
    return null;
  }
}

/**
 * Serialize native builds across pnpm/turbo processes. The directory creation is
 * the atomic claim; owner.json exists only to recover a lock left by a killed build.
 */
export async function withExclusiveBuildLock(
  directory,
  task,
  { timeoutMs = DEFAULT_LOCK_TIMEOUT_MS, pollMs = 100 } = {},
) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      await mkdir(directory, { mode: 0o700 });
      try {
        await writeFile(
          join(directory, "owner.json"),
          `${JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() })}\n`,
          { mode: 0o600 },
        );
        return await task();
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;

      const [owner, lockStat] = await Promise.all([
        readLockOwner(directory),
        stat(directory).catch(() => null),
      ]);
      const ageMs = lockStat ? Date.now() - lockStat.mtimeMs : 0;
      const ownerIsDead = owner?.pid !== undefined && !isProcessAlive(owner.pid);
      const ownerWasNeverWritten = owner === null && ageMs >= ORPHAN_GRACE_MS;
      if (ownerIsDead || ownerWasNeverWritten) {
        // The directory name is exact and package-owned. A live owner is never removed.
        await rm(directory, { recursive: true, force: true }).catch(() => {});
        continue;
      }
      if (Date.now() >= deadline) {
        throw new Error(
          `Timed out waiting for win_job_object native build lock (${directory}); owner=${JSON.stringify(owner)}`,
        );
      }
      await delay(pollMs);
    }
  }
}

async function nativeSourceFiles(directory = nativeRoot) {
  const result = [];
  const visit = async (current) => {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      if (current === nativeRoot && (entry.name === "build" || entry.name.startsWith(".win-"))) {
        continue;
      }
      const absolute = join(current, entry.name);
      if (entry.isDirectory()) {
        await visit(absolute);
      } else if (/\.(?:c|cc|cpp|cxx|gyp|gypi|h|hh|hpp)$/u.test(entry.name)) {
        result.push(absolute);
      }
    }
  };
  await visit(directory);
  return result.sort((a, b) => relative(nativeRoot, a).localeCompare(relative(nativeRoot, b)));
}

async function buildFingerprint() {
  const nodeGypPackage = JSON.parse(
    await readFile(require.resolve("node-gyp/package.json"), "utf8"),
  );
  const hash = createHash("sha256");
  hash.update(
    JSON.stringify({
      stampVersion: BUILD_STAMP_VERSION,
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.versions.node,
      nodeModuleAbi: process.versions.modules,
      nodeGypVersion: nodeGypPackage.version,
    }),
  );
  for (const source of await nativeSourceFiles()) {
    hash.update("\0");
    hash.update(relative(nativeRoot, source));
    hash.update("\0");
    hash.update(await readFile(source));
  }
  return hash.digest("hex");
}

async function sha256File(path) {
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
}

async function readBuildStamp() {
  try {
    return JSON.parse(await readFile(stampPath, "utf8"));
  } catch {
    return null;
  }
}

async function currentBuildState() {
  const fingerprint = await buildFingerprint();
  const stamp = await readBuildStamp();
  if (
    !(await exists(binaryPath)) ||
    !(await exists(launcherPath)) ||
    stamp?.fingerprint !== fingerprint
  ) {
    return { current: false, fingerprint };
  }
  const binarySha256 = await sha256File(binaryPath);
  const launcherSha256 = await sha256File(launcherPath);
  return {
    current: stamp.binarySha256 === binarySha256 && stamp.launcherSha256 === launcherSha256,
    fingerprint,
    binarySha256,
    launcherSha256,
  };
}

async function runNodeGyp(directory) {
  // Invoke node-gyp through its reviewed module API. This keeps the build
  // script out of Convira's direct child_process inventory; node-gyp remains
  // the single dependency-owned bootstrap for compiler/make subprocesses.
  const createNodeGyp = require("node-gyp");
  const nodeGypRequire = createRequire(require.resolve("node-gyp/package.json"));
  const envPaths = nodeGypRequire("env-paths");
  const program = createNodeGyp();
  program.parseArgv([process.execPath, "node-gyp", "rebuild"]);
  const home = homedir();
  // Package-scoped devdir - see the matching note in runtime-core's
  // build-safe-workspace-native.mjs. Both packages build a native addon, turbo
  // runs them concurrently, and sharing one node-gyp cache directory raced
  // during header install (windows-2025, exit 13 "unsettled top-level await").
  // Isolating the trees leaves no shared mutable state to contend on.
  program.devDir = program.opts.devdir
    ? String(program.opts.devdir).replace(/^~/u, home)
    : join(envPaths("node-gyp", { suffix: "" }).cache, "convira-sandbox-runtime");

  const priorCwd = process.cwd();
  process.chdir(directory);
  try {
    while (program.todo.length > 0) {
      const command = program.todo.shift();
      if (!command) break;
      await program.commands[command.name](command.args);
    }
  } finally {
    process.chdir(priorCwd);
  }
}

async function copyNativeSources(destination) {
  for (const source of await nativeSourceFiles()) {
    const target = join(destination, relative(nativeRoot, source));
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    await copyFile(source, target);
  }
}

/**
 * node-gyp rebuild deletes its cwd/build directory. Compile in OS-private
 * scratch, then atomically publish only the finished addon so a concurrent
 * test or packaging process can never observe the stable artifact disappearing.
 */
async function compileAndPublishBinary() {
  const scratch = await mkdtemp(join(tmpdir(), "convira-win-job-object-native-build-"));
  try {
    await copyNativeSources(scratch);
    await runNodeGyp(scratch);
    const artifacts = [
      { staged: join(scratch, "build", "Release", "win_job_object.node"), target: binaryPath },
      {
        staged: join(scratch, "build", "Release", "convira_sbx_launch.exe"),
        target: launcherPath,
      },
    ];
    for (const artifact of artifacts) {
      if (!(await exists(artifact.staged))) {
        throw new Error(`node-gyp succeeded without producing ${artifact.staged}`);
      }
    }
    for (const artifact of artifacts) {
      await mkdir(dirname(artifact.target), { recursive: true, mode: 0o700 });
      const publishTemp = join(
        dirname(artifact.target),
        `.${process.pid}.${randomBytes(6).toString("hex")}.tmp`,
      );
      try {
        await copyFile(artifact.staged, publishTemp);
        await rename(publishTemp, artifact.target);
      } finally {
        await rm(publishTemp, { force: true }).catch(() => {});
      }
    }
  } finally {
    await rm(scratch, { recursive: true, force: true }).catch(() => {});
  }
}

async function writeBuildStamp(fingerprint) {
  const binarySha256 = await sha256File(binaryPath);
  const launcherSha256 = await sha256File(launcherPath);
  const value = {
    version: BUILD_STAMP_VERSION,
    fingerprint,
    binarySha256,
    launcherSha256,
    platform: process.platform,
    arch: process.arch,
    nodeVersion: process.versions.node,
    nodeModuleAbi: process.versions.modules,
  };
  const temporary = join(
    buildRoot,
    `.convira-win-job-object-native.${process.pid}.${randomBytes(6).toString("hex")}.tmp`,
  );
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, stampPath);
}

export async function ensureWinJobObjectNativeBuild({ verifyOnly = false } = {}) {
  if (process.platform !== "win32") {
    process.stdout.write("win_job_object native addon is Windows-only; skipping\n");
    return;
  }
  return withExclusiveBuildLock(lockPath, async () => {
    const before = await currentBuildState();
    if (before.current) {
      process.stdout.write("win_job_object addon + convira_sbx_launch launcher are current\n");
      return;
    }
    if (verifyOnly) {
      throw new Error(
        "win_job_object addon or convira_sbx_launch launcher is missing, stale, or corrupt; run pnpm --filter @convira/sandbox-runtime build:native",
      );
    }

    await compileAndPublishBinary();
    // Recompute after compilation so a source edit racing the compiler cannot be stamped current.
    const afterFingerprint = await buildFingerprint();
    if (afterFingerprint !== before.fingerprint) {
      throw new Error("win_job_object native sources changed during compilation; rebuild required");
    }
    await writeBuildStamp(afterFingerprint);
    process.stdout.write("win_job_object addon + convira_sbx_launch launcher built and stamped\n");
  });
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  await ensureWinJobObjectNativeBuild({ verifyOnly: process.argv.includes("--verify") });
}
