import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ensureWinJobObjectNativeBuild } from "./build-win-job-object-native.mjs";

// The Job Object addon exists only on Windows; every other platform has
// nothing to verify and must not fail desktop `package` runs there.
if (process.platform !== "win32") {
  process.stdout.write("win_job_object native addon is Windows-only; skipping check\n");
  process.exit(0);
}

// Take the same package-owned lock as compilation. This prevents a release
// check from loading the addon while another turbo task is replacing
// native/build.
await ensureWinJobObjectNativeBuild({ verifyOnly: true });

const require = createRequire(import.meta.url);
const binding = require("../native/build/Release/win_job_object.node");
const info = binding.getInfo();

assert.equal(info.abiVersion, 2, "unexpected win_job_object native ABI");
assert.equal(info.platform, "win32", "native addon platform mismatch");
assert.equal(info.primitives.killOnClose, true, "kill-on-close primitive missing");
assert.equal(info.primitives.processMemory, true, "process-memory primitive missing");
assert.equal(info.primitives.activeProcess, true, "active-process primitive missing");
assert.equal(info.primitives.jobUserTime, true, "job-user-time primitive missing");
assert.equal(info.primitives.appContainer, true, "AppContainer primitive missing");
assert.equal(
  info.primitives.securityCapabilitiesSpawn,
  true,
  "SECURITY_CAPABILITIES spawn primitive missing",
);
assert.equal(info.primitives.directorySidAcl, true, "directory SID ACL primitive missing");
assert.equal(
  info.primitives.networkCapabilitySids,
  true,
  "network capability SID primitive missing",
);

// The launcher EXE ships alongside the addon (same stamp) — packaging must
// fail when it is missing, not discover that at first Windows spawn.
const launcherPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "native",
  "build",
  "Release",
  "convira_sbx_launch.exe",
);
assert.ok(existsSync(launcherPath), `convira_sbx_launch.exe missing at ${launcherPath}`);

// Live smoke: the launcher must actually RUN its self-test verb table, not
// merely exist. Every Windows capability probe now spawns
// `convira_sbx_launch --selftest <verb>`, so a launcher that is present but
// cannot execute here would surface as "the sandbox is unavailable" at
// runtime, on a user's machine, with the build having said OK.
{
  const nonce = randomBytes(16).toString("hex");
  const outFile = join(mkdtempSync(join(tmpdir(), "sbx-selftest-check-")), "nonce");
  const result = spawnSync(
    launcherPath,
    ["--selftest", "echo", "--nonce", nonce, "--out", outFile],
    {
      stdio: "ignore",
      timeout: 30_000,
    },
  );
  assert.ok(
    !result.error,
    `launcher --selftest echo failed to run: ${result.error?.message ?? ""}`,
  );
  assert.strictEqual(
    readFileSync(outFile, "utf-8").trim(),
    nonce,
    "launcher --selftest echo did not round-trip its nonce",
  );
}

// Live smoke: a kill-on-close job can be created and closed.
const jobId = binding.createJob({ memoryLimitMb: 64, maxProcesses: 4, killOnClose: true });
assert.ok(Number.isSafeInteger(jobId) && jobId > 0, "createJob returned an invalid handle id");
binding.closeJob(jobId);

// Live smoke: the AppContainer profile lifecycle round-trips for this user
// (create → derive → delete; delete is idempotent).
const profileName = `ConviraSbxCheck-${process.pid}-${Date.now() % 100000}`;
const sid = binding.createAppContainerProfile(profileName);
try {
  assert.ok(
    typeof sid === "string" && sid.startsWith("S-1-15-2-"),
    `createAppContainerProfile returned an invalid SID: ${sid}`,
  );
  assert.equal(binding.deriveAppContainerSid(profileName), sid, "derived SID mismatch");
} finally {
  binding.deleteAppContainerProfile(profileName);
}
binding.deleteAppContainerProfile(profileName);

process.stdout.write("win_job_object addon + convira_sbx_launch launcher OK\n");
