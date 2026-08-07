// A Node stand-in for `convira_sbx_launch --selftest <verb>`.
//
// The real payload is a C++ verb table inside the signed launcher, and it only
// exists on Windows. Every probe decision test - kill-tree, memory, pids, cpu,
// disk watchdog, and the three AppContainer probes - needs a REAL child process
// that behaves like that payload so the orchestration can be exercised on
// macOS and Linux. This shim is that child.
//
// It implements the same verbs with the same argument names and the same
// published values, so a test that pins this as the payload host measures the
// probe's decision logic and nothing else. Deviating from the C++ contract here
// would make these tests agree with themselves and disagree with what ships.
//
// `--fail-marker` is the anti-false-positive lever: it makes long-lived verbs
// skip the marker they are supposed to publish, so a test can prove a probe
// FAILS when its subject never really started. That is the exact defect the
// old probes could not see.

import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";

const argv = process.argv.slice(2);
// The verb is the first non-flag token, not argv[0]: a test pins its levers
// through `prefixArgs`, which `probePayloadArgv` emits BEFORE the verb.
const verb = argv.find((a) => !a.startsWith("--"));

function flag(name) {
  const at = argv.indexOf(name);
  return at !== -1 && at + 1 < argv.length ? argv[at + 1] : null;
}

const suppressMarker = argv.includes("--fail-marker");

function publish(target, text) {
  const tmp = `${target}.tmp`;
  fs.writeFileSync(tmp, text);
  fs.renameSync(tmp, target);
}

function idle() {
  setInterval(() => {}, 1000);
}

// `detached` so the grandchild's lifetime is its own. A kill-tree probe is
// only meaningful if a descendant can OUTLIVE its parent - otherwise a tree
// that reaps itself looks exactly like a Job Object that reaped it, and the
// probe gets credit for enforcement it never performed. This does not weaken
// the real win32 lane: detached sets DETACHED_PROCESS / CREATE_NEW_PROCESS_GROUP
// and NOT CREATE_BREAKAWAY_FROM_JOB, so the grandchild still inherits job
// membership and TerminateJobObject still reaps it.
function spawnIdleSelf() {
  return spawn(process.execPath, [path.resolve(process.argv[1]), "idle"], {
    stdio: "ignore",
    detached: true,
  });
}

switch (verb) {
  case "echo": {
    const nonce = flag("--nonce");
    const out = flag("--out");
    if (!nonce || !out || !/^[0-9a-f]{8,64}$/.test(nonce)) process.exit(2);
    publish(out, nonce);
    break;
  }
  case "idle":
    idle();
    break;
  case "spawn-child": {
    const pidFile = flag("--pid-file");
    const waitFor = flag("--wait-for");
    if (!pidFile) process.exit(2);
    const go = () => {
      const child = spawnIdleSelf();
      child.unref();
      publish(pidFile, String(child.pid));
      idle();
    };
    if (waitFor) {
      const started = Date.now();
      const poll = setInterval(() => {
        if (fs.existsSync(waitFor) || Date.now() - started > 10_000) {
          clearInterval(poll);
          go();
        }
      }, 20);
    } else {
      go();
    }
    break;
  }
  case "try-spawn": {
    const out = flag("--out");
    if (!out) process.exit(2);
    try {
      const child = spawnIdleSelf();
      child.unref();
      // The fake bindings cannot enforce ActiveProcessLimit, so the caller
      // signals the expected verdict rather than the OS doing it.
      publish(out, argv.includes("--deny") ? "denied" : "spawned");
      try {
        process.kill(child.pid, "SIGKILL");
      } catch {
        /* already gone */
      }
    } catch {
      publish(out, "denied");
    }
    break;
  }
  case "alloc": {
    const out = flag("--out");
    const mib = Number(flag("--mib") ?? 0);
    if (!out || !mib) process.exit(2);
    try {
      const block = Buffer.alloc(mib << 20, 1);
      if (block.length !== mib << 20) throw new Error("short");
      publish(out, "ok");
    } catch {
      publish(out, "alloc-failed");
    }
    break;
  }
  case "burn-cpu": {
    const marker = flag("--marker");
    if (!marker) process.exit(2);
    if (!suppressMarker) publish(marker, "spinning");
    // Spin on a timer rather than a tight loop: the probe polls synchronously
    // from the parent, so what matters is that this process stays ALIVE and
    // busy, not that it saturates a core on the test machine.
    setInterval(() => {
      let x = 0;
      for (let i = 0; i < 1e6; i += 1) x += i;
      return x;
    }, 5);
    break;
  }
  case "fill": {
    const dir = flag("--dir");
    const marker = flag("--marker");
    if (!dir || !marker) process.exit(2);
    if (!suppressMarker) publish(marker, "spinning");
    const chunk = Buffer.alloc(1 << 20, 1);
    let n = 0;
    setInterval(() => {
      if (n >= 64) return;
      try {
        fs.appendFileSync(path.join(dir, `w${n % 4}`), chunk);
      } catch {
        /* best-effort */
      }
      n += 1;
    }, 20);
    break;
  }
  case "fs-check": {
    const outside = flag("--outside");
    const granted = flag("--granted");
    if (!outside || !granted) process.exit(2);
    let outsideVerdict = "denied";
    try {
      fs.readFileSync(outside);
      outsideVerdict = "read";
    } catch {
      outsideVerdict = "denied";
    }
    let insideVerdict = "failed";
    try {
      const inner = path.join(granted, "inner.txt");
      fs.writeFileSync(inner, "x");
      if (fs.readFileSync(inner, "utf-8") === "x") insideVerdict = "ok";
    } catch {
      insideVerdict = "failed";
    }
    publish(path.join(granted, "result.txt"), `${outsideVerdict}:${insideVerdict}`);
    break;
  }
  case "listen": {
    const portFile = flag("--port-file");
    if (!portFile) process.exit(2);
    const server = net.createServer((socket) => socket.end("hi"));
    server.listen(0, "127.0.0.1", () => {
      publish(portFile, String(server.address().port));
    });
    idle();
    break;
  }
  case "connect": {
    const out = flag("--out");
    const port = Number(flag("--port") ?? 0);
    if (!out || !port) process.exit(2);
    const report = (verdict) => {
      try {
        publish(out, verdict);
      } catch {
        /* best-effort */
      }
      process.exit(0);
    };
    const socket = net.connect(port, "127.0.0.1");
    socket.on("connect", () => report("connected"));
    socket.on("error", () => report("denied"));
    setTimeout(() => report("timeout"), 10_000);
    break;
  }
  default:
    process.exit(2);
}
