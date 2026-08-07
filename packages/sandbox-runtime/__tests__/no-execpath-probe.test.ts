import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const srcRoot = path.join(dirname(fileURLToPath(import.meta.url)), "..", "src");

function walk(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(dir, entry.name);
    if (entry.isDirectory()) return walk(target);
    return entry.isFile() && target.endsWith(".ts") ? [target] : [];
  });
}

describe("probe subjects never resolve to process.execPath", () => {
  it("has no process.execPath reference anywhere in src/", () => {
    // This is the guard for the whole regression class, and it is the only one
    // that works on every platform.
    //
    // Probes used to spawn `process.execPath -e "<script>"`. Under Node - which
    // is where every unit test runs - that IS the Node binary and everything
    // passes. In a packaged Electron build it is the application, and the
    // `runAsNode` fuse (deliberately disabled so a signed binary can never be
    // reused as a general-purpose interpreter) makes it ignore `-e`: the child
    // booted the app, quit on the single-instance lock, and every Windows
    // capability reported unavailable. No test could catch it, because the
    // difference IS the packaging.
    //
    // If this fails, someone reintroduced an interpreter as a probe subject.
    // The payload host in probe-payload.ts is the supported way.
    // Comments are stripped first: the modules that replaced the old spawn
    // sites explain in prose what they no longer do, and that prose is the
    // reason the next person will not reintroduce it.
    const offenders = walk(srcRoot).filter((file) => {
      const code = fs
        .readFileSync(file, "utf-8")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/^\s*\/\/.*$/gm, "");
      return code.includes("process.execPath");
    });
    expect(offenders.map((f) => path.relative(srcRoot, f))).toEqual([]);
  });
});
