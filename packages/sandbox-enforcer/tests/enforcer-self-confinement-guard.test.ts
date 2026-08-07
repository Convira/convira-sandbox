import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, it, expect } from "vitest";

// ---------------------------------------------------------------------------
// enforcer-self-confinement-guard.test.ts -- the enforcer suite must never
// apply a REAL Landlock ruleset to the vitest worker that is running it.
//
// `applyKernelHardening({ landlock: ... })` is irrevocable by design: on a Linux
// host with the native binding built, it calls landlock_restrict_self on the
// CURRENT process. Two tests in enforcer.test.ts passed a real ruleset without
// stubbing `process.platform`, so on Linux they confined the worker to
// readOnly ["/usr"] / readWrite ["/tmp"] and still reported green -- every
// later test in that worker then ran inside a sandbox nobody asked for, and the
// suite could only fail in ways that look like unrelated filesystem errors.
// The hazard lives in the test file, so this guard reads that file: a runtime
// assertion cannot see it from a darwin host, which is exactly how it survived.
//
// The parser is exercised against synthetic sources as well as the real file,
// because a source-reading guard fails OPEN in two quiet ways: a block shape it
// cannot see (an `it.each`, an `it` at a different indentation), and a stub it
// accepts without reading it -- `mockReturnValue("linux")` is a
// `vi.spyOn(process, "platform"` too, and re-opens the exact hazard.
// ---------------------------------------------------------------------------

const ENFORCER_TEST = path.join(path.dirname(fileURLToPath(import.meta.url)), "enforcer.test.ts");

interface TestBlock {
  title: string;
  body: string;
}

/**
 * Start of an `it` / `test` block at ANY indentation, including the modifier
 * forms (`it.each(...)`, `it.only`, `test.skip`). Keying off one hard-coded
 * indentation made every other shape invisible to the filter below, and a
 * filter that selects nothing is a guard that passes because it looked at
 * nothing.
 */
const BLOCK_START = /(?:^|\n)[ \t]*(?:it|test)(?:\.[A-Za-z]+(?:\([^\n]*\))?)*\s*[(`]/gu;

/** Split a suite into one entry per test block, keyed by its title. */
function testBlocks(source: string): TestBlock[] {
  const starts: number[] = [];
  BLOCK_START.lastIndex = 0;
  for (let match = BLOCK_START.exec(source); match; match = BLOCK_START.exec(source)) {
    starts.push(match.index);
    BLOCK_START.lastIndex = match.index + match[0].length;
  }

  return starts.map((start, index) => {
    const body = source.slice(start, starts[index + 1] ?? source.length);
    // First quoted string in the block is its title, whichever call shape it
    // was declared with.
    return { title: /["'`]([^"'`\n]*)["'`]/u.exec(body)?.[1] ?? "<unnamed>", body };
  });
}

/** Every platform value a block pins `process.platform` to. */
function platformStubs(body: string): string[] {
  const stub =
    /vi\.spyOn\(\s*process\s*,\s*"platform"[\s\S]{0,200}?\.mockReturnValue\(\s*"([a-z0-9]+)"/gu;
  const values: string[] = [];
  for (let match = stub.exec(body); match; match = stub.exec(body)) {
    values.push(match[1]);
  }
  return values;
}

/**
 * Titles of the blocks that hand `applyKernelHardening` a real Landlock ruleset
 * without pinning `process.platform` to a platform where nothing is applied.
 */
function unguardedLandlockBlocks(source: string): string[] {
  return testBlocks(source)
    .filter((block) => {
      // Only a `landlock` ruleset reaches landlock_restrict_self. An empty
      // config, or a seccomp-only config, compiles a filter for bubblewrap
      // and never restricts this process.
      if (!block.body.includes("applyKernelHardening(")) return false;
      if (!/landlock:\s*\{/u.test(block.body)) return false;

      const stubbed = platformStubs(block.body);
      // No stub at all, or a stub that pins the one platform where the ruleset
      // is real. "linux" is the whole hazard, so it is named rather than
      // inferred from a spy being present.
      return stubbed.length === 0 || stubbed.includes("linux");
    })
    .map((block) => block.title);
}

describe("the enforcer suite cannot confine its own worker", () => {
  it("stubs process.platform to a non-linux platform in every real-ruleset test", async () => {
    const source = await readFile(ENFORCER_TEST, "utf8");
    const blocks = testBlocks(source);
    expect(blocks.length).toBeGreaterThan(10);
    // Non-vacuous: the selector must still be finding the hazardous shape.
    const withRuleset = blocks.filter((block) => /landlock:\s*\{/u.test(block.body));
    expect(withRuleset.length).toBeGreaterThan(0);

    expect(unguardedLandlockBlocks(source)).toEqual([]);
  });
});

describe("the guard's own parser", () => {
  const RULESET = `applyKernelHardening({ landlock: { readOnly: ["/usr"], readWrite: [] } });`;
  const stub = (platform: string): string =>
    `vi.spyOn(process, "platform", "get").mockReturnValue("${platform}" as NodeJS.Platform);`;

  it("flags a real-ruleset test with no platform stub", () => {
    const source = `describe("x", () => {\n    it("applies a ruleset", () => {\n      ${RULESET}\n    });\n});\n`;
    expect(unguardedLandlockBlocks(source)).toEqual(["applies a ruleset"]);
  });

  it("flags a real-ruleset test stubbed to linux, which a presence-only check accepts", () => {
    const source = `describe("x", () => {\n    it("applies a ruleset on linux", () => {\n      ${stub("linux")}\n      ${RULESET}\n    });\n});\n`;
    expect(unguardedLandlockBlocks(source)).toEqual(["applies a ruleset on linux"]);
  });

  it("accepts a real-ruleset test stubbed to a platform that applies nothing", () => {
    const source = `describe("x", () => {\n    it("applies a ruleset", () => {\n      ${stub("darwin")}\n      ${RULESET}\n    });\n});\n`;
    expect(unguardedLandlockBlocks(source)).toEqual([]);
  });

  it("sees blocks at any indentation and in the it.each / test forms", () => {
    const source = [
      `it("top level", () => {\n  ${stub("darwin")}\n  ${RULESET}\n});`,
      `        it("deeply indented", () => {\n          ${RULESET}\n        });`,
      `  it.each([1, 2])("each %i", () => {\n    ${RULESET}\n  });`,
      `  test("test alias", () => {\n    ${RULESET}\n  });`,
    ].join("\n");

    expect(testBlocks(source).map((block) => block.title)).toEqual([
      "top level",
      "deeply indented",
      "each %i",
      "test alias",
    ]);
    expect(unguardedLandlockBlocks(source)).toEqual(["deeply indented", "each %i", "test alias"]);
  });

  it("ignores a config that cannot restrict this process", () => {
    const source = `    it("seccomp only", () => {\n      applyKernelHardening({ seccompProfile: "gateway" });\n    });\n`;
    expect(unguardedLandlockBlocks(source)).toEqual([]);
  });
});
