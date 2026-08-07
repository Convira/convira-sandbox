/**
 * Bug hunt W0-39 — the Landlock access-flag policy was advertised as tested and
 * was not tested at all.
 *
 * `landlock.test.ts` carried a `describe("ABI version flag computation")` block
 * whose six tests never imported `../src/landlock.js`. They did bitwise
 * arithmetic over `mockBinding.LANDLOCK_ACCESS_FS_*` constants declared 190
 * lines earlier in the same file and asserted the result equalled a literal:
 * `expect(baseFlags).toBe(8191n)`. A sibling `describe("path resolution")`
 * asserted that `mockRealpathSync` behaved the way the test had just configured
 * it. Deleting `buildHandledAccessFlags` and `resolvePath` from production would
 * not have failed one of them.
 *
 * `landlock-with-binding.test.ts` does drive the real code, but only checks the
 * REFER and TRUNCATE bits per ABI, plus "READ_FILE present / WRITE_FILE absent"
 * for a read-only rule. So the failure scenario in the finding - a MAKE_* bit
 * dropped from the handled set, meaning Landlock silently stops mediating that
 * operation everywhere - passed every test in the package. So did the inverse
 * and worse case: adding a mutating bit to the read-only mask, which makes every
 * "readOnly" path writable.
 *
 * This file pins the whole policy as exact bitmasks read off the real
 * `landlockCreateRuleset` / `landlockAddRule` calls, per ABI. Exact rather than
 * "contains": anything outside the handled set is not restricted-by-default, it
 * is UNMEDIATED, so a missing bit is a silent hole rather than a visible failure.
 * A deliberate policy change is expected to fail these and be re-reviewed.
 */
import path from "node:path";
// node:fs is mocked below, so the source-reading test uses the promises module,
// which is not.
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Mock native binding. Values are the real kernel bit positions.
// ---------------------------------------------------------------------------

const mockBinding = {
  landlockGetAbiVersion: vi.fn().mockReturnValue(3),
  landlockCreateRuleset: vi.fn().mockReturnValue(42),
  landlockAddRule: vi.fn(),
  landlockRestrictSelf: vi.fn(),

  LANDLOCK_ACCESS_FS_EXECUTE: 1n,
  LANDLOCK_ACCESS_FS_WRITE_FILE: 2n,
  LANDLOCK_ACCESS_FS_READ_FILE: 4n,
  LANDLOCK_ACCESS_FS_READ_DIR: 8n,
  LANDLOCK_ACCESS_FS_REMOVE_DIR: 16n,
  LANDLOCK_ACCESS_FS_REMOVE_FILE: 32n,
  LANDLOCK_ACCESS_FS_MAKE_CHAR: 64n,
  LANDLOCK_ACCESS_FS_MAKE_DIR: 128n,
  LANDLOCK_ACCESS_FS_MAKE_REG: 256n,
  LANDLOCK_ACCESS_FS_MAKE_SOCK: 512n,
  LANDLOCK_ACCESS_FS_MAKE_FIFO: 1024n,
  LANDLOCK_ACCESS_FS_MAKE_BLOCK: 2048n,
  LANDLOCK_ACCESS_FS_MAKE_SYM: 4096n,
  LANDLOCK_ACCESS_FS_REFER: 8192n,
  LANDLOCK_ACCESS_FS_TRUNCATE: 16384n,
};

const B = mockBinding;

/** Every access this ruleset is expected to mediate at ABI 1. */
const BASE_FLAGS =
  B.LANDLOCK_ACCESS_FS_EXECUTE |
  B.LANDLOCK_ACCESS_FS_WRITE_FILE |
  B.LANDLOCK_ACCESS_FS_READ_FILE |
  B.LANDLOCK_ACCESS_FS_READ_DIR |
  B.LANDLOCK_ACCESS_FS_REMOVE_DIR |
  B.LANDLOCK_ACCESS_FS_REMOVE_FILE |
  B.LANDLOCK_ACCESS_FS_MAKE_CHAR |
  B.LANDLOCK_ACCESS_FS_MAKE_DIR |
  B.LANDLOCK_ACCESS_FS_MAKE_REG |
  B.LANDLOCK_ACCESS_FS_MAKE_SOCK |
  B.LANDLOCK_ACCESS_FS_MAKE_FIFO |
  B.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
  B.LANDLOCK_ACCESS_FS_MAKE_SYM;

/** Read-only paths may be opened, listed and executed. Nothing else. */
const EXPECTED_READ_ACCESS =
  B.LANDLOCK_ACCESS_FS_EXECUTE | B.LANDLOCK_ACCESS_FS_READ_FILE | B.LANDLOCK_ACCESS_FS_READ_DIR;

/**
 * Bits that must NEVER appear on a read-only rule. Enumerated by name so that
 * "readOnly is read-only" is asserted per-operation instead of via WRITE_FILE
 * alone: MAKE_REG on a read-only path is file creation, REMOVE_FILE is
 * deletion, and REFER is a rename INTO the path.
 */
const MUTATING_FLAGS: ReadonlyArray<[string, bigint]> = [
  ["WRITE_FILE", B.LANDLOCK_ACCESS_FS_WRITE_FILE],
  ["REMOVE_DIR", B.LANDLOCK_ACCESS_FS_REMOVE_DIR],
  ["REMOVE_FILE", B.LANDLOCK_ACCESS_FS_REMOVE_FILE],
  ["MAKE_CHAR", B.LANDLOCK_ACCESS_FS_MAKE_CHAR],
  ["MAKE_DIR", B.LANDLOCK_ACCESS_FS_MAKE_DIR],
  ["MAKE_REG", B.LANDLOCK_ACCESS_FS_MAKE_REG],
  ["MAKE_SOCK", B.LANDLOCK_ACCESS_FS_MAKE_SOCK],
  ["MAKE_FIFO", B.LANDLOCK_ACCESS_FS_MAKE_FIFO],
  ["MAKE_BLOCK", B.LANDLOCK_ACCESS_FS_MAKE_BLOCK],
  ["MAKE_SYM", B.LANDLOCK_ACCESS_FS_MAKE_SYM],
  ["REFER", B.LANDLOCK_ACCESS_FS_REFER],
  ["TRUNCATE", B.LANDLOCK_ACCESS_FS_TRUNCATE],
];

/** ABI -> the exact mask the ruleset must declare as handled. */
const EXPECTED_HANDLED: ReadonlyArray<[number, bigint]> = [
  [1, BASE_FLAGS],
  [2, BASE_FLAGS | B.LANDLOCK_ACCESS_FS_REFER],
  [3, BASE_FLAGS | B.LANDLOCK_ACCESS_FS_REFER | B.LANDLOCK_ACCESS_FS_TRUNCATE],
  // A kernel newer than anything this code knows about must still mediate
  // everything ABI 3 did. Clamping down on an unknown-higher ABI would silently
  // widen the sandbox on exactly the kernels most likely to run in production.
  [4, BASE_FLAGS | B.LANDLOCK_ACCESS_FS_REFER | B.LANDLOCK_ACCESS_FS_TRUNCATE],
];

// ---------------------------------------------------------------------------
// node:fs is mocked so realpathSync is the identity - path resolution is
// covered by landlock-with-binding.test.ts; this file is only about flags.
// ---------------------------------------------------------------------------

const mockReadFileSync = vi.fn();
const mockRealpathSync = vi.fn();
const mockExistsSync = vi.fn();

vi.mock("node:fs", async (importOriginal) => {
  const actual = (await importOriginal()) as typeof import("node:fs");
  return {
    ...actual,
    readFileSync: (...args: unknown[]) => mockReadFileSync(...args),
    realpathSync: (...args: unknown[]) => mockRealpathSync(...args),
    existsSync: (...args: unknown[]) => mockExistsSync(...args),
    default: {
      ...actual,
      readFileSync: (...args: unknown[]) => mockReadFileSync(...args),
      realpathSync: (...args: unknown[]) => mockRealpathSync(...args),
      existsSync: (...args: unknown[]) => mockExistsSync(...args),
    },
  };
});

// ---------------------------------------------------------------------------
// Redirect the native require() to the mock above.
// ---------------------------------------------------------------------------

const here = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(here, "../src/landlock.ts");

// eslint-disable-next-line @typescript-eslint/no-require-imports
const Module = require("node:module");
const originalResolveFilename = Module._resolveFilename;
const FAKE_NATIVE_ID = path.resolve(here, "__landlock_access_policy_mock__");

function installHook() {
  Module._resolveFilename = function (request: string, ...rest: unknown[]) {
    if (request.endsWith("landlock_binding.node")) return FAKE_NATIVE_ID;
    return originalResolveFilename.call(this, request, ...rest);
  };
  const fake = new Module(FAKE_NATIVE_ID);
  fake.exports = mockBinding;
  fake.loaded = true;
  Module._cache[FAKE_NATIVE_ID] = fake;
}

function removeHook() {
  Module._resolveFilename = originalResolveFilename;
  delete Module._cache[FAKE_NATIVE_ID];
}

const RO = "/sandbox-ro";
const RW = "/sandbox-rw";

interface CapturedPolicy {
  handled: bigint;
  readAccess: bigint;
  writeAccess: bigint;
}

/**
 * Drive the real `applyLandlockRuleset` at a given ABI and read the three masks
 * back off the binding calls it made. Nothing here is computed by the test: the
 * numbers come out of production code.
 */
async function capturePolicy(abi: number): Promise<CapturedPolicy> {
  vi.resetModules();
  mockBinding.landlockGetAbiVersion.mockReturnValue(abi);
  mockBinding.landlockCreateRuleset.mockReset().mockReturnValue(42);
  mockBinding.landlockAddRule.mockReset();
  mockBinding.landlockRestrictSelf.mockReset();

  const mod = await import("../src/landlock.js");
  mod.applyLandlockRuleset({ readOnly: [RO], readWrite: [RW] });

  const createCalls = mockBinding.landlockCreateRuleset.mock.calls;
  expect(createCalls, "production must create exactly one ruleset").toHaveLength(1);

  const addCalls = mockBinding.landlockAddRule.mock.calls;
  expect(addCalls, "production must add exactly one rule per path").toHaveLength(2);

  const byPath = new Map<string, bigint>(
    addCalls.map((call) => [call[1] as string, call[2] as bigint]),
  );
  const readAccess = byPath.get(RO);
  const writeAccess = byPath.get(RW);
  expect(readAccess, `no rule was added for the read-only path ${RO}`).toBeDefined();
  expect(writeAccess, `no rule was added for the read-write path ${RW}`).toBeDefined();

  return {
    handled: createCalls[0][0] as bigint,
    readAccess: readAccess!,
    writeAccess: writeAccess!,
  };
}

const names = (mask: bigint): string =>
  [...MUTATING_FLAGS, ["EXECUTE", B.LANDLOCK_ACCESS_FS_EXECUTE] as [string, bigint]]
    .filter(([, bit]) => (mask & bit) !== 0n)
    .map(([name]) => name)
    .join("|") || "<none>";

describe("landlock access policy", () => {
  beforeEach(() => {
    vi.spyOn(process, "platform", "get").mockReturnValue("linux" as NodeJS.Platform);
    mockReadFileSync.mockReturnValue("landlock,apparmor,bpf");
    mockRealpathSync.mockImplementation((p: string) => p);
    mockExistsSync.mockReturnValue(true);
    installHook();
  });

  afterEach(() => {
    removeHook();
    vi.restoreAllMocks();
  });

  // =========================================================================
  // The handled set: anything omitted here is UNMEDIATED, not denied.
  // =========================================================================
  for (const [abi, expected] of EXPECTED_HANDLED) {
    it(`declares the exact handled-access mask at ABI v${abi}`, async () => {
      const { handled } = await capturePolicy(abi);
      expect(
        handled,
        `ABI v${abi} handled mask drifted. Any bit missing from this mask is an operation ` +
          `Landlock does not mediate AT ALL, on every path, which is a silent widening of the ` +
          `sandbox rather than a visible failure. got=${names(handled)}`,
      ).toBe(expected);
    });
  }

  it("mediates every access constant the binding declares", async () => {
    // Completeness check across two lists in the same production file: a new
    // LANDLOCK_ACCESS_FS_* added to NativeBinding but never OR-ed into
    // buildHandledAccessFlags is a permanently unmediated operation, and no
    // behavioural test can see a constant that nothing references.
    const source = await readFile(SRC, "utf8");
    const iface = /interface NativeBinding \{([\s\S]*?)\n\}/u.exec(source);
    expect(iface, "NativeBinding interface not found; this test needs updating").not.toBeNull();
    const declared = [...iface![1].matchAll(/\b(LANDLOCK_ACCESS_FS_\w+)\b/gu)].map((m) => m[1]);
    expect(declared.length).toBeGreaterThan(0);

    const builder = /function buildHandledAccessFlags[\s\S]*?\n\}/u.exec(source);
    expect(builder, "buildHandledAccessFlags not found in production source").not.toBeNull();
    // Comments stripped first. `includes(name)` is a raw substring scan over the
    // function's SOURCE TEXT, so a constant named only in a comment inside it -
    // "// LANDLOCK_ACCESS_FS_TRUNCATE: not mediated yet" - counted as handled.
    // The one shape that makes this completeness check vacuous is precisely the
    // one a developer writes while deferring the work. (bug hunt W0-39)
    const builderCode = builder![0].replace(/\/\*[\s\S]*?\*\//gu, " ").replace(/\/\/[^\n]*/gu, " ");
    const unhandled = declared.filter((name) => !builderCode.includes(name));
    expect(
      unhandled,
      "these access types are declared by the native binding but never handled by the ruleset, " +
        "so the kernel does not mediate them on any path",
    ).toEqual([]);

    // And the fixture above must not drift from the interface, or these tests
    // quietly stop covering the new flag.
    const fixtureConstants = Object.keys(mockBinding).filter((k) =>
      k.startsWith("LANDLOCK_ACCESS_FS_"),
    );
    expect(fixtureConstants.sort()).toEqual([...declared].sort());
  });

  // =========================================================================
  // Read-only must mean read-only.
  // =========================================================================
  it("grants read-only paths exactly execute + read-file + read-dir", async () => {
    const { readAccess } = await capturePolicy(3);
    expect(
      readAccess,
      `the read-only mask drifted: got=${names(readAccess)} ` +
        `expected=EXECUTE|READ_FILE|READ_DIR`,
    ).toBe(EXPECTED_READ_ACCESS);
  });

  it("does not gate the read-only mask on the ABI version", async () => {
    // Read access predates every ABI extension, so it must be identical across
    // them. An ABI-conditional read mask would mean a path is read-only on one
    // kernel and something else on another.
    // Sequentially: capturePolicy resets shared mock counters, so concurrent
    // captures would read each other's calls.
    for (const [abi] of EXPECTED_HANDLED) {
      const { readAccess } = await capturePolicy(abi);
      expect(readAccess, `read mask differs at ABI v${abi}`).toBe(EXPECTED_READ_ACCESS);
    }
  });

  for (const [label, bit] of MUTATING_FLAGS) {
    it(`never grants ${label} to a read-only path`, async () => {
      const { readAccess } = await capturePolicy(3);
      expect(
        (readAccess & bit) !== 0n,
        `a "readOnly" path that permits ${label} is not read-only; every caller passing a ` +
          "trusted directory in readOnly would have it mutable by the sandboxed process",
      ).toBe(false);
    });
  }

  // =========================================================================
  // Read-write, and the kernel's own subset requirement.
  // =========================================================================
  for (const [abi, expected] of EXPECTED_HANDLED) {
    it(`grants read-write paths every mediated access at ABI v${abi}`, async () => {
      const { writeAccess } = await capturePolicy(abi);
      // Equal to the handled set by design: a read-write path is unrestricted
      // within the sandbox. Narrowing this deliberately should fail here and be
      // re-reviewed, because it changes what every writable path can do.
      expect(
        writeAccess,
        `ABI v${abi} read-write mask drifted from the handled set: got=${names(writeAccess)}`,
      ).toBe(expected);
    });

    it(`keeps both rule masks inside the handled set at ABI v${abi}`, async () => {
      const { handled, readAccess, writeAccess } = await capturePolicy(abi);
      // landlock_add_rule() rejects allowed_access ⊄ handled_access with
      // EINVAL, which would make applyLandlockRuleset throw on a real kernel -
      // a failure no mocked test can reproduce unless the subset is asserted.
      expect(readAccess & ~handled, "read mask carries bits outside handled_access").toBe(0n);
      expect(writeAccess & ~handled, "write mask carries bits outside handled_access").toBe(0n);
    });
  }

  it("grants read-write paths everything read-only paths get", async () => {
    const { readAccess, writeAccess } = await capturePolicy(3);
    expect(
      readAccess & ~writeAccess,
      "a read-write path must permit at least what a read-only path permits, or moving a path " +
        "from readOnly to readWrite would REMOVE an access",
    ).toBe(0n);
  });

  it("applies the restriction after every rule is added", async () => {
    // Ordering matters and is irrevocable: restrict_self() before the rules
    // exist would confine the process to nothing.
    const invocations: string[] = [];
    mockBinding.landlockAddRule.mockImplementation(() => void invocations.push("add"));
    mockBinding.landlockRestrictSelf.mockImplementation(() => void invocations.push("restrict"));

    vi.resetModules();
    mockBinding.landlockGetAbiVersion.mockReturnValue(3);
    const mod = await import("../src/landlock.js");
    mod.applyLandlockRuleset({ readOnly: [RO], readWrite: [RW] });

    expect(invocations).toEqual(["add", "add", "restrict"]);
    mockBinding.landlockAddRule.mockReset();
    mockBinding.landlockRestrictSelf.mockReset();
  });
});
