import { describe, it, expect, beforeEach, vi } from "vitest";
import { passthroughAdapter, _resetPassthroughWarning } from "../src/adapters/passthrough.js";
import type { SandboxSpawnConfig } from "../src/types.js";

function makeConfig(): SandboxSpawnConfig {
  return {
    command: "node",
    args: ["gateway.js", "--port", "18789"],
    cwd: "/home/user/convira",
    env: { PATH: "/usr/bin", NODE_ENV: "production" },
    filesystem: {
      readPaths: ["/home/user/project"],
      writePaths: ["/tmp/staging"],
    },
    network: {
      enabled: true,
      allowLoopback: true,
    },
    resources: {
      memoryMb: 2048,
      maxProcesses: 64,
    },
  };
}

describe("passthroughAdapter", () => {
  beforeEach(() => {
    _resetPassthroughWarning();
  });

  it("has the correct platform identifier", () => {
    expect(passthroughAdapter.platform).toBe("passthrough");
  });

  it("is always available", async () => {
    expect(await passthroughAdapter.available()).toBe(true);
  });

  it("reports no isolation capabilities", () => {
    const caps = passthroughAdapter.capabilities();
    expect(caps.filesystemIsolation).toBe(false);
    expect(caps.networkIsolation).toBe(false);
    expect(caps.resourceLimits).toBe(false);
  });

  it("returns the original command unchanged", async () => {
    const config = makeConfig();
    const spec = await passthroughAdapter.wrapSpawn(config);
    expect(spec.command).toBe("node");
    expect(spec.args).toEqual(["gateway.js", "--port", "18789"]);
    expect(spec.env).toEqual(config.env);
    expect(spec.cwd).toBe(config.cwd);
  });

  it("does not include a postSpawnHook", async () => {
    const spec = await passthroughAdapter.wrapSpawn(makeConfig());
    expect(spec.postSpawnHook).toBeUndefined();
  });

  it("warns exactly once across repeated wrapSpawn calls", async () => {
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      _resetPassthroughWarning();
      await passthroughAdapter.wrapSpawn(makeConfig());
      await passthroughAdapter.wrapSpawn(makeConfig());
      const warnings = stderrSpy.mock.calls.filter((c) =>
        String(c[0]).includes("No OS-level sandbox active"),
      );
      expect(warnings.length).toBe(1);
    } finally {
      stderrSpy.mockRestore();
    }
  });
});
