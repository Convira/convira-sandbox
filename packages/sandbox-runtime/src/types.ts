/**
 * Sandbox Runtime — platform-native process isolation for gateway
 * and code execution subprocesses.
 *
 * The adapter pattern wraps `child_process.spawn()` calls with
 * OS-level sandboxing (bubblewrap on Linux, sandbox-exec on macOS,
 * Job Objects on Windows) without requiring Docker or cloud services.
 */

// ---------------------------------------------------------------------------
// Spawn configuration — describes the process to sandbox
// ---------------------------------------------------------------------------

export interface SandboxSpawnConfig {
  /** Command to execute (e.g. "pnpm", "python3") */
  command: string;
  /** Command arguments */
  args: string[];
  /** Working directory */
  cwd: string;
  /** Environment variables for the child process */
  env: Record<string, string>;

  /** Filesystem access restrictions */
  filesystem: {
    /** Paths the sandboxed process can read (mounted read-only) */
    readPaths: string[];
    /** Paths the sandboxed process can read and write */
    writePaths: string[];
    /** Paths hidden after broader mounts/allows (last-match/overlay deny). */
    denyPaths?: string[];
    /**
     * Leaf kind for deny paths that may not exist yet, keyed by the same
     * absolute path used in `denyPaths`.
     *
     * Windows AND Linux consult it, because a deny path that does not exist yet
     * still has to be covered by SOMETHING: a deny sitting inside a read-write
     * mount is otherwise creatable by the sandboxed process, and the write
     * reaches the host.
     *
     * The two platforms pay very different prices for getting it wrong:
     *
     *   - Windows MATERIALIZES the leaf in the PARENT, on the host filesystem,
     *     because an AppContainer DENY ace needs a real object to attach to. So
     *     the kind must be right: `.gitconfig` created as a directory
     *     permanently breaks git for that user, outside the app, with nothing
     *     in the app to undo it. An unresolvable kind FAILS CLOSED there.
     *   - Linux creates nothing. bwrap needs a mount point, so the adapter
     *     seals the deny's deepest EXISTING ancestor with a `--tmpfs` and
     *     re-binds that directory's real, non-denied children; the missing leaf
     *     then materializes on the tmpfs and dies with the sandbox. The kind
     *     only selects which inert object the SANDBOX sees (an empty tmpfs dir
     *     or a `/dev/null` ro-bind), so an unresolvable kind falls back to a
     *     tmpfs directory instead of failing the spawn - nothing it can get
     *     wrong reaches the host.
     *
     * The kind is caller-supplied rather than guessed, because `path.extname`
     * cannot tell `.zshrc` from `.ssh`. See `deny-leaf-kind.ts` for the shared
     * fallback table.
     *
     * macOS ignores it: the Seatbelt profile denies by name and needs no object.
     */
    denyPathKinds?: Record<string, "file" | "dir">;
  };

  /** Network access restrictions */
  network: {
    /** Whether outbound network is allowed at all (false = fully isolated) */
    enabled: boolean;
    /** Whether loopback (127.0.0.1) connections are allowed */
    allowLoopback: boolean;
  };

  /** Resource limits */
  resources: {
    /** Maximum memory in megabytes */
    memoryMb: number;
    /** Maximum number of child processes */
    maxProcesses: number;
    /** Optional execution timeout in milliseconds */
    timeoutMs?: number;
    /**
     * Long-lived subprocess (e.g. a STDIO MCP server) that legitimately runs
     * for the whole session. When true the RLIMIT_CPU (`ulimit -t`) budget is
     * OMITTED so the kernel does not SIGKILL the server after a cumulative
     * CPU-seconds ceiling; the file-size / descriptor / process-count (and, on
     * Linux, address-space) caps still apply. Defaults to false (bounded
     * one-shot tool invocation, which keeps the derived CPU budget).
     */
    longLived?: boolean;
  };

  /** Kernel-level hardening (Linux only — ignored on other platforms) */
  kernelHardening?: {
    /** Apply a seccomp BPF filter via bubblewrap --seccomp <fd> */
    seccompProfile?: "gateway" | "execute-code";
    /** Apply Landlock filesystem restrictions after process start */
    landlockRuleset?: {
      readOnly: string[];
      readWrite: string[];
    };
  };
}

// ---------------------------------------------------------------------------
// Spawn specification — the wrapped command ready for child_process.spawn()
// ---------------------------------------------------------------------------

export interface SpawnSpec {
  /** Executable to run (e.g. "bwrap", "sandbox-exec", or the original command) */
  command: string;
  /** Full argument list including wrapper args + original command + original args */
  args: string[];
  /** Environment variables to pass */
  env: Record<string, string>;
  /** Working directory */
  cwd: string;
  /**
   * Optional hook called after spawn with the child PID.
   * Used on Windows where restrictions are applied post-spawn via Job Objects.
   */
  postSpawnHook?: (pid: number) => void;
}

// ---------------------------------------------------------------------------
// Adapter capabilities — what a platform's sandbox can enforce
// ---------------------------------------------------------------------------

export interface SandboxCapabilities {
  /**
   * Whether filesystem path restrictions are enforced at the OS level.
   * Windows: enforceable since the AppContainer increment (deny-by-default
   * ACLs against the per-spawn AppContainer SID), reported true only while
   * the AppContainer filesystem probe passes on this host.
   */
  filesystemIsolation: boolean;
  /**
   * Whether network access can be blocked at the OS level.
   * Windows: AppContainer default-deny outbound (no capability SIDs),
   * reported true only while the network-denial probe passes. Loopback
   * exemption is admin-only and never granted.
   */
  networkIsolation: boolean;
  /**
   * Whether the CPU-time, output-file-size, descriptor, and process-count
   * rlimits are enforced (the `ulimit` wrapper's probe passed on this host).
   *
   * NOTE: this coarse boolean does NOT assert a hard MEMORY ceiling. Memory
   * enforcement varies by platform and is reported precisely by
   * {@link ExecutionCapabilityReportV2.memory} (Linux: hard RLIMIT_AS; macOS:
   * an RSS process-group watchdog; nowhere: "none"). Consumers that need the
   * memory posture MUST read the V2 report rather than infer it from this flag.
   */
  resourceLimits: boolean;
}

/**
 * How a hard MEMORY ceiling is enforced for a sandboxed tool and its
 * descendants:
 *   - "hard-address-space" — the kernel fails every allocation past the cap.
 *     Linux: RLIMIT_AS (`ulimit -v`; macOS `ulimit` rejects `-v`). Windows:
 *     JOB_OBJECT_LIMIT_PROCESS_MEMORY (a hard commit-charge cap), reported
 *     only while the Job Object memory probe passes on this host.
 *   - "rss-watchdog" — a resident-set poller sums the process group's RSS and
 *     SIGKILLs the group once it exceeds the budget. Best-effort: sampling can
 *     lag a very fast allocator by one interval, so it is NOT a hard kernel cap.
 *   - "none" — no memory ceiling is enforced.
 */
export type MemoryEnforcementTier = "hard-address-space" | "rss-watchdog" | "none";

/**
 * Granular, per-control capability report (A2 / HARDENING_MASTER_PLAN_V5).
 *
 * Every field states a FACT proven by that control's own passing probe on this
 * host — a declared capability without a passing probe is reported false/none.
 * The legacy tri-boolean {@link SandboxCapabilities} is derived from this and
 * stays wire-compatible; this report exists because a single `resourceLimits`
 * boolean cannot express (for example) a host that enforces CPU/file-size/PID
 * rlimits but has no hard address-space cap — the exact macOS situation.
 */
export interface ExecutionCapabilityReportV2 {
  /** Adapter identity — matches {@link SandboxAdapter.platform}. */
  adapter: string;
  /** How a hard memory ceiling is enforced (see {@link MemoryEnforcementTier}). */
  memory: MemoryEnforcementTier;
  /** RLIMIT_CPU wall-CPU-seconds ceiling is enforced. */
  cpu: boolean;
  /** RLIMIT_NPROC process-count ceiling is enforced. */
  pids: boolean;
  /**
   * An output-file-size ceiling is enforced. macOS/Linux: the kernel
   * RLIMIT_FSIZE cap. Windows (no RLIMIT_FSIZE analog): the sampled
   * granted-dir disk-write watchdog — a best-effort tier like the
   * "rss-watchdog" memory tier, reported only while its own measure+kill
   * probe passes.
   */
  fileSize: boolean;
  /** The runner can SIGKILL the whole process group on a wall-clock deadline. */
  wallClockKill: boolean;
  /** A group SIGKILL reaps backgrounded descendants (no orphan survives). */
  killTree: boolean;
  /** OS-level filesystem path confinement is enforced. */
  filesystemIsolation: boolean;
  /** OS-level network egress control is enforced. */
  networkIsolation: boolean;
}

// ---------------------------------------------------------------------------
// Adapter interface — each platform implements this
// ---------------------------------------------------------------------------

export interface SandboxAdapter {
  /** Human-readable platform identifier (e.g. "linux-bubblewrap") */
  readonly platform: string;

  /**
   * Check whether this adapter's sandbox tooling is available on the
   * current system. Returns false if the required binary/API is missing.
   */
  available(): Promise<boolean>;

  /** Report what this adapter can enforce (legacy tri-boolean). */
  capabilities(): SandboxCapabilities;

  /**
   * Granular per-control capability report. Optional so structural test
   * doubles need not implement it; every shipped adapter does. Each field is
   * gated on its own passing probe. Production consumers that need the exact
   * memory posture (or want to name the precise missing control in a refusal)
   * read this instead of the coarse {@link capabilities} boolean.
   */
  capabilitiesV2?(): ExecutionCapabilityReportV2;

  /**
   * Why {@link available} last returned false, as a STATIC classification an
   * operator can act on — never a path, argv, or anything user-derived.
   *
   * `available()` is a bare boolean, so a host that must refuse code execution
   * can only report "the sandbox is unavailable". That collapses a missing
   * native addon, a kernel control this host does not permit, and a probe that
   * timed out into one message, and on a packaged build there is no other way
   * to tell them apart. Optional so structural test doubles need not implement
   * it; undefined when the adapter is available or has not been asked yet.
   */
  unavailableReason?(): string | undefined;

  /**
   * Wrap a spawn configuration into a SpawnSpec that applies
   * OS-level sandboxing. The caller feeds the result directly
   * into `child_process.spawn()`.
   */
  wrapSpawn(config: SandboxSpawnConfig): SpawnSpec | Promise<SpawnSpec>;
}

// ---------------------------------------------------------------------------
// Isolation mode — user-facing configuration
// ---------------------------------------------------------------------------

export type IsolationMode = "auto" | "native" | "off";
