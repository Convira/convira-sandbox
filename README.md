# Convira Sandbox

[![CI](https://github.com/Convira/convira-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/Convira/convira-sandbox/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The operating-system confinement layer from [Convira](https://www.convira.ai), a desktop AI
agent that works on the files already on your computer.

This is the code that decides what the agent is physically allowed to do on your machine:
which paths it can read and write, whether it can reach the network, how much memory, CPU,
disk and how many processes it gets, and how it is killed when it exceeds any of those.

It runs on your computer, not on ours. That is the whole reason it is published: you can read
it, run its tests, and watch your own machine to check that it behaves the way this code says
it does.

## What this does not prove

Read this part before the rest.

- **Publishing source does not prove the app you installed contains this source.** Nothing in
  this repository establishes that. Reproducible builds would; we do not have them yet.
- **This is one layer, not a security guarantee.** It confines a child process using the
  facilities the host OS provides. It does not audit the agent's decisions, the model, the
  network protocol, or anything running outside the sandbox.
- **Confinement is not equal across platforms.** A macOS host cannot enforce a hard
  address-space memory cap the way Linux can. The code says so at runtime rather than
  pretending otherwise - see [Capability reporting](#capability-reporting).
- **No third-party audit has been performed on this code.** When one is, the report will be
  linked here. Until then, treat this as source you can read, not as source someone else has
  vouched for.
- **Only the macOS CI leg currently exercises real confinement.** Four integration cases launch
  an actually-confined process; the rest of the suite is unit-level. Today those four run on
  macOS only:

  | Leg | Integration cases | Why |
  | --- | --- | --- |
  | macOS | run | `sandbox-exec` is present |
  | Linux | skipped | `bwrap` is not installed on the hosted runner, so the adapter resolves to passthrough |
  | Windows | skipped | the AppContainer launcher fails with `CreateProcessW failed (code 203)` - [issue #1](https://github.com/Convira/convira-sandbox/issues/1) |

  They are skipped, never passed, so the suite never reports confinement it has not observed.
  But read a green Linux or Windows tick as "the unit suites hold", not as proof that the
  sandbox confines anything on that platform.

We would rather state these plainly than have someone discover them and conclude the rest was
oversold too.

## What is in here

| Package | What it does |
| --- | --- |
| [`sandbox-runtime`](packages/sandbox-runtime) | The confinement layer for macOS, Linux and Windows, plus resource limits, watchdogs, and probes that verify each control actually works on the host. |
| [`sandbox-enforcer`](packages/sandbox-enforcer) | Linux kernel hardening applied inside the sandbox: Landlock filesystem rulesets and seccomp-bpf syscall filters. |

Roughly 5,300 lines of TypeScript, 1,900 lines of C/C++ for the native Windows and Linux
bindings, and 7,600 lines of tests - 460 tests across 30 files.

## How confinement is achieved

| Platform | Mechanism |
| --- | --- |
| **macOS** | Seatbelt (`sandbox-exec`) profiles. Filesystem paths are allowed by explicit grant; everything else, including `~/.ssh`, `~/.aws`, browser cookie stores and the app's own credential store, is denied. |
| **Linux** | User namespaces and bind mounts, plus Landlock filesystem rulesets and seccomp-bpf syscall filtering from `sandbox-enforcer`. |
| **Windows** | AppContainer for filesystem and network confinement, and Job Objects for process-tree and memory limits. |
| **Unsupported hosts** | A passthrough adapter that applies no confinement and reports every capability as absent. It never claims protection it is not providing. |

## Capability reporting

The design decision worth explaining, because it is the one that makes the rest checkable.

Every field in the capability report states a fact proven by that control's own passing probe
**on the machine it is running on**. A capability that is declared but whose probe does not
pass is reported as `false` or `none`.

The probes are not static checks. They spawn real processes and observe real outcomes: whether
a group `SIGKILL` actually reaps a backgrounded descendant, whether a large allocation actually
fails under a tight address-space limit.

This is why the report distinguishes tiers instead of using booleans. Memory enforcement is
one of:

- `hard-address-space` - the kernel fails every allocation past the cap
- `rss-watchdog` - a poller sums the process group's resident set and kills it over budget.
  Best-effort: sampling can lag a fast allocator by one interval. Not a hard kernel cap.
- `none` - no memory ceiling is enforced

A single boolean cannot express a host that enforces CPU, file-size and process-count limits
but has no hard address-space cap. That is exactly the macOS situation, and reporting it as
"resource limits: yes" would be a lie of convenience.

## Running the tests

```sh
pnpm install
pnpm test
```

Requires Node 22 and pnpm 10. On a clean checkout this reports 460 passing tests.

Platform-specific suites skip on hosts that cannot run them, so a full picture needs a run on
each of the three operating systems. The Windows native addon is Windows-only and its build
step exits cleanly with a skip message elsewhere; on Windows it needs `node-gyp` and the
Visual Studio build tools.

`pnpm typecheck` and `pnpm build` are also available.

## Checking it yourself

Reading code is one kind of evidence. Watching your own machine is a better one.

- **Filesystem**: run the agent on a task and watch file access with `fs_usage` on macOS,
  `strace`/`inotifywait` on Linux, or Process Monitor on Windows. Paths outside the grant
  should produce denials, not reads.
- **Network**: in Local mode, watch outbound connections with Little Snitch, `lsof -i`,
  `ss -tp` or Wireshark. Cut the network entirely and the agent should keep working.
- **Process limits**: give it a task that allocates without bound and confirm the process group
  dies rather than taking the machine with it.

If any of that does not match what this code says, that is a bug and we want the report.

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

## A note on the comments

Some source comments reference internal document identifiers such as
`HARDENING_MASTER_PLAN_V5`, `S2-08` and `A2`. Those are our internal work-tracking references
and are not published. They are left in place because rewriting comments purely for
presentation risks changing what they mean, and the comments are more useful accurate than
tidy.
