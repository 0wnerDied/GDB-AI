# GDB/AI

[![CI](https://github.com/0wnerDied/GDB-AI/actions/workflows/ci.yml/badge.svg)](https://github.com/0wnerDied/GDB-AI/actions/workflows/ci.yml)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-2ea44f)](LICENSE)
[![Rust: 1.88+](https://img.shields.io/badge/Rust-1.88%2B-dea584)](Cargo.toml)
[![GDB: MI3 / MI4](https://img.shields.io/badge/GDB-MI3%20%2F%20MI4-315d8a)](docs/compatibility.md)

**GDB/AI is an Agent-oriented interface to GNU GDB.** Its objective is to
reduce the interaction, output-processing, and coordination costs of Agent
debugging relative to direct GDB CLI or GDB/MI use, while preserving the
information needed to establish a diagnosis.

The server exposes MCP tools and a canonical JSON-RPC API. A run-control
request can provide input, wait for a stop or exit, and return requested
observations together with target output. Each debugging session owns a GDB
process and explicit execution state. GDB remains responsible for target
control, symbols, unwinding, expressions, and JIT registration; GDB/AI uses
the existing [GDB/MI interface][gdb-mi].

The grouping of operations and bounded responses are interface properties.
Their effect on debugging accuracy, token consumption, and elapsed time
requires task-level measurement; see [Evaluation](#evaluation).

[System model](#system-model) · [Targets](#supported-targets-and-verification-scope) ·
[Build](#build-and-connect) · [Tools](#agent-operations) ·
[Verification](#reproducible-verification) · [Evaluation](#evaluation)

## System model

![GDB/AI architecture: shared protocol and admission layers route requests to a session actor and GDB process; target PTY capture and history storage have separate paths.](docs/assets/gdb-ai-architecture.svg)

*Figure 1. Logical data paths for one debugging session. Additional sessions
have independent actors and GDB processes within the same server. The PTY
path shown applies to locally launched targets; remote and attached targets
retain their target-specific I/O arrangements. Storage connections indicate
recording, not a universal durability requirement.*

| Responsibility | GDB/AI behavior |
| --- | --- |
| Process ownership | One GDB child per session; an actor correlates MI command tokens and owns live session state. |
| Execution context | Stop IDs and execution epochs bind observations. Resuming invalidates previous frame and value handles. |
| Compound operations | Run, wait, input, and requested inspection can share one Agent call. Probes combine a temporary breakpoint, bounded capture, and cleanup. |
| Output | Structured replies omit MI envelopes and debugger prompts. Inferior PTY bytes and GDB console, target, and log streams remain separately accessible. |
| Large results | Pagination and artifact references bound responses. Continuation, truncation, and evidence-gap metadata identify incomplete data. |
| Persistence | Live state belongs to the actor. Journal durability and output retention are explicit configuration choices. |

![Illustrative sequence of one MCP continue call: GDB command result, asynchronous state events, independent PTY output, stop-bound inspection, and one response.](docs/assets/gdb-ai-operation-sequence.svg)

*Figure 2. A successful continue-to-breakpoint call with requested inspection.
The MI command result acknowledges execution control; asynchronous records
report target-state changes. MI and PTY traffic have no common ordering
guarantee. The server verifies the stop context before returning the requested
views. Persistence behavior is governed separately by the configured mode.*

This distinction between command completion and target stopping follows
[GDB/MI execution semantics][gdb-execution]. The figures describe logical
relationships and one illustrative interaction, rather than measured latency
or a mandatory ordering of all runtime events.

## Supported targets and verification scope

GDB/AI runs on Linux and uses [all-stop debugging][gdb-all-stop].
Required CI exercises x86-64 and AArch64. MI4 is preferred; an MI3 fallback
uses a fresh GDB process. The compatibility matrix tests GDB **9.2, 10.2,
11.2, and 12.1 with MI3**, and **13.2, 14.2, 15.2, 16.3, and 17.2 with MI4**.
Each version runs the same local-debugging scenario, including literal
argument preservation. This matrix does not test every runtime against every
GDB version.

| Target or environment | Available debugging interface | Reproducible verification |
| --- | --- | --- |
| Linux user space | Launch, attach, cores, threads, breakpoints, values, registers, memory, and disassembly | Workspace integration tests; AArch64 remote and system tests |
| gdbserver and RSP targets | GDB remote connection and capability-dependent inspection/control | Native gdbserver, QEMU user-mode, and system-target tests |
| Linux kernel | Remote GDB access plus kernel tasks, modules, stacks, and conditional symbol/page-table views | Pinned Debian Linux 6.1 and 6.12 x86-64, and 6.12 AArch64 under QEMU |
| V8 / Node.js | Native engine debugging and caller-supplied GDB runtime helpers | Native GDB/MCP comparison at V8 isolate initialization |
| PHP / CGI | Native interpreter and CGI process debugging | Native GDB/MCP comparisons at PHP request startup |
| LLVM / Clang / JIT | Native compiled-code debugging and GDB-supported JIT symbols | Clang-compiled fixture and LLVM MCJIT comparisons |

For V8, PHP/CGI, and LLVM/JIT, the compatibility target is the native debugging
capability of the **same GDB and runtime builds**. The runtime checks compare
breakpoints, native stack frames, GDB helper output, target output, and exit
status. Language frames, object decoding, optimized-code unwinding, and JIT
visibility depend on matching symbols, runtime support, and supplied helpers.
JIT integration uses [GDB's JIT interface][gdb-jit]. The MCJIT check establishes
coverage for that JIT configuration.

Kernel views depend on architecture, target capabilities, and available
symbols. Typed traversal requires a matching `vmlinux`; the symbol-free
bootstrap and page-table paths are specific to supported x86-64 QEMU targets.
See [compatibility](docs/compatibility.md) and
[kernel debugging](docs/kernel.md) for prerequisites and exact test commands.

Native Windows/macOS hosts, non-stop execution, an LLDB backend, and live
inferior restoration after GDB death are outside the implemented scope.

## Build and connect

Running the server requires Linux and a supported GDB. Building from source
requires Rust 1.88 or later. A C compiler is needed for native test fixtures;
gdbserver, QEMU, runtime binaries, and cross-compilers are needed only for the
corresponding integration tests. Python-enabled GDB is needed for helpers
that execute Python inside GDB.

[Published releases](https://github.com/0wnerDied/GDB-AI/releases) provide
packaged binaries and checksums. Use the README at the corresponding tag
when running a release binary; this document describes its repository revision.

```sh
cargo build --locked --release -p gdb-ai
target/release/gdb-ai doctor
target/release/gdb-ai serve --stdio
```

Run the server from the target workspace or configure
`security.workspace_roots` explicitly. The default root is the server's
working directory. Build native test programs with debug information when
source-level inspection is required. `doctor` checks the local environment;
`--version` reports the source commit, compiler, and canonical-schema hash.

Stdio serves a local MCP client. For multiple local connections, choose a
Unix socket or loopback HTTP:

```sh
target/release/gdb-ai serve --unix "$XDG_RUNTIME_DIR/gdb-ai.sock"
target/release/gdb-ai serve --http 127.0.0.1:8080
```

Choose a socket directory owned by the server account when `XDG_RUNTIME_DIR`
is unavailable. HTTP exposes `/mcp`, `/healthz`, and `/metrics`; bearer-token
authentication is available through `--auth-token-file`. Remote HTTP access
requires a same-host TLS reverse proxy. Browser requests additionally need
an explicit `--trusted-origin` entry.

The [Agent connection guide](docs/mcp-clients.md) documents client setup,
transport negotiation, and examples. MCP tools and the canonical
`gdb.ai/call` method share the server; the canonical namespace is `gdb.ai/v1`.
The [Python and TypeScript SDKs](sdk) provide canonical clients. Python also
offers `Client.call_tool` for projected MCP calls.

## Agent operations

Create a session with `gdb_session` action `create`, then use `launch` with
the returned `session_id`. `program` names the executable; `argv` contains
only its arguments. Empty arguments, whitespace, quotes, and shell characters
in `argv` are preserved literally. Use `stop: "main"` when the target has an
appropriate main symbol, or `first_instruction` when setup must precede
further execution. The caller supplies the intended executable, loader,
libraries, symbols, and runtime helpers.

For an existing stopped session with a breakpoint configured, the following
`tools/call` parameters supply input, continue, wait, and inspect the resulting
stop in one request:

```json
{
  "name": "gdb_run",
  "arguments": {
    "action": "continue",
    "session_id": "<session-id>",
    "input": {"text": "1\n"},
    "inspect": [
      {"view": "stack", "limit": 8},
      {"view": "registers", "roles": ["pc", "sp"]}
    ]
  }
}
```

Continue and step wait for a stop or exit by default. Requested views apply
to a resulting stop; a target that exits instead is reported as exited.
An `observation_error` reports failed post-stop inspection while preserving
the execution outcome; it does not imply that execution should be repeated.
Use `accepted` or `running` without `inspect` for asynchronous interaction.
A response waiter timeout does not cancel target execution: use the returned
`operation_id` with `gdb_session` action `operation_status`, or explicitly
interrupt or close the session.

The default MCP catalog contains eleven tools:

| Tool | Purpose |
| --- | --- |
| `gdb_session` | Session creation, launch, lifecycle, capabilities, and operation status |
| `gdb_run` | Execution control, direct restart, input, waits, and requested views |
| `gdb_probe` | Temporary breakpoint, optional trigger, bounded capture, and cleanup |
| `gdb_breakpoints` | Breakpoints, watchpoints, catchpoints, conditions, and scopes |
| `gdb_inspect` | Target, thread, stack, symbol/type, source, mapping, and snapshot views |
| `gdb_batch` | Multiple bounded views at one stop |
| `gdb_evaluate` | Single or ordered-batch expression evaluation |
| `gdb_memory` | Memory reads and retrieval of artifact content |
| `gdb_disassemble` | Instructions, addresses, bytes, and available source context |
| `gdb_io` | PTY I/O and separate GDB console, target, and log streams |
| `gdb_events` | Bounded event waits |

`--advanced-tools` adds remote/attach/core actions, mutation actions, variable
objects, registers, tracking, signals, Agent operations, and kernel views.
`--raw-admin` independently exposes `gdb_raw` and defaults newly created
sessions to the raw profile. Raw console calls accept native GDB commands
and runtime helpers, returning their console, target, and log output in the
same reply; output preceding a command error remains in `error.details`.
Consecutive raw commands defer registry reconciliation until a structured
operation needs the cached state. Capability responses describe target-specific
availability. The [canonical protocol](docs/protocol.md) and
[schemas](schemas) define the complete interface.

## Multiple Agents and concurrent targets

Independent sessions can progress concurrently. Within a session, normal
mutations are serialized, observations validate their execution context, and
interrupt/close have a separate control path. MCP-created sessions retain a
fixed caller controller without recurring lease renewal. Same-principal
callers may observe within their access rights; concurrent clients do not
automatically acquire independent mutation authority over one target.

The canonical API retains explicit write leases and revision checks. In MCP,
an omitted `stop_id` binds to the current stop; supplying a returned ID makes
a later call reject a different stop. Frame and value handles expire on
resume. Control transfer and cancellation semantics are documented in
[operations](docs/operations.md).

For a hang or suspected thread race, `gdb_inspect` with `view: "threads"`
and `stack_depth: 8` returns thread identities, including available Linux
LWP IDs, and their stacks at one stop. The same view can be included in a
`gdb_run` interrupt request. Use `limit` and `offset` to page threads;
returned frame offsets allow deeper stack inspection. Per-thread unwind
failures are reported explicitly.

These observations support diagnosis of the captured state. All-stop
debugging changes scheduling, and a captured stop does not establish
deterministic reproduction of a race. Repeated trials and independent
root-cause evidence are necessary when evaluating race-localization accuracy.

## Output, persistence, and deployment boundaries

Target input/output uses a dedicated PTY for local launches. Stdout and stderr
share that terminal; they are not independently attributable streams.
`gdb_io` stream `target` refers to GDB/MI `@` records. Byte-oriented I/O
provides text or base64 as appropriate, offsets, and truncation metadata;
bounded retention does not imply a complete transcript. The default output
mode is an ephemeral ring, with bounded spooling and artifact modes available.
Large projected replies are bounded after projection and retain their
original session's artifact ownership.

The default `journal.durability = "performance"` coalesces full-state
checkpoints. A history-storage failure reports an evidence gap while live
debugging continues. `durable` mode requires evidence writes to succeed and
fails the session on an evidence-storage failure. Replay reconstructs recorded
debugger state and snapshots without executing or restoring the inferior.
An incomplete journal is identified as a prefix. See
[operations](docs/operations.md) for replay, retention, and storage maintenance.

Configuration is supplied with `--config`; see
[gdb-ai.example.toml](gdb-ai.example.toml). Without an explicit configuration,
persistent data is placed under `$XDG_STATE_HOME/gdb-ai` or
`$HOME/.local/state/gdb-ai` when those variables are available.

The default profile is `lab_mutation`. Workspace roots constrain structured
target file operations; PID attach requires an allowlist entry. An empty
remote allowlist accepts parsed GDB endpoints, while a nonempty list restricts
them. GDB and its children inherit OS resource limits unless explicit positive
caps are configured. Bubblewrap isolation is optional and disabled by default.

Target auto-load is disabled. Explicit GDB helpers execute with the GDB
process's host permissions; probe trigger commands execute with the server
account and environment. Matching kernel log helpers may be loaded by an
explicit kernel inspection. These interfaces are suitable for a trusted
debugging workspace; untrusted-code isolation requires an external container
or VM boundary. See the [security model](docs/security.md) for the complete
deployment contract.

## Reproducible verification

The [CI workflow](.github/workflows/ci.yml) defines required checks and
toolchain versions. The following commands reproduce its core Rust checks
with the pinned toolchain:

```sh
rustup toolchain install 1.88.0 --profile minimal --component clippy,rustfmt
cargo +1.88.0 fmt --all -- --check
GDB_AI_REQUIRE_INTEGRATION=1 cargo +1.88.0 test --locked --workspace --all-targets
cargo +1.88.0 clippy --locked --workspace --all-targets -- -D warnings
```

Install the prerequisites listed in the workflow for the integration targets.
The required integration flag makes missing prerequisites fail checks that
would otherwise be skipped. Kernel artifact selection and QEMU system setup
are separate, explicitly configured lanes.

To reproduce the native runtime comparisons, install GDB, Clang, LLVM `lli`,
Node.js, PHP CLI, and PHP CGI, then run:

```sh
cargo build --locked -p gdb-ai
python3 tests/runtimes/verify.py target/debug/gdb-ai
```

The script accepts explicit executable paths for each runtime and GDB. CI
also verifies schema hashes, both SDKs, and bounded libFuzzer campaigns for
the MI parser, MI framer, and state reducer. Compatibility jobs build
checksum-pinned GDB releases. The legacy GDB build recipe includes an XSAVE
buffer adjustment for current x86 hosts; see the
[build recipe](tests/compatibility/build-gdb.sh). Kernel artifacts are pinned
separately. Exact results and release provenance belong to
[CI runs](https://github.com/0wnerDied/GDB-AI/actions) and release artifacts.

## Evaluation

Compatibility checks establish specified behavior on the tested configurations.
They do not establish that an Agent solves arbitrary debugging tasks faster
or more accurately. A performance comparison should define the task and an
independent criterion for a correct diagnosis before running trials.

Compare GDB/AI with both direct GDB CLI and direct GDB/MI under the same
model, tool access, targets, symbols, host resources, and time budgets. Allow
each interface its normal batching and scripting capabilities. Report cold
startup separately from reused-session work, and distinguish independent
sessions from multiple clients sharing one session.

| Measure | Reporting requirement |
| --- | --- |
| Diagnostic success | Ground-truth criterion, number of trials, failures, and timeouts |
| Interaction cost | Agent tool calls and backend debugger commands counted separately |
| Context cost | Model/tokenizer, discovery overhead, and actual tokens consumed; bytes are a separate measure |
| Elapsed time | End-to-end wall time with startup, target execution, waits, and helper costs identified |
| Concurrency | Worker/session count, throughput, latency distribution, and resource use |
| Race localization | Repeated trials, scheduling conditions, and evidence linking the observation to the root cause |

Record exact versions and trial conditions, vary execution order, and report
variation or uncertainty alongside aggregate results. The
[evaluation utility](benchmarks/python/evaluate.py) summarizes supplied JSONL
metrics by variant. Its [example input](benchmarks/python/example.jsonl)
illustrates the format; it is not an empirical result or a speedup claim.

## Documentation and license

- [Agent connections and interaction recipes](docs/mcp-clients.md)
- [Canonical protocol](docs/protocol.md) and [static schemas](schemas)
- [Architecture](docs/architecture.md) and [operations](docs/operations.md)
- [Compatibility](docs/compatibility.md) and [Linux kernel debugging](docs/kernel.md)
- [Security model](docs/security.md) and [provider SDK](docs/provider-sdk.md)

GDB/AI is independently versioned and requires no binutils-gdb source
modification. Contributor planning is maintained in [PLAN.md](PLAN.md).
License: [GPL-3.0-or-later](LICENSE).

[gdb-mi]: https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI.html
[gdb-execution]: https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Program-Execution.html
[gdb-all-stop]: https://sourceware.org/gdb/current/onlinedocs/gdb.html/All_002dStop-Mode.html
[gdb-jit]: https://sourceware.org/gdb/current/onlinedocs/gdb.html/JIT-Interface.html
