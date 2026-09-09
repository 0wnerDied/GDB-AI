<h1 align="center">GDB/AI</h1>

<p align="center">
  <strong>GDB Agent Interface</strong><br>
  Stateful, bounded access to GNU GDB for software Agents.
</p>

<p align="center">
  <!-- 2026-09-09: Keep each badge's semantic color and let CI report live status. -->
  <a href="https://github.com/0wnerDied/GDB-AI/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/0wnerDied/GDB-AI?label=release&amp;style=flat&amp;color=007ec6"></a>
  <a href="https://github.com/0wnerDied/GDB-AI/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/0wnerDied/GDB-AI/ci.yml?branch=master&amp;label=CI&amp;style=flat"></a>
  <a href="Cargo.toml"><img alt="Rust 1.88 or later" src="https://img.shields.io/badge/Rust-1.88%2B-ea7233?style=flat"></a>
  <a href="docs/compatibility.md"><img alt="GDB MI3 and MI4" src="https://img.shields.io/badge/GDB-MI3%20%2F%20MI4-8a2be2?style=flat"></a>
  <a href="LICENSE"><img alt="GPL-3.0-or-later" src="https://img.shields.io/badge/license-GPL--3.0--or--later-67ac09?style=flat"></a>
</p>

<p align="center">
  <a href="#build-and-connect">Build</a> ·
  <a href="#one-agent-turn">Agent turn</a> ·
  <a href="#system-model">System model</a> ·
  <a href="#interface">Interface</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="#scope-and-trust-boundary">Scope</a> ·
  <a href="#reproducible-verification">Verification</a>
</p>

GDB/AI is the **GDB Agent Interface**, a Rust server that gives software Agents
stateful, bounded access to GNU GDB through MCP and a canonical JSON-RPC API.
GNU GDB retains target execution, symbols, unwinding, expressions, and JIT
registration. GDB/AI manages sessions, typed operations, concurrency, and
evidence around those semantics.

The interface is organized around an Agent's debugging turn. A launch request
can create a session, install breakpoints, run to a stop, and collect a
stop-bound inspection plan. Later run-control requests can provide target input,
wait for another stop or exit, and return requested observations. Responses
identify their execution context and any incomplete evidence. This reduces
protocol bookkeeping and output parsing while preserving the facts needed to
support a diagnosis.

The primary workflow is native Linux crash and blocked-thread diagnosis in a
trusted development workspace. Attach, core, gdbserver, QEMU, Linux kernel,
and native runtime debugging use the same interface when their documented
prerequisites are present.

## Build and connect

Running GDB/AI requires Linux and a supported GNU GDB. Building from source
requires Rust 1.88 or later. Published [releases](https://github.com/0wnerDied/GDB-AI/releases)
provide binaries and checksums; use the README at the corresponding tag for a
release binary.

```sh
cargo build --locked --release -p gdb-ai
target/release/gdb-ai doctor
target/release/gdb-ai serve --stdio
```

Run the server from the target workspace or set `security.workspace_roots`
explicitly. `doctor` checks the debugger environment, and `--version` reports
the release, source commit, compiler, and canonical-schema hash. The
[connection guide](docs/mcp-clients.md) provides exact MCP configuration for
supported clients.

Stdio is the direct local transport. Multiple local clients can use an
owner-only Unix socket or loopback HTTP:

```sh
target/release/gdb-ai serve --unix "$XDG_RUNTIME_DIR/gdb-ai.sock"
target/release/gdb-ai serve --http 127.0.0.1:8080
```

HTTP exposes `/mcp`, `/healthz`, and `/metrics`. Bearer authentication uses
`--auth-token-file`, and browser clients require explicit `--trusted-origin`
values. For remote access, terminate TLS at a trusted same-host proxy; GDB/AI
accepts HTTP only on loopback.

## One Agent turn

The shortest crash workflow creates a session, launches the program, waits for
a stop or exit, and requests a compact crash observation. Omitting
`session_id` performs session creation within the launch call.

```json
{
  "name": "gdb_session",
  "arguments": {
    "action": "launch",
    "program": "/workspace/app",
    "stop": "none",
    "inspect": [{"view": "crash", "profile": "brief"}]
  }
}
```

The response contains `result.session.session_id` for later operations.
Launch can install up to sixteen persistent software breakpoint locations
before execution. `program` identifies the executable and `argv` contains only
its arguments, preserving empty values, whitespace, quotes, and shell
characters literally.

Run-control operations share the same bounded inspection plans. For a blocked
target, an interrupt with the `threads` view, `stack_depth: 8`, and
`include_locals: true` collects thread identities, stacks, arguments, and
typed local values, including aggregate contents, from one stop.

Independent inspection failures retain successful results and mark the
observation incomplete. Inspection errors preserve the execution outcome;
they do not imply that the Agent should repeat the run-control operation.

<p align="center">
  <a href="docs/assets/gdb-ai-operation-sequence.svg">
    <img src="docs/assets/gdb-ai-operation-sequence.svg" width="900"
         alt="One launch request optionally creates a session, configures GDB and breakpoints, runs a local target, captures independent PTY bytes, inspects the stop, records an observation, and returns contextual evidence.">
  </a>
</p>
<p align="center"><em>Figure 1. The stop path of a fused launch and inspection turn.</em></p>

The sequence records logical dependencies, not a shared clock.
[GDB/MI][gdb-mi] state records and local inferior PTY bytes are independent
streams. GDB/AI checks the stop ID and execution epoch before publishing the
requested observation. A normal exit reports exit state without a stopped
observation. An HTTP response timeout does not cancel target execution; query
the returned `operation_id` with `gdb_session` action `operation_status`.

## System model

Each session owns one GNU GDB process and one actor that alone writes its MI
command stream and live reducer state. Sessions progress independently, while
mutations within one session remain serialized. Interrupt and close use a
separate control path so they do not wait behind a pending normal operation.

<p align="center">
  <a href="docs/assets/gdb-ai-architecture.svg">
    <img src="docs/assets/gdb-ai-architecture.svg" width="900"
         alt="Agents and SDK clients pass through transport adapters and the Gateway to one session actor and GDB process; control, MI reduction, evidence, and local PTY paths remain separate.">
  </a>
</p>
<p align="center"><em>Figure 2. One-session ownership and the separate control, MI reduction, target I/O, and evidence paths.</em></p>

Stop IDs and execution epochs bind observations to debugger state. Resuming a
target invalidates earlier frame and value handles. A context change during a
multi-command read returns a stale-context error instead of mixed evidence.
Successful run-control inspection plans, batches, and snapshots publish
immutable `observation_id` values that authorized callers retrieve without
issuing new GDB commands. Persisted observations remain available after resume
or session close within the configured retention limits.

MCP control remains with the creating caller until close or an explicit
handoff to another caller under the same authenticated principal.

Every public response is bounded. Large results are paged, moved to
content-addressed artifacts, or explicitly truncated; metadata describes
continuations and evidence gaps. Local target input and output use a PTY; GDB
console, target, and log streams remain separate. PTY stdout and stderr share
one terminal and cannot be attributed as distinct streams.

The default `performance` journal mode keeps live debugging available when
history storage fails and reports the evidence gap. `durable` mode requires
evidence writes to succeed. Replay reconstructs recorded debugger state and
observations without executing or restoring the inferior. Detailed ownership,
cancellation, and persistence invariants live in
[architecture](docs/architecture.md) and [operations](docs/operations.md).

## Interface

MCP tools and canonical calls share the same server and operation registry.
The [canonical protocol](docs/protocol.md) uses the `gdb.ai/v1` namespace;
static [schemas](schemas) define its request, event, and resource contracts.
The default MCP catalog groups eleven tools by debugging responsibility:

| Responsibility | Tools | Interface |
| --- | --- | --- |
| Session and execution | `gdb_session`, `gdb_run`, `gdb_events` | Lifecycle, control, input, waits, handoff, and operation status |
| Instrumentation | `gdb_probe`, `gdb_breakpoints` | Temporary probes and persistent breakpoints, watchpoints, or catchpoints |
| Observation | `gdb_inspect`, `gdb_batch` | Stop-bound semantic views, snapshots, history, differences, and mixed reads |
| Program data | `gdb_evaluate`, `gdb_memory`, `gdb_disassemble` | Expressions, exact hexadecimal bytes, artifacts, and instructions |
| Target I/O | `gdb_io` | Inferior PTY bytes and separate GDB console, target, and log streams |

`--advanced-tools` adds attach, core, remote and mutation operations, variable
objects, registers, tracking, signals, Agent operations, and Linux kernel
views. `--raw-admin` separately exposes native MI and console commands,
including caller-supplied runtime helpers. Raw commands execute with the GDB
process's host authority.

The [Python and TypeScript SDKs](sdk/README.md) expose canonical sessions,
projected MCP calls, and bounded resources over HTTP.

<!-- 2026-09-09: Keep every public guide reachable from the README's primary navigation. -->
## Documentation

| Goal | Start here |
| --- | --- |
| Connect an Agent | [Client setup](docs/mcp-clients.md) for supported MCP clients and the first debugging turn |
| Use the APIs | [Canonical protocol](docs/protocol.md), [schemas](schemas), and [Python and TypeScript SDKs](sdk/README.md) |
| Operate the server | [Operations](docs/operations.md), [architecture](docs/architecture.md), and the [security model](docs/security.md) |
| Qualify or extend | [Compatibility](docs/compatibility.md), [kernel debugging](docs/kernel.md), the [provider boundary](docs/provider-sdk.md), and [evaluation](docs/evaluation.md) |

## Scope and trust boundary

GDB/AI runs on Linux in GDB's all-stop mode. MI4 is preferred, with MI3 in a
fresh fallback GDB process. Required CI qualifies GDB 9 through 17 on x86-64
and exercises separate native and QEMU AArch64 lanes. The
[compatibility matrix](docs/compatibility.md) records the exact maintenance
releases, target prerequisites, and qualification boundary.

Linux user-space coverage includes launch, attach, cores, threads,
breakpoints, values, registers, memory, and disassembly. Remote coverage uses
gdbserver and QEMU RSP. Conditional Linux kernel views cover tasks, modules,
stacks, symbols, and selected page-table operations. Node.js/V8, PHP, CGI,
LLVM, Clang, and JIT checks exercise native debugging with matching GDB and
runtime builds; language-specific decoding still depends on matching symbols
and caller-supplied helpers.

Native Windows and macOS hosts, non-stop execution, an LLDB backend, and
restoration of a live inferior after GDB exits are outside the current
interface.

The deployment boundary is a trusted local workspace under the server's OS
account. GDB starts with initialization files, target auto-load, debuginfod,
and inferior function calls disabled. Workspace roots constrain structured
target paths, and operators can configure PID and remote allowlists, resource
limits, or bubblewrap hardening.

These controls do not form a complete target sandbox. Place the server, GDB,
helpers, and untrusted targets inside an external container or VM; the
[security model](docs/security.md) defines the full contract.

## Reproducible verification

The [CI workflow](.github/workflows/ci.yml) is the executable definition of
required checks and toolchain versions. These commands reproduce its core
Rust checks with the pinned toolchain:

```sh
rustup toolchain install 1.88.0 --profile minimal --component clippy,rustfmt
cargo +1.88.0 fmt --all -- --check
GDB_AI_REQUIRE_INTEGRATION=1 cargo +1.88.0 test --locked --workspace --all-targets
cargo +1.88.0 clippy --locked --workspace --all-targets -- -D warnings
```

Install the integration prerequisites listed in the workflow. The required
flag converts missing prerequisites from skips into failures. Compatibility,
AArch64, runtime, kernel, SDK, schema, and bounded fuzzing lanes are documented
beside their implementations.

Compatibility establishes behavior on specified configurations. Claims about
Agent diagnostic success, interaction cost, context use, or elapsed time need
controlled task-level trials. [Evaluation methodology](docs/evaluation.md)
defines comparable conditions, fixed native evidence checks, metric semantics,
and reproducible commands.

## License

GDB/AI is independently versioned and requires no binutils-gdb source
modification. It is licensed under [GPL-3.0-or-later](LICENSE).

[gdb-mi]: https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI.html
