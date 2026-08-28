# GDB/AI

**GDB/AI (Agent Interface)** is a stateful interface for modern Agents doing
dynamic debugging, vulnerability validation, and authorized vulnerability
exploitation. It runs above GDB and the GDB/MI machine interface, exposing
bounded semantic operations through MCP and canonical JSON-RPC instead of
requiring Agents to manage debugger processes, parse terminal prompts, or
depend on implicit GDB context.

GDB/AI does not define or replace GDB/MI. GDB/MI is part of GNU GDB in the
binutils-gdb project and serves only as GDB/AI's backend protocol. Each GDB/AI
session runs one dedicated GDB process, separates inferior PTY traffic from
MI control traffic, and reduces asynchronous records into explicit state.

The repository is independently versioned as `gdb-ai`; the executable is
`gdb-ai`, the stable protocol is `gdb.ai/v1`, and resources use `gdbai://`.
The complete normative design is in [PLAN.md](PLAN.md).

## Implemented system

- Bounded byte-stream MI4/MI3 framer, parser, encoder, lossless AST, saved
  fixtures, property-style chunk tests, and cargo-fuzz targets
- One session actor and GDB child per session with token correlation,
  serialized commands, finite deadlines, cancellation, and interrupt support
- Journal-before-reducer state, revisions, execution epochs, stop IDs,
  stale-handle rejection, snapshots, tracked state, diffs, and replay
- Local launch, allowlisted PID attach, core files, allowlisted gdbserver/RSP,
  detach, restart, kill, fork/exec policy, and structured signal policy
- Structured breakpoints/watchpoints/catchpoints, threads, frames, locals,
  arguments, registers, variable objects, memory, disassembly, modules,
  mappings, source excerpts, and inferior I/O
- Compare-and-swap memory writes, register writes, bounded search, paged
  values, content-addressed artifacts, and owner-checked resource access
- Agent probes, experiments, hypothesis checks, observation budgets, tracked
  expressions/memory, crash signatures, and provider provenance
- Write leases, optimistic revisions, idempotency, profiles, rate limits,
  redacted SQLite audit, WAL metadata, JSONL evidence, and reconciliation
- MCP stdio, MCP Streamable HTTP, Unix socket, canonical JSON-RPC, Python SDK,
  TypeScript SDK, CLI operations, schema files, and Prometheus text metrics
- Secure GDB startup, clean inferior environment, workspace path policy,
  bubblewrap filesystem/network hardening when available, `no_new_privs`, and
  process rlimits; untrusted targets require an external container or VM
- Optional SHA-256-pinned GDB Python MI extension and conditional kernel
  provider with bounded tasks/modules/panic context and an explicit monitor
  allowlist; see [Linux kernel debugging](docs/kernel.md)

Version 1 intentionally remains all-stop and Linux-only. It does not claim
non-stop execution, native Windows/macOS debugging, an LLDB backend, arbitrary
interactive CLI/Python/shell access, proprietary JTAG unification, or live
inferior restoration after GDB death.

## Requirements

- Linux and Rust 1.88 or newer
- GDB 13 or newer for MI4, or GDB 9 or newer for MI3 compatibility
- Bubblewrap for optional mount/network hardening (`auto` reports absence;
  `required` fails closed); it is not a complete untrusted-code sandbox
- A C compiler for integration tests
- Optional: gdbserver, Python-enabled GDB, Node.js 18 or newer

## Build and verify

```sh
cargo build --locked --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p gdb-ai -- doctor
```

Additional checks:

```sh
cargo check --manifest-path fuzz/Cargo.toml --bins
python3 -m compileall -q gdb-extension sdk/python benchmarks/python
npm --prefix sdk/typescript ci
npm --prefix sdk/typescript run build
(cd schemas && sha256sum -c SHA256SUMS)
```

## Serve MCP and JSON-RPC

Single-client stdio:

```sh
target/release/gdb-ai serve --stdio
```

Multi-client local socket:

```sh
target/release/gdb-ai serve --unix /run/user/1000/gdb-ai.sock
```

Streamable HTTP is loopback-only unless a bearer-token file is supplied:

```sh
target/release/gdb-ai serve --http 127.0.0.1:8080
target/release/gdb-ai serve --http 0.0.0.0:8080 \
  --auth-token-file /run/secrets/gdb-ai-token
```

HTTP endpoints are `/mcp`, `/healthz`, and `/metrics`. The same connection
accepts MCP tools and the canonical `gdb.ai/call` JSON-RPC method. Supported
MCP protocol versions are `2025-11-25`, `2025-06-18`, `2025-03-26`, and
`2024-11-05`.

## Tools

| Tool | Purpose |
| --- | --- |
| `gdb_session` | Sessions, leases, launch/attach/core/remote, lifecycle, capabilities |
| `gdb_run` | Continue, interrupt, source/instruction stepping, and waits |
| `gdb_breakpoints` | Breakpoints, watchpoints, catchpoints, conditions, and scopes |
| `gdb_inspect` | Bounded target, stack, variable, source, module, mapping, and snapshot views |
| `gdb_evaluate` | Side-effect-denied one-shot expression evaluation |
| `gdb_values` | Stop-scoped variable objects with paged children and updates |
| `gdb_memory` | Bounded read, CAS write, compare, and explicit-range search |
| `gdb_registers` | Semantic register roles and audited writes |
| `gdb_disassemble` | Normalized bounded instructions with source and bytes |
| `gdb_io` | Separate PTY, MI target, console, and log I/O plus `send_eof` and resize |
| `gdb_tracking` | Tracked expressions/memory and bounded histories |
| `gdb_signals` | Structured stop/print/pass signal policy |
| `gdb_batch` | Multiple reads constrained to one stop |
| `gdb_agent` | Probes, experiments, hypothesis checks, and evidence budgets |
| `gdb_events` | Finite event waits |
| `gdb_kernel` | Conditional kernel inspection and allowlisted monitor operations |
| `gdb_raw` | Audited MI/CLI escape hatch, registered only with `--raw-admin` |

Mutations require both the exact current `expected_revision` and `lease_id`,
or an explicit `accept_latest_revision` where permitted. `session.create`
returns the first expiring lease. Renew it with
`session.acquire_write_lease`. Starting execution invalidates every previous
frame and value handle.

## Configuration and SDKs

```sh
gdb-ai --config /absolute/path/to/gdb-ai.toml serve --stdio
```

See [gdb-ai.example.toml](gdb-ai.example.toml) and the hardened distribution
sample in [packaging/distro/gdb-ai.toml](packaging/distro/gdb-ai.toml).
Python and TypeScript clients live under [sdk](sdk). Static protocol schemas
and their SHA-256 hashes live under [schemas](schemas).

The optional extension at [gdb-extension/gdb_ai.py](gdb-extension/gdb_ai.py)
must be configured with an absolute path and its exact SHA-256 digest. It is
never auto-loaded from a target directory.

## Replay and operations

```sh
gdb-ai transcript export <session-id>
gdb-ai transcript inspect /path/to/journal.jsonl
gdb-ai replay /path/to/journal.jsonl --session-id sess_replay
gdb-ai session list
gdb-ai session inspect <session-id>
gdb-ai session close <session-id>
gdb-ai schema export
```

Session CLI commands connect to `server.unix_socket`. Replay validates strict
journal ordering and reconstructs controller state and stored snapshots. A
recorded `session.created` ID overrides `--session-id`; the flag supplies a
legacy MI-only fallback. Replay never executes or claims to restore an
inferior.

## Embedding in binutils-gdb

```sh
git submodule add https://github.com/0wnerDied/GDB-AI.git gdb-ai
cargo build --manifest-path gdb-ai/Cargo.toml --release
```

No binutils-gdb source modification is required. GDB/AI controls the built or
installed `gdb` executable through GDB's existing GDB/MI machine interface.

## License

[GPL-3.0-or-later](LICENSE).
