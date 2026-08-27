# gdb/ai

gdb/ai is a stateful, agent-oriented control plane that runs GDB through its
machine interface. It keeps GDB control traffic separate from inferior I/O,
turns asynchronous MI records into explicit state, and exposes bounded
semantic operations over MCP and canonical JSON-RPC.

The repository currently implements the first local Linux vertical slice.
The complete North-star design and its delivery boundaries are recorded in
[PLAN.md](PLAN.md).

## Implemented scope

- Rust GDB/MI framer, parser, encoder, and lossless AST
- MI4 startup with MI3 fallback and command-based capability probing
- One actor and one GDB child per session, with serialized MI commands
- Separate inferior PTY with bounded offset-based output rings
- Event-first reducer, revisions, execution epochs, stop IDs, and stale
  context rejection
- Local launch, run control, breakpoints, stack, locals, registers,
  expression evaluation, memory reads, disassembly, and inferior I/O
- Policy profiles, canonical path checks, bounded responses, audit records,
  content-addressed artifacts, SQLite WAL metadata, and JSONL journals
- MCP stdio tools and resources plus the `gdb.ai/call` JSON-RPC method
- Deterministic replay from a complete journal

This slice intentionally does not claim attach, core, remote, non-stop,
HTTP, multi-user leases, production namespaces/seccomp, persistent variable
objects, SDKs, the Python extension, or kernel providers. Those remain in
the delivery plan until the local path and Agent evaluation justify them.

## Requirements

- Linux
- Rust 1.88 or newer
- GDB 13 or newer for MI4, or GDB 9 or newer for MI3 compatibility
- A C compiler for the live integration fixture

## Build and verify

```sh
cargo build --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p gdb-ai -- doctor
```

`doctor` starts a securely configured GDB session, completes capability
negotiation, prints the result as JSON, and closes the session.

## Run as an MCP server

```sh
target/release/gdb-ai serve --stdio
```

A typical MCP client entry is:

```json
{
  "mcpServers": {
    "gdb-ai": {
      "command": "/absolute/path/to/gdb-ai",
      "args": ["serve", "--stdio"]
    }
  }
}
```

The stdio server supports MCP protocol versions `2025-11-25`,
`2025-06-18`, `2025-03-26`, and `2024-11-05`. It exposes these tools:

| Tool | Purpose |
| --- | --- |
| `gdb_session` | Create, launch, inspect, list, and close sessions |
| `gdb_run` | Continue, interrupt, step, and wait |
| `gdb_breakpoints` | Create and manage breakpoints and watchpoints |
| `gdb_inspect` | Read bounded debugger views |
| `gdb_evaluate` | Evaluate with inferior calls and writes disabled |
| `gdb_memory` | Read bounded memory ranges |
| `gdb_disassemble` | Read bounded disassembly |
| `gdb_io` | Read and write the separate inferior PTY |

Large results contain a `gdbai://artifact/sha256:...` URI. MCP clients can
retrieve it through `resources/read`. Session status is available at
`gdbai://session/<session-id>/status`.

Mutation calls require either the exact `expected_revision` returned by the
previous response or `accept_latest_revision: true`. State-sensitive reads
require the current `stop_id`; starting execution invalidates all previous
stop-scoped handles.

For clients that already implement the canonical protocol, the same stdio
connection accepts the JSON-RPC method `gdb.ai/call`. Its params are a
`gdb.ai/v1` request envelope. Export that envelope's JSON Schema with:

```sh
gdb-ai schema export
```

## Configuration

Pass a TOML file with the global option:

```sh
gdb-ai --config /absolute/path/to/gdb-ai.toml serve --stdio
```

See [gdb-ai.example.toml](gdb-ai.example.toml). Target programs and working
directories are canonicalized and must stay under a configured
`workspace_roots` entry.

GDB starts without initialization files or target auto-load scripts. The
service disables debuginfod, shell-based inferior launch, and inferior
function calls, preserves normal ASLR behavior, clears GDB's inherited
environment, and does not expose raw commands through the default MCP tool
list.

## Replay

Every session writes a complete JSONL journal under its configured session
directory. Rebuild controller state without re-executing the inferior:

```sh
gdb-ai replay /path/to/journal.jsonl --session-id sess_replay
```

Replay reconstructs gdb/ai controller state. It does not restore a live
inferior.

## Embedding in binutils-gdb

The repository is independent and can be attached to a binutils-gdb checkout
once it has a remote URL:

```sh
git submodule add <gdb-ai-repository-url> gdb-ai
cargo build --manifest-path gdb-ai/Cargo.toml --release
```

No binutils-gdb source modification is required; gdb/ai controls the built or
installed `gdb` executable through MI.

## License

GPL-3.0-or-later.
