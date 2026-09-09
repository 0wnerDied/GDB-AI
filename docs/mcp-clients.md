# Connect an Agent

GDB/AI is an MCP server. The Agent harness is the MCP client that starts or
connects to it, discovers its tools, and presents those tools to the model:

```text
Agent model -> CLI harness / MCP client -> GDB/AI -> GDB/MI -> GDB -> target
```

For local debugging, prefer stdio. The harness starts GDB/AI as a child process,
and GDB/AI can access the same local workspace, debugger, PTY, and target
processes. Replace `/absolute/path/to/gdb-ai` in every example with the installed
binary path. Check the host first:

```sh
/absolute/path/to/gdb-ai doctor
```

Use an absolute configuration path when needed. Global GDB/AI options precede
the `serve` command:

```text
/absolute/path/to/gdb-ai --config /absolute/path/to/gdb-ai.toml serve --stdio
```

## Codex CLI

Register the local stdio server:

```sh
codex mcp add gdb-ai -- /absolute/path/to/gdb-ai serve --stdio
codex mcp list
```

Inside Codex, use `/mcp` to inspect the connection and discovered tools. Codex
stores the equivalent configuration in `~/.codex/config.toml`:

```toml
[mcp_servers.gdb-ai]
command = "/absolute/path/to/gdb-ai"
args = ["serve", "--stdio"]
```

See the official [Codex MCP documentation](https://developers.openai.com/codex/mcp/).

## Claude Code

Register GDB/AI for the current user:

```sh
claude mcp add --transport stdio --scope user gdb-ai -- \
  /absolute/path/to/gdb-ai serve --stdio
claude mcp get gdb-ai
```

Use `claude mcp list` or `/mcp` inside Claude Code to inspect its status. Use
`--scope project` instead of `--scope user` only when the absolute command is
appropriate for every user of that project.

See the official [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).

## OpenHands CLI

Register the stdio command, then start a new conversation:

```sh
openhands mcp add gdb-ai --transport stdio \
  /absolute/path/to/gdb-ai -- serve --stdio
openhands mcp get gdb-ai
```

Within OpenHands, `/mcp` shows the active server. The equivalent manual entry in
`~/.openhands/mcp.json` is:

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

See the official [OpenHands MCP documentation](https://docs.openhands.dev/openhands/usage/cli/mcp-servers).

## Kimi Code CLI

Register and test the local server:

```sh
kimi mcp add --transport stdio gdb-ai -- \
  /absolute/path/to/gdb-ai serve --stdio
kimi mcp test gdb-ai
```

`kimi mcp list` shows the stored configuration and connection state. See the
official [Kimi Code MCP command reference](https://moonshotai.github.io/kimi-cli/en/reference/kimi-mcp.html).

## DeepSeek Harness

DeepSeek Harness exposes MCP servers through its official
`@deepseek-ai/dsh-mcp-client` plugin. Save this as
`/absolute/path/to/gdb-ai.cordis.yml`:

```yaml
- insert:
    - id: mcp-gdb-ai
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: gdb_ai
        transport: stdio
        command: /absolute/path/to/gdb-ai
        args: ['serve', '--stdio']
        env: {}
        cwd: !!js process.cwd()
```

Apply the overlay to the selected harness profile:

```sh
dsh web --patch /absolute/path/to/gdb-ai.cordis.yml
```

The model receives tools under names such as `mcp__gdb_ai__gdb_session`. See
the official
[DeepSeek Harness MCP client documentation](https://github.com/deepseek-ai/deepseek-harness/tree/master/packages/mcp/mcp-client).

## Other MCP clients

Clients that accept the common `mcpServers` JSON shape can use:

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

<!-- 2026-09-09: Keep this link on the stable build section so README
     subsection changes cannot strand the HTTP setup instructions. -->
If a client accepts only Streamable HTTP, start the loopback server described
in the [README](../README.md#build-and-connect) and connect it to
`http://127.0.0.1:8080/mcp`. Do not expose plaintext HTTP outside the host.

## Verify tool discovery

After initialization, the client calls `tools/list`. A default GDB/AI server
advertises these bounded tools:

```text
gdb_session       gdb_run          gdb_probe
gdb_breakpoints   gdb_inspect      gdb_evaluate
gdb_memory        gdb_disassemble  gdb_io
gdb_batch         gdb_events
```

The initialization response also teaches the Agent the stateful workflow:
launch with optional session creation, retain its `session_id`, use the current
stop for inspection, reuse the session across attempts, and close it when
finished. Supply `stop_id` only when a later read must reject a newer stop.

## Native crash and thread diagnosis

Launch a native program and collect its initial crash evidence in one
`tools/call` request. Omitting `session_id` creates the session too:

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

With this inspection plan, launch waits for a stop or exit and returns bounded
target output with the collected observations. Keep `result.session.session_id`
for later calls. A failure after creation retains that metadata under
`error.details.session`, so the session can still be inspected or closed.
Launch may include `breakpoints: [{"function": "main"}]` to install ordinary
software breakpoints before execution. Keep `result.created_breakpoints` for
later updates or deletion; these breakpoints persist across restart. Use
`create` separately for other pre-launch configuration.
A normal exit has no stopped
observations. Inspection failure preserves the execution outcome; do not repeat
execution merely to recover a failed read. Use `gdb_run` action `restart` with
the same `inspect` plan for another run in the existing session.

For a running process that appears blocked, interrupt and collect its thread
stacks in one call:

```json
{
  "name": "gdb_run",
  "arguments": {
    "action": "interrupt",
    "session_id": "<session-id>",
    "inspect": [{"view": "threads", "stack_depth": 8}]
  }
}
```

All returned stacks belong to the same stop; per-thread unwind failures remain
explicit. A captured stop supports diagnosis, not proof of a reproducible race.
Use `first_instruction` or `main` at launch only when setup must precede
execution, then include the needed views in `gdb_run` action `continue`.

Share a returned `observation_id` with authorized observers through
`gdb_inspect` view `observation` and `snapshot_id: "<observation-id>"`.
This reads immutable historical evidence without another GDB command. Only
the session controller may mutate the target; see [control handoff and
cancellation](operations.md) for coordinating multiple clients.

## Input and output

Run-control requests may supply byte-exact `input` and include the resulting
bounded `output`. For larger retained results, use
`gdb_memory` action `artifact` with the returned URI and `next_offset` to page
large results without repeating the debugger read. Use
`gdb_run` action `wait` with `input` when execution is already asynchronous,
and reserve `gdb_io` for open-ended interaction. An MCP `gdb_io` read with no
`max_bytes` returns at most 4096 bytes; request a larger bound only when the
additional output is needed. Projected tools do not expose lease or revision
fields and bind omitted reads to the current stop.
Inferior stdin, stdout, and stderr use `stream: "pty"`; `stream: "target"`
selects GDB/MI `@` output, not the inferior's stdout.

A `gdb_io` write may replace one `text` or `data_base64` payload with `steps`.
Each step contains one payload and an optional `wait_for` substring. Matching
starts at the PTY position when the call begins, so omit `wait_for` on the
first step when the inferior is already waiting at its current prompt. The
single `timeout_ms` bounds the complete transaction.

Advanced targets, mutations, variable objects, tracking, and kernel operations
appear only when the server is started with `--advanced-tools`. Raw GDB access
appears only with `--raw-admin`; do not enable either flag by default.
See the [canonical protocol](protocol.md) for bounded breakpoint captures and
other specialized operations.

## Security

An stdio MCP entry is a trusted local executable. Review project-provided MCP
configuration before allowing a harness to start it. GDB/AI hardens GDB startup,
but running an untrusted target still requires placing GDB/AI, GDB, and the
target together inside an external container or VM.
