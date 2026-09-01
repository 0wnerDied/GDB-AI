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

If a client accepts only Streamable HTTP, start the loopback server described
in the [README](../README.md#serve-mcp-and-json-rpc) and connect it to
`http://127.0.0.1:8080/mcp`. Do not expose plaintext HTTP outside the host.

## Verify tool discovery

After initialization, the client calls `tools/list`. A default GDB/AI server
advertises these bounded tools:

```text
gdb_session       gdb_run          gdb_breakpoints
gdb_inspect       gdb_evaluate     gdb_memory
gdb_disassemble   gdb_io           gdb_batch
gdb_events
```

The initialization response also teaches the Agent the stateful workflow:
create a session, retain its `session_id`, launch a target, use the current
stop for inspection, reuse the session across attempts, and close it when
finished. Supply `stop_id` only when a later read must reject a newer stop.

## Fast exploit loop

For the shortest reliable local crash-or-exit loop:

1. Create a session and retain its `session_id`.
2. Launch at the first useful stop. Use `aslr: "disable"` for repeatable
   layout probes only, then `aslr: "preserve"` for final exploit validation.
3. Call `gdb_run` action `continue` with byte-exact `input` and its trailing LF
   when required. The default wait runs through the next stop or exit. Add
   `inspect: [{"view": "crash", "profile": "brief"}]` when stopped crash
   context is needed in the same call.
4. Use `gdb_session` action `restart` for the next attempt instead of creating
   another session. Batch deterministic commands into one PTY write.

For a counted one-shot breakpoint, use `gdb_run` action `probe` with `input`,
`ignore_count`, and bounded expression or stack captures. It inserts and
cleans up its temporary breakpoint in the same call.

The result reports bounded `output` produced during the call, plus
`settled_by: "stopped"`, one `stop_id`, and requested observations, or
`settled_by: "exited"` after normal termination. Use
`gdb_memory` action `artifact` with the returned URI and `next_offset` to page
large results without repeating the debugger read. Use
`gdb_run` action `wait` with `input` when execution is already asynchronous,
and reserve `gdb_io` for open-ended interaction. An MCP `gdb_io` read with no
`max_bytes` returns at most 4096 bytes; request a larger bound only when the
additional output is needed. Projected tools do not expose lease or revision
fields and bind omitted reads to the current stop.

Advanced targets, mutations, variable objects, tracking, and kernel operations
appear only when the server is started with `--advanced-tools`. Raw GDB access
appears only with `--raw-admin`; do not enable either flag by default.

## Security

An stdio MCP entry is a trusted local executable. Review project-provided MCP
configuration before allowing a harness to start it. GDB/AI hardens GDB startup,
but running an untrusted target still requires placing GDB/AI, GDB, and the
target together inside an external container or VM.
