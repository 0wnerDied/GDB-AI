# Canonical Protocol

The current major namespace is `gdb.ai/v1`. Protocol compatibility and
release qualification are separate: the schema follows the version-1
compatibility rules, while [`compatibility.md`](compatibility.md) records
which target matrices have actually run. Requests carry a request ID,
optional session ID, method, expected revision, idempotency key, and
parameters. Mutations require the current revision and write lease.
Stop-sensitive reads require the current `stop_id`.

Schema files and hashes live in [`../schemas`](../schemas). MCP is a compact
projection over the same methods; `gdb.ai/call` exposes the canonical envelope
without translating it into a tool action. Rust method contracts validate
allowed, required, and typed parameters and generate both the canonical JSON
Schema branches and MCP tool input schemas.

MCP discovery defaults to nine bounded tools for ordinary Agent debugging.
Starting the server with `--advanced-tools` exposes the existing advanced
target, mutation, value, tracking, batch, probe, and kernel projections;
`--raw-admin` independently exposes the audited raw escape hatch. Hidden MCP
projections do not remove methods from the canonical API.

Stdio and Unix stream clients may attach `_meta.progressToken` to a request.
GDB/AI emits ordered `notifications/progress` records before and after the
operation while continuing to accept cancellation and I/O requests.
Canonical operations expose `operation.get` through `gdb_session` action
`operation_status`. Actor-scoped target cancellation uses `operation.cancel`;
waiter detachment and target control are distinct operations.

Streamable HTTP supports MCP `2025-11-25`. The negotiated version is stored in
the transport session and is required in `Mcp-Protocol-Version` on every later
POST or DELETE. Older message versions remain limited to tested stdio/Unix
compatibility; GDB/AI does not advertise the legacy HTTP+SSE transport.

Large results return `gdbai://artifact/sha256:...`. Artifact reads re-check
session ownership; the URI itself is not authorization. `artifact.get` uses
`offset` and `max_bytes` and reports `next_offset` plus `truncated` so binary
evidence never exceeds the response envelope. MCP `resources/read` returns a
JSON manifest for the base artifact URI. Clients read complete bounded pages
through `?offset=<n>&length=<m>` range URIs and verify the reconstructed
SHA-256; a partial page is never labeled as the complete digest resource.

Inferior PTY bytes currently share one session-scoped ring and are exposed as
`gdbai://session/<session_id>/output/pty`. GDB/AI does not claim per-inferior
output attribution until the backend can provide genuinely separate streams.
The `output.evidence` setting selects an `ephemeral_ring`, a retained
`bounded_spool`, or an `artifact` finalized when the session closes. I/O reads
and close responses report captured, spooled, dropped, completeness, digest,
and durability metadata; output capture never backpressures the inferior.

Successful responses retain the method-specific `result` and also promote
`warnings`, `truncated`, `continuation`, and artifact references into the
canonical response envelope. Clients can therefore handle pagination and
bounded-output metadata without knowing each result's internal shape.

Canonical selector and binary-input shapes are deterministic: breakpoint
locations, expected memory, search patterns, memory writes, and PTY writes
accept exactly one supported representation. Source line numbers start at 1.

`events.wait` reports `EVENT_GAP` with the requested cursor, dropped event
count, current resumption cursor, and a status resource for resynchronization.
`STREAM_CLOSED` instead means the session event source has terminated.

The conditional `kernel.inspect` contract accepts `capabilities`, `version`,
`base`, `current_task`, `init_task`, `tasks`, `modules`, `stack`, and `panic`.
`kernel.monitor` remains an audited mutation restricted by the configured
first-word allowlist. These contracts are generated into both the canonical
schema and the `gdb_kernel` MCP projection; they are not GDB/MI extensions.
