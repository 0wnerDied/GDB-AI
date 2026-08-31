# Canonical Protocol

The current major namespace is `gdb.ai/v1`. Protocol compatibility and
release qualification are separate: the schema follows the version-1
compatibility rules, while [`compatibility.md`](compatibility.md) records
which target matrices have actually run. Requests carry a request ID,
optional session ID, method, expected revision, idempotency key, and
parameters. Mutations require the current revision and write lease.
Stop-sensitive reads require the current `stop_id`.

Session recovery authority is separate from a business write lease. The owner
or an administrator may call `session.attempt_recovery` or
`session.force_abort` after lease expiry or consistency loss. Forced abort
returns `clean_shutdown=false`; it is a resource cleanup guarantee, not a
claim that GDB detached cleanly from the target.

Schema files and hashes live in [`../schemas`](../schemas). MCP is a compact
projection over the same methods; `gdb.ai/call` exposes the canonical envelope
without translating it into a tool action. Rust method contracts validate
allowed, required, and typed parameters and generate both the canonical JSON
Schema branches and MCP tool input schemas. MCP itself remains UTF-8 JSON-RPC;
large binary evidence uses bounded artifact resources instead of embedding a
second wire format inside tool calls.

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

Wait objects accept `accepted`, `running`, `stopped`, `settled`, `snapshot`,
and `exited`. `settled` completes at the first attributable stop or terminal
inferior state and reports that branch in `settled_by`. An omitted launch or
restart wait observes `running` for `stop: "none"`, and the selected stop plus
its snapshot for other start policies; an explicit `accepted` remains
non-blocking. Execution control without a wait is also accepted immediately.

Streamable HTTP supports two version-specific request paths over the same
endpoint and canonical dispatcher. MCP `2025-11-25` stores the negotiated
version in a transport session and requires it in
`Mcp-Protocol-Version` on every later POST or DELETE. Stateless MCP
`2026-07-28` needs neither initialization nor `Mcp-Session-Id`; each request
instead carries `io.modelcontextprotocol/protocolVersion` and
`io.modelcontextprotocol/clientCapabilities` under `_meta`. Stateless results
include `resultType`, and discovery results carry private cache hints. POST
requests advertise `application/json` and `text/event-stream`; responses use
JSON, while GET returns HTTP 405 because the server does not open an optional
SSE stream. Older message versions remain limited to tested stdio/Unix
compatibility; GDB/AI does not advertise the legacy HTTP+SSE transport.

Large results return `gdbai://artifact/sha256:...`. Artifact reads re-check
session ownership; the URI itself is not authorization. `artifact.get` uses
`offset` and `max_bytes` and reports `next_offset` plus `truncated` so binary
evidence never exceeds the response envelope. MCP `resources/read` returns a
JSON manifest for the base artifact URI. Clients read complete bounded pages
through `?offset=<n>&length=<m>` range URIs and verify the reconstructed
SHA-256; a partial page is never labeled as the complete digest resource.
Digest paths become visible only after complete content is synchronized and
atomically published, so concurrent writers cannot expose a partial artifact.

Inferior PTY bytes currently share one session-scoped ring and are exposed as
`gdbai://session/<session_id>/output/pty`. GDB/AI does not claim per-inferior
output attribution until the backend can provide genuinely separate streams.
The base PTY and transcript resource URIs return current-bound manifests;
`?offset=<n>&length=<m>` returns that exact bounded range or fails if the bytes
are unavailable. A resource page therefore never inherits an ambiguous base
URI.
Canonical I/O and transcript reads return exactly one lossless representation:
`text` for valid UTF-8 or `data_base64` for binary bytes. This avoids charging
an Agent context for the same evidence twice. MCP session resource ranges use
`text` for UTF-8 and a base64 `blob` for binary bytes, never both.
The inferior PTY starts in raw mode, so `data_base64` input reaches the target
without terminal flow-control, signal, newline, or echo transformations.
`send_eof` requires a stopped inferior, switches to canonical mode, and queues
an EOF boundary for resume. A later ordinary write restores raw mode.
The `output.evidence` setting selects an `ephemeral_ring`, a retained
`bounded_spool`, or an `artifact` finalized when the session closes. I/O reads
and close responses report captured, spooled, dropped, completeness, digest,
and durability metadata; output capture never backpressures the inferior.

Successful responses retain the method-specific `result` and also promote
`warnings`, `truncated`, `continuation`, and artifact references into the
canonical response envelope. Clients can therefore handle pagination and
bounded-output metadata without knowing each result's internal shape.
The `mappings` inspection applies `offset` and `limit` while parsing and
returns the next offset in `continuation` only when more mappings remain.

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
