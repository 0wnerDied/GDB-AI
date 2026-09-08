# Canonical Protocol

The current major namespace is `gdb.ai/v1`. Protocol compatibility and
release qualification are separate: the schema follows the version-1
compatibility rules, while [`compatibility.md`](compatibility.md) records
which target matrices have actually run. Requests carry a request ID,
optional session ID, method, expected revision, idempotency key, and
parameters. Mutations require the current revision and write lease.
Stop-sensitive canonical reads require the current `stop_id` or an explicit
`accept_current_stop` binding.
MCP-created sessions use fixed caller control without write-lease renewal.
Projected tools omit canonical revision and lease fields. An omitted projected
`stop_id` binds the current stop; a supplied ID remains a stale-stop pin.

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

MCP discovery defaults to eleven bounded tools for ordinary Agent debugging,
including same-stop inspection batching. Starting the server with
`--advanced-tools` exposes the existing advanced target, mutation, value,
tracking, and kernel projections; `--raw-admin` independently exposes the
audited raw escape hatch. Hidden MCP projections do not remove methods from
the canonical API.

Projected mapping records retain start and end addresses, file offset,
permissions, and path. Filesystem device, inode, and provider-source metadata
remain available through the canonical API.

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
non-blocking. Canonical execution control without a wait is accepted
immediately; projected `gdb_run` control waits until settled by default.
Execution control and wait requests may include one bounded byte-exact `input`
and bounded `inspect` views. Input is fed before the wait, and the result
reports only a partial write or error; success adds no redundant input echo. A
stopped result returns views from that same stop; an exited result returns no
observations. Run/wait `inspect`, `inspection.batch.requests`, and
`inspection.snapshot.inspect` use the same item contract. Each turn accepts
1–16 uniquely named items (`name` defaults to `view`), at most 16 total
expressions, and at most `limits.memory_read_bytes` total bytes across
explicit memory reads. The whole plan is validated before run control or
input delivery.

Alongside existing inspection views, items accept `view: "evaluate"` with
`expression` or `expressions`, `view: "memory"` with `address` or
`address_expression` plus `length`, and `view: "disassembly"` with the normal
`around` or `range` selectors. Applicable thread, frame, source, paging, and
format selectors are shared across these entry points. Expressions remain
read-only; resolved memory ranges retain the session profile's access policy.
`view: "tracked"` samples configured tracking definitions and returns both
their current values and changes from the preceding sample, advancing the
existing bounded tracking history. `view: "diff"` accepts
`before_snapshot_id` and `after_snapshot_id` and compares retained facts;
its result is explicitly historical and preserves both observation IDs.

Composite results include `observation_context` with the captured stop,
execution epoch, revision, and available inferior/thread/frame identity.
This is the default stopped focus. Results retain explicit per-item context
overrides in `selection`, and single-expression results include `expression`.
Batch results contain `results`, keyed `failures`, and `complete`; run results
use `observations`, `observation_failures`, and `observation_complete`.
Independent read failures keep successful siblings. A changed stop/epoch,
cancellation, or deadline invalidates the composite observation instead of
returning mixed evidence. Register-name metadata and identical eligible
metadata/register views are reused only within that fenced turn; live
expressions, memory, and disassembly are not memoized.

Completed and partially successful captures have an immutable
`observation_id`, also accepted as `snapshot_id` by
`inspection.snapshot_get` (MCP `gdb_inspect` view `observation`). A lookup
returns the stored capture with `historical: true`, without issuing GDB
commands or waiting behind target execution. Stop IDs do not establish
freshness: memory may change without a resume. Lookup rechecks ownership and
remains available for retained evidence after resume or close, subject to
`storage.max_snapshots_per_session` and session retention. It never refreshes
the original capture or revalidates historical frame/value handles.

`session.create` and `session.get` expose the exact `caller_identity` and
current `controller` (null for a closed session). `session.handoff` accepts
`to`, requires the current controller and normal mutation preconditions, and
transfers fixed MCP control only within the authenticated owner principal.
Its result returns the new `controller` and coordination `generation`.
The former controller keeps observation access but loses mutation authority.

Variable-object `value.children` returns semantic `children` and paging
metadata; `value.update` returns semantic `changes`, including availability
and type changes. Debugger values remain strings, or lossless binary objects,
not floating-point JSON conversions. Canonical v1 results retain the legacy
MI reply for compatibility; projected tools expose the semantic collections.

Streamable HTTP supports two version-specific request paths over the same
endpoint and canonical dispatcher. MCP `2025-11-25` stores the negotiated
version in a transport session and requires it in
`Mcp-Protocol-Version` on every later POST or DELETE. Stateless MCP
`2026-07-28` needs neither initialization nor `Mcp-Session-Id`. Sessionless
HTTP requests default to that protocol; callers may explicitly carry
`io.modelcontextprotocol/protocolVersion` and
`io.modelcontextprotocol/clientCapabilities` under `_meta`. Stateless results
include `resultType`, and discovery results carry private cache hints. POST
requests advertise `application/json` and `text/event-stream`; responses use
JSON, while GET returns HTTP 405 because the server does not open an optional
SSE stream. Older message versions remain limited to tested stdio/Unix
compatibility; GDB/AI does not advertise the legacy HTTP+SSE transport.

Stateful clients select a coordination label with `initialize.clientInfo.name`.
Stateless clients may send `_meta["gdb-ai.dev/clientName"]` on each request;
omission preserves the existing transport identity. Labels contain 1–128
UTF-8 bytes and never change the authenticated principal or administrative
authority. They are cooperative controller labels, not tenant isolation.

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
`text` for UTF-8 without control characters other than tab and line endings,
or `data_base64` otherwise. This avoids both JSON control-byte expansion and
charging an Agent for the same evidence twice. MCP session resource ranges use
`text` for UTF-8 and a base64 `blob` for binary bytes, never both.
Projected successful tools leave MCP text content empty because the structured
result is authoritative. Their compact current state omits healthy/active
defaults, null frame fields, and a complete ready snapshot that repeats the
same `stop_id`; abnormal values remain explicit.
The inferior PTY starts in raw mode, so `data_base64` input reaches the target
without terminal flow-control, signal, newline, or echo transformations.
`inferior_io.write` also accepts ordered `steps`; an optional `wait_for`
substring gates each step's exact text or binary payload on PTY output produced
after the transaction begins. The timeout bounds the whole sequence, which
prevents broad target reads from consuming answers intended for later prompts.
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

The conditional `kernel.inspect` contract accepts `bootstrap`, `symbols`,
`page_table`, `capabilities`, `version`, `base`, `current_task`, `init_task`,
`tasks`, `modules`, `dmesg`, `stack`, and `panic`. The `page_table` view
requires an `address_expression`.
`kernel.monitor` remains an audited mutation restricted by the configured
first-word allowlist. These contracts are generated into both the canonical
schema and the `gdb_kernel` MCP projection; they are not GDB/MI extensions.
