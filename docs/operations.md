# Operations

Run `gdb-ai doctor` before serving. Use stdio for one local MCP client, a Unix
socket for multiple local clients, or loopback HTTP behind a same-host TLS
reverse proxy. HTTP never binds directly to a non-loopback address.

Every session returns an expiring write lease. Renew it with
`session.acquire_write_lease`; expiration never interrupts a running target.
An HTTP waiter timeout returns `operation_id` in the error data. Query it with
`gdb_session` action `operation_status`; the returned canonical record contains
the eventual response or an explicit `OUTCOME_UNKNOWN` state. A waiter timeout
never means the operation stopped or the inferior exited.

MCP cancellation defaults to `cancel_mode: "detach_waiter"`: it stops the
client wait while the accepted debugger operation finishes in the background.
Use `interrupt_target` or `close_session` on a tool request when cancellation
must enter the session actor (`SessionWorker`) control lane; both require
`session_id` and `lease_id`.

Dropping a Streamable HTTP connection does not imply MCP cancellation. The
Gateway owns the accepted canonical operation until a recorded outcome, while
HTTP owns only the response waiter and pending request key. The result remains
queryable after that waiter disconnects or expires. Only an explicit
cancellation notification or transport-session DELETE applies the request's
`cancel_mode`.

Journals are stored per session. Use `gdb-ai transcript inspect`, `transcript
export`, and `replay` for diagnosis without executing the inferior again.
Replay rejects gaps and mismatches among raw MI, adjacent normalized events,
and recorded reducer state checkpoints. MI-only transcripts have no checkpoint
integrity guarantee and reconstruct only MI-derived controller state.

Artifact storage has per-session, per-owner, and daemon-wide byte limits. Use
`gdb-ai storage status` for metadata and filesystem inventory, `storage verify`
for SQLite and full content-digest verification, and `storage gc` for a safe
dry-run. `storage gc --execute` removes only valid digest files absent from the
database and session artifacts with no remaining owner, then checkpoints the
SQLite WAL. Stop the daemon first; the shared lock rejects maintenance while
the data directory is live.

Historical sessions are retained for at most `storage.max_closed_sessions`
and `storage.closed_session_retention_ms`. A session not owned by the current
daemon process is historical, including state left by a previous crash.
Retention runs at daemon startup and session create/close boundaries; it
removes the exact session directory, stop-scoped rows, leases, operations, and
artifact ownership. Shared content remains until its final owner expires.

Live SQLite histories are bounded at their shared writers. Audit request and
result rows obey `storage.max_audit_rows` and `storage.audit_retention_ms`;
snapshots and operations obey their per-session limits. `storage status`
reports current audit row counts alongside artifact and session inventory.

`storage status` also reports hard-cap watermarks, `storage verify` reports
the number of artifacts checked, and executed GC reports reclaimed artifact
bytes. HTTP metrics include pending requests, artifact usage and verification
cache activity, finalized PTY spool bytes, and event gaps.
