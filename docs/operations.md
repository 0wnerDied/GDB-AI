# Operations

Run `gdb-ai doctor` before serving. Use stdio for one local MCP client, a Unix
socket for multiple local clients, or loopback HTTP behind a same-host TLS
reverse proxy. HTTP never binds directly to a non-loopback address.

Every session returns an expiring write lease. Renew it with
`session.acquire_write_lease`; expiration never interrupts a running target.
On timeout, inspect the returned operation and choose wait, interrupt, or
close. A timeout never means the inferior exited.

MCP cancellation defaults to `cancel_mode: "detach_waiter"`: it stops the
client wait while the accepted debugger operation finishes in the background.
Use `interrupt_target` or `close_session` on a tool request when cancellation
must enter the SessionActor control lane; both require `session_id` and
`lease_id`.

Dropping a Streamable HTTP connection does not imply MCP cancellation. The
accepted operation continues to its deadline, owns removal of its pending
entry, and discards its response if the network waiter is gone. Only an
explicit cancellation notification or transport-session DELETE applies the
request's `cancel_mode`.

Journals are stored per session. Use `gdb-ai transcript inspect`, `transcript
export`, and `replay` for diagnosis without executing the inferior again.
Replay rejects gaps and mismatches among raw MI, adjacent normalized events,
and recorded reducer state checkpoints. MI-only transcripts have no checkpoint
integrity guarantee and reconstruct only MI-derived controller state.
