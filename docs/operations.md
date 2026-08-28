# Operations

Run `gdb-ai doctor` before serving. Use stdio for one local MCP client, a Unix
socket for multiple local clients, or authenticated HTTP for remote adapters.

Every session returns an expiring write lease. Renew it with
`session.acquire_write_lease`; expiration never interrupts a running target.
On timeout, inspect the returned operation and choose wait, interrupt, or
close. A timeout never means the inferior exited.

MCP cancellation defaults to `cancel_mode: "detach_waiter"`: it stops the
client wait while the accepted debugger operation finishes in the background.
Use `interrupt_target` or `close_session` on a tool request when cancellation
must enter the SessionActor control lane; both require `session_id` and
`lease_id`.

Journals are stored per session. Use `gdb-ai transcript inspect`, `transcript
export`, and `replay` for diagnosis without executing the inferior again.
Replay rejects gaps and mismatches among raw MI, adjacent normalized events,
and recorded reducer state checkpoints. MI-only transcripts have no checkpoint
integrity guarantee and reconstruct only MI-derived controller state.
