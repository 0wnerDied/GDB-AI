# Operations

Run `gdb-ai doctor` before serving. Use stdio for one local MCP client, a Unix
socket for multiple local clients, or authenticated HTTP for remote adapters.

Every session returns an expiring write lease. Renew it with
`session.acquire_write_lease`; expiration never interrupts a running target.
On timeout, inspect the returned operation and choose wait, interrupt, or
close. A timeout never means the inferior exited.

Journals are stored per session. Use `gdb-ai transcript inspect`, `transcript
export`, and `replay` for diagnosis without executing the inferior again.
