# GDB/MI Architecture

The server is one Rust process with a Gateway and one Tokio session actor per
GDB child. The actor is the only writer of MI commands and the only owner of
the reducer. GDB output is framed, parsed, journaled, normalized, and reduced
before it becomes public state. Inferior input and output use a separate PTY.

The production boundary is `Agent -> MCP/JSON-RPC -> Gateway -> SessionWorker
-> DebugBackend -> GDB`. The current backend is GDB/MI; its command strings and
record classes do not appear in the canonical API.

Linux sessions use bubblewrap when available, a read-only host mount, a
writable session directory, optional network namespace, `no_new_privs`, and
rlimits. Capability output states exactly which controls were applied.
