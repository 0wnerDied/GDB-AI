# GDB/AI Architecture

The server is one Rust process with a Gateway and one Tokio session actor per
GDB child. The actor is the only writer of MI commands and the only owner of
the reducer. GDB output is framed, parsed, journaled, normalized, and reduced
before it becomes public state. Inferior input and output use a separate PTY.
The PTY reader writes directly to its bounded ring and emits coalesced
high-water notifications, so a slow actor cannot stop target-output draining.

The production boundary is `Agent -> MCP/JSON-RPC -> Gateway -> SessionWorker
-> DebugBackend -> GDB`. The current backend is GDB/MI; its command strings and
record classes do not appear in the canonical API.

Linux sessions use bubblewrap when available for a read-only host mount, a
writable session directory, optional network namespace, `no_new_privs`, and
rlimits. These are defense-in-depth controls, not a complete sandbox. Untrusted
targets require a deployment supervisor that supplies PID/user namespaces,
cgroups, seccomp, or a VM boundary.
