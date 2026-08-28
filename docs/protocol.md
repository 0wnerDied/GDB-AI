# Canonical Protocol

The stable namespace is `gdb.ai/v1`. Requests carry a request ID, optional
session ID, method, expected revision, idempotency key, and parameters.
Mutations require the current revision and write lease. Stop-sensitive reads
require the current `stop_id`.

Schema files and hashes live in [`../schemas`](../schemas). MCP is a compact
projection over the same methods; `gdb.ai/call` exposes the canonical envelope
without translating it into a tool action. Rust method contracts validate
allowed, required, and typed parameters and generate both the canonical JSON
Schema branches and MCP tool input schemas.

Large results return `gdbai://artifact/sha256:...`. Artifact reads re-check
session ownership; the URI itself is not authorization. `artifact.get` uses
`offset` and `max_bytes` and reports `next_offset` plus `truncated` so binary
evidence never exceeds the response envelope.
