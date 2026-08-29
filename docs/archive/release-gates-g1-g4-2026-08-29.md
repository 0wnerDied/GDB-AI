# GDB/AI release gates G1-G4 archive

Archived: 2026-08-29

Implementation baseline: `eca9806`

This document preserves the completed post-audit release work. `GDB/AI`
means GDB Agent Interface. GNU GDB supplies GDB/MI; this project builds a
stateful Agent interface above it.

The earlier qualified functional baseline remains `4195050`, with required
CI run `33225096633`. G1-G4 were verified on their final source tree with 88
core unit tests, 15 server unit tests, formatting checks, and workspace
Clippy with warnings denied. This evidence is bound to the named baselines;
later release-owner distribution work is outside this archive.

## G1: MCP and HTTP release blockers

Status: complete.

### Artifact resource integrity

The base content-addressed URI now returns an artifact manifest. Exact range
URIs contain both offset and length and return only when the complete named
range is available. Canonical `artifact.get` remains the paged API.

Preserved invariant:

> A content-addressed resource is either complete, or its URI identifies the
> exact complete range returned.

Evidence includes small and multi-page manifests, exact boundaries, malformed
and out-of-range requests, and reconstruction metadata.

Implementation: `ebc3cac` (`mcp: Preserve artifact resource integrity`).

### HTTP pending ownership

Accepted operations own pending-entry cleanup. Handler disconnect, task
completion, panic, timeout, explicit cancellation, and transport-session
deletion no longer rely on the network waiter to remove bookkeeping.

Network disconnect still does not silently mean target interruption.

Implementation: `5193f76` (`http: Make pending cleanup operation-owned`).

### HTTP origin and binding boundary

HTTP binds only to loopback. Present browser Origins must match the explicit
allowlist. Remote exposure requires a trusted same-host TLS reverse proxy;
bearer authentication is not treated as transport confidentiality.

Implementation: `ee70bc7` (`http: Enforce the loopback Origin boundary`).

### HTTP MCP version

Streamable HTTP advertises only MCP `2025-11-25`. The negotiated value is
stored with the transport session and required on subsequent POST and DELETE
requests. Unsupported or mismatched versions fail with HTTP 400. Legacy
HTTP+SSE is not claimed.

Implementation: `197bc0b` (`mcp: Bind HTTP sessions to the negotiated
version`).

## G2: Evidence and output data plane

Status: complete.

### Linear artifact paging

Artifact ranges reuse a verified file fingerprint. The complete digest is
recomputed only after file identity or metadata changes, or during explicit
verification. Sequential pages no longer rehash the entire file per page.

Implementation: `b645f7a` (`artifacts: Reuse verified range reads`).

### Truthful PTY resources and durable modes

The public PTY resource is session scoped:

```text
gdbai://session/<session>/output/pty
```

GDB/AI does not claim per-inferior attribution while one session PTY is used.
Output evidence has explicit `ephemeral_ring`, `bounded_spool`, and `artifact`
modes. Bounded capture never backpressures the target; dropped bytes and final
durability are explicit.

Implementations:

- `65f73e9` (`mcp: Describe PTY output at session scope`)
- `06bdc71` (`pty: Preserve bounded inferior output evidence`)

### Nonblocking PTY notification

The PTY reader writes bytes before issuing a one-slot, coalesced high-water
notification. A full metadata channel no longer stops PTY draining.

Implementation: `d94b882` (`pty: Coalesce output notifications without
backpressure`).

### Event resynchronization

Subscriber lag returns `EVENT_GAP` with cursor and resynchronization metadata.
Closure returns `STREAM_CLOSED`; neither condition is collapsed into a generic
internal error.

Implementation: `64a1693` (`events: Distinguish gaps from closed streams`).

### Journal durability

`performance` mode preserves ordering and batched flushes. `durable` mode also
calls `sync_data` at declared API, state, snapshot, periodic, and close
boundaries. Documentation no longer equates process ordering with host-crash
durability.

Implementation: `22763c8` (`journal: Make crash durability explicit`).

## G3: Deterministic policy and Agent projection

Status: complete.

### Deterministic contracts

Runtime validation and generated JSON Schema reject ambiguous breakpoint
locations, binary inputs, expected-memory forms, search patterns, and invalid
source positions. Unknown methods use fallible conversion.

Implementation: `b116ac9` (`protocol: Reject ambiguous request
representations`).

### Server-owned memory effect classification

The Gateway classifies local ordinary mappings, device mappings, remote
targets, core targets, and unknown ranges. Caller acknowledgement cannot turn
an unknown or volatile range into an ordinary read.

Implementation: `b729dda` (`memory: Classify target read effects on the
server`).

### Monotonic artifact sensitivity

A shared digest's global sensitivity can remain equal or become more
restrictive, never less. Every session owner remains independently recorded.

Implementation: `9c3384f` (`artifacts: Prevent sensitivity downgrades`).

### Default Agent surface

MCP discovery now exposes nine bounded tools by default. Advanced targets,
mutations, values, tracking, probe, kernel operations, and aliases require
`--advanced-tools`; raw access independently requires `--raw-admin`.

The canonical API remains available and versioned separately from the default
Agent projection.

Implementation: `5943d2c` (`mcp: Reduce the default Agent tool surface`).

## G4: Bounded daemon storage and operations

Status: complete.

### Quotas and ownership

Artifact registration reserves capacity in the serialized SQLite metadata
transaction before content is written. Limits exist per session, per owner,
and daemon wide. A digest is charged once at each applicable ownership scope.
Unknown session ownership fails closed.

Implementations:

- `7c466d8` (`storage: Enforce a global artifact quota`)
- `99c9418` (`storage: Enforce artifact quotas per owner`)

### Verification and safe GC

`storage status`, `storage verify`, dry-run `storage gc`, and explicit
`storage gc --execute` share a nonblocking data-directory lock with the
daemon. GC removes only validated untracked files or metadata entries with no
owner, preserves global and shared content, and checkpoints SQLite.

Implementation: `d0596d4` (`storage: Add safe artifact maintenance
commands`).

### Session and SQLite retention

Historical sessions are bounded by age and count. Cleanup excludes sessions
live in the current daemon, validates exact session directories, removes all
session-scoped metadata, and releases artifact content only after the final
owner expires.

Live histories are also bounded: audit rows by age and count, and snapshots
and operations by per-session count. Journals and PTY spools already have
per-session byte caps.

Implementations:

- `3e964e0` (`storage: Bound retained session history`)
- `fd866d5` (`storage: Bound persistent event histories`)

### Operational evidence

Prometheus output reports HTTP pending requests, PTY spool bytes, event gaps,
artifact verification-cache activity, and current artifact usage against the
hard limit. Storage commands report configured watermarks, verified artifact
counts, and reclaimed artifact bytes.

Implementation: `eca9806` (`metrics: Expose storage and evidence pressure`).

## Preserved boundaries

G1-G4 completion does not create release provenance. Signed tags,
deterministic source archives, binary checksums, SBOM, and CI attestation are
release-owner distribution concerns, not an additional project gate.
Behavior-preserving module decomposition was subsequently completed as G5.
Repeated paired Agent A/B/C/D evaluation remains explicitly deferred and is
required only before comparative Agent-effect claims.
