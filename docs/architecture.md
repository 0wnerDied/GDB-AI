# GDB/AI architecture

GDB/AI is a Rust control plane above GNU GDB and its built-in GDB/MI
protocol. It gives Agents bounded semantic operations for dynamic debugging,
vulnerability validation, and authorized vulnerability exploitation. GDB/AI
does not define or replace GDB/MI.

The server is one Rust process with a Gateway and one Tokio session actor per
GDB child. A session actor is the only writer of MI commands and the only
owner of its reducer. GDB output is framed, parsed, journaled, normalized, and
reduced before it becomes public state. Inferior input and output use a
separate PTY data path.

## Workspace boundaries

The implementation keeps three Rust crates because these are the dependency
boundaries used by the product today:

```text
crates/
├── gdb-ai-mi/                 byte-oriented GDB/MI codec and lossless AST
├── gdb-ai-core/               domain, Gateway, sessions, policy, evidence
│   └── src/
│       ├── gateway.rs         policy and concurrency trust boundary
│       ├── gateway/
│       │   ├── operations/    canonical operation domains
│       │   └── tests.rs       Gateway boundary regressions
│       ├── session.rs         public SessionHandle and session data types
│       └── session/
│           ├── actor.rs       SessionWorker loop, control lane, MI input
│           ├── state.rs       live reduction and atomic state publication
│           └── tests.rs       session facade and wait regressions
└── gdb-ai/                    executable, CLI, MCP and JSON-RPC adapters
    └── src/
        ├── main.rs            CLI commands and local administrative client
        └── server/
            ├── mod.rs         shared MCP/JSON-RPC dispatch
            ├── stream.rs      stdio and Unix stream lifecycle
            ├── http.rs        HTTP sessions, auth, versions, cancellation
            ├── resources.rs   MCP resource and artifact URI projection
            └── tests.rs       shared protocol regressions
```

The canonical operation modules are grouped by their actual state and helper
dependencies:

```text
agent          bounded probes and Agent observations
context        stop, frame, wait, module, and source context
encoding       binary and address encoding
evaluation     safe expression evaluation
evidence       artifacts, events, and transcripts
execution      run control, breakpoints, registers, and signals
inspection     stacks, snapshots, batches, mappings, and tracking
io             inferior PTY and GDB stream operations
kernel         conditional Linux kernel provider
lifecycle      sessions and target lifecycle
memory         stop-consistent memory operations
mi             MI result normalization
raw            controlled raw MI and console operations
reconciliation managed-state reconciliation
request        request parsing and common validation
values         stop-scoped variable objects
```

These are modules below the Gateway rather than independent crates. They use
the same policy, caller control, stable-observation, and audit boundary, so a
crate split would add public interfaces without separating runtime ownership.

## Request and event flow

```text
Agent
  -> MCP stdio / Unix / Streamable HTTP / canonical JSON-RPC
  -> shared server dispatch
  -> Gateway validation, policy, caller control, and audit
  -> canonical operation
  -> SessionHandle
  -> session actor (`SessionWorker`) control or normal channel
  -> GDB/MI backend
  -> GNU GDB
```

Backend input follows a separate path:

```text
GDB stdout bytes
  -> MI framer and parser
  -> raw journal evidence
  -> normalized domain event
  -> reducer
  -> coherent public revision and bounded event publication
```

MI framing scans newly received bytes without rescanning an unfinished
record's retained prefix. It retains the complete record for lossless parsing
and applies the record-size limit before publishing it to the session actor.

The PTY reader writes target output directly into its bounded ring or
configured evidence spool. It emits coalesced high-water metadata instead of
placing bulk bytes on the MI control queue, so a slow actor or journal cannot
starve debugger state events.

## Ownership and dependency rules

- Only `SessionWorker` sends commands to one GDB process or mutates its
  authoritative reducer state.
- `SessionHandle` is the public facade. Multi-command observations hold its
  command-sequence guard and verify one `stop_id` and `execution_epoch`.
- Each session's target read/write lock admits stable readers and serializes
  normal mutations. Sessions have independent locks; preemptive control uses
  a separate short-operation mutex.
- Interrupt and close use the actor control lane; they do not wait behind a
  blocking normal operation.
- Timeout enters `CommandOutcomeUnknown`. Normal commands remain fenced until
  the late result is attributed or recovery reaches a known state.
- Canonical operations are descendants of the Gateway trust boundary. They
  can use private Gateway state, while unrelated core modules cannot bypass
  policy and scheduling.
- Transport modules only decode, route, cancel, and encode protocol messages.
  They do not construct GDB/MI commands.
- MCP resources call the same canonical Gateway operations as tools. Artifact
  base URIs return manifests; range URIs return exactly the bytes they name.
- The Gateway registry owns canonical operations; Streamable HTTP pending state
  owns only request IDs and response waiters. A waiter timeout returns a
  queryable operation ID and never detaches untracked target work.
- GDB-specific command strings and record classes remain inside the core and
  backend implementation and never enter the canonical protocol.

## State and evidence invariants

- MI result records acknowledge commands; async events advance target state.
- A running edge invalidates all prior stop-scoped frame and value handles.
- Snapshot, batch, and chunked memory success belongs to one stop and one
  execution epoch. A context change returns `STALE_CONTEXT` instead of mixed
  evidence.
- Every public response is bounded. Large content becomes a content-addressed
  artifact or a paged result with explicit continuation metadata. MCP applies
  this bound after projection, including its tool-result wrapper and recovered
  operation results; artifacts retain the originating session's ownership.
- Raw commands mark cached state dirty and return their output immediately.
  Structured operations reconcile when they need the registries. Consecutive
  raw commands and output reads do not trigger registry rebuilds.
- Raw MI and normalized events share one monotonic sequence before reducer
  application. In default `performance` mode, full-state journal checkpoints
  and operation history are coalesced at the 250 ms flush, transcript-read, and
  close boundaries. The actor reduces directly into its watched live state and
  publishes related capability and value invalidation with that transition;
  scalar inspections borrow it and returned snapshots own their data.
- A full or unwritable performance journal stops recording and publishes an
  evidence-gap limitation; it does not stop GDB or invalidate live stop handles.
  SQLite failure leaves live snapshots and operation waits available, suspends
  history writes, and retries final session metadata on close. Failed final
  writes retain a bounded in-memory terminal state. Historical state can
  lag live state and missing history is never reconstructed from current state.
- `durable` mode preserves per-revision checkpoints, calls `sync_data` at API,
  state, snapshot, periodic, and close boundaries, and fails the session when
  required evidence cannot be retained. Revised state remains staged until its
  checkpoint succeeds, then becomes visible to readers as one publication.
- Artifact sensitivity is monotonic for each ownership association. Retention
  and garbage collection preserve any content with a live owner.

## Security boundary

Gateway dispatch keeps authentication identity, ownership, policy effects,
caller control, stable-observation locks, idempotency, rate limits, and audit
ordering in one lexical boundary. Canonical sessions retain write leases and
optimistic revisions; MCP sessions use fixed caller ownership. It is intentionally
not divided into independent services. Stable reads retain their target-state
guard through the complete checked dispatch; snapshot publication occurs only
after the actor validates and atomically commits the original stop baseline.

GDB starts with initialization files, target auto-load, debuginfod, and inferior
function calls disabled by default. Launch uses GDB's standard shell startup
with each argument quoted literally across supported GDB versions. Linux
bubblewrap is disabled by default; `sandbox = "auto"` or `"required"` enables
its filesystem and network hardening. It is not a complete sandbox. Untrusted targets require
an external container or VM supervisor for PID/user namespaces, cgroups,
seccomp, and stronger isolation.

HTTP is loopback-only. Remote access must terminate TLS at a trusted same-host
proxy, use explicit authentication, and validate browser origins. Stdio and
Unix transports remain the simplest local deployment boundary.

## Non-Rust boundaries

The optional `gdb-extension/gdb_ai.py` exposes only small, trusted GDB Python
MI helpers; it never owns session truth. Python and TypeScript SDKs are client
projections of the canonical API. Benchmarks and test targets may use Python,
C, C++, or Rust, but cannot bypass Gateway or `SessionWorker` ownership.
