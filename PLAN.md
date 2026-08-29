# GDB/AI Active Release Plan

Status: North-star functional baseline qualified; production-stable v1
release gates remain open

This file tracks only unfinished release work. The completed architecture,
implementation history, compatibility matrix, Agent pilots, and full
normative specification are preserved in the
[North-star plan archive](docs/archive/north-star-plan-2026-08-29.md).

`GDB/AI` means **GDB Agent Interface**. It runs above GNU GDB and GDB/MI to
give modern Agents a stateful interface for dynamic debugging, vulnerability
validation, and authorized vulnerability exploitation. GDB/MI is GDB's
backend protocol; it is not defined by this project.

The `gdb.ai/v1` name identifies the protocol major version. It does not by
itself mean that a software release or every transport is production-stable.

## 1. Current baseline

The qualified functional baseline is commit `4195050`. Required CI run
`33225096633` covered the locked Rust workspace, Clippy, Rust 1.88, schemas,
both SDKs, bounded fuzz campaigns, GDB 9.2-17.1 across MI3 and MI4, x86-64,
AArch64 user and system targets, and Debian kernel-provider matrices. A local
10,000-cycle create/launch/stop/close soak completed without a session,
startup, parser, timeout, or consistency failure.

The latest audit examined `GDB-AI-main (1).zip`, SHA-256
`c2663adbcd2dbfa3050fad107c17fdf7910b6f792ccb5066d53d4048ed17b8c1`.
The archive has no Git metadata, so it corroborates behavior but cannot prove
its own commit identity. Release provenance must bind a signed tag, source,
binary, checksums, SBOM, and CI run.

The following control-plane invariants are implemented and must not regress:

- one SessionActor owns one GDB process and authoritative state;
- MI, GDB stderr, and inferior PTY data use separate paths;
- result records and asynchronous target events have distinct semantics;
- control requests preempt normal commands;
- deadlines include queue time and unknown outcomes fence normal work;
- `revision`, `execution_epoch`, and `stop_id` scope observations;
- running invalidates stale frame and value handles;
- typed stop reasons preserve breakpoint, watchpoint, signal, and scope data;
- probes count only stops from their own breakpoint;
- composite observations and snapshot commits cannot cross a stop or epoch;
- advertised minimal snapshots exist in storage;
- duplicate running events do not create duplicate epochs;
- reused backend thread IDs receive a new public generation; and
- invalid sessions and unknown methods return typed errors instead of panic.

The local stdio/Unix control core is near release-candidate quality. The full
HTTP/resource daemon and complete 17-tool projection remain pre-production.

## 2. Release blockers

### P0: Preserve artifact resource integrity

`artifact.get` returns bounded pages with `size`, `offset`, `next_offset`, and
`truncated`. MCP `resources/read` currently discards those fields and exposes
the first page under the full content-addressed URI. A large artifact can
therefore look complete while its remaining bytes are missing.

The resource invariant is:

> Bytes returned for a content-addressed URI must hash to that URI's digest,
> or the URI must explicitly identify the complete byte range returned.

Implement:

```text
gdbai://artifact/sha256:<digest>
    -> application/vnd.gdb-ai.artifact-manifest+json

gdbai://artifact/sha256:<digest>?offset=<n>&length=<m>
    -> a complete application/octet-stream range
```

The manifest contains digest, size, MIME type, sensitivity, page size, and a
range URI template. `artifact.get` remains the canonical paged API. SDK
helpers may stream and reassemble ranges and must verify the final SHA-256.

Required tests cover small and multi-page artifacts, exact boundaries,
invalid ranges, deleted content, owner denial, and digest-verified
reconstruction. MCP does not define a `resources/read` continuation field;
see the [resource schema](https://modelcontextprotocol.io/specification/2025-11-25/schema)
and [pagination rules](https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/pagination).

Exit condition: no partial resource is represented as the complete artifact.

### P1: Make HTTP pending cleanup operation-owned

A dropped HTTP handler can currently skip pending-entry cleanup while its
target operation continues. The operation task, not the network waiter, must
remove its pending entry on success, typed error, panic, timeout, or abort.

Each pending entry records an absolute deadline, abort handle, and explicit
cancellation policy. A sweeper removes stale bookkeeping. Deleting a
transport session applies its recorded policy to pending work. Network
disconnect, waiter cancellation, target interruption, and session closure
remain distinct operations.

Exit condition: forced client disconnect, task panic, timeout, and session
deletion all return the pending count to zero without silently cancelling the
target.

### P1: Close the HTTP Origin and confidentiality boundary

Default transport policy is:

```text
loopback HTTP                     allowed
Unix socket                       allowed
non-loopback plaintext HTTP       denied
trusted TLS reverse proxy         explicit configuration required
```

Every `/mcp` request with `Origin` must match an allowlist or return HTTP 403.
Loopback non-browser clients may omit Origin. Bearer authentication does not
make plaintext transport confidential. Forwarding headers are trusted only
from configured proxy addresses. Metrics remain authenticated and health
responses contain no sensitive state. This follows the MCP
[Streamable HTTP transport rules](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

Exit condition: invalid Origin is rejected and default configuration cannot
bind plaintext HTTP to a non-loopback address.

### P1: Declare only implemented HTTP protocol versions

HTTP currently accepts several MCP versions without retaining the negotiated
version or implementing their different transport behavior. Initially expose
Streamable HTTP only as `2025-11-25`. Validate `MCP-Protocol-Version` on later
requests and return HTTP 400 for unsupported values. Do not claim the
2024-11-05 HTTP+SSE transport until its endpoints and conformance tests exist.

Exit condition: every advertised HTTP MCP version has an independent
transport conformance test.

## 3. Evidence and data-plane closure

### 3.1 Artifact paging

`ArtifactStore::get_range` must not re-hash the full file for every page.
Compute and sync the digest at `put`, retain verified immutable metadata, and
revalidate only when metadata changes or an explicit scrub runs.

Exit condition: sequential range reads perform approximately one artifact's
worth of I/O rather than one full scan per page.

### 3.2 Inferior output evidence

Support explicit modes:

```text
ephemeral_ring   bounded live output; overwritten bytes are unrecoverable
bounded_spool    quota-limited sequential evidence with explicit gaps
artifact         finalized content-addressed output
```

Journal durable chunks with offset, length, digest, content reference, and
durability. Until true per-inferior routing exists, use the truthful resource
URI `gdbai://session/<session>/output/pty`.

PTY readers write bytes to the ring or spool first and use a coalesced,
non-blocking high-water notification. A full metadata queue must not stop PTY
draining or block the inferior.

### 3.3 Event and journal recovery

Map subscriber lag to `EVENT_GAP` with requested, earliest, and current
cursors plus a resynchronization resource. Map closure to a terminal stream
or session state rather than `INTERNAL`.

Document two journal modes:

```text
performance   ordered and batch-flushed; final host-crash batch may be lost
durable       flush and sync at operation, stop, snapshot, and close boundaries
```

Do not use “journaled” as a synonym for crash-durable.

## 4. Protocol, policy, and storage closure

### 4.1 Deterministic contracts

The shared runtime/schema contract must express exactly-one and mutual
exclusion. Both runtime validation and generated JSON Schema must reject the
same corpus, including:

- multiple breakpoint location selectors;
- nested and top-level location selectors together;
- both text and base64 input;
- expected bytes and digest together;
- multiple search-pattern encodings; and
- source line or column below one.

Prefer one canonical tagged location shape after a documented deprecation
period instead of maintaining two permanent forms.

### 4.2 Server-side range effects

The backend or provider classifies a memory range as ordinary, volatile,
MMIO, unknown, or forbidden. Client `volatile=true` is acknowledgement, not
the source of truth. Volatile and unknown reads require the corresponding
profile and explicit target-effect acknowledgement.

### 4.3 Monotonic sensitivity

Artifact sensitivity belongs to the owner/session association where possible.
Any global label may only stay equal or become more restrictive when the same
digest is registered again.

### 4.4 Bounded daemon storage

Implement global, owner, and session byte/count/age limits; closed-session
retention; pinned ownership; orphan cleanup; journal rotation; SQLite WAL
checkpointing; disk watermarks; storage verification; and dry-run plus
explicit GC commands.

Exit condition: long-running soak remains inside configured disk limits, GC
never removes content with a live owner, and hard-cap failure rejects new work
without damaging existing evidence.

## 5. Dependency-ordered gates

### G0: Auditable release identity

Create a signed tag, deterministic source archive, binary checksums, SBOM,
toolchain inventory, and CI attestation. Exclude caches, local build output,
runtime fuzz corpora, and temporary files. `gdb-ai doctor` reports build
commit, dirty state, software version, Rust version, GDB/MI version, and MCP
version.

### G1: MCP and HTTP blockers

Complete the artifact manifest/range resource, operation-owned pending
cleanup, Origin and binding policy, and truthful HTTP protocol negotiation.
This gate blocks the complete MCP/HTTP daemon, not a restricted build that
explicitly omits those surfaces.

### G2: Evidence data plane

Complete linear artifact paging, output durability modes, non-blocking PTY
notifications, truthful output URIs, typed event gaps, and declared journal
durability.

### G3: Contracts and default Agent projection

Complete exactly-one validation, server-side range-effect classification,
monotonic sensitivity, and one invalid-request corpus shared by runtime and
schema tests. Reduce the default Agent-visible projection to the core tools in
section 6; advanced canonical methods require explicit feature/profile
configuration.

### G4: Daemon storage and operations

Complete retention, quotas, owner-aware reference accounting, orphan cleanup,
WAL checkpoints, disk metrics, verification, and safe GC.

### G5: Behavior-preserving module split

Only after G1-G4 and golden replay/schema/tool-catalog tests, split one domain
per commit from `operations.rs`, `session.rs`, `main.rs`, and `gateway.rs`.
Do not combine moves with protocol, security, or concurrency changes.

### G6: Agent-effect evaluation

Repeated paired A/B/C/D evaluation is explicitly deferred and does not block
engineering correctness or the restricted RC. Before comparative product
claims, use matched model versions, prompts, permissions, budgets,
environments, tasks, and multiple seeds:

```text
A  shell plus CLI GDB
B  persistent raw GDB
C  structured core GDB/AI
D  C plus typed probe/experiment
```

Existing CTF pilots are usability cases only. Resume this gate before claiming
that structured tools or probe semantics generally improve Agent success.

### G7: Post-North-star options

Promote non-stop per-thread execution, record/replay, fuller multi-inferior
support, managed GDB handoff, LLDB, or vendor providers only when measured
demand justifies them. None blocks the Linux all-stop GDB/MI release.

## 6. Target default product surface

G3 will make these the default Agent-visible tools:

```text
gdb_session
gdb_run
gdb_breakpoints
gdb_inspect
gdb_evaluate
gdb_memory
gdb_io
```

`gdb_events` may be enabled for explicit event waiting. Disassembly remains
an inspect view or an optional projection. Other surfaces are feature-gated:

```text
extended-targets    attach, core, remote
mutation            memory, register, and signal writes
advanced-values     variable objects, tracking, and diffs
multi-client        HTTP, authentication, leases, and idempotency
experimental-agent  probe, hypothesis, and experiment
kernel              kernel inspection and monitor
raw-admin           raw MI and controlled CLI
```

G3 hides and deprecates the `agent.experiment` probe alias,
`inferior_io.close_stdin` duplicate, and thin `agent.hypothesis_check` from
the default projection. A future experiment needs distinct setup, execution,
capture, verdict, cleanup, and budget semantics.

## 7. Release claims and definition of done

Current acceptable claims are:

- GDB/AI is a stateful Agent Interface above GDB and GDB/MI;
- the qualified core separates MI control from inferior I/O;
- asynchronous state, stop-scoped context, and composite observations are
  bounded and consistency checked;
- probes attribute their own breakpoint stops; and
- exact compatibility, kernel, chaos, fuzz, and soak evidence exists for the
  named functional baseline.

Do not yet claim that the complete HTTP/resource daemon is
production-stable, every tool belongs in the default Agent prompt, all PTY
evidence is durably replayable, or structured/probe interfaces generally
increase Agent success.

Production-stable v1 requires one signed tag with:

- no silently truncated artifact resource;
- no leaked HTTP pending work or transport session;
- compliant Origin, confidentiality/proxy, and protocol-version handling;
- deterministic rejection of ambiguous requests;
- explicit PTY and journal durability;
- bounded storage with safe GC;
- green locked workspace, Clippy, MSRV, SDK, schema, fuzz, GDB, AArch64,
  kernel, chaos, and soak gates; and
- verifiable source, binary, SBOM, checksum, and CI provenance.

Documentation-only commits require focused link, formatting, and consistency
checks; they do not wait for the full runtime CI matrix. Code and release
changes retain exact-commit verification appropriate to their risk.

When a gate is complete, preserve its design and evidence in a dated archive
and remove it from this active file. Do not delete historical requirements or
rewrite archived results.
