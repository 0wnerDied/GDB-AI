# GDB/AI release-hardening R0-R6 archive

Status: superseded on 2026-08-30.

This historical plan recorded the work that followed the North-star G1-G5
implementation. Operation ownership, scoped cancellation, recovery authority,
atomic artifact publication, version-specific MCP request paths, and release
qualification are now implemented. The checklist below is retained as design
history, not as an active product or release claim.

Two original aspirations were deliberately not treated as completed version-1
requirements. Published canonical aliases remain available for version-1
compatibility, and repository release tags are annotated rather than
cryptographically signed.

The remaining sections preserve the original checklist, including its future
tense and exit conditions.

`GDB/AI` means **GDB Agent Interface**. It runs above GNU GDB and native
GDB/MI to give modern Agents a stateful interface for dynamic debugging,
vulnerability validation, and authorized vulnerability exploitation.

Completed plans and their evidence are archived in:

- [North-star architecture](north-star-plan-2026-08-29.md);
- [release gates G1-G4](release-gates-g1-g4-2026-08-29.md); and
- [behavior-preserving refactor G5](behavior-preserving-refactor-g5-2026-08-29.md).

The `gdb.ai/v1` namespace identifies the protocol major version. It does not
by itself claim that a software release has passed the gates below.

## 1. Release-hardening scope

The remaining release work has four runtime priorities:

- keep accepted operations traceable after transport timeout or disconnect;
- bind cancellation to the operation and execution generation it may affect;
- preserve owner and administrator cleanup paths after lease expiry or state
  loss; and
- publish content-addressed artifacts atomically under concurrency and crash.

Release qualification then binds an exact tag, required CI run, source
archive, binaries, checksums, and SBOM. New debugger targets, backends,
providers, and Agent abstractions remain outside this hardening phase.

## 2. R0: Freeze the release surface

- Keep the default nine-tool catalog fixed:
  `gdb_session`, `gdb_run`, `gdb_breakpoints`, `gdb_inspect`,
  `gdb_evaluate`, `gdb_memory`, `gdb_disassemble`, `gdb_io`, and
  `gdb_events`.
- Keep mutation, advanced values, probe, kernel, and raw administration behind
  their existing explicit switches.
- Add no target, backend, provider, or transport version during R1-R5.
- Track the exact release matrix in one machine-readable qualification file;
  generated documentation must distinguish configured and passed lanes.
- Mark `agent.experiment` and `inferior_io.close_stdin` for removal at R6;
  keep `agent.hypothesis_check` experimental and outside the default catalog.

Exit condition: the default surface and v1 candidate method set stop growing,
and every compatibility claim names an exact source and test baseline.

## 3. R1: Establish canonical operation ownership

Reuse the existing `OperationId`, operation persistence, Gateway admission,
and session control lane. Extend them only where transport requests currently
lose ownership.

- Give every accepted canonical API operation a record with its
  caller, session, method, effect, admission state, deadline, captured cleanup
  authority, and result.
- Separate an HTTP waiter from the operation it observes. A waiter timeout or
  disconnect must not erase the operation or claim that an issued GDB command
  was cancelled.
- Add operation lookup/result paths for work that outlives a waiter.
- Bind cancellation to an operation ID and admitted resume generation. The
  session actor may interrupt only while that operation still owns the current
  execution state.
- Return typed stale/already-completed results instead of converting late
  cancellation into a generic interrupt or close.
- Keep pure-read cooperative cancellation small; never pretend dropping a
  Rust future reverses an already-issued target mutation.

Exit condition: every accepted operation reaches a recorded terminal or
outcome-unknown state; HTTP timeout, handler drop, panic, cancellation, and
transport deletion leak neither waiters nor untracked target work.

## 4. R2: Separate cleanup and recovery authority

- Keep normal business mutations protected by revision and active write lease.
- Let a session owner or administrator terminate resources through
  `session.force_abort` without a business lease; report
  `clean_shutdown=false` and audit the action.
- Permit lease acquisition or renewal while an outcome is unknown or
  consistency is lost.
- Let owner/admin recovery authority invoke `session.attempt_recovery`
  independently of a stale business lease.
- Capture operation cleanup authority at admission so later lease expiry does
  not prevent cleanup of that operation.
- Preserve a reachable owner/admin termination path in every session state.

Exit condition: no expired lease, unknown result, failed worker, or lost
consistency state can strand GDB, inferior, or session resources.

## 5. R3: Publish artifacts atomically and bound evidence I/O

- Write an artifact to a same-directory private temporary file, hash and sync
  it, publish it without replacing an existing digest, verify an existing
  winner, sync the parent directory, and remove the temporary file.
- Recover stale temporary files and published files whose metadata transaction
  did not complete; report metadata that references missing bytes as
  corruption.
- Move complete artifact verification, long transcript scans, and output spool
  finalization off Tokio/session actor critical paths.
- Stream spool ingestion instead of reading an operator-sized spool fully in
  the actor.
- Give transcript and PTY resources exact range URIs; a returned resource must
  correspond exactly to its URI.
- Normalize artifact digest URIs to lowercase.

Exit condition: concurrent same-content writers and injected crashes cannot
expose a partial final digest path; sequential paging remains linear; large
evidence work does not block session control.

## 6. R4: Keep MCP versions inside transport adapters

- Keep canonical Gateway, operation, and session semantics transport-neutral.
- Retain the implemented Streamable HTTP `2025-11-25` adapter with exact
  version headers, origin validation, loopback binding, POST and DELETE, and an
  explicit GET 405 response.
- Do not add conditional future behavior to the 2025 adapter. A protocol with
  different session or cancellation semantics gets a separate adapter only
  when implemented and tested.
- Update transport activity on request admission, notification, completion,
  explicit cancellation, resource read, and deletion.

Exit condition: every adapter advertises only behavior it implements, and a
transport version change requires no GDB/MI or session actor change.

## 7. R5: Qualify and identify the exact release

- Make required GDB tests fail closed and report planned, executed, and skipped
  integration counts.
- Pin release workflow actions and toolchains immutably; keep rolling toolchain
  jobs non-blocking.
- Run formatting, locked tests, Clippy, MSRV, schemas, SDKs, fuzz, GDB 9.2
  through current, x86-64/AArch64, kernel, chaos, lifecycle soak, artifact
  failpoints, and HTTP interoperability on the exact signed release tag.
- Generate a clean allowlisted source archive without caches or local build
  output, plus binary checksums, SBOM, and provenance.
- Make `gdb-ai --version --verbose` report tag, full commit, dirty state,
  toolchain, and compatibility-schema hash.

Exit condition: a third party can trace source archive and binaries through a
signed tag to the exact required CI run and published checksums.

## 8. R6: Freeze protocol v1

- Remove `inferior_io.close_stdin`; retain the accurate `send_eof`/PTY VEOF
  operation.
- Remove the `agent.experiment` alias. A future experiment requires distinct
  setup, execution, evidence, verdict, and cleanup semantics.
- Keep experimental methods marked and outside the default tool projection.
- Add operation, scoped-cancel, force-abort, and recovery errors to the stable
  taxonomy.
- Document local principal and external multi-tenant identity boundaries.
- Keep capability states expressive; do not collapse conditional, limited,
  temporary, or unknown support into a Boolean.

Exit condition: v1 has no synonymous methods or ambiguous operation lifecycle;
all schema branches have positive and negative fixtures.

## 9. Tracked secondary work

Close these within their owning gates without promoting them above F1-F4:

- R1/R4: refresh transport `last_active` on operation completion and cancel;
- R3: range transcript/PTY resource URIs, blocking-I/O isolation, output
  finalization, and evidence durability profiles;
- R5: fail-closed integration helpers, immutable Actions, safe state-directory
  defaults, clean archives, and generated compatibility baselines;
- R6: canonical aliases, principal/tenant semantics, and deployment wording for
  bubblewrap as hardening rather than an untrusted-target isolation boundary.

## 10. G6: Deferred Agent-effect evaluation

Repeated paired A/B/C/D evaluation remains deferred until release hardening is
complete. Existing CTF trials are usability evidence only.

Before making comparative Agent-effect claims, run matched model builds,
prompts, permissions, budgets, environments, tasks, blind grading, and
multiple seeds:

```text
A  shell plus CLI GDB
B  persistent raw GDB
C  default nine-tool structured GDB/AI
D  C plus typed probe
```

G6 does not block release of a correct debugger control plane. It blocks any
general claim that structured tools or probe semantics improve Agent success.

## 11. Optional post-North-star work

Promote non-stop per-thread execution, record/replay providers, fuller
multi-inferior semantics, managed GDB handoff, an LLDB backend, or vendor JTAG
providers only when measured demand justifies their complexity.

Documentation-only commits require link, formatting, and consistency checks;
they do not wait for the runtime CI matrix. Runtime and release commits retain
verification proportional to their risk.
