# GDB/AI behavior-preserving refactor G5 archive

Status: completed on 2026-08-29

G5 reduced review cost without changing protocol, concurrency, security, or
runtime behavior. The work started from the completed G1-G4 tree at `71cb39c`.
Code changes end at `6ac934e`; architecture documentation follows separately.

## Design decisions

The refactor followed actual ownership rather than the speculative full crate
tree in the North-star design:

- retain the existing `gdb-ai-mi`, `gdb-ai-core`, and `gdb-ai` crates;
- keep policy, lease, revision, audit, and stable-observation ordering in one
  Gateway trust boundary;
- keep one session actor (`SessionWorker`) and one select loop as the sole
  GDB/reducer owner;
- place canonical handlers below Gateway by shared domain dependencies;
- separate CLI, shared RPC, stream lifecycle, HTTP lifecycle, and resources;
  and
- add no dependency, public compatibility interface, factory, or fallback
  layer.

The proposed fourteen-crate layout was not adopted because those components
do not have independent runtime ownership, failure isolation, or release
cycles in the current implementation.

## Completed code boundaries

### Gateway operations

Commits `7e8fe14` through `34e47c1` moved the former 6,156-line operations
module under `gateway/operations/`. Its 109-line `mod.rs` now performs only
exhaustive `CanonicalMethod` routing. Handlers and helpers are grouped into:

```text
agent context encoding evaluation evidence execution inspection io kernel
lifecycle memory mi raw reconciliation request values
```

Tests remain beside the domain whose behavior they protect. Production
modules use explicit imports, and `execute_method` is visible only to its
Gateway parent.

### Session ownership

Commit `64387e3` split the former 3,602-line session module into:

```text
session.rs          864 lines   public types, SessionHandle, wait predicates
session/actor.rs   2084 lines   actor state, control lane, MI loop, scheduler
session/tests.rs    812 lines   facade and wait regressions
```

The actor loop was moved intact. It was not decomposed into services because
that would create multiple apparent owners for command ordering, timeout
fencing, reducer transitions, and PTY metadata.

### Server and transports

Commits `81f753c` through `3226e8b` reduced the former 2,234-line binary entry
point to a CLI and administrative client, then introduced:

```text
main.rs               502 lines   CLI and local administrative client
server/mod.rs         506 lines   shared MCP/JSON-RPC service
server/stream.rs      582 lines   stdio and Unix lifecycle plus tests
server/http.rs       1011 lines   HTTP state, pending ownership, auth, versions
server/resources.rs   429 lines   resource discovery and exact artifact ranges
server/tests.rs        76 lines   shared protocol tests
```

HTTP session state, pending cleanup, authentication, Origin validation, and
protocol negotiation remain together because they form one transport
lifecycle. Resource parsing is independent and therefore moved separately.
Production modules no longer inherit the CLI prelude with wildcard imports.

### Gateway boundary

Commits `e87a571` and `6ac934e` moved 452 lines of Gateway tests to
`gateway/tests.rs` and made session entries, storage helpers, and internal
Gateway fields private. The 955-line runtime module remains intact: splitting
`dispatch_checked` would separate policy and lock ordering without creating a
real owner boundary.

## Preserved invariants

- Only `SessionWorker` writes GDB/MI commands and advances reducer state.
- Result records and async target events retain distinct semantics.
- Control requests can preempt a normal operation.
- Unknown command outcomes continue to fence normal commands.
- Stable observations remain bound to one stop and execution epoch.
- Snapshot publication still requires actor-side atomic baseline validation.
- Gateway policy, ownership, lease, revision, idempotency, and audit checks
  retain their original lexical order.
- MCP schemas, tool catalogs, JSON-RPC methods, error codes, and resource URIs
  are unchanged.

## Verification and review

Before the first move, the locked workspace passed all unit and integration
targets, including 88 core and 15 server unit tests. Each operation-domain
move was checked with the 88 core tests and Clippy with warnings denied.
Session and Gateway moves repeated the core suite; server moves repeated all
15 server tests and binary Clippy.

The final tree passed `cargo fmt --all -- --check`, the locked workspace with
all targets, workspace Clippy with warnings denied, and all published Schema
checksums. The workspace run included local launch, attach, core, gdbserver,
AArch64 RSP, Agent probe, noisy PTY, output evidence, raw reconciliation,
thread context, stripped PIE, storage chaos, and replay/parser tests. The
10,000-cycle soak remains explicitly ignored in ordinary test runs because it
was already qualified at the named functional baseline.

A read-only `gpt-5.6-sol` critical reviewer at maximum reasoning independently
checked route exhaustiveness, moved-block equivalence, import dependencies,
visibility, `SessionWorker` ownership, HTTP pending ownership, and the decision
not to introduce speculative crates. No behavior-changing refactor was
recommended or applied.

G5 adds no new feature and fixes no runtime defect. Source comments with bug
dates were therefore not added to mechanically moved code.
