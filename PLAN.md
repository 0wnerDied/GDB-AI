# GDB/AI maintenance plan

Status: the North-star implementation and its runtime release hardening are
complete. This file tracks maintenance and evidence gates that remain relevant
after the version-1 release; it is not a second implementation backlog.

Completed and superseded plans are preserved in:

- [North-star architecture](docs/archive/north-star-plan-2026-08-29.md);
- [release gates G1-G4](docs/archive/release-gates-g1-g4-2026-08-29.md);
- [behavior-preserving refactor G5](docs/archive/behavior-preserving-refactor-g5-2026-08-29.md); and
- [release hardening R0-R6](docs/archive/release-hardening-r0-r6-2026-08-30.md).

## Version-1 maintenance

- Preserve the `gdb.ai/v1` compatibility rules and the default ten-tool MCP
  catalog. Add public surface only for a demonstrated user or Agent need.
- Keep correctness, bounded output, stop consistency, operation ownership,
  cancellation scope, evidence integrity, and cleanup paths covered by a
  regression whenever they change.
- Keep README, protocol schemas, generated MCP contracts, examples, and CLI
  behavior synchronized. Documentation must describe configured qualification
  separately from the result of any particular CI run.
- Qualify runtime releases with the required workspace, GDB compatibility,
  AArch64, kernel, schema, SDK, and fuzz lanes. The tag-only 10,000-cycle soak
  remains useful diagnostic evidence but does not gate release packaging.

Canonical compatibility aliases already published in version 1 remain outside
the default MCP catalog. Removing `agent.experiment` or
`inferior_io.close_stdin` requires a new protocol major version rather than a
version-1 maintenance release. `agent.hypothesis_check` remains experimental
and outside the default catalog.

## Agent token efficiency

The only optimization target is less Agent context for the same or better
debugging accuracy. Wall time and RPC latency matter only when they reduce the
number or quality of useful debugging turns. Preserve precise stop, frame,
memory, register, and crash evidence; remove transport bookkeeping, duplicated
state, and low-value prose from the Agent surface.

GDB/AI is a semantic compressor over GDB, not a decomposition of GDB commands
into transport steps. Strip prompts, terminal formatting, control bytes, and
duplicate state while preserving exact debugger facts. One projected call
should perform an operation that GDB can complete atomically; coordination IDs
are returned evidence and optional cross-call pins, not required preflight.

Complete these changes before the next comparison:

- [x] Remove lease, revision, idempotency, and cancellation bookkeeping from
  projected MCP schemas and responses; manage it inside the transport.
- [x] Keep active projected controllers alive across Agent reasoning pauses,
  while preserving per-session mutation serialization.
- [x] Shorten session-scoped stop, inferior, thread, frame, breakpoint, and
  value handles without weakening stale-context checks.
- [x] Keep only launch-relevant session creation data and high-value target
  state in normal tool results; leave full status and capabilities on demand.
- [x] Hide compatibility-only start-policy aliases and incidental capability
  registries from projected lifecycle calls.
- [x] Omit successful-call journal pointers while retaining failure evidence
  and explicit event resources.
- [x] Compact distinct execution-wait states and deduplicate them when their
  target semantics match the current state.
- [x] Keep only address, offset, permission, and path semantics in projected
  mapping records.
- [x] Expose same-stop inspection batching without loading the unrelated
  advanced catalog.
- [x] Make canonical Python and TypeScript `Session` clients retain rejected
  revisions and renew then retry one pre-effect lease-expiry rejection.
- [x] Teach Agents to reuse one session with `target.restart`, batch deterministic
  PTY input, and use the existing batch and probe operations before adding a
  new exploit-specific interface.
- [x] Verify independent sessions remain concurrent, then run real-GDB schema,
  SDK, workspace, and lint checks before comparative evaluation.

The next comparison must use the projected MCP `tools/call` surface and a
prebuilt server. A custom `gdb.ai/call` client does not measure Agent-facing
schemas or compact tool results. Record prompt-visible schema bytes, request
and response bytes, tool calls, coordination errors, useful exploit progress,
stable success, and wall time.

Comparative claims still require matched model builds, prompts, permissions,
budgets, environments, tasks, blind grading, and multiple seeds:

```text
A  shell plus CLI GDB
B  persistent raw GDB
C  default ten-tool structured GDB/AI
D  C plus typed probe
```

For the first post-fix gate, projected coordination fields and redundant
acquisitions must disappear. GDB/AI must use fewer prompt-visible bytes than
the native transcript while matching or improving verified exploit progress;
stable success remains the strongest evidence. Otherwise use the recorded call
trace for one more bounded change rather than adding a general pwn subsystem.

The blind exploit comparison reached the same controlled-callback proof on five
fresh ASLR processes in both groups, but failed the context gate. Native
GDB used 23,746 transcript bytes and 12m43s; the projected interface used 63
tool calls, 48,094 response bytes, and 20m34s. Even with one ideal discovery
instead of the harness's four reconnects, its 15,468-byte catalog plus responses
was larger than the native transcript. Median projected-call latency was only
2.118ms, so reduce avoidable calls and misleading schema choices rather than
optimizing transport latency.

Complete only the issues demonstrated by that trace before another blind task:

- [x] Do not advertise a selectable projected session profile when the server
  owns that choice, and distinguish inspection profiles in Agent instructions.
- [x] Bind omitted projected reads to the current stop while retaining explicit
  `stop_id` pins for cross-call evidence.
- [x] Make projected continue and step wait for stop or exit by default while
  preserving explicit asynchronous waits for interactive input.
- [x] Reuse the existing breakpoint-run-capture probe through `gdb_run` instead
  of making Agents reconstruct it from several tools.
- [x] Let `gdb_run` control and wait actions return selected views from their
  resulting stop so one debugger turn does not require a follow-up batch call.
- [x] Compact projected status polls to target coordination and the event cursor;
  keep complete target registries behind their explicit inspection view.
- [x] Preserve logical module-offset breakpoints across ASLR relaunches without
  attempting to insert the previous process's absolute address.
- [x] Replay the failed calls against the release binary and exclude harness
  reconnect behavior from debugger output.
- [x] Use a new blind target for the next post-fix comparative claim.

The three-round post-fix comparison confirmed that same-stop observations are
correct and that warm replay is fast, but the cold trace exposed a larger turn
amplifier. One structured run made 1,890 tool calls; 1,573 were PTY writes
replaying deterministic input around stops. A stopped 17 KiB write also blocked
for more than 37 seconds. The comparison additionally paid setup retries because
the default session denied ordinary inferior input, and a brief loader crash
returned 10,081 bytes of duplicated arguments, locals, source, and disassembly.

Complete only these trace-backed changes before the next comparison:

- [x] Let `gdb_run` feed bounded byte-exact input while it controls or waits for
  the target, then return requested same-stop observations in that one call.
- [x] Give PTY writes a deadline and an exact partial-write count so a stopped
  or non-reading inferior cannot wedge its session worker.
- [x] Make the default local Agent session mutation-capable; keep read-only and
  raw profiles available only when explicitly configured.
- [x] Keep `crash=brief` focused on the top-frame values, compact disassembly,
  registers, and a short stack; retain complete detail in deeper profiles.
- [x] Return an immediate terminal-state error when a running/stopped wait is
  made impossible by target exit instead of consuming the full wait timeout.
- [x] Repeat matched cold-start measurements, reject fixed-layout success, and
  use the exact trace to remove demonstrated turn amplifiers without losing
  the verified primitive or stop attribution.

Focused regression evidence now replaces a three-call input/EOF/continue path
with one run turn, bounds a stalled 64 KiB PTY write near its 100 ms deadline,
and keeps the worker responsive afterward. Reprojecting the recorded 10,081-byte
brief crash response yields 4,852 bytes while retaining top-frame variables.
The stateful default tool-discovery response is 17,346 bytes versus 17,374 bytes
before inline input, so the one-call capability adds no discovery-token debt.
The following matched cold-start run supplied the remaining comparison.

### Blind three-interface comparison

The matched one-hour allocator comparison required final payload addresses to
come from target output and pass in three fresh ASLR-enabled processes. An
early native result disabled ASLR and embedded debugger-observed PIE, libc,
heap, and stack addresses; it is a local diagnostic and not a successful
remote-capable exploit.

| Interface | Valid elapsed result | Debugger traffic | Highest stable result |
| --- | ---: | ---: | --- |
| Native GDB CLI | 52m46s | 23 starts, 362 script lines, 45,846 response bytes | target-derived libc/heap leak and backward consolidation |
| Default GDB/AI | 43m30s | 552 calls, 190,159 request and 516,506 response bytes | target-derived libc/heap leak and two live overlapping buffers |
| Alternative GDB MCP | 52m40s | 257 calls, 37,415 request and 1,297,941 response bytes | target-derived leak, overlap/UAF, and a guarded large-bin pointer write |

No group completed an unrestricted remote arbitrary write, ORW, or flag
path. The alternative MCP reached the deepest guarded allocator write but
returned 2.5 times GDB/AI's response bytes. GDB/AI reached its first live
overlap in about
17 minutes and its service-only leak-to-overlap proof in about 21 minutes.
Native GDB's early apparent lead came from an invalid fixed-layout run; its
corrected ASLR-on primitive completed after 50 minutes.

Native GDB was efficient when one command file combined a counter-gated
breakpoint, silent continues, target input, and hypothesis-sized memory
windows. The GDB/AI trace instead exposed separate breakpoint and input turns,
stale input across restart, missing same-turn output, an ignored launch
environment, ordinary adjacent mappings classified as unknown-effect, and an
artifact URI with no projected resolver. Complete only the shared root fixes:

- [x] Apply inferior environment values exactly and reject values GDB's MI
  setting cannot preserve.
- [x] Flush stale inferior input and bind restart completion to the new
  execution generation.
- [x] Return bounded lossless PTY output from the synchronous run or probe that
  produced it.
- [x] Treat gap-free ordinary ranges across adjacent local mappings as reads,
  while retaining device and unmapped boundaries.
- [x] Let the existing probe combine input, a GDB ignore count, bounded capture,
  output, and breakpoint cleanup in one call.
- [x] Require preserved ASLR for final exploit validation while permitting
  disabled ASLR only for repeatable layout probes.
- [x] Project the existing paged artifact reader as `gdb_memory` action
  `artifact`, so a large read is not repeated in smaller windows.

The recorded default discovery response was 17,345 bytes. Counted probe input
adds 194 bytes and replaces at least three debugger turns; artifact paging adds
267 bytes and replaces the observed five-window reread. The resulting 17,806
byte catalog keeps ten top-level tools and preserves the canonical validation,
ownership, stop attribution, page bounds, and byte encoding. Focused real-GDB
regressions cover each combined path; another challenge-specific run is not
required until a new blind target is selected.

## Optional post-North-star work

Non-stop per-thread execution, record/replay providers, fuller multi-inferior
semantics, managed GDB handoff, an LLDB backend, and vendor JTAG providers are
not version-1 commitments. Promote one only when measured demand justifies its
runtime, protocol, and qualification cost.

Documentation-only commits require formatting, link, and consistency checks;
they do not wait for the runtime CI matrix.
