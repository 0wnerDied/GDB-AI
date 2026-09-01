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
- [ ] Use a new blind target for the next post-fix comparative claim.

## Optional post-North-star work

Non-stop per-thread execution, record/replay providers, fuller multi-inferior
semantics, managed GDB handoff, an LLDB backend, and vendor JTAG providers are
not version-1 commitments. Promote one only when measured demand justifies its
runtime, protocol, and qualification cost.

Documentation-only commits require formatting, link, and consistency checks;
they do not wait for the runtime CI matrix.
