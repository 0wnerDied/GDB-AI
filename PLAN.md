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

- Preserve the `gdb.ai/v1` compatibility rules and the default eleven-tool MCP
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

## Agent exploit speed

The only optimization target is shorter wall time from the first debugger turn
to a reproducible exploit. Tool calls, output size, and RPC latency are
diagnostics only: optimize them when they delay Agent reasoning or split one
debugging operation into several turns. Preserve precise stop, frame, memory,
register, and crash evidence.

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
prebuilt server. A custom `gdb.ai/call` client does not measure the Agent-facing
workflow. Record time to the first runtime primitive, time to a stable exploit,
fresh-process verification, debugger turns, retries, errors, and final wall
time. Record traffic size only when it explains a delay or a bad tool choice.

Comparative claims still require matched model builds, prompts, permissions,
budgets, environments, tasks, blind grading, and multiple seeds:

```text
A  shell plus CLI GDB
B  persistent raw GDB
C  default structured GDB/AI
D  C plus typed probe
```

For each post-fix gate, GDB/AI must match or beat native GDB's verified runtime
progress and stable-exploit wall time. Otherwise use the recorded call trace
for one more bounded shared-interface fix rather than adding a general pwn
subsystem.

Historical traffic totals below remain diagnostic evidence from earlier gates;
they are not current acceptance targets.

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
remote-capable exploit. This is an evaluation rule owned by the Agent prompt,
not debugger initialization or component policy.

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
- [x] Project the existing paged artifact reader as `gdb_memory` action
  `artifact`, so a large read is not repeated in smaller windows.

The recorded default discovery response was 17,345 bytes. Counted probe input
adds 194 bytes and replaces at least three debugger turns; artifact paging adds
267 bytes and replaces the observed five-window reread. The resulting 17,806
byte catalog keeps ten top-level tools and preserves the canonical validation,
ownership, stop attribution, page bounds, and byte encoding. Focused real-GDB
regressions cover each combined path; another challenge-specific run is not
required until a new blind target is selected.

### Post-fix two-interface rerun

A matched blind rerun used the same stripped PIE, libc, Terra xhigh model,
one-hour limit, source restrictions, and three-fresh-process ASLR validity gate.
The alternative MCP was excluded after prior testing established that it was
not competitive.

| Interface | Dynamic time | Debugger traffic | Highest valid result |
| --- | ---: | ---: | --- |
| Native GDB CLI | 15m49s | 14 starts, 233 command lines, 32,646 output bytes | target-output libc and heap disclosure; adjacent size-byte clearing |
| Default GDB/AI | 20m51s | 265 calls, 74,583 request and 228,143 response bytes | target-output libc disclosure; adjacent size-byte clearing |

Neither group completed arbitrary write, control flow, ORW, or a flag path.
Native GDB reached its first stable disclosure in 3m15s; GDB/AI reached its
first stable disclosure in 17m03s. Both final claims passed three ordinary
ASLR-enabled processes, but native GDB retained the deeper heap disclosure and
won both progress and context gates. GDB/AI's 33 initializations and 29
create/launch pairs include the comparison harness restarting its stdio server
for each sequence; report them separately rather than treating them as GDB
output, while retaining their Agent-visible cost in the measured total.

The trace contained no projected probe calls. A focused replay showed the
causes in the interface rather than transport latency:

- [x] Let a module-offset probe start at the loader stop, use the existing
  pending PIE rebind path, follow the stable breakpoint ID, and clean up the
  materialized breakpoint in the same call.
- [x] Add bounded address-expression memory windows to probe capture so a
  counted input turn does not require a later `gdb_memory` call.
- [x] Describe probe as batched exact input, skipped intermediate hits,
  same-stop expression/stack/memory capture, output, and cleanup.
- [x] Encode control-bearing UTF-8 as one lossless binary value instead of
  expanding each NUL into a JSON escape.
- [x] Omit successful `ok` text, healthy/active state defaults, null frame
  fields, and ready snapshot identity duplicated by the current `stop_id`.

The default serialized catalog is now 18,151 bytes, 345 bytes above the rerun
catalog because memory capture and the stripped-target hint are explicit. In
exchange, an end-to-end replay from the loader stop queued two protocol
commands, skipped their intermediate
breakpoint hits, captured an exact memory window, returned target output, and
cleaned up with one `gdb_run` call. Encoding the NUL-heavy output reduced that
probe response from 8,621 to 2,679 bytes; compact state reduced it again to
2,459 bytes. The complete four-call create/launch/probe/close replay fell from
11,105 to 4,554 response bytes. Applying only the state and success-envelope
projection to the recorded blind trace reduces 228,143 response bytes to
193,587 bytes (15.1%) without dropping stop, frame, process, inferior, thread,
origin, or stop-reason facts.

Run the next blind comparison against these exact commits. The targeted replay
proves the previous long path can collapse correctly; only a fresh Agent run
can establish natural probe adoption and comparative exploit progress.

### Cold-start Agent-interface rerun

A fresh Terra xhigh pair used the same stripped PIE, one-hour ceiling, source
isolation, and three-process ASLR gate. The native group stopped dynamic work
after 10m42s and the projected group after 11m42s; both completed their reports
early.

| Interface | Verified progress | Debugger traffic | Highest valid result |
| --- | ---: | ---: | --- |
| Native GDB CLI | 10m42s | 3 starts, 29 command lines, 3,081 output bytes | listed capability bypass with VFS read, delete, and bounded overwrite |
| Default GDB/AI | 15m46s including ordinary validation | 41 calls, 15,276 request and 47,067 response bytes | fixed one-byte heap NUL overflow |

The native Agent recognized that a listed hash and a static XOR constant remove
the application authorization boundary. The GDB/AI Agent derived the same
capability formula but treated only the adjacent heap byte as its final
primitive. That difference is Agent reasoning on a predominantly static target,
not evidence that either debugger changed target semantics. Use a target whose
next primitive requires runtime state before making another comparative debugger
claim.

The projected trace did expose independent interface costs. Its 18,196-byte
catalog dominated the short run. Thirteen benchmark-driver invocations added
about 144 seconds outside debugger response time. Two cold GDB starts timed out;
the server had created 194 Tokio threads before a session and synchronously
probed bubblewrap. An unmapped memory read was rejected by policy before GDB
could return its precise error. An exit-only wait missed a crash, and the Agent
did not naturally use probe because the supplied libc failed before the command
loop and later default-libc sessions hit the startup failure. Driver placeholder,
invented tool-name, and missing-session follow-on calls remain harness or Agent
errors and are not debugger defects.

Complete only the shared fixes demonstrated by this run:

- [x] Bound the I/O runtime to four workers instead of the host CPU count. A
  release server now has six threads before session creation and seven with one
  GDB, versus 194 and 196; eight concurrent GDB sessions start successfully in
  108 ms with 15 server threads.
- [x] Disable optional bubblewrap probing by default while retaining explicit
  `auto` and `required` deployment modes.
- [x] Keep memory reads admitted by mutation-capable profiles on read
  coordination, so unmapped local reads reach `GDB_ERROR` without an
  acknowledgement or mutation revision. Omit the ineffective compatibility
  flags from projected schemas.
- [x] Remove the redundant MI AST from projected GDB failures. The reproduced
  32-byte unmapped read falls from 830 to 581 wire bytes while retaining code,
  message, retry semantics, state, and evidence.
- [x] State that omitting a run wait already returns at the next attributable
  stop or exit with bounded output; reserve accepted/running for later I/O.
- [x] Emit only positive MCP annotations and one breakpoint-location syntax.
  The same ten-tool catalog falls from 18,196 to 16,865 wire bytes without
  removing a debugger action or canonical request form.

### Dynamic-service exploit-speed comparison

A matched blind Terra xhigh pair used the same stripped PIE, loader, libraries,
network shim, and three-process success gate. The host has ASLR disabled by
configuration, so validity was checked by inspecting both exploit programs:
neither embeds a debugger-observed absolute address, and both derive the PIE
base from target output plus module-relative offsets.

| Interface | First runtime primitive | Stable control flow | Three-process proof | Debugger traffic |
| --- | ---: | ---: | ---: | --- |
| Native GDB CLI | 2m04s | 11m51s | 12m44s | 2 starts, 62 command lines |
| Default GDB/AI | 3m18s | 5m24s | 7m26s | 24 projected calls, about 105 ms API time |
| Current GDB/AI adoption | 3m43s | 5m43s | 9m26s | 15 calls, one persistent connection |

GDB/AI reached the stable controlled callback about 2.2 times faster and
finished ordinary-process verification about 1.7 times faster. Native GDB
found the first leak earlier, so the remaining target is faster early runtime
discovery without regressing the combined path that won the full exploit.

A subsequent fresh GDB/AI-only run reached its first runtime primitive in
1m51s and the three-process proof in 11m32s using 18 projected calls. It used
the launch convention correctly and needed no standalone register evaluation,
but naturally rebuilt a running-service probe from breakpoint, event, inspect,
and resume calls. It also exposed a loaded-library SONAME breakpoint that
silently remained pending.

An intermediate adoption run reached its first primitive in about 2m20s but
took 17m39s to finish. It reopened the one-shot client for 64 calls, could not
read a pointer expression directly, omitted the main executable from its module
view, and did not recognize how a blocking probe coordinates with a concurrent
network trigger. These were interface evidence, not traffic-size targets.

After the shared fixes, the current blind replay naturally selected
`gdb_probe`, reused one persistent connection, reached controlled flow in
5m43s, and completed three ordinary-process proofs in 9m26s. Its first malformed
payload aborted before the requested probe point, so the bounded probe timed
out and the Agent correctly switched to a persistent breakpoint while fixing
the payload. The final exploit derives every runtime address from a target
leak and module offsets; it contains no absolute process address.

A fresh matched source-free stripped-PIE comparison then reached the same
runtime OOB write and three-process crash proof in both arms. Native GDB took
17m58s; the default projected interface took about 23 minutes and 116 calls.
The structured arm spent 101 calls preparing one prompt-driven menu because a
single queued transcript was consumed by the target's broad reads, and a probe
memory capture rejected a valid decimal register address. The trace-driven
replay now performs all 101 prompt-synchronized writes in one transaction.
Twelve release replays completed it in 0.01--0.61s and completed create,
launch, resume, setup, module-offset probe, and close in six projected calls.
Every replay recovered the exact `INT_MIN` index without embedding an absolute
runtime address.

A later matched source-free network-service run did not beat native GDB.
Native reached its first externally visible primitive in at most 2m06s,
stable leak-derived control flow in 10m54s, and three-process proof in 13m37s
with two GDB starts and 17 commands. GDB/AI reached its first post-copy dynamic
proof in 12m22s and completed three address-independent controlled-crash proofs
in 15m22s with 51 calls across ten sessions. The native first primitive came
from static analysis and ordinary socket traffic before GDB started, so it is
not evidence that the CLI debugger itself was faster.

The projected trace spent 18 calls diagnosing an executable whose supplied
runtime was not prepared before launch, and nine calls repeated state already
returned by the preceding operation. Runtime binding now remains an explicit
pre-debugging responsibility instead of changing the target inside GDB/AI.
Existing `restart` removes seven calls from three-process replay.
`continue_to_stop` removes the remaining probe-capture/run-to-crash split while
preserving the first capture and returning bounded crash inspection.

A stricter source-free follow-up treated runtime patching as a caller-owned
precondition and required a network-derived, address-independent control proof
across three fresh processes. Native GDB completed that proof in 28m39s with
one debugger and 82 entered command or confirmation lines, including socket
clients launched through GDB. An independent replay reproduced all three
controlled exits. The projected arm found stable heap and library leaks plus
the correct live object relationships, but did not obtain controlled behavior
before the 60-minute cutoff. It made 75 successful API requests across two
sessions; its earlier repeated crashes were correctly excluded from the final
score because their fatal address was not selected by the input.

The projected trace exposed two concrete adoption costs. Its create
description advertised a profile hidden from ordinary callers and caused one
guaranteed policy retry; the description now directs Agents to the usable
default. Seventeen candidate trials each issued separate restart and resume
calls before a probe. `gdb_probe restart=true` now owns that complete retry and
removes those 34 calls. Neither fix is credited retroactively, and neither
would by itself have supplied the missing heap-staging exploitation insight.

A third matched source-free run used a multi-process HTTP/IPC target and a
60-minute cutoff. Native GDB reached debugger-observed control in 11m18s, the
first debugger-assisted flag response in 19m30s, and three fresh-stack proofs
in 20m40s. It used three GDB starts and at least 78 commands; the count is a
lower bound because machine logging did not begin with the first command. It
did not find a network-visible runtime address, so the proofs remain
debugger-assisted rather than standalone remote exploitation.

The projected arm found an address-independent controlled crash and later
replayed three debugger-assisted flag responses using 108 accepted operations
across 19 sessions. Three raw-GDB commands appeared in its isolated shell
history after the common start, however, and their output provenance cannot be
excluded. The entire projected solve-time result is therefore contaminated
and receives no A/B score. Its later MCP journal independently verifies the
mechanics of one projected proof, but does not repair the strategy provenance.

The run exposed reused-inferior exit waits, unattributed child exits, discarded
trigger output, ambiguous inferior-output naming, and stale live-looking state
after daemon replacement. A current-build warm replay does not count toward
the comparison: three repeated exit waits completed in 55.7--71.5 ms, a probe
returned both 20-byte trigger streams without another client session, a child
exit left the parent running, and replacement startup reported abandoned
sessions as `FAILED/DEAD` with their old leases removed.

### Blind kernel exploit-speed qualification

A concurrent source-free ring-1 run exposed a different adoption gap. Native
GDB reached the first symbolized module stop in 5m06s, proved the runtime UAF
in 12m44s, obtained privilege in 31m37s, and completed three fresh KASLR boots
in 55m26s. The GDB/AI arm reached the module stop in 7m28s but produced no
verified primitive or exploit within the hour. It was paused for live interface
fixes, so the final wall time is censored rather than a clean product score;
the failed calls still identify the missing adoption path precisely.

On the same stripped target, the specialized GEF oracle recovered the kernel
layout, full version, and per-CPU current tasks in 2.65s. The first GDB/AI
symbol-free bootstrap now returns the exact image range and version plus four
module mapping candidates in 1.14s. Internal filtering reduced three semantic
views from a 64 MiB journal failure to 65 KiB while keeping the target facts.
The combined one-call bootstrap also returns exact requested symbols and all
CPU tasks. Fresh official x86-64 distribution kernels spanning Linux 5.15,
6.1, 6.6, 6.12, and 7.2 completed it in 1.60s, 1.15s, 2.13s, 2.08s, and 3.05s.
Every symbol address matched the independent GEF decoder; a second KASLR boot
changed every kernel base and passed again, excluding fixed runtime addresses.
The same call now resolves loaded module names, bases, sizes, and memory
segments. Two-module Linux 6.1 and 6.12 names and bases matched guest
`/proc/modules` in 1.17s and 2.07s versus GEF's 2.50s and 3.00s; a
randomized-layout target also resolved in 2.22s where both GEF module commands
failed. Official Arch packages for Linux 6.13.8, 6.15.9, and 7.2.2 cover the
remaining layout branches; their two-module names and bases matched
`/proc/modules` in 2.88s, 2.80s, and 3.09s.
A text-relative one-call probe then resolved a loaded distribution module,
armed the dynamic breakpoint, captured its externally triggered execution, and
cleaned up in 2.30s and 2.09s across two fresh KASLR boots. The legacy Linux
6.1 `core_layout` path hit the same one-call probe without typed symbols.
A blind single-module boot also exposed an incidental two-byte ASCII field as
the inferred module name. The parser now requires the complete fixed-size name
field and its zero padding; a focused GDB-Python regression rejects both the
nonzero-padded and truncated candidates.

Complete only the shared fixes demonstrated by these runs:

- [x] Reset exit state when GDB reuses an inferior identifier for a new process.
- [x] Include ABI argument registers in the standard register view.
- [x] Surface the existing one-call breakpoint probe as `gdb_probe`.
- [x] Project process exit codes as decimal integers.
- [x] State that launch `program` is the executable and `argv` contains only
  following arguments.
- [x] Resolve loaded-module SONAME symlinks against the inferior working
  directory before calculating their mapping load bias.
- [x] Let `gdb_probe` arm an already-running target and wait for its first hit
  without an interrupt and redundant resume.
- [x] Resolve and read one address expression under the same stopped-state
  fence, including pointer-cast dereferences used during exploit development.
- [x] Include the main executable's local mappings in the module view.
- [x] State that socket and other external triggers run concurrently with a
  blocking probe while `input` remains target PTY data.
- [x] Let one `gdb_probe` start a host command after its breakpoint is armed
  and the inferior runs, returning trigger status on a hit or timeout.
- [x] Let `gdb_probe` remove its temporary breakpoint, continue to the next
  stop or exit, and return optional bounded inspection in the same call.
- [x] Let a repeated `gdb_probe` restart the current inferior before arming,
  eliminating separate restart and resume calls from exploit trials.
- [x] Distinguish reused inferior generations when waiting for exit, so a new
  fast process cannot be mistaken for the preceding terminal state.
- [x] Leave an exit without a thread-group unattributed when several inferiors
  exist, preserving the live parent's state after a child exits.
- [x] Return bounded stdout and stderr from a probe's external trigger instead
  of requiring an extra debugger-managed client session.
- [x] Identify inferior stdio as `pty` and reserve `target` for GDB/MI's
  `@` stream in the Agent-facing tool description.
- [x] Mark persisted nonterminal sessions and leases abandoned when a new
  daemon owns their store, rather than advertising dead actors as controllable.
- [x] Keep a detached multi-client server alive when GDB teardown delivers
  SIGHUP, so closing one session cannot drop the other Agents.
- [x] Run a fresh blind natural-adoption replay against the current release,
  verify direct module-relative debugging and no absolute exploit address, and
  record bounded-probe fallback separately from interface failure.
- [x] Repeat a matched native/GDB-AI comparison on a new runtime-dependent
  userland target after the adoption gate passes.
- [x] Accept unsigned decimal addresses returned for bare GDB register
  expressions so same-stop memory capture does not require a literal-address
  retry.
- [x] Let one projected PTY write gate ordered input steps on exact target
  output, avoiding one Agent round trip per prompt without pre-queuing answers
  that a broad target read can consume.
- [x] Finish the concurrent blind ring-1 qualification, measuring stop
  attribution, guest symbol/module discovery, reconnects, primitive and exploit
  wall time without supplying source.
- [x] Add one symbol-free x86-64 QEMU bootstrap view and make `base` and
  `version` fall back to it, filtering the monitor map inside GDB before MI.
- [ ] Detect matching Linux `CONFIG_GDB_SCRIPTS` helpers and project the proven
  `lx-symbols`, module, task, dmesg, current/per-CPU, and address-translation
  semantics as bounded kernel views; keep the typed provider as the fallback.
- [x] Decode exact requested kallsyms and per-CPU current tasks inside GDB for
  measured Linux 5.15 through 7.2 layouts, returning only semantic facts.
- [x] Resolve stripped module identity and validated memory segments in the
  existing one-call bootstrap, including measured randomized layouts.
- [x] Reject incomplete or nonzero-padded module-name candidates before the
  randomized-layout offset scan selects them.
- [x] Let the default lab profile connect remote stubs, treat a configured
  endpoint list as an opt-in restriction, and enable kernel inspection without
  an administrative profile retry.
- [x] Let one `gdb_probe` resolve a stripped kernel module text offset, run,
  capture the attributed hit, and clean up without raw GDB or fixed addresses.
- [x] Inspect symbol-free kernels from KPTI userspace stops through Linux's
  paired kernel PGD, restoring CR3 within every bounded observation.
- [x] Let bounded QEMU page-table and runtime-symbol observations outlive the
  generic MI deadline under TCG load without fencing the session.
- [x] Replace the native multi-command page-table workflow with one x86-64
  virtual-to-physical walk; do not import GEF's UI or compatibility surface.
- [ ] Detect KGDB/KDB separately from a QEMU gdbstub. Normalize read-oriented
  `monitor` process, module, and dmesg results while GDB remains the sole run
  controller, as required by the upstream debugger contract.
- [ ] Use drgn/crash typed-object and vmcore traversal semantics as references
  for offline targets; add neither dependency until a measured target needs it.

## Optional post-North-star work

Non-stop per-thread execution, record/replay providers, fuller multi-inferior
semantics, managed GDB handoff, an LLDB backend, and vendor JTAG providers are
not version-1 commitments. Promote one only when measured demand justifies its
runtime, protocol, and qualification cost.

Documentation-only commits require formatting, link, and consistency checks;
they do not wait for the runtime CI matrix.
