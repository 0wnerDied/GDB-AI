# GDB/AI Implementation Plan and Normative Specification

Status: implemented version 1; host-dependent qualification remains capability-gated

This document records the complete project requested for `GDB/AI`. It is the
normative implementation and release checklist. Host-dependent functions are
reported as supported only when runtime probes and tests agree; unavailable
kernel, architecture, sandbox, Python, and remote facilities remain explicit
capability results rather than simulated success.

## 1. Product definition

`GDB/AI` means **GDB Agent Interface**. It is a stateful debugging control
plane for modern Agents doing dynamic debugging, vulnerability validation,
and authorized vulnerability exploitation. It runs on top of GDB and its
GDB/MI machine interface. It does not replace GDB or expose GDB/MI as the
normal Agent interface. It turns GDB asynchronous events, implicit context,
inferior I/O, lifecycle, and safety policy into:

- a versioned semantic API;
- an explicit debugger state machine;
- bounded structured observations;
- cancellable, time-bounded, auditable operations;
- results traceable to raw debugging evidence; and
- MCP, JSON-RPC, Python SDK, and TypeScript SDK interfaces.

GDB/MI is supplied by GNU GDB in binutils-gdb and is only the backend
protocol. GDB/AI does not define it. Terminal prompt parsing is never the
control foundation.

Canonical names:

```text
project:             GDB/AI (Agent Interface)
repository:          gdb-ai
executable:          gdb-ai
protocol namespace:  gdb.ai/v1
resource scheme:     gdbai://...
```

The product must ensure that:

1. agents never manage the GDB process or terminal lifecycle directly;
2. agents never infer execution state from natural-language console output;
3. inferior standard I/O is separate from the GDB control channel;
4. agent calls never depend on selected thread/frame implicit state;
5. long operations can be waited for, timed out, cancelled, or interrupted;
6. stacks, variables, registers, memory, and disassembly are bounded and
   pageable;
7. resuming a target invalidates old frames, values, and current snapshots;
8. raw GDB commands remain a controlled escape hatch, not the primary API;
9. every state-changing action is authorized and audited; and
10. replaying the same complete event journal reconstructs the same controller
    state; MI output alone is only one journal input.

Non-goals:

- a new debugger core;
- replacing symbolic execution, decompilation, or fuzzing systems;
- automatic exploit-chain generation;
- mapping every GDB CLI command to an agent tool;
- restoring the identical live process after GDB or inferior failure;
- an LLDB backend in version 1;
- arbitrary shell, Python, script loading, or inferior function calls by
  default.

## 2. Supported scope

The North-star support matrix is:

| Dimension | Version 1 support |
| --- | --- |
| Host | Linux |
| Architectures | x86-64 and AArch64 |
| Targets | local launch, existing PID, core, gdbserver, GDB RSP target |
| Run mode | all-stop |
| Process model | multiple inferiors/thread groups in the domain model |
| Symbols | full, partial, and stripped binaries |
| Binaries | ELF, PIE, and shared libraries |
| Transports | MCP stdio, MCP Streamable HTTP, JSON-RPC, Python and TypeScript SDKs |
| GDB/MI | full MI4, compatible MI3 |
| Session | one independent GDB process per GDB/AI session |
| Concurrency | one writer, multiple observers |

Compatibility levels:

- **Full:** MI4, complete structured capabilities, full automated tests.
- **Compatible:** MI3, core debugging, with explicitly reported missing
  fields or commands.
- **Legacy:** optional best-effort MI2 with no formal compatibility promise.

MI4 is available from GDB 13.1 and MI3 from GDB 9.1. MI compatibility permits
new fields, commands, and enum values in a version; decoders must preserve and
tolerate unknown data.

Explicit version 1 exclusions:

- non-stop per-thread execution;
- a complete reverse-execution abstraction;
- native Windows or macOS debugging;
- uniform semantics for proprietary JTAG functions;
- arbitrary interactive GDB CLI sessions;
- non-invasive takeover of an arbitrary running GDB instance; and
- restoring a live inferior across GDB processes.

The model may reserve per-thread running state, reverse capabilities, and a
narrow backend boundary, but it must not claim unavailable capabilities.

## 3. Architecture and ownership

The data path is:

```text
Agent / IDE / SDK
        |
        +-- MCP
        +-- JSON-RPC / SDK
        v
Gateway
  protocol validation, authentication, session registry, write leases,
  policy routing, rate limits, resource/artifact routing, audit frontend
        |
        v
Session supervisor
  worker lifecycle, quotas/watchdog, persistent metadata
        |
        v       one worker per session
Session worker
  scheduler, reducer, capability registry, snapshots, reconciliation,
  MI token correlation, event journal, inferior I/O, providers, artifacts
        |                         |
        v                         v
      GDB/MI                  inferior PTY
        |                         |
        +-------------+-----------+
                      v
       native / core / gdbserver / remote
```

The gateway contains no GDB-specific parsing or state logic. It validates the
protocol version and schema, authenticates and authorizes, routes sessions,
manages leases and rates, exposes resources, and records caller-facing audit
events.

The supervisor creates and destroys workers, applies CPU/memory/file/runtime
quotas, watches workers and GDB, marks crashed sessions `FAILED`, retains
metadata/transcripts/artifacts, and isolates sessions from one another.

The worker is the sole state owner and GDB writer. Every MI record is journaled
before reduction. Snapshot, diff, breakpoint mapping, inferior PTY ownership,
and provider execution live in the worker.

Every session owns one GDB child. One GDB may own multiple inferiors; GDB
processes are never shared between sessions.

## 4. Implementation technology

The core is Rust, using the smallest maintained components that satisfy these
requirements:

```text
async runtime          Tokio
serialization          serde / serde_json
schema                  schemars plus JSON Schema validation
errors                  thiserror
structured logging     tracing
telemetry               OpenTelemetry
PTY/process             rustix or nix
persistence             SQLite in WAL mode
identifiers             ULID
hashing                 SHA-256
HTTP                    hyper / axum
MCP                     separate adapter boundary
```

Rust is required because the worker handles untrusted GDB/target output,
parser memory and recursion must be bounded, daemons must isolate many
sessions reliably, single-owner state should be explicit, and fuzzing must be
first-class.

An optional, narrowly scoped extension lives at
`gdb-extension/gdb_ai.py`. It may register trusted MI commands and private
notifications for gaps that native MI cannot express reliably. It is loaded
from a fixed absolute path, has a checked hash and protocol version, never
auto-loads from a target, never overrides built-in MI commands, degrades
without breaking basic debugging, and never accesses GDB objects from a
background Python thread.

Candidate commands are:

```text
-gdb-ai-capabilities
-gdb-ai-inferior-configure
-gdb-ai-safe-evaluate
-gdb-ai-value-metadata
-gdb-ai-architecture
-gdb-ai-signal-policy
```

## 5. Process isolation and leases

The in-process bubblewrap backend implements filesystem/network hardening only.
The complete isolation model below remains the production architecture and
requires an external container or VM supervisor; capabilities distinguish the
two levels.

The intended process tree is one gateway with one worker and one GDB per
session. Each worker runs, when supported by the host deployment, with a PID,
mount, and network namespace; cgroup quotas; rlimits; seccomp; a restricted
filesystem; a dedicated temporary directory; and a separate Unix user.

Default sandbox policy:

```text
network       disabled
filesystem    read-only workspace plus writable session directory
ptrace        only worker-managed child processes
devices       hidden
host /proc    not directly exposed
environment   explicit allowlist
```

PID attach, remote targets, and host-level debugging require higher-privilege
profiles and cannot auto-escalate. If a host isolation feature is unavailable,
capabilities and warnings must say so; the service must not report a sandbox
that was not applied.

Only one live write lease exists per session. Writers can control and mutate
within policy; observers can read state, snapshots, transcripts, and
artifacts. A lease contains `lease_id`, `session_id`, owner, expiry, and a
monotonic generation. Every mutation carries a valid lease. Expiry rejects
later mutations but does not silently interrupt a running target.

## 6. Domain model and identifiers

Core objects:

```text
Session, Backend, Target, Inferior, Thread, Frame, Breakpoint,
BreakpointLocation, ValueObject, StopSnapshot, TrackedExpression,
TrackedMemoryRange, Artifact, Operation, Event, PolicyDecision
```

Public identifiers are allocated by GDB/AI, generation-safe, and do not expose
temporary GDB numbers as stable IDs:

```text
session              sess_<ULID>
inferior             inf_<session>_<generation>_<ordinal>
thread               thr_<inferior>_<generation>_<gdb-thread-id>
frame                frm_<thread>_<stop-id>_<level>
breakpoint           bp_<ULID>
breakpoint location  bpl_<bp-id>_<generation>_<ordinal>
value                val_<stop-id>_<ULID>
snapshot             snap_<stop-id>
operation            op_<ULID>
artifact             sha256:<digest>
```

Backend IDs remain explicit internal provenance fields.

Addresses are canonical hexadecimal strings, never JSON numbers. Address
objects may include module, module offset, symbol, and symbol offset.

## 7. State model

State has four orthogonal axes.

Session lifecycle:

```text
CREATING -> READY -> ACTIVE -> CLOSING -> CLOSED
                  \--------------------> FAILED
```

Backend health:

```text
STARTING, HEALTHY, BUSY, UNRESPONSIVE, DEAD
```

Per-inferior state:

```text
EMPTY, CONNECTING, STOPPED, RUNNING, EXITED, DETACHED, DISCONNECTED,
CORE, UNKNOWN
```

Consistency:

```text
CLEAN, MANAGED_DIRTY, RECONCILING, TAINTED, LOST
```

`MANAGED_DIRTY` means a known operation changed controller-managed GDB state
and a targeted reconciliation is possible. `TAINTED` means an unknown raw
operation may have changed state outside the managed surface; finite queries
cannot prove complete GDB equivalence. A tainted session exposes the bounded
state that was re-observed but never claims full reconciliation.

Every session exposes `event_seq`, `revision`, `execution_epoch`,
`reconciliation_required`, and an optional `stop_id`. The event sequence
counts received/generated events.
Revision increments for public state changes. Execution epoch increments on
every stopped-to-running transition. A stop ID uniquely names one stopped
context.

Every `*running` event invalidates all previous frame and stop-scoped value
handles. Historical snapshots remain evidence but are not current. Tracking
definitions remain while their GDB variable objects do not. Using an old
handle returns `STALE_CONTEXT` with its stop and the current state.

## 8. Event-sourced reduction

The only legal state path is:

```text
GDB stdout bytes -> MI framing -> lexer/parser -> RawMiRecord
  -> append journal -> normalize -> StateReducer
  -> immutable StateRevision -> events/snapshot work
```

No module bypasses the reducer to mutate session state.

Normalized events include at least:

```text
BackendStarted, BackendExited, CommandAccepted, CommandCompleted,
TargetRunning, TargetStopped, InferiorAdded, InferiorRemoved,
InferiorExited, ThreadCreated, ThreadExited, LibraryLoaded,
LibraryUnloaded, BreakpointCreated, BreakpointModified,
BreakpointDeleted, MemoryChanged, InferiorOutput, ConsoleOutput,
LogOutput, TargetDisconnected, SnapshotStarted, SnapshotReady,
SnapshotFailed, ConsistencyDirty, ConsistencyRestored, PolicyDenied
```

Tokened result records correlate command completion. Async records alone
advance target state. Specifically, `^done`/`^running` mean a command was
accepted or completed, `*running` means execution actually began,
`*stopped` means the target stopped, and notify records describe background
state changes. A result class is never substituted for an async transition.

## 9. Formal GDB/MI parser

A regular-expression approximation is forbidden. The parser is a bounded
byte-oriented lexer/parser supporting:

- optional numeric tokens;
- result, exec async, status async, and notify async records;
- console, target, and log streams;
- prompts;
- tuples, value lists, and result lists;
- C-string escapes and non-UTF-8 stream bytes;
- empty lists and tuples;
- duplicate keys and ordered fields;
- unknown result/async classes and unknown fields;
- arbitrary read/chunk boundaries;
- LF and CRLF, partial records, and EOF;
- configured maximum nesting and record/decoded-string sizes.

The lossless AST is:

```rust
enum MiRecord {
    Result { token: Option<u64>, class: String, results: Vec<MiResult> },
    ExecAsync { token: Option<u64>, class: String, results: Vec<MiResult> },
    StatusAsync { token: Option<u64>, class: String, results: Vec<MiResult> },
    NotifyAsync { token: Option<u64>, class: String, results: Vec<MiResult> },
    ConsoleStream(Vec<u8>),
    TargetStream(Vec<u8>),
    LogStream(Vec<u8>),
    Prompt,
}

struct MiResult { name: String, value: MiValue }

enum MiValue {
    Const(Vec<u8>),
    Tuple(Vec<MiResult>),
    ValueList(Vec<MiValue>),
    ResultList(Vec<MiResult>),
}
```

Ordered vectors are mandatory because fields may repeat and unknown future
fields must survive. Framing is byte-stream based, not one-read-per-record.

Default limits:

```text
MI record bytes          8 MiB
nesting depth            128
decoded C-string bytes   8 MiB
unterminated buffer      8 MiB
```

A limit violation stores a bounded preview, records a parser violation,
terminates the session, and returns `MI_PROTOCOL_LIMIT`; it does not attempt
unsafe resynchronization. Normalization consumes known fields while retaining
the AST/raw record and unknown extensions with a `raw_ref` evidence URI.

## 10. GDB startup and handshake

Targets are loaded only after secure startup and capability negotiation. The
preferred launch is:

```text
gdb -q -nx
  -iex "set auto-load no"
  -iex "set debuginfod enabled off"
  -iex "set startup-with-shell off"
  -iex "set disable-randomization off"
  -iex "set may-call-functions off"
  --interpreter=mi4
```

On MI4 startup failure, create a fresh process using MI3. `-nx` and disabled
auto-load prevent untrusted init/target scripts. Debuginfod is off unless a
policy explicitly enables constrained URLs. Shell launch is off. ASLR keeps
normal application behavior unless a session explicitly requests otherwise.

Handshake order:

1. spawn GDB;
2. wait for a prompt or first valid MI record;
3. validate the interpreter;
4. enable MI async;
5. disable non-stop;
6. set output and safety parameters;
7. query MI capabilities;
8. optionally load the verified extension;
9. query extension capabilities; and
10. enter `READY`.

Initialization/probe commands:

```text
-gdb-set mi-async on
-gdb-set non-stop off
-gdb-set pagination off
-gdb-set style enabled off
-gdb-set print elements 200
-gdb-set may-call-functions off
-list-features
-info-gdb-mi-command -data-read-memory-bytes
-info-gdb-mi-command -data-write-memory-bytes
-info-gdb-mi-command -data-disassemble
-info-gdb-mi-command -break-watch
-info-gdb-mi-command -thread-info
```

MI async does not permit arbitrary target reads while running.

Capabilities are probed, not guessed from the version string, with
`-list-features`, `-info-gdb-mi-command`, `-list-target-features`, extension
capabilities, and safe read-only probes. Target capabilities are refreshed
after attach, connect, target change, and reconnect. Results state backend,
MI/GDB versions, supported features, and explicit limitations.

Capabilities are not booleans. Every target-scoped capability reports one of
`supported`, `unsupported`, `conditional`, `limited`, `unknown`, or
`temporarily_unavailable`, plus scope, constraints, source, and the revision
at which it was checked. In particular, target observation may be volatile or
target-defined rather than side-effect-free.

## 11. Scheduler and operations

One normal MI command is in flight per session. This preserves stream
attribution, explicit context, mutation order, deterministic transcripts, and
recoverable timeout semantics.

Command classes are `Read`, `Control`, `Mutation`, `Raw`, `Recovery`, and
`Shutdown`. Priority is shutdown, interrupt/cancel, recovery, control,
mutation, read, then background snapshot enrichment.

An agent operation can span many MI records. For example, continue-and-wait
sends `-exec-continue`, receives its result, observes `*running`, waits for a
later `*stopped`, builds a snapshot, and only then completes. Operations have
an ID, kind, state, originating revision, accepted event, and completed event.

Wait modes are `accepted`, `running`, `stopped`, and `snapshot`; every wait has
a finite default or explicit timeout. Timeout does not imply target death and
returns the operation ID, current target state, and whether interruption is
possible.

Cancellation modes:

- `DETACH_WAITER` (default): stop waiting; target continues;
- `INTERRUPT_TARGET`: stop waiting and issue `-exec-interrupt`;
- `TERMINATE_SESSION`: terminate GDB and a session-created inferior.

Escalation is API cancellation, detach waiter, optional MI interrupt, SIGINT
to the GDB process group if unresponsive, mark `UNRESPONSIVE`, and finally
terminate the worker/GDB when policy permits.

## 12. Explicit context

Every context-sensitive request carries `inferior_id`, `thread_id`,
`frame_id`, and `stop_id` as applicable. Backend execution prefers native
`--thread`/`--frame`, then thread-group filtering, then a scheduler critical
section that changes selection, executes, restores it, and verifies state.
Temporary selection is never visible to concurrent calls.

## 13. Inferior I/O

Local launches use an independent PTY:

```text
GDB stdin/stdout/stderr       MI pipes
inferior stdin/out/err        PTY slave
GDB/AI                        PTY master
```

The worker binds it with `-inferior-tty-set`. Every output record names its
source: `INFERIOR_PTY`, `MI_TARGET_STREAM`, `GDB_CONSOLE_STREAM`,
`GDB_LOG_STREAM`, or `SERVER_DIAGNOSTIC`.

UTF-8 output may be inline; binary data has a hex preview and artifact URI.
Each stream uses byte offsets and a ring. Defaults are 8 MiB inferior, 2 MiB
console, 2 MiB log, and 64 KiB maximum per read. If requested data has rolled
off, return a gap with the earliest available offset. Complete output may be
persisted as an artifact.

## 14. Canonical API

Every request contains:

```json
{
  "api_version": "gdb.ai/v1",
  "request_id": "req_...",
  "session_id": "sess_...",
  "method": "execution.control",
  "expected_revision": 42,
  "idempotency_key": "agent-step-173",
  "parameters": {}
}
```

Mutations use optimistic revision control and idempotency keys. Reads may omit
expected revision. Execution, breakpoint, and memory mutations must specify a
revision or explicitly accept the latest.

Every successful response contains the protocol/request/session IDs, current
revision and state axes, result, warnings, truncation/continuation fields,
artifacts, and evidence.

Canonical methods:

```text
session.create, session.get, session.list, session.close
session.acquire_write_lease, session.release_write_lease
session.attempt_recovery, session.capabilities, session.providers
session.transcript, session.event

target.launch, target.attach, target.connect_remote, target.open_core
target.detach, target.restart, target.kill

execution.control, execution.wait

breakpoint.create, breakpoint.update, breakpoint.delete, breakpoint.list

inspection.get, inspection.snapshot, inspection.diff, inspection.batch
inspection.snapshot_get

value.evaluate, value.create, value.children, value.update, value.release

memory.read, memory.write, memory.search, memory.compare
register.read, register.write
disassembly.read

inferior_io.read, inferior_io.write, inferior_io.send_eof
inferior_io.close_stdin (deprecated compatibility alias)
inferior_io.resize

tracking.add_expression, tracking.add_memory, tracking.remove, tracking.list
signal.get, signal.update

agent.probe, agent.experiment, agent.hypothesis_check
kernel.inspect, kernel.monitor

artifact.get, events.wait
raw.mi, raw.console
```

## 15. MCP projection

The canonical API remains independent of MCP. MCP exposes a compact tool set
with machine-readable structured content and a short text summary. Large
transcripts, memory, and binary data use resource URIs. Cancellation and
progress are supported.

Tools:

- `gdb_session`: create, launch, attach, connect_remote, open_core, status,
  capabilities, detach, restart, close;
- `gdb_run`: continue, interrupt, step, next, finish, step_instruction,
  next_instruction, until, wait;
- `gdb_breakpoints`: create, update, enable, disable, delete, list;
- `gdb_inspect`: stop_context, threads, stack, frame, locals, arguments,
  registers, modules, mappings, source, signals, breakpoints, capabilities,
  target;
- `gdb_evaluate`: explicit thread/frame/stop and denied side effects by
  default;
- `gdb_values`: create, children, update, release;
- `gdb_memory`: read, write, search, compare;
- `gdb_disassemble`: bounded around/range disassembly with optional bytes and
  source;
- `gdb_io`: read, write, send_eof, resize; `close_stdin` remains a deprecated
  compatibility alias and never claims an OS-level half-close;
- `gdb_batch`: multiple reads at the same stop revision; and
- `gdb_raw`: MI or console, registered only for `raw_admin`.

Launch supports program, argv, cwd, clean/inherited environment policy, PTY,
ASLR policy, entry stop, fork following, and detach-on-fork. Breakpoint kinds
include software/hardware/temporary/instruction breakpoints, write/read/access
watchpoints, and catchpoints. Locations support function, source/line,
address, module offset, and expression. Attributes include pending,
condition, ignore count, and thread/inferior scope.

All collection tools expose offset/limit or stable continuations and carry
session plus stop/revision context where relevant.

## 16. GDB/MI semantic mapping

Primary mappings:

| Semantic operation | GDB/MI command |
| --- | --- |
| Load executable | `-file-exec-and-symbols` |
| Arguments | `-exec-arguments` |
| Working directory | `-environment-cd` |
| Launch | `-exec-run` |
| Attach/detach | `-target-attach`, `-target-detach` |
| Remote/core | `-target-select remote|extended-remote|core` |
| Continue/interrupt | `-exec-continue`, `-exec-interrupt` |
| Step/next/finish | `-exec-step`, `-exec-next`, `-exec-finish` |
| Instruction step | `-exec-step-instruction` |
| Breakpoint CRUD | `-break-insert`, `-break-delete`, `-break-enable`, `-break-disable` |
| Watchpoint | `-break-watch` |
| Threads | `-thread-info` |
| Frames/args/locals | `-stack-list-frames`, `-stack-list-arguments`, `-stack-list-locals`, `-stack-list-variables` |
| Variable objects | `-var-create`, `-var-list-children`, `-var-update` |
| Evaluate | `-data-evaluate-expression` |
| Registers | `-data-list-register-names`, `-data-list-register-values` |
| Memory | `-data-read-memory-bytes`, `-data-write-memory-bytes` |
| Disassembly | `-data-disassemble` |
| Shared libraries | `-file-list-shared-libraries` |
| Inferior TTY | `-inferior-tty-set` |
| CLI fallback | `-interpreter-exec console` |

The service composes these into stable state and objects; it does not parse
equivalent human CLI output when structured MI exists.

## 17. Breakpoints

A logical breakpoint is separate from its one or more concrete locations.
Public IDs map to GDB numbers such as `7`, `7.1`, and `7.2`, and location
generation changes safely as libraries and templates resolve.

The registry reduces `=breakpoint-created`, `=breakpoint-modified`, and
`=breakpoint-deleted`. After any raw command, the complete list is queried
again.

Ordinary profiles cannot install arbitrary breakpoint command lists. The
controlled action set is `stop`, `log`, `capture_snapshot`,
`increment_counter`, `disable_after_hit`, and `continue_after_capture`, with
bounded hit counts. The controller implements these actions without arbitrary
CLI scripts.

## 18. Stop snapshots

On `*stopped`, the reducer immediately emits a minimal stop event and allocates
a stop ID. Snapshot enrichment must not delay that event. The worker then:

1. marks the snapshot `BUILDING`;
2. identifies the stopped thread/top frame;
3. reads semantic register roles;
4. reads a bounded stack;
5. reads current-frame arguments and locals;
6. disassembles around PC;
7. resolves modules and mappings;
8. computes tracked-state changes;
9. persists the snapshot; and
10. emits `SnapshotReady` or a partial/failed status.

Profiles:

| Profile | Content |
| --- | --- |
| `minimal` | reason, thread, PC, function, source |
| `brief` | minimal + 3 frames + PC/SP/FP + 8 nearby instructions |
| `standard` | brief + 8 frames + current-frame simple args/locals |
| `deep` | explicitly bounded registers, variables, stack, and memory |

Snapshots include snapshot/stop/revision/profile, normalized reason and
signal, focus IDs, location, register roles, stack, args, locals,
disassembly, tracked changes, warnings, partial status, and evidence URIs.
Failure of one enrichment returns a partial snapshot with a stable warning;
it never discards all available stop evidence.

## 19. Snapshot diffs and tracking

There is no implicit whole-process memory diff. Diff scope is limited to
semantic/explicit registers, tracked expressions and memory ranges, call-chain
summary, bounded simple locals in the current frame, and module/mapping
changes.

Tracked expressions define expression, thread/frame scope, format, and a
maximum value size. Tracked memory defines an address expression, bounded
length, changed-range output, and bounded history. Memory diff results report
offset and before/after bytes only for changed ranges.

## 20. Values and expressions

Simple one-shot evaluation uses `-data-evaluate-expression`. Structured,
pageable, or cross-stop tracking uses MI variable objects. Value objects carry
their stop ID, expression, type, value, child metadata, and presentation.

Defaults and maxima:

```text
children default/max       100 / 1000
recursion default/max      1 / 8
value text default/max     16 KiB / 1 MiB
```

Evaluation denies inferior function calls by default. A distinct high-policy
`inferior.call` API represents a mutation. Read-only evaluation saves and
temporarily disables `may-call-functions`, `may-write-memory`, and
`may-write-registers`, restores them in a finally path, and marks consistency
dirty/reconciles if restoration fails. String regexes are not a security
boundary.

## 21. Registers

Register names/numbers are discovered from the current target, not fixed.
Architecture providers map semantic roles:

```text
x86-64:  pc=rip sp=rsp fp=rbp return=rax
         args=rdi,rsi,rdx,rcx,r8,r9
AArch64: pc=pc sp=sp fp=x29 return=x0 args=x0..x7
```

Roles also include flags, syscall number/return, and TLS. Availability follows
the actual target description.

Register writes are mutations requiring lease, revision, expected stop, and a
reason. Results include before/after values and snapshot invalidation.

## 22. Memory

Reads accept a hexadecimal address, bounded length, format, and partial-read
policy. Inline responses include base64, hash, and actual length. Large reads
return length/hash/preview plus a content-addressed artifact.

Defaults:

```text
inline bytes          4 KiB
logical read maximum  16 MiB
backend chunk         64 KiB
```

Writes use compare-and-swap with expected bytes or SHA-256 and the expected
stop ID. A mismatch returns `MEMORY_PRECONDITION_FAILED`. Success audits old
and new hashes, increments revision, invalidates affected caches, and emits
`MemoryChanged`.

Search always has an explicit start, length, bounded pattern, and maximum
results. There is no unbounded “search all process memory” default.

## 23. Disassembly

Disassembly returns architecture, syntax, normalized range, and bounded
instructions with address, offset, optional bytes, mnemonic/operands,
function, source, and current-PC marker. The backend uses
`-data-disassemble` and capability-selects opcode/source modes.

## 24. Modules, mappings, and source

Modules prefer `-file-list-shared-libraries` and expose normalized address
ranges, symbol status, path/name, and optional build ID.

Mappings use a provider chain:

```text
LinuxLocalProcProvider -> GdbStructuredProvider -> RemoteTargetProvider
  -> TrustedConsoleProvider -> KernelProvider
```

Local Linux reads `/proc/<pid>/maps` within the session namespace. Each range
has hexadecimal start/end/offset, permissions, device, inode, path, and
source. Remote results explicitly report partial data and limitations rather
than fabricating completeness.

Source maps translate build paths to workspace paths. Every source path is
canonicalized, checked against allowed workspace roots, and protected against
symlink escape.

## 25. Raw commands

Raw MI accepts a command name plus a separate argument array and timeout. The
backend generates the token; callers cannot inject one. Raw console always
uses `-interpreter-exec console` because direct CLI text in an MI interpreter
can produce unpredictable output and non-MI prompts.

Raw console accepts only an explicit host-safe command set. Shell, Python,
script, maintenance, monitor, target-selection, file-loading, settings, quit,
and unknown or abbreviated commands are rejected. The allowlisted verbs are:

```text
apropos, backtrace, break, catch, condition, continue, delete, disable,
disassemble, down, enable, finish, frame, help, ignore, info, list, next,
nexti, print, ptype, rbreak, run, show, step, stepi, tbreak, thread, until,
up, watch, whatis, x
```

`monitor` is available only through target-specific allowlisted providers.
Raw MI cannot select/attach a target, transfer files, change GDB safety
settings, replace executable/symbol paths, redirect the inferior TTY, enter a
CLI interpreter, or exit GDB; those actions use policy-checked semantic APIs.

Before a known managed raw command, set consistency to `MANAGED_DIRTY`; an
unknown raw command sets `TAINTED`. On completion, reconcile the declared
managed surface and return bounded output plus state/revision changes. A
managed path may reach `CLEAN`; a tainted path stays `TAINTED` unless the
session is recreated. A raw result is never merely an unstructured text blob.

## 26. Reconciliation

Reconciliation is mandatory after:

- raw console commands;
- unknown async events;
- delayed results following a command timeout;
- backend output contradicting controller state;
- unknown breakpoint IDs;
- target reconnect;
- potentially mutating extension commands;
- failure to restore temporary parameters; or
- thread/inferior registry mismatch.

The engine queries thread groups/inferiors, thread information, target
running/stopped/exited status, selected context, all breakpoints, shared
libraries, and target features, then verifies whether the current stop ID
remains valid.

Managed outcomes are `CLEAN`, `CLEAN_WITH_WARNINGS`, or `LOST`. Unknown raw
effects remain `TAINTED` even when core thread/breakpoint/target facts were
re-observed. In `LOST`, only status, transcript/artifact reads, explicit
recovery, and close are allowed. Ordinary mutations are rejected.

## 27. Stable errors

Protocol error codes:

```text
INVALID_ARGUMENT, INVALID_STATE, STALE_REVISION, STALE_CONTEXT,
NOT_FOUND, ALREADY_EXISTS, CONFLICT, WRITE_LEASE_REQUIRED,
WRITE_LEASE_EXPIRED, POLICY_DENIED, CAPABILITY_MISSING, UNSUPPORTED,
TARGET_RUNNING, TARGET_STOPPED, TARGET_EXITED, TARGET_DISCONNECTED,
TARGET_UNAVAILABLE, TIMEOUT, CANCELLED, OUTPUT_LIMIT,
MEMORY_PRECONDITION_FAILED, PARTIAL_READ, GDB_ERROR, GDB_UNRESPONSIVE,
GDB_EXITED, MI_PARSE_ERROR, MI_PROTOCOL_LIMIT, CONSISTENCY_DIRTY,
CONSISTENCY_LOST, INTERNAL
```

Errors include code, safe message, retryability, current state/revision,
suggested actions, optional backend detail, and evidence. Human GDB error text
is supplemental detail, never the only API semantics.

## 28. Security

Threats include malicious inferiors, ELF/DWARF/symbol data, auto-load scripts,
pretty-printers, remote stubs, prompt-injected agent actions, unbounded GDB
output, unauthorized attach, host-command execution through raw interfaces,
inferior function-call side effects, transcript/memory leakage, and
cross-session data exposure.

Profiles:

| Profile | Allowed capability |
| --- | --- |
| `offline_core` | core/symbol/stack/value/memory reads; no execution |
| `live_observer` | stopped-state observation; no breakpoints, writes, or interrupt |
| `debug_control` | breakpoints, execution, stepping, reads; no direct writes/calls |
| `lab_mutation` | memory/register writes, input, and controlled calls |
| `raw_admin` | audited raw MI/CLI and extension management |

GDB observer/write-prevention settings are defense in depth; the server policy
engine remains authoritative.

Every canonical method declares an effect:

```text
READ, CONTROL, TARGET_MUTATION, HOST_MUTATION, NETWORK, RAW
```

Examples: inspection is `READ`; continue and breakpoints are `CONTROL`;
memory writes/calls are `TARGET_MUTATION`; shell is `HOST_MUTATION`; remote
connect is `NETWORK`.

Secure defaults:

```text
init files                  disabled
target auto-load scripts    disabled
pretty-printer auto-load    disabled
debuginfod/network          disabled
shell launch                disabled
ASLR                        normal program behavior
inferior function calls     disabled
raw CLI and MI              disabled
remote network              disabled
PID attach                  disabled
memory/register writes      disabled
```

Audit records include caller, session/lease, original API request, schema
result, policy decision, generated MI and token, raw MI evidence references,
inferior input, memory/register writes, function calls, raw commands,
revisions, operation outcome, errors/timeouts, artifact access, and close
reason. Sensitive fields support `redact`, `hash-only`, `metadata-only`, and
`encrypted` handling. Logs do not emit full memory, environment values,
inferior input, or sensitive expression results.

## 29. Artifacts and resources

Artifacts are SHA-256 content-addressed:

```text
gdbai://artifact/sha256:<digest>
```

Artifact types include memory dumps, inferior output, MI transcripts, core
metadata, snapshots, source excerpts, large values, disassembly blocks, and
audit exports.

Session resources include:

```text
gdbai://session/<id>/status
gdbai://session/<id>/capabilities
gdbai://session/<id>/events
gdbai://session/<id>/event/<seq>
gdbai://session/<id>/transcript
gdbai://session/<id>/snapshot/<stop-id>
gdbai://session/<id>/inferior/<id>/output
gdbai://session/<id>/breakpoints
```

Artifact metadata contains URI, MIME type, size/hash, creating session and
operation, sensitivity, and expiry. Resource authorization is checked on
every access.

## 30. Persistence and replay

SQLite WAL persists sessions/configuration, capabilities, operations, state
revisions, breakpoints, tracking definitions, artifacts, policy decisions,
and the audit index. The append-only journal records API requests, MI input,
MI results/async/stream metadata, normalized events, revisions, and snapshots.
Large data is stored in the artifact store, not SQLite.

Transcripts use JSONL with monotonically increasing sequence values. A replay
command:

```text
gdb-ai replay session.jsonl
```

must validate parsing, rebuild deterministic reducer state, compare reducer
versions, rebuild snapshots, reproduce mismatches, and support protocol
migration tests. Replay rejects disagreement between adjacent raw MI and
normalized events and between reducer output and recorded state checkpoints.
It never executes an inferior or claims to restore a process. A complete
deterministic replay journal includes MI input/output,
PTY events, provider results, API requests, policy decisions,
deadlines/cancellation, ID allocation (or a deterministic seed), and state
transitions. An MI-only transcript can validate parsing and MI-derived
reduction, but cannot recreate external `/proc`, provider, time,
cancellation, or policy inputs.

On worker/GDB death, backend becomes `DEAD`, session becomes `FAILED`, and the
service retains configuration, transcript, last known state, snapshots,
artifacts, GDB stderr, and crash metadata. `session.clone_from_config` may
start a new session ID but cannot claim live-state recovery.

## 31. Providers and plugins

Providers are `Send + Sync`, declare a descriptor, probe availability, and
execute a bounded typed request. Descriptors state name/version, supported
targets, required capabilities, and effects.

Built-ins:

- **Generic GDB:** threads, stack, locals, registers, memory, disassembly,
  breakpoints, run control.
- **Linux userland:** `/proc` mappings, ELF metadata, crash/signal context,
  source mapping, shared-library correlation.
- **Remote:** normalized capability and connection lifecycle, reconnect/path
  policy, remote process metadata.
- **Userland security:** bounded crash triage, PC/SP/fault instruction,
  mappings, tracked ranges, crash signatures, two-snapshot comparison; no
  exploit payload construction.
- **Linux kernel:** symbols/modules/tasks/stacks/panic context and an allowlisted
  QEMU/KGDB monitor adapter.

Kernel providers may combine MI, controlled console, trusted Python helpers,
and target adapters, but all results use the canonical schema and declare
source and incompleteness. Every provider result includes provider/version,
mechanism, and evidence URI.

## 32. Backend boundary

The core keeps a narrow async `DebugBackend` interface for start, typed command
execution, events, interrupt, reconciliation, and shutdown. Version 1 has one
implementation: GDB/MI.

MI strings such as `-break-insert`, `^done`, and `*stopped` are confined to the
GDB/MI backend. The canonical core sees typed commands such as
`CreateBreakpoint`, `Resume`, and `ReadMemory`, and typed events such as
`Stopped`.

This boundary exists to prevent MI leakage, not to pretend that an LLDB
backend is already planned or supported.

## 33. Worker loop and ownership invariants

The worker selects over API requests, GDB stdout records, GDB stderr,
inferior PTY bytes, deadlines, and watchdog ticks, then dispatches the next
eligible scheduled command.

Strict ownership:

```text
only the reducer changes current state
only the scheduler writes GDB/MI commands
only the artifact writer writes large data
every external request passes the policy engine
```

## 34. Session creation

Creation validates profile/workspace/target policy, creates the worker sandbox,
starts GDB MI4 (or a fresh MI3 fallback), parses and handshakes, verifies safe
parameters, negotiates capabilities, optionally loads the trusted extension,
and enters `READY`.

The response includes a session ID/status resource, state, backend name/MI
version, profile, capabilities, and limitations.

## 35. Target lifecycle

Launch validates/canonicalizes program, cwd, and source maps; configures
argv/environment; allocates a PTY; loads symbols; sets args/cwd/TTY;
configures fork/signal/ASLR policy; applies the entry stop; runs; and waits for
actual async running/stopped events.

Attach requires an attach-capable profile, an allowed PID and matching
UID/namespace policy, explicit audit, and configured detach/kill behavior on
close.

Remote connect requires endpoint allowlisting, pinned DNS resolution, a
network namespace, finite timeout/retries, and capability refresh. Unsupported
features return `CAPABILITY_MISSING`.

Core requires executable and core paths. Its inferior state is `CORE`;
execution/mutation capabilities are false and inspection is true.

## 36. Threads, inferiors, fork, and exec

Thread groups map to inferiors. The domain supports multiple inferiors from the
start instead of binding one PID to the session root.

Version 1 is all-stop: one stop produces a global stop ID and a coherent
stopped view. Continue applies to the requested inferior or all threads
according to typed semantics.

Fork/exec configuration explicitly states:

```text
follow_fork      parent | child
detach_on_fork   true | false
follow_exec      same-inferior
```

New inferiors receive generation-safe IDs, refresh thread groups, inherit or
recompute breakpoint scope, and record fork/exec evidence.

## 37. Signal policy

Signal handling uses structured `stop`, `print`, and `pass` booleans keyed by
signal, never agent-built `handle` CLI strings. A trusted MI extension or
controlled console provider applies it. Changes are control mutations and are
audited.

## 38. Observability

Required metrics:

```text
gdbai_sessions_total
gdbai_sessions_active
gdbai_session_failures_total
gdbai_gdb_start_failures_total
gdbai_mi_records_total
gdbai_mi_parse_errors_total
gdbai_mi_unknown_classes_total
gdbai_commands_total
gdbai_command_latency_seconds
gdbai_command_timeouts_total
gdbai_target_stops_total
gdbai_snapshot_latency_seconds
gdbai_snapshot_partial_total
gdbai_raw_commands_total
gdbai_reconciliations_total
gdbai_consistency_lost_total
gdbai_response_truncations_total
gdbai_artifact_bytes_total
gdbai_inferior_output_dropped_bytes_total
```

One agent request traces validation, authorization, routing, policy,
scheduling, MI send/result, state transition, snapshot, artifact, and response
serialization. Logs default to metadata and hashes and apply redaction policy.

## 39. Configuration

The supported TOML surface is:

```toml
[server]
transport = "stdio"
max_sessions = 8
max_http_sessions = 128
http_session_idle_ms = 900000

[gdb]
path = "/usr/bin/gdb"
preferred_mi = "mi4"
fallback_mi = "mi3"
python_extension = "/usr/lib/gdb-ai/gdb_ai.py"

[gdb.defaults]
mi_async = true
non_stop = false
auto_load = false
debuginfod = false
startup_with_shell = false
preserve_aslr = true
allow_inferior_calls = false

[limits]
mi_record_bytes = 8388608
tool_response_bytes = 262144
inline_memory_bytes = 4096
memory_read_bytes = 16777216
inferior_output_ring_bytes = 8388608
console_output_ring_bytes = 2097152
stack_frames = 64
value_children = 1000
value_depth = 8
session_artifact_bytes = 536870912
journal_bytes = 67108864

[artifacts]
backend = "filesystem"
path = "/var/lib/gdb-ai/artifacts"

[persistence]
sqlite = "/var/lib/gdb-ai/gdb-ai.sqlite"

[security]
default_profile = "debug_control"
network_default = "deny"
attach_default = "deny"
raw_default = "deny"
```

## 40. Repository shape

The target repository is independently versioned and can be mounted as a
binutils-gdb submodule. The desired component boundaries are:

```text
gdb-ai/
├── Cargo.toml
├── crates/
│   ├── gdb-ai-protocol/
│   ├── gdb-ai-domain/
│   ├── gdb-ai-mi/
│   ├── gdb-ai-backend/
│   ├── gdb-ai-backend-gdb-mi/
│   ├── gdb-ai-session/
│   ├── gdb-ai-policy/
│   ├── gdb-ai-artifacts/
│   ├── gdb-ai-persistence/
│   ├── gdb-ai-providers/
│   ├── gdb-ai-mcp/
│   ├── gdb-ai-jsonrpc/
│   ├── gdb-ai-server/
│   └── gdb-ai-cli/
├── gdb-extension/
├── sdk/python/
├── sdk/typescript/
├── schemas/
├── tests/{mi-fixtures,parser,replay,integration,targets,remote,
│          compatibility,security,chaos}/
├── fuzz/{mi_parser,mi_framer,state_reducer}/
├── docs/
└── packaging/{container,systemd,distro}/
```

This is a logical boundary map, not permission to create empty crates. The
initial implementation may combine components that change together, then
split only when real ownership, dependency, build, or security boundaries
require it. The final public API and invariants remain unchanged.

## 41. CLI

Required commands:

```text
gdb-ai serve --stdio
gdb-ai serve --unix /run/user/1000/gdb-ai.sock
gdb-ai serve --http 127.0.0.1:8080

gdb-ai doctor
gdb-ai session list
gdb-ai session inspect <session-id>
gdb-ai session close <session-id>

gdb-ai transcript export <session-id>
gdb-ai transcript inspect <file>
gdb-ai replay <file>

gdb-ai schema export
gdb-ai capabilities
```

`doctor` checks GDB executable and MI4/MI3, Python/extension, PTY, ptrace,
target architecture, gdbserver, workspace permissions, sandbox features,
network policy, artifact store, and SQLite.

## 42. Tests

Parser unit coverage:

```text
all record types; empty tuple/list; value and result lists; duplicate keys;
unknown classes/fields; escapes; non-UTF-8 streams; partial and multiple
records; every-byte chunking; LF/CRLF; long tokens/strings; deep nesting;
EOF; malformed suffixes
```

Property/fuzz invariants:

```text
encode(parse(valid)) preserves semantics
chunk boundaries do not change AST
unknown fields never panic
bounded input yields bounded memory
parser never loops forever
same event sequence yields same reducer state
revision is monotonic
running always invalidates old frames
```

Replay fixtures cover native x86-64/AArch64, attach, core, gdbserver,
disconnect, fork/exec, shared libraries, pending breakpoints, watchpoints,
signals, exit, and GDB errors.

Integration targets cover normal main/exit, SIGSEGV/SIGABRT, threads and
rapid churn, blocking/binary stdin, large output, dlopen/dlclose, PIE,
stripped/optimized binaries, pending and multi-location breakpoints,
hardware breakpoints/watchpoints, fork/exec, attach/detach, core, gdbserver,
remote disconnect, target/GDB death, and raw commands changing selection or
breakpoints.

Compatibility CI covers GDB 13-17 MI4 and GDB 9-12 MI3; x86-64/AArch64;
native/attach/core/gdbserver; full/partial/no symbols; PIE/non-PIE; and
single/multi-thread. It must not depend on one rolling image.

Chaos injects delayed/interleaved MI, stderr noise, sudden target/GDB exit,
PTY EOF, remote disconnect, command timeout, artifact/SQLite failure, client
cancellation, lease expiry, and raw-command state changes.

Security tests cover malicious `.gdbinit`, target auto-load/Python and
pretty-printers, oversized DWARF/MI, traversal and symlink escape,
unauthorized attach/remote/raw shell/raw Python/function call/writes,
artifact authorization, secret leakage, and session isolation.

## 43. Protocol compatibility

The major protocol is `gdb.ai/v1`. Optional response fields, capabilities,
and enum values may be added. Clients tolerate unknown response fields.
Servers reject unknown mutation actions. Existing field semantics never
change silently. Removal or semantic change requires a major version. Every
schema has an ID and content hash.

Clients request capabilities rather than inferring them from versions. Missing
target-scoped requirements return `CAPABILITY_MISSING` with the missing list
and scope.

## 44. Non-negotiable invariants

1. Every GDB output record enters the journal before it changes state.
2. Only the reducer changes session state.
3. Only the scheduler writes commands to GDB.
4. Agent APIs never depend on selected thread or selected frame.
5. `^done` never implies that a target actually stopped or ran.
6. Every `*running` invalidates all old stop-scoped handles.
7. Every mutation requires a write lease, revision, and policy decision.
8. Every response has a size bound.
9. Every large payload is returned through an artifact.
10. Every raw command marks consistency `MANAGED_DIRTY` or `TAINTED` before
    execution.
11. Every raw command is followed by reconciliation.
12. Timeout never silently means the target terminated.
13. Every partial result is explicitly labelled.
14. Target-dependent capabilities are re-probed after connection changes.
15. Every memory or register write is audited.
16. An inferior call never masquerades as a read-only evaluation.
17. Every filesystem path is canonicalized and workspace-policy checked.
18. GDB and inferior output are never merged into one stream.
19. Unsupported backend capability fails explicitly; it never fakes success.
20. The same complete event journal deterministically produces the same
    reducer state; an MI-only transcript makes no claim about external inputs.

## 45. Acceptance criteria

Correctness:

- 10,000 create/launch/stop/close cycles without unrecoverable deadlock;
- arbitrary MI chunking does not change parsed output;
- unknown MI fields do not crash a session;
- old frame/value requests always fail after running resumes;
- reconciliation restores breakpoint/thread registries after raw commands;
- target exit, disconnect, and GDB exit remain distinguishable.

Boundedness:

- no tool call lacks a deadline;
- no unbounded stack, variable, memory, or output request;
- no full large memory block enters agent context;
- every paged endpoint has a stable continuation token.

Security:

- target scripts, network, shell/Python/source, memory/register writes, and
  inferior calls are denied by default;
- ordinary agents cannot acquire `raw_admin`;
- every mutation has a complete audit trail.

Recovery:

- command timeout supports cancellation or interrupt escalation;
- watchdogs clean unresponsive GDB;
- one worker crash cannot affect another session;
- failed sessions retain transcript/artifacts;
- replay rebuilds the last known controller state.

Agent usability:

- ordinary debugging needs neither MI construction nor terminal parsing;
- every stop has bounded context;
- every observation names revision and stop ID;
- every fact links to evidence;
- run control, inferior I/O, and observation are independently usable.

## 46. Boundary with DAP and LLDB MCP

GDB DAP is primarily IDE-oriented. Its REPL can still execute blocking or
state-changing CLI commands, so DAP may become an adapter but never the core
state or security foundation.

LLDB's MCP session URIs, create/list/close operations, and command
serialization are useful precedents. Its command-interpreter text model and
separate inferior output are not sufficient here. GDB/AI keeps persistent
sessions/resources while placing typed semantic tools, independent PTY I/O,
and event reduction in the core.

## 47. Final system and delivery phases

The complete system is:

```text
Agent
  -> MCP / JSON-RPC adapter
  -> canonical gdb.ai/v1 request
  -> gateway (auth, schema, lease, routing)
  -> worker (policy, scheduler, capabilities, reducer, snapshot/diff,
             artifacts, audit, providers)
  -> GDB/MI backend (formal parser, tokens, async normalization,
                     reconciliation, trusted extension, inferior PTY)
  -> native / attach / core / gdbserver / remote target
```

The product is the combination of persistent sessions, a strict asynchronous
state machine, bounded and traceable observations, an agent-semantic API, and
isolation/authorization/audit/recovery. Backend and provider layers contain
GDB version and target differences so agents never have to recover terminal
state themselves.

Implementation order is dependency-driven:

1. formal parser/framer/encoder, lossless AST, limits, fixtures, fuzz target;
2. domain events, reducer, deterministic IDs/revisions, transcript replay;
3. GDB process, handshake/capabilities, scheduler/token correlation, PTY;
4. sessions, leases, policy, deadlines/cancellation, audit, persistence;
5. launch/core/attach/remote lifecycle and explicit-context operations;
6. breakpoints, bounded inspection, values, registers, memory, disassembly;
7. snapshots/diffs/tracking, reconciliation, providers, artifacts/resources;
8. canonical schemas, MCP stdio/HTTP, JSON-RPC, SDKs, CLI;
9. sandbox/package deployment and observability;
10. compatibility, integration, replay, chaos, and security acceptance gates.

No phase may weaken the invariants in section 44. Capability reporting must
remain truthful while later phases are incomplete.

## 48. Language ownership

Rust is the primary product language, not the only repository language. The
ownership boundary is fixed:

| Component | Language | Authority |
| --- | --- | --- |
| Core service | Rust | Production control plane |
| GDB/MI parser | Rust | Streaming trust boundary |
| Session worker and state machine | Rust | Sole debugging-state owner |
| MCP, JSON-RPC, and HTTP | Rust | External protocol boundary |
| Policy, audit, artifacts, persistence | Rust | Security and durable evidence |
| Optional GDB extension | Python 3 | Small trusted MI/API bridge only |
| Python SDK | Python | Agent/research integration |
| TypeScript SDK | TypeScript | Node.js integration |
| Benchmarks and experiment analysis | Python | Evaluation and reports |
| Debug targets | C, C++, Rust | Reproducible debugging scenarios |
| Build/deployment helpers | Shell or Python | Non-authoritative automation |

Expected mature code distribution is approximately 75-85% Rust, 10-15%
Python, 3-5% TypeScript, and 3-5% C/C++ target fixtures. Percentages are a
forecast, not a quota.

The non-replaceable rule is:

> MI parsing, session ownership, the reducer/state machine, scheduler, policy
> engine, and server are implemented in Rust.

The core is an external controller over GDB/MI pipes and an inferior PTY. It
does not link private GDB libraries or require C++ merely to be close to GDB.
Rust owns subprocess lifecycle, asynchronous streams, timeouts/cancellation,
protocol parsing, state transitions, serialization, isolation controls, and
long-running memory bounds.

The preferred Rust stack remains Tokio, serde/serde_json, bytes, thiserror,
tracing, axum/tower, schemars plus JSON Schema validation, ULID, SHA-256,
base64, SQLite, and Unix PTY/process primitives. Property tests, snapshots,
temporary isolated filesystems, and cargo-fuzz/libFuzzer cover parser and
reducer boundaries. The MI parser is handwritten and streaming; a parser
generator is not required for this grammar.

The implemented optional Python extension may query narrow GDB Python APIs,
aggregate data
that native MI cannot express, return dictionaries/lists as MI results, and
emit private notifications. It cannot own MCP, authoritative session state,
persistence, authentication, large asynchronous work, or background access to
GDB objects. All GDB API calls execute on GDB's main/event thread; cross-thread
work returns through mechanisms such as `gdb.post_event`.

Python SDKs never bypass the canonical API to send arbitrary MI. Providers
never bypass the scheduler. MCP adapters contain no GDB-specific logic. The
Python extension remains optional and is activated only when a measured
native-MI gap requires it. Loading requires an absolute path and configured
SHA-256 digest.

## 49. Document roles and implementation layering

Sections 1-47 are the North-star architecture. They describe final boundaries,
invariants, security posture, and extension direction. They are not one flat
version-1 backlog.

Delivery is split into four specifications:

1. **North-star Architecture** (this document): final boundaries and
   invariants.
2. **Core Vertical Slice** (section 50): the first independently useful
   implementation.
3. **Agent Semantics** (section 51): hypothesis, experiment, evidence, probe,
   tracking, and observation-budget abstractions.
4. **Evaluation Protocol** (section 52): measures whether structured dynamic
   debugging improves Agent outcomes.

Complexity categories:

```text
Core correctness       required before any useful release
Production extension   implemented only for a concrete deployment need
Future provider        retained as a boundary, not prebuilt as scaffolding
```

Core correctness includes formal MI framing/parsing, token correlation,
result/async separation, PTY separation, stop IDs, stale-handle invalidation,
timeouts/interrupts, bounded output, and controlled raw access. These are not
removed in the name of an MVP.

Production extensions include physical gateway/supervisor/worker process
separation, multi-user leases, persistent operation routing, namespace/cgroup
orchestration, HTTP, and broad observability. Future providers include kernel,
LLDB, vendor JTAG, and a public plugin SDK.

Version 1 uses one Rust gateway process with one session actor and one
sandboxed GDB child per session. Stdio, Unix, and HTTP adapters share the same
Gateway. The narrow `DebugBackend` trait and actor ownership preserve the
process boundary; deployments add a separate service supervisor when their
fault-domain or scaling policy requires it. Empty crates and speculative
interfaces are not created.

## 50. Core vertical slice

The first shippable slice supports Linux x86-64, local executable launch,
all-stop operation, one process, one transport, and one GDB process per
session. It contains exactly:

```text
session create / launch / status / close
software breakpoint create / delete / list
continue / interrupt / wait
minimal stopped event
bounded stack / locals / registers / evaluate
bounded memory read and disassembly
inferior PTY read / write
stop_id and stale-context enforcement
bounded structured responses and evidence references
controlled raw console escape hatch
complete local event journal and deterministic reducer replay
```

Required implementation internals:

- MI4 preferred with a fresh-process MI3 fallback;
- a bounded lossless byte parser and arbitrary chunk framing;
- one command in flight, controller-owned tokens, and async-driven target
  transitions;
- a Tokio session actor as the only state and GDB-command owner;
- GDB control pipes separated from the inferior PTY;
- finite command/wait deadlines and explicit interrupt;
- an immediate minimal stop record; and
- on-demand, budgeted enrichment.

The original vertical slice excluded attach/core/remote, HTTP, SDKs, leases,
tracking, providers, and deployment controls. The completed version 1 adds
those surfaces while retaining capability gates for host AArch64 execution,
gdbserver, bubblewrap, Python-enabled GDB, KGDB/QEMU, and external cgroup or
service-supervisor policy. Non-stop and a mandatory Python extension remain
explicit non-goals.

Snapshot policy is two-stage:

```text
*stopped
  -> immediate minimal event: reason, inferior/thread, PC, frame 0,
     source location, stop_id, enrichment availability
  -> explicit or policy-driven enrichment under an observation budget
```

`standard` enrichment defaults to eight frames, simple current-frame locals,
semantic PC/SP/FP registers, and a small PC disassembly window. Crash triage
adds signal, fault address/instruction, relevant mapping, and a bounded stack.
Probe capture reads only declared fields. Deep inspection is always explicit.

## 51. Agent-oriented debugging semantics

The control plane alone can become a good debugger daemon without improving
Agent reasoning. The `/ai` layer therefore adds typed experiment semantics
after the vertical slice is stable:

- **Probe:** location/condition plus an explicit bounded capture plan, hit
  limit, and stop/continue policy.
- **Hypothesis check:** a falsifiable runtime claim, required observations,
  success/failure predicate, and linked evidence.
- **Experiment:** setup, controlled execution, observation budget, result, and
  cleanup as one auditable operation.
- **Tracked state:** only values/memory/register roles relevant to the current
  question, with bounded history and diffs.
- **Observation budget:** maximum calls, bytes, frames, values, instructions,
  wall time, and Agent-context bytes.
- **Evidence link:** every conclusion references concrete stop, expression,
  memory, transcript, or artifact data.

A probe can express, without a long sequence of low-level calls:

```json
{
  "location": {"function": "parse_packet"},
  "condition": "length > 4096",
  "capture": [
    {"expression": "length"},
    {"expression": "request->type"},
    {"stack": {"limit": 4}}
  ],
  "max_hits": 20,
  "stop_policy": "on_condition"
}
```

Semantic operations compile to ordinary scheduler commands and reducer events;
they never introduce a second source of state truth.

## 52. Agent-effect evaluation

Correctness and security gates prove that the service works, not that it helps
an Agent. Evaluation compares:

```text
A. shell plus CLI GDB
B. persistent raw GDB
C. structured GDB/AI control plane
D. structured GDB/AI plus semantic probes/experiments
```

Tasks are labelled `static-solvable`, `runtime-helpful`, or
`runtime-required`. Report at least:

- final task resolution rate;
- root-cause localization rate;
- turns to first useful breakpoint;
- turns to first useful runtime evidence;
- proportion of debugger calls that do not test a relevant hypothesis;
- rate at which runtime evidence corrects an incorrect hypothesis;
- tokens consumed before root-cause localization;
- debugger calls per successful task;
- raw-command usage rate; and
- wall-clock time and target resumes per successful task.

Correctness, boundedness, security, replay, and chaos tests remain release
gates. Agent-effect metrics decide whether a semantic abstraction belongs in
the product; they are not replaced by architecture completeness.

## 53. Corrected guarantees

The following wording supersedes any broader interpretation elsewhere in this
document:

- Determinism applies to the complete event journal, not MI output alone.
- Raw reconciliation covers the declared managed state surface. Unknown raw
  commands produce `TAINTED`; they cannot prove complete GDB equivalence.
- Capabilities are scoped status records with constraints, not global booleans.
- `READ` is split conceptually into control-plane reads, ordinary target
  observations, volatile target reads, and target-defined effects. Providers
  classify MMIO and similar ranges conservatively.
- Snapshot enrichment is minimal-first and budgeted on demand.
- The North-star matrix is not a claim that the vertical slice already
  supports every target, transport, architecture, SDK, or isolation feature.

## 54. Version 1 implementation conformance

The repository implements every canonical method in section 14 without a
placeholder or deferred response. MCP exposes the complete semantic surface,
including values, registers, tracking, batching, Agent experiments, events,
raw administration, and the conditional kernel provider.

Implemented release surfaces:

```text
MI4 with fresh-process MI3 fallback
native launch, allowlisted attach, core, gdbserver/RSP, detach/restart/kill
write leases, revisions, idempotency, policy, audit, rate limits
breakpoints/watchpoints/catchpoints and generation-safe locations
threads/frames/locals/arguments/registers/values/memory/disassembly
minimal and enriched snapshots, tracked state, changed ranges, diffs
raw MI/CLI classification, durable taint, managed reconciliation
MCP stdio, MCP Streamable HTTP, Unix socket, canonical JSON-RPC
Python and TypeScript SDKs, schema hashes, CLI, metrics, replay
bubblewrap, no_new_privs, rlimits, workspace/source-map enforcement
hash-pinned optional GDB Python extension and provider provenance
parser/reducer fuzz targets, native/core/attach/remote integration fixtures
```

The service never converts an absent host feature into success. Runtime
capabilities report bubblewrap, network isolation, Python extension, target
features, reverse support, memory/watchpoint availability, and provider
limitations. Remote, attach, and monitor access remain deny-by-default and
require explicit allowlists. Kernel inspection remains conditional on a
configured KGDB/QEMU target and symbols.

Release verification commands and deployment assets are maintained in
`README.md`, `packaging/`, `schemas/`, `fuzz/`, and `tests/`. The 10,000-cycle
soak and the GDB 13-17/AArch64 matrix are release-environment qualification
gates; a development host that lacks those binaries reports the missing gate
instead of claiming it ran.
