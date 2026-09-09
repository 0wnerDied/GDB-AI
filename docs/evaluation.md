# Evaluation methodology

GDB/AI compatibility tests establish specified behavior on the configurations
they exercise. They do not establish that an Agent solves arbitrary debugging
tasks faster, with fewer tokens, or with greater accuracy. A task-level study
must define an independently checkable diagnosis criterion before trials begin.

Compare GDB/AI with direct GDB CLI and direct GDB/MI under the same model, tool
access, target, symbols, host resources, and time budget. Let each interface use
its normal batching and scripting facilities. Record exact versions and trial
conditions, vary execution order, and report variation or uncertainty with
aggregate results. Cold startup and reused-session work require separate
measurements, as do independent sessions and several clients sharing one
session.

## Study measures

The primary outcome is whether the Agent reaches the predefined diagnosis.
Known failures and timeouts count as unsuccessful outcomes; a missing value
means that the outcome was not observed. The remaining measures describe cost
and behavior and cannot substitute for diagnostic success.

| Measure | Required report |
| --- | --- |
| Diagnostic success | Ground-truth criterion, successes, trials, failures, and timeouts |
| Interaction cost | Agent tool calls and backend debugger commands counted separately |
| Context cost | Model, tokenizer, discovery overhead, and consumed tokens; bytes reported separately |
| Elapsed time | End-to-end wall time with startup, execution, waits, and helper costs identified |
| Concurrency | Worker and session count, throughput, latency distribution, and resource use |
| Race localization | Repeated trials, scheduling conditions, and evidence connecting the observation to the cause |

The repository's JSONL format records variants `A` through `D` and task
classes `static-solvable`, `runtime-helpful`, and `runtime-required`. The
[example input](../benchmarks/python/example.jsonl) demonstrates the format and
contains no empirical result or performance claim. Summarize a supplied result
set and verify the utility with:

```sh
python3 benchmarks/python/evaluate.py path/to/results.jsonl
python3 -m unittest discover -s benchmarks/python
```

`resolved` and `root_cause_localized` accept booleans or numeric `0` and `1`.
Their reports contain successes, observed total, missing outcomes, and a rate
from zero to one. Cost and per-trial rate metrics contain count, missing,
median, and inclusive p90; one sample supplies both statistics. Null values are
excluded and counted explicitly. Numeric costs must be finite and nonnegative,
and rates must remain between zero and one.

## Fixed native evidence comparison

The dependency-free native comparison is a controlled interface-cost check on
Linux x86-64. It rotates direct CLI, direct MI, and projected MCP execution
order and uses the same GDB and MI version in both MI-backed arms. Run its four
evidence cases with:

```sh
cargo build --locked --release -p gdb-ai
python3 benchmarks/python/compare_native.py target/release/gdb-ai
python3 benchmarks/python/compare_native.py target/release/gdb-ai --case threads
python3 benchmarks/python/compare_native.py target/release/gdb-ai --case full-stack
python3 benchmarks/python/compare_native.py target/release/gdb-ai --case expressions
```

The default signal case checks stack, argument, and variable values in a
generated fixture. The thread case stops at `pthread_join` and checks three
stacks, worker inputs, and lock-pointer arguments; it requires matching pthread
debug information. The full-stack case checks arguments and typed locals,
including aggregate contents, across three frames. The expressions case checks
sixteen scalar, structure, and array results while permitting CLI and MI to
pipeline their commands. Use `--mi mi3` or `--mi mi2` only when evaluating an
older GDB that does not provide MI4.

Each projected cold sample creates a session, optionally installs its
breakpoint, launches, and inspects in one request. Bootstrap cost belongs to
the cold capture, and projected MCP therefore has no separately measured
startup row. Timers stop when the final response arrives, before fact
assertions; teardown and discovery are excluded. The script reports raw
samples and minimum, median, and maximum costs for startup, cold capture, and
same-session restart. It also records debugger commands, stdin batches, wire
bytes, and the original response bytes. CLI framing bytes are included, while
framing commands and command-line startup settings do not count as debugger
commands. Closed projected journals must replay completely, with replay
outside the timed interval.

These cases verify fixed evidence and measurement mechanics. They do not prove
deadlock, complete diagnostic equivalence, or Agent diagnosis quality. Use the
study design above for claims about Agent outcomes.
