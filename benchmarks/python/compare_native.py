#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Measure fixed Linux x86-64 stop evidence, not Agent diagnostic success."""

import argparse
import base64
from collections import defaultdict
import itertools
import json
import os
from pathlib import Path
import re
import select
import shutil
import statistics
import subprocess
import sys
import tempfile
import time


INITIAL_COMMANDS = (
    "set auto-load no",
    "set debuginfod enabled off",
    "set disable-randomization off",
    "set may-call-functions off",
    "unset environment MALLOC_ARENA_MAX",
)
END = b"\nGDB_AI_SAMPLE_END\n"
FULL_STACK = (
    ("finish", {"total": ("int", "9")}, {"expected": ("int", "10")}),
    ("collect", {"requested": ("int", "8")}, {
        "counts": ("struct summary", "{accepted = 8, rejected = 1}"), "total": ("int", "9"),
    }),
    ("main", {}, {"requested": ("int", "8")}),
)
EXPRESSIONS = [
    ("observed", "42"), ("pair", "{left = 41, right = 42}"), ("numbers", "{2, 3, 5}"),
    ("pair.left", "41"), ("pair.right", "42"),
    ("numbers[0]", "2"), ("numbers[1]", "3"), ("numbers[2]", "5"),
    *[(f"observed + {index}", str(42 + index)) for index in range(8)],
]


def mi_variable_lists(output):
    # ponytail: these fixtures use only flat string fields and JSON-compatible
    # ASCII values; arbitrary MI needs the project's full parser instead.
    lists = []
    for record in re.findall(rb"(?m)^\d+\^done,variables=(.*)$", output):
        variables = [
            {key.decode(): json.loads(value) for key, value in
             re.findall(rb'([a-z-]+)=("(?:\\.|[^"])*")', item)}
            for item in re.findall(rb'\{(?:[a-z-]+="(?:\\.|[^"])*",?)+\}', record)
        ]
        assert record == b"[]" or variables, record
        assert len({item["name"] for item in variables}) == len(variables), record
        lists.append(variables)
    return lists


def verify_full_stack_cli(output):
    frames = re.split(rb"(?m)^(?:\(gdb\) )*#\d+\s+", output)[1:]
    assert len(frames) == len(FULL_STACK), output
    for frame, (function, arguments, locals_) in zip(frames, FULL_STACK):
        header, body = frame.split(b"\n", 1)
        assert re.search(rb"\b" + function.encode() + rb"\s*\(", header), header
        for name, (_, value) in arguments.items():
            assert re.search(rb"\b" + name.encode() + b"=" + re.escape(value.encode())
                             + rb"(?:,|\))", header), header
        for name, (_, value) in locals_.items():
            assert re.search(rb"(?m)^\s*" + name.encode() + b" = "
                             + re.escape(value.encode()) + b"$", body), body


def executable(name):
    found = shutil.which(name)
    if not found:
        raise argparse.ArgumentTypeError(f"required executable is missing: {name}")
    return str(Path(found).resolve())


def exchange(process, payload, done):
    started = time.perf_counter()
    process.stdin.write(payload)
    process.stdin.flush()
    output = bytearray()
    while not done(output):
        remaining = 15 - (time.perf_counter() - started)
        if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
            raise TimeoutError(f"debugger response timed out: {bytes(output)!r}")
        block = os.read(process.stdout.fileno(), 65536)
        if not block:
            raise RuntimeError(f"debugger closed its output: {bytes(output)!r}")
        output.extend(block)
    return {
        "seconds": time.perf_counter() - started,
        "request_bytes": len(payload),
        "response_bytes": len(output),
        "stdin_batches": 1,
    }, bytes(output)


def finish(process):
    process.stdin.close()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
        raise
    finally:
        process.stdout.close()
    assert process.returncode == 0, process.returncode


def combined(*parts):
    return {key: sum(part[key] for part in parts) for key in parts[0]}


def native(gdb, program, interface, mi, case):
    started = time.perf_counter()
    received_at = started
    process = subprocess.Popen(
        [gdb, "-q", "-nx", *(arg for command in INITIAL_COMMANDS for arg in ("-iex", command)),
         *([f"--interpreter={mi}"] if interface == "mi" else [])],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd=program.parent, bufsize=0,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "TERM": "dumb",
             "TMPDIR": str(program.parent), "MALLOC_ARENA_MAX": "2"},
    )
    token = 0
    # ponytail: assertions parse only these fixed fixtures; use a MI parser
    # before accepting arbitrary targets or record grammars here.

    def commands(items, stopped=False):
        nonlocal token, received_at
        if interface == "cli":
            payload = ("\n".join([*items, "echo \\nGDB_AI_SAMPLE_END\\n"]) + "\n").encode()
            done = lambda output: END in output
        else:
            numbered = []
            for item in items:
                token += 1
                numbered.append(f"{token}{item}\n")
            payload = "".join(numbered).encode()
            marker = b"*stopped," if stopped else f"{token}^done".encode()
            # 2026-09-09: A failed MI command has no ^done or stop record;
            # report its actual error instead of waiting for a false timeout.
            done = lambda output: (marker in output or b"^error" in output) and output.endswith(b"\n")
        cost, output = exchange(process, payload, done)
        received_at = time.perf_counter()
        assert b"^error" not in output, output
        cost["debugger_commands"] = len(items)
        return cost, output

    try:
        setup = (["set pagination off", "set confirm off", "set style enabled off", "set width 0",
                  "unset environment", f"file {json.dumps(str(program))}"] if interface == "cli" else
                 ["-gdb-set pagination off", "-gdb-set confirm off", "-gdb-set style enabled off",
                  "-gdb-set mi-async on", '-interpreter-exec console "unset environment"',
                  f"-file-exec-and-symbols {json.dumps(str(program))}"])
        if case == "threads":
            setup += (["set breakpoint pending on", "break pthread_join"] if interface == "cli"
                      else ["-break-insert -f pthread_join"])
        startup, startup_output = commands(setup)
        startup["seconds"] = received_at - started
        captures = []
        for _ in range(2):
            capture_started = time.perf_counter()
            if case == "threads":
                if interface == "cli":
                    cost, output = commands(["run", "thread apply all bt 8"])
                    assert len(re.findall(rb"(?m)^(?:\(gdb\) )*Thread \d+ \(", output)) == 3, output
                    frames = output
                else:
                    run, stopped = commands(["-exec-run"], stopped=True)
                    info, output = commands(["-thread-info"])
                    threads = re.findall(rb'\{id="(\d+)"', output)
                    assert len(set(threads)) == len(threads) == 3, output
                    stacks, frames = commands([
                        command for thread in threads for command in (
                            f"-stack-list-frames --thread {thread.decode()} 0 7",
                            f"-stack-list-arguments --thread {thread.decode()} --simple-values 0 7",
                        )
                    ])
                    assert frames.count(b"^done,stack=[frame=") == 3, frames
                    assert frames.count(b"^done,stack-args=[frame=") == 3, frames
                    cost = combined(run, info, stacks)
                    output = stopped + output + frames
                for worker in (b"worker_left", b"worker_right", b"main"):
                    assert worker + (b" (" if interface == "cli" else b'"') in frames, frames
                # 2026-09-09: Stack-name checks accepted captures without the
                # lock values present in native bt. Require diagnostic inputs
                # too; this case needs matching pthread debug information.
                for lock in (b"first", b"second"):
                    assert b"<" + lock + b">" in frames, frames
                if interface == "cli":
                    assert len(re.findall(rb"worker_(?:left|right) \(argument=0x0\)", frames)) == 2, frames
                else:
                    assert len(re.findall(rb'name="argument"[^}]*value="0x0"', frames)) == 2, frames
                assert b"pthread_join" in output, output
            elif case == "full-stack":
                if interface == "cli":
                    cost, output = commands(["run", "bt full 8"])
                    verify_full_stack_cli(output)
                else:
                    run, stopped = commands(["-exec-run"], stopped=True)
                    # MI requires a thread selector with --frame; use the
                    # actual stop identity rather than assuming thread one.
                    thread = re.search(rb'thread-id="(\d+)"', stopped)
                    assert thread, stopped
                    thread = thread.group(1).decode()
                    stack, frames = commands(["-stack-list-frames 0 7"])
                    levels = [int(level) for level in re.findall(rb'frame=\{level="(\d+)"', frames)]
                    assert levels == list(range(len(FULL_STACK))), frames
                    typed, types_output = commands([
                        f"-stack-list-variables --thread {thread} --frame {level} --simple-values" for level in levels
                    ])
                    types = mi_variable_lists(types_output)
                    assert len(types) == len(levels), types_output
                    values = dict(zip(levels, types))
                    missing = [level for level, variables in values.items()
                               if any("value" not in variable for variable in variables)]
                    cost = combined(run, stack, typed)
                    output = stopped + frames + types_output
                    if missing:
                        full, full_output = commands([
                            f"-stack-list-variables --thread {thread} --frame {level} --all-values" for level in missing
                        ])
                        lists = mi_variable_lists(full_output)
                        assert len(lists) == len(missing), full_output
                        values.update(zip(missing, lists))
                        cost = combined(cost, full)
                        output += full_output
                    for level, (function, arguments, locals_) in enumerate(FULL_STACK):
                        assert re.search(f'level="{level}"[^}}]*func="{function}"'.encode(), frames), frames
                        expected = arguments | locals_
                        assert {item["name"]: item["type"] for item in types[level]} == {
                            name: type_ for name, (type_, _) in expected.items()}, types[level]
                        assert {item["name"]: item["value"] for item in values[level]} == {
                            name: value for name, (_, value) in expected.items()}, values[level]
                        assert {item["name"] for item in types[level] if item.get("arg") == "1"} == set(arguments), types[level]
            elif case == "expressions":
                if interface == "cli":
                    cost, output = commands(["run", *[f"print {expression}" for expression, _ in EXPRESSIONS]])
                    values = [value.decode() for value in re.findall(rb"(?m)^(?:\(gdb\) )*\$\d+ = (.*)$", output)]
                else:
                    run, stopped = commands(["-exec-run"], stopped=True)
                    evaluated, output = commands([
                        f"-data-evaluate-expression {json.dumps(expression)}" for expression, _ in EXPRESSIONS
                    ])
                    cost = combined(run, evaluated)
                    output = stopped + output
                    values = [json.loads(value) for value in re.findall(rb'\d+\^done,value=("(?:\\.|[^"])*")', output)]
                assert values == [value for _, value in EXPRESSIONS], output
            elif interface == "cli":
                cost, output = commands(["run", "bt 8", "info locals", "info args"])
                for name, value in (("observed", 42), ("input", 41)):
                    assert re.search(rb"(?m)^(?:\(gdb\) )*" + name.encode()
                                     + f" = {value}$".encode(), output), output
                assert re.search(rb"(?m)^(?:\(gdb\) )*#0\s+.*\bcapture_value\s*\(input=41\)", output), output
                assert re.search(rb"(?m)^(?:\(gdb\) )*#1\s+.*\bmain\s*\(", output), output
            else:
                run, stopped = commands(["-exec-run"], stopped=True)
                inspect, output = commands(["-stack-list-frames 0 7",
                                            "-stack-list-arguments --simple-values 0 7",
                                            "-stack-list-variables --simple-values"])
                cost = combined(run, inspect)
                output = stopped + output
                assert re.search(rb'stack-args=\[frame=\{level="0",args=\[\{name="input"[^}]*value="41"', output), output
                for name, value in (("observed", 42), ("input", 41)):
                    assert re.search(f'name="{name}"[^}}]*value="{value}"'.encode(), output), output
                for level, function in ((0, "capture_value"), (1, "main")):
                    assert re.search(f'level="{level}"[^}}]*func="{function}"'.encode(), output), output
            if case != "threads":
                assert b"SIGILL" in output, output
            # 2026-09-09: Growing fixture assertions inflated reported latency.
            # End the timer at receipt, before ground-truth verification.
            cost["seconds"] = received_at - capture_started
            cost["response_base64"] = base64.b64encode(output).decode()
            if not captures:
                cold_seconds = received_at - started
            captures.append(cost)
        cold = combined(startup, captures[0])
        cold["seconds"] = cold_seconds
        cold["response_base64"] = base64.b64encode(
            startup_output + base64.b64decode(captures[0]["response_base64"])
        ).decode()
        startup["response_base64"] = base64.b64encode(startup_output).decode()
        return {"startup": startup, "cold": cold, "reused": captures[1]}
    finally:
        finish(process)


def projected(server, gdb, program, state, mi, case):
    state.mkdir()
    config = state / "server.toml"
    config.write_text(
        f'[gdb]\npath = {json.dumps(gdb)}\n'
        f'preferred_mi = {json.dumps(mi)}\nfallback_mi = {json.dumps(mi)}\n'
        '[journal]\ndurability = "performance"\n'
        f'[security]\nworkspace_roots = {json.dumps([str(program.parent)])}\n'
        f'[artifacts]\npath = {json.dumps(str(state / "artifacts"))}\n'
        f'[persistence]\nsqlite = {json.dumps(str(state / "state.sqlite"))}\n'
        f'sessions = {json.dumps(str(state / "sessions"))}\n'
    )
    with (state / "server.log").open("w+") as log:
        started = time.perf_counter()
        received_at = started
        process = subprocess.Popen(
            [server, "--config", str(config), "serve", "--stdio"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
            cwd=program.parent, bufsize=0,
        )
        sequence = 0

        def call(action, **arguments):
            nonlocal sequence, received_at
            sequence += 1
            payload = (json.dumps({
                "jsonrpc": "2.0", "id": sequence, "method": "tools/call",
                "params": {"name": "gdb_session", "arguments": {"action": action, **arguments},
                           "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                     "io.modelcontextprotocol/clientCapabilities": {}}},
            }, separators=(",", ":")) + "\n").encode()
            cost, output = exchange(process, payload, lambda output: output.endswith(b"\n"))
            received_at = time.perf_counter()
            cost["response_base64"] = base64.b64encode(output).decode()
            response = json.loads(output)
            assert response["id"] == sequence and "error" not in response, response
            assert not response["result"]["isError"], response
            return cost, response["result"]["structuredContent"]

        try:
            session = None
            launch = {"program": str(program)}
            if case == "threads":
                launch["breakpoints"] = [{"function": "pthread_join"}]
                inspect = [{"view": "threads", "stack_depth": 8}]
            elif case == "full-stack":
                inspect = [{"view": "stack", "limit": 8, "include_locals": True}]
            elif case == "expressions":
                inspect = [{"view": "evaluate", "expressions": [expression for expression, _ in EXPRESSIONS]}]
            else:
                inspect = [{"view": "stack", "limit": 8}, {"view": "locals"}]
            captures = []
            for action in ("launch", "restart"):
                capture_started = time.perf_counter()
                cost, response = call(
                    action, stop="none", **({"session_id": session} if session else {}),
                    inspect=inspect,
                    **(launch if action == "launch" else {}),
                )
                if session is None:
                    session = response["result"]["session"]["session_id"]
                    if case == "threads":
                        assert len(response["result"]["created_breakpoints"]) == 1, response
                assert response["complete"] and response["context"]["stop_id"], response
                assert response["state"].get("snapshot", {}).get("status") != "BUILDING", response
                observations = response["result"]["observations"]
                if case == "threads":
                    threads = observations["threads"]["threads"]
                    assert len(threads) == 3 and not observations["threads"]["partial"], response
                    stacks = [{frame["function"] for frame in thread["frames"]} for thread in threads]
                    for worker in ("worker_left", "worker_right", "main"):
                        assert sum(worker in stack for stack in stacks) == 1, response
                    for worker, lock in (("worker_left", "second"), ("worker_right", "first")):
                        thread = next(thread for thread in threads
                                      if any(frame["function"] == worker for frame in thread["frames"]))
                        frame = next(frame for frame in thread["frames"] if frame["function"] == worker)
                        assert any(argument["name"] == "argument" and argument["value"] == "0x0"
                                   for argument in frame.get("arguments", [])), response
                        values = [argument["value"] for frame in thread["frames"]
                                  for argument in frame.get("arguments", [])]
                        assert any(isinstance(value, str) and f"<{lock}>" in value for value in values), response
                elif case == "full-stack":
                    frames = observations["stack"]["frames"]
                    assert len(frames) == len(FULL_STACK), response
                    for level, (frame, (function, arguments, locals_)) in enumerate(zip(frames, FULL_STACK)):
                        assert frame["level"] == level and frame["function"] == function, frame
                        assert frame["frame_id"] and frame["address"] and frame["source"], frame
                        for field, expected in (("arguments", arguments), ("locals", locals_)):
                            assert {item["name"]: (item["type"], item["value"]) for item in frame[field]} == expected, frame
                            assert all(item["status"] == "available" for item in frame[field]), frame
                elif case == "expressions":
                    assert observations["evaluate"]["results"] == [
                        {"expression": expression, "value": value, "type": None, "status": "available"}
                        for expression, value in EXPRESSIONS
                    ], response
                else:
                    assert "SIGILL" in json.dumps(response["state"]), response
                    assert [frame["function"] for frame in observations["stack"]["frames"]] == [
                        "capture_value", "main"], response
                    assert any(argument["name"] == "input" and argument["value"] == "41"
                               for argument in observations["stack"]["frames"][0].get("arguments", [])), response
                    values = {item["name"]: item["value"] for item in observations["locals"]["variables"]}
                    assert values == {"observed": "42", "input": "41"}, response
                if case != "threads":
                    assert "SIGILL" in json.dumps(response["state"]), response
                cost["seconds"] = received_at - capture_started
                if not captures:
                    cold_seconds = received_at - started
                captures.append(cost)
            _, closed = call("close", session_id=session)
            assert closed["result"]["clean_shutdown"] and not closed.get("warnings"), closed
        except BaseException:
            log.flush()
            log.seek(0)
            print(log.read(), end="", file=sys.stderr)
            raise
        finally:
            finish(process)
    counts = defaultdict(int)
    phase = "startup"
    for line in (state / "sessions" / session / "journal.jsonl").read_text().splitlines():
        entry = json.loads(line)
        if entry["type"] == "api.request":
            method = entry["data"]["method"]
            phase = "startup" if method == "session.create" else method
        elif entry["type"] == "mi.input":
            counts[phase] += 1
    for cost, phase in zip(captures, ("target.launch", "target.restart")):
        cost["debugger_commands"] = counts[phase]
        assert counts[phase] >= 3, counts
    # 2026-09-09: Both workflows fuse creation and breakpoint setup into
    # launch. Charge all bootstrap commands to cold capture, with no
    # separately measured startup row.
    captures[0]["debugger_commands"] += counts["startup"]
    assert sum(cost["debugger_commands"] for cost in captures) == sum(
        count for phase, count in counts.items() if phase != "session.close"), counts
    captures[0]["seconds"] = cold_seconds
    replayed = subprocess.run(
        [server, "replay", str(state / "sessions" / session / "journal.jsonl")],
        check=True, capture_output=True, text=True, timeout=15,
    )
    replay = json.loads(replayed.stdout)
    assert replay["complete"] and replay["evidence_gap"] is None, replay
    captures[0]["journal_replay"] = {key: replay[key] for key in ("complete", "entries", "parsed_mi_records")}
    return {"cold": captures[0], "reused": captures[1]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server", type=executable)
    parser.add_argument("--gdb", default="gdb", type=executable)
    parser.add_argument("--cc", default="cc", type=executable)
    parser.add_argument("--mi", choices=("mi2", "mi3", "mi4"), default="mi4")
    parser.add_argument("--case", choices=("signal", "threads", "full-stack", "expressions"), default="signal")
    parser.add_argument("--samples", default=6, type=int)
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("samples must be positive")
    samples = []
    orders = list(itertools.permutations(("cli", "mi", "projected")))
    with tempfile.TemporaryDirectory(prefix="gdb-ai-native-") as temporary:
        root = Path(temporary)
        if args.case == "threads":
            source = Path(__file__).resolve().parents[2] / "tests/targets/c/deadlock.c"
        elif args.case == "full-stack":
            source = Path(__file__).resolve().parents[2] / "tests/targets/c/stack_locals.c"
        else:
            source = root / f"{args.case}.c"
            source.write_text(
                "int capture_value(int input) {\n"
                "  int observed = input + 1;\n  __builtin_trap();\n  return observed;\n}\n"
                "int main(void) { return capture_value(41); }\n" if args.case == "signal" else
                "struct pair { int left; int right; };\n"
                "int main(void) {\n"
                "  int observed = 42;\n  struct pair pair = {41, 42};\n"
                "  int numbers[3] = {2, 3, 5};\n  __builtin_trap();\n"
                "  return observed + pair.left + numbers[0];\n}\n"
            )
        program = root / args.case
        subprocess.run([args.cc, "-g", "-O0", "-fno-omit-frame-pointer", "-pthread", str(source),
                        "-o", str(program)], check=True, timeout=30)
        for sample in range(args.samples):
            for interface in orders[sample % len(orders)]:
                costs = (projected(args.server, args.gdb, program, root / f"state-{sample}", args.mi, args.case)
                         if interface == "projected" else native(args.gdb, program, interface, args.mi, args.case))
                for cost in costs.values():
                    assert len(base64.b64decode(cost["response_base64"])) == cost["response_bytes"], cost
                samples.extend({"sample": sample, "interface": interface, "phase": phase, **cost}
                               for phase, cost in costs.items())
    grouped = defaultdict(list)
    for row in samples:
        grouped[row["interface"], row["phase"]].append(row)
    summary = []
    for (interface, phase), rows in sorted(grouped.items()):
        group = {"interface": interface, "phase": phase, "samples": len(rows)}
        for key in ("seconds", "request_bytes", "response_bytes", "stdin_batches", "debugger_commands"):
            values = [row[key] for row in rows]
            group[key] = {"min": min(values), "median": statistics.median(values), "max": max(values)}
        summary.append(group)
    print(json.dumps({
        "conditions": "Fixed stop evidence; Linux x86-64; performance journal; "
                      "thread case requires pthread debug information and both lock argument values; "
                      "cold includes process/session startup; reused restarts the same target; "
                      "timers end at final response receipt, before final fact assertions; "
                      "discovery and teardown excluded; response bytes include CLI framing marker; "
                      "command counts cover stdin commands, excluding CLI framing and argv settings; "
                      "startup rows measure separate native setup only; "
                      "projected creation and breakpoint setup are fused into cold launch; "
                      "full-stack checks all three frames and aggregate contents, with types in MI/MCP; "
                      "expressions pipelines native print/evaluate commands for 16 mixed values; "
                      "raw responses are base64 encoded and projected closed journals must replay; "
                      "script batches are not Agent calls; bytes are not tokens",
        "mi": args.mi,
        "case": args.case,
        "versions": {name: subprocess.check_output([path, "--version"], text=True, timeout=10).strip()
                     for name, path in (("server", args.server), ("gdb", args.gdb), ("cc", args.cc))},
        "samples": samples, "summary": summary,
    }, indent=2))


if __name__ == "__main__":
    main()
