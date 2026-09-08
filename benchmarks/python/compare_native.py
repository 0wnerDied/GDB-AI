#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Measure fixed Linux x86-64 stop evidence, not Agent diagnostic success."""

import argparse
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
        nonlocal token
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
            done = lambda output: marker in output and output.endswith(b"\n")
        cost, output = exchange(process, payload, done)
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
        startup, _ = commands(setup)
        startup["seconds"] = time.perf_counter() - started
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
            if case == "signal":
                assert b"SIGILL" in output, output
            cost["seconds"] = time.perf_counter() - capture_started
            if not captures:
                cold_seconds = time.perf_counter() - started
            captures.append(cost)
        cold = combined(startup, captures[0])
        cold["seconds"] = cold_seconds
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
        process = subprocess.Popen(
            [server, "--config", str(config), "serve", "--stdio"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
            cwd=program.parent, bufsize=0,
        )
        sequence = 0

        def call(action, tool="gdb_session", **arguments):
            nonlocal sequence
            sequence += 1
            payload = (json.dumps({
                "jsonrpc": "2.0", "id": sequence, "method": "tools/call",
                "params": {"name": tool, "arguments": {"action": action, **arguments},
                           "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                     "io.modelcontextprotocol/clientCapabilities": {}}},
            }, separators=(",", ":")) + "\n").encode()
            cost, output = exchange(process, payload, lambda output: output.endswith(b"\n"))
            response = json.loads(output)
            assert response["id"] == sequence and "error" not in response, response
            assert not response["result"]["isError"], response
            return cost, response["result"]["structuredContent"]

        try:
            startup = None
            session = None
            if case == "threads":
                startup, created = call("create")
                session = created["result"]["session_id"]
                breakpoint, _ = call("create", tool="gdb_breakpoints", session_id=session,
                                     function="pthread_join", pending=True)
                startup = combined(startup, breakpoint)
                startup["seconds"] = time.perf_counter() - started
            captures = []
            for action in ("launch", "restart"):
                capture_started = time.perf_counter()
                cost, response = call(
                    action, stop="none", **({"session_id": session} if session else {}),
                    inspect=([{"view": "threads", "stack_depth": 8}] if case == "threads" else
                             [{"view": "stack", "limit": 8}, {"view": "locals"}]),
                    **({"program": str(program)} if action == "launch" else {}),
                )
                if session is None:
                    session = response["result"]["session"]["session_id"]
                assert response["complete"] and response["context"]["stop_id"], response
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
                else:
                    assert "SIGILL" in json.dumps(response["state"]), response
                    assert [frame["function"] for frame in observations["stack"]["frames"]] == [
                        "capture_value", "main"], response
                    assert any(argument["name"] == "input" and argument["value"] == "41"
                               for argument in observations["stack"]["frames"][0].get("arguments", [])), response
                    values = {item["name"]: item["value"] for item in observations["locals"]["variables"]}
                    assert values == {"observed": "42", "input": "41"}, response
                cost["seconds"] = time.perf_counter() - capture_started
                if not captures:
                    cold_seconds = time.perf_counter() - started
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
            phase = "startup" if method in ("session.create", "breakpoint.create") else method
        elif entry["type"] == "mi.input":
            counts[phase] += 1
    if startup is not None:
        startup["debugger_commands"] = counts["startup"]
    for cost, phase in zip(captures, ("target.launch", "target.restart")):
        cost["debugger_commands"] = counts[phase]
        assert counts[phase] >= 3, counts
    # 2026-09-09: The signal workflow no longer needs a separate create.
    # Charge its bootstrap commands to the fused cold call, never drop them
    # or invent a separately measured zero-cost startup row.
    if startup is None:
        captures[0]["debugger_commands"] += counts["startup"]
    cold = combined(startup, captures[0]) if startup is not None else captures[0].copy()
    cold["seconds"] = cold_seconds
    return {**({"startup": startup} if startup is not None else {}),
            "cold": cold, "reused": captures[1]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server", type=executable)
    parser.add_argument("--gdb", default="gdb", type=executable)
    parser.add_argument("--cc", default="cc", type=executable)
    parser.add_argument("--mi", choices=("mi2", "mi3", "mi4"), default="mi4")
    parser.add_argument("--case", choices=("signal", "threads"), default="signal")
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
        else:
            source = root / "signal.c"
            source.write_text(
                "int capture_value(int input) {\n"
                "  int observed = input + 1;\n  __builtin_trap();\n  return observed;\n}\n"
                "int main(void) { return capture_value(41); }\n"
            )
        program = root / args.case
        subprocess.run([args.cc, "-g", "-O0", "-fno-omit-frame-pointer", "-pthread", str(source),
                        "-o", str(program)], check=True, timeout=30)
        for sample in range(args.samples):
            for interface in orders[sample % len(orders)]:
                costs = (projected(args.server, args.gdb, program, root / f"state-{sample}", args.mi, args.case)
                         if interface == "projected" else native(args.gdb, program, interface, args.mi, args.case))
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
                      "discovery and teardown excluded; response bytes include CLI framing marker; "
                      "command counts cover stdin commands, excluding CLI framing and argv settings; "
                      "startup rows measure separate native setup or projected thread-case setup; "
                      "projected signal creation is fused into cold launch and has no separate startup row; "
                      "script batches are not Agent calls; bytes are not tokens",
        "mi": args.mi,
        "case": args.case,
        "versions": {name: subprocess.check_output([path, "--version"], text=True, timeout=10).strip()
                     for name, path in (("server", args.server), ("gdb", args.gdb), ("cc", args.cc))},
        "samples": samples, "summary": summary,
    }, indent=2))


if __name__ == "__main__":
    main()
