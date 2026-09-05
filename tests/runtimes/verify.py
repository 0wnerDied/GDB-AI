#!/usr/bin/env python3
"""Compare native GDB and projected MCP on native runtime breakpoints."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def executable(name):
    found = shutil.which(name)
    if not found:
        raise SystemExit(f"required executable is missing: {name}")
    return str(Path(found).resolve())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server", type=executable)
    for name in ("gdb", "clang", "lli", "node", "php", "php-cgi"):
        parser.add_argument(f"--{name}", default=name, type=executable)
    parser.add_argument("--library-path", help="target LD_LIBRARY_PATH for unpacked runtimes")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="gdb-ai-runtimes-") as temporary:
        root = Path(temporary)
        source = root / "jit.c"
        source.write_text(
            '#include <stdio.h>\n'
            'int runtime_increment(int value) { return value + 1; }\n'
            'int main(void) { printf("runtime-result=%d\\n", runtime_increment(41)); return 0; }\n'
        )
        bitcode = root / "jit.bc"
        native = root / "native"
        for options, output in (([], native), (["-emit-llvm", "-c"], bitcode)):
            subprocess.run([args.clang, "-g", "-O0", *options, str(source), "-o", str(output)], check=True)
        php_source = root / "request.php"
        php_source.write_text('<?php echo "runtime-result=42\\n"; ?>\n')
        helper = root / "runtime.gdb"
        helper.write_text('printf "helper-result=%d\\n", 42\n')
        cases = [
            ("clang", str(native), [], "runtime_increment"),
            ("llvm-jit", args.lli, ["--jit-kind=mcjit", str(bitcode)], "runtime_increment"),
            ("node-v8", args.node, ["--eval", 'console.log("runtime-result=42")'], "v8::Isolate::Initialize"),
            ("php", args.php, ["-n", str(php_source)], "php_request_startup"),
            ("php-cgi", args.php_cgi, ["-n", "-f", str(php_source)], "php_request_startup"),
        ]
        environment = {"REDIRECT_STATUS": "200", "REQUEST_METHOD": "GET",
                       "SCRIPT_FILENAME": str(php_source)}
        if args.library_path:
            environment["LD_LIBRARY_PATH"] = args.library_path
        roots = sorted({str(root), *(str(Path(program).parent) for _, program, _, _ in cases)})
        config = root / "server.toml"
        config.write_text(
            f'[gdb]\npath = {json.dumps(args.gdb)}\n'
            f'[security]\nworkspace_roots = {json.dumps(roots)}\n'
            f'[artifacts]\npath = {json.dumps(str(root / "artifacts"))}\n'
            f'[persistence]\nsqlite = {json.dumps(str(root / "state.sqlite"))}\n'
            f'sessions = {json.dumps(str(root / "sessions"))}\n'
        )
        with subprocess.Popen(
            [args.server, "--config", str(config), "serve", "--stdio", "--raw-admin"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        ) as server:
            sequence = 0

            def call(name, **arguments):
                nonlocal sequence
                sequence += 1
                server.stdin.write(json.dumps({
                    "jsonrpc": "2.0", "id": sequence, "method": "tools/call",
                    "params": {"name": name, "arguments": arguments, "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }},
                }) + "\n")
                server.stdin.flush()
                response = json.loads(server.stdout.readline())
                assert "error" not in response, response
                assert not response["result"]["isError"], response
                return response["result"]["structuredContent"]

            try:
                for label, program, argv, breakpoint in cases:
                    commands = ["set pagination off", "set breakpoint pending on"]
                    commands += [f"set environment {name}={value}" for name, value in environment.items()]
                    commands += [f"tbreak {breakpoint}", "run", "bt 2", f"source {helper}", "continue"]
                    reference = subprocess.run(
                        [args.gdb, "-q", "-nx", "-batch", *(arg for command in commands for arg in ("-ex", command)),
                         "--args", program, *argv],
                        capture_output=True, text=True, timeout=30,
                        env={**os.environ, "LC_ALL": "C"},
                    )
                    assert reference.returncode == 0, reference.stderr
                    # 2026-09-05: Loose searches accepted the wrong top frame or
                    # a suffixed result; match the frame and complete marker lines.
                    assert re.search(r"^#0\s+(?:0x[0-9a-fA-F]+\s+in\s+)?" + re.escape(breakpoint) + r"\s*\(",
                                     reference.stdout, re.MULTILINE), reference.stdout
                    for marker in ("runtime-result", "helper-result"):
                        assert [line for line in reference.stdout.splitlines()
                                if line.startswith(marker + "=")] == [marker + "=42"], reference.stdout
                    assert "exited normally" in reference.stdout, reference.stdout
                    session = call("gdb_session", action="create")["result"]["session_id"]
                    try:
                        call("gdb_session", action="launch", session_id=session, program=program,
                             argv=argv, environment=environment, stop="first_instruction")
                        call("gdb_breakpoints", action="create", session_id=session,
                             function=breakpoint, pending=True, temporary=True)
                        stopped = call("gdb_run", action="continue", session_id=session,
                                       inspect=[{"view": "stack", "limit": 2}])
                        frame = stopped["result"]["observations"]["stack"]["frames"][0]
                        assert frame["function"].split("(", 1)[0] == breakpoint, stopped
                        output = call("gdb_raw", action="console", session_id=session,
                                      command=f"source {helper}")
                        assert output["result"]["console"]["text"] == "helper-result=42\n", output
                        assert "command" not in output["result"], output
                        finished = call("gdb_run", action="continue", session_id=session)
                        assert finished["result"]["settled_by"] == "exited", finished
                        assert finished["state"]["exit_code"] == 0, finished
                        text = "".join(result["result"].get("output", {}).get("text", "")
                                       for result in (stopped, finished))
                        assert [line for line in text.splitlines()
                                if line.startswith("runtime-result=")] == ["runtime-result=42"], (stopped, finished)
                        print(f"{label}: native breakpoint, stack, helper output and exit match GDB")
                    finally:
                        call("gdb_session", action="close", session_id=session)
            finally:
                server.stdin.close()
                server.wait(timeout=10)


if __name__ == "__main__":
    main()
