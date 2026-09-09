#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify both SDKs against real GDB over both HTTP protocol paths and journal modes."""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.request import urlopen


def executable(name):
    found = shutil.which(name)
    if not found:
        raise argparse.ArgumentTypeError(f"required executable is missing: {name}")
    return str(Path(found).resolve())


def wait_ready(server, endpoint):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise RuntimeError(f"server exited during startup: {server.returncode}")
        try:
            with urlopen(f"{endpoint}/healthz", timeout=1):
                return
        except URLError:
            time.sleep(0.05)
    raise TimeoutError("SDK test server did not become ready")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server", type=executable)
    for name in ("cc", "gdb", "node"):
        parser.add_argument(f"--{name}", default=name, type=executable)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    environment = {**os.environ, "PYTHONPATH": str(repo / "sdk/python/src")}
    with tempfile.TemporaryDirectory(prefix="gdb-ai-sdk-") as temporary:
        root = Path(temporary)
        program = root / "vertical"
        subprocess.run([args.cc, "-g", "-O0", str(repo / "tests/targets/c/vertical.c"),
                        "-o", str(program)], check=True, timeout=30)
        for durability in ("performance", "durable"):
            state = root / durability
            state.mkdir()
            config = state / "server.toml"
            # 2026-09-09: The shared-principal matrix could exhaust the default
            # 300-request window before the next client started. Budget this
            # bounded verification workload without changing production limits.
            config.write_text(
                f'[gdb]\npath = {json.dumps(args.gdb)}\n'
                f'[journal]\ndurability = {json.dumps(durability)}\n'
                '[server]\nrequests_per_second = 1000\nrequest_burst = 0\n'
                '[output]\nevidence = "artifact"\n'
                f'[security]\nworkspace_roots = {json.dumps([str(root)])}\n'
                f'[artifacts]\npath = {json.dumps(str(state / "artifacts"))}\n'
                f'[persistence]\nsqlite = {json.dumps(str(state / "state.sqlite"))}\n'
                f'sessions = {json.dumps(str(state / "sessions"))}\n'
            )
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            endpoint = f"http://127.0.0.1:{port}"
            with (state / "server.log").open("w+") as log:
                server = subprocess.Popen(
                    [args.server, "--config", str(config), "serve", "--http", f"127.0.0.1:{port}"],
                    cwd=root, stdout=log, stderr=subprocess.STDOUT,
                )
                try:
                    wait_ready(server, endpoint)
                    for version in ("2025-11-25", "2026-07-28"):
                        for runtime, script in (
                            (sys.executable, repo / "sdk/python/tests/integration.py"),
                            (args.node, repo / "sdk/typescript/integration.mjs"),
                        ):
                            subprocess.run([runtime, str(script), f"{endpoint}/mcp", str(program), version],
                                           env=environment, check=True, timeout=60)
                except BaseException:
                    log.flush()
                    log.seek(0)
                    sys.stderr.write(log.read())
                    raise
                finally:
                    if server.poll() is None:
                        server.send_signal(signal.SIGINT)
                        try:
                            server.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            server.kill()
                            server.wait(timeout=10)
                    if server.returncode:
                        raise RuntimeError(f"SDK test server exited with {server.returncode}")
            journals = sorted((state / "sessions").glob("*/journal.jsonl"))
            assert len(journals) == 8, journals
            for journal in journals:
                result = subprocess.run([args.server, "replay", str(journal)],
                                        capture_output=True, text=True, check=True, timeout=10)
                report = json.loads(result.stdout)
                assert report["complete"] and report["evidence_gap"] is None, report
            print(f"{durability}: all {len(journals)} SDK session journals replay completely", flush=True)


if __name__ == "__main__":
    main()
