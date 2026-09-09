# SPDX-License-Identifier: GPL-3.0-or-later
"""Real HTTP/GDB SDK contract check, launched by sdk/verify.py."""

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import statistics
import sys
import time
from urllib.request import urlopen

from gdb_ai import ApiError, Client, RpcError, Session


def verify_output(client, session_id, result, expected):
    assert ("text" in result) != ("data_base64" in result), result
    actual = (result["text"].encode() if "text" in result
              else base64.b64decode(result["data_base64"], validate=True))
    assert actual == expected, result
    assert result["next_offset"] == len(expected), result
    assert result["gap"] is False, result
    uri = f"gdbai://session/{session_id}/output/pty"
    manifest = json.loads(client.read_resource(uri)[0]["text"])
    assert manifest["end_offset"] == len(expected), manifest
    uri += f"?offset=0&length={len(expected)}"
    contents = client.read_resource(uri)[0]
    assert contents["uri"] == uri, contents
    actual = (contents["text"].encode() if "text" in contents
              else base64.b64decode(contents["blob"], validate=True))
    assert actual == expected, contents


def verify_close(client, response, expected):
    assert response["result"]["closed"], response
    assert response["result"]["clean_shutdown"], response
    evidence = response["result"]["inferior_output_evidence"]
    assert evidence["complete"] and evidence["dropped_bytes"] == 0, evidence
    assert evidence["captured_bytes"] == len(expected), evidence
    digest = hashlib.sha256(expected).hexdigest()
    assert evidence["sha256"] == digest, evidence
    uri = evidence["artifact_uri"]
    manifest = json.loads(client.read_resource(uri)[0]["text"])
    assert manifest["size"] == len(expected) and manifest["sha256"] == digest, manifest
    page = client.read_resource(f"{uri}?offset=0&length={len(expected)}")[0]
    assert base64.b64decode(page["blob"], validate=True) == expected, page


def verify_history_readers(pool, readers, lookup, expected, waiting):
    def command_count():
        endpoint = readers[0].endpoint.removesuffix("/mcp")
        with urlopen(f"{endpoint}/metrics", timeout=5) as response:
            return next(int(line.split()[1]) for line in response.read().decode().splitlines()
                        if line.startswith("gdbai_commands_total "))

    def read(peer):
        durations = []
        for _ in range(16):
            started = time.perf_counter()
            response = peer.call_tool("gdb_inspect", lookup)
            durations.append(time.perf_counter() - started)
            assert response["historical"], response
            assert response["complete"] == expected["complete"], response
            assert response["context"] == expected["context"], response
            assert response["result"] == expected["result"], response
        return durations

    for concurrency in (1, 4, 8):
        assert not waiting.done(), "control must remain pending during historical reads"
        before = command_count()
        started = time.perf_counter()
        futures = [pool.submit(read, peer) for peer in readers[:concurrency]]
        durations = [duration for future in futures for duration in future.result(timeout=10)]
        elapsed = time.perf_counter() - started
        extra_commands = command_count() - before
        assert extra_commands == 0, extra_commands
        assert not waiting.done(), "reads must complete without releasing the pending controller"
        print(json.dumps({"mixed_history": {
            "protocol": readers[0].protocol_version, "readers": concurrency,
            "reads": len(durations), "seconds": elapsed,
            "reads_per_second": len(durations) / elapsed,
            "latency_seconds": {"min": min(durations), "median": statistics.median(durations),
                                "max": max(durations)},
            "latency_samples_seconds": durations,
            "extra_mi_commands": extra_commands,
        }}), flush=True)


def canonical(client, program):
    session = Session.create(client)
    expected = "environment: sdk-世界\nmarker reached\ninput received: Q\n".encode()
    try:
        session.renew()
        launched = session.call("target.launch", {
            "program": program, "environment": {"GDB_AI_TEST_ENV": "sdk-世界"},
            "stop": "none", "breakpoints": [{"function": "main"}],
            "wait": {"until": "snapshot", "timeout_ms": 5000},
            "inspect": [{"view": "stack", "limit": 4, "include_locals": True}],
        })
        stop_id = launched["state"]["stop_id"]
        assert launched["result"]["observations"]["stack"]["frames"], launched
        assert isinstance(launched["result"]["observations"]["stack"]["frames"][0]["locals"], list), launched
        assert len(launched["result"]["created_breakpoints"]) == 1, launched
        assert launched["semantics"]["context"]["stop_id"] == stop_id, launched
        assert all(item["kind"] == "journal-entry" for item in launched["evidence"]), launched
        context = session.call("inspection.get", {"view": "stop_context"})
        assert context["result"]["stop_id"] == stop_id, context
        stack = session.call("inspection.get", {"view": "stack", "stop_id": stop_id, "limit": 4})
        assert stack["result"]["frames"], stack
        assert stack["semantics"]["projection"] == "detailed", stack
        assert stack["semantics"]["context"]["stop_id"] == stop_id, stack
        memory = session.call("memory.read", {
            "stop_id": stop_id, "address_expression": "&large_buffer", "length": 4,
        })["result"]
        assert memory["data_base64"] == "WgAAAA==" and "data_hex" not in memory, memory
        try:
            session.call("inspection.get", {"view": "stack", "stop_id": "stale"})
        except ApiError as error:
            assert error.code == "STALE_CONTEXT", error.response
            assert error.response["revision"] == session.revision, error.response
        else:
            raise AssertionError("stale canonical stop was accepted")
        # Explicit latest-revision I/O keeps the keyed request identical for
        # replay, even though successful delivery advances session.revision.
        written = session.call("inferior_io.write", {"text": "Q\n"}, idempotency_key="input-once")
        replayed = session.call("inferior_io.write", {"text": "Q\n"}, idempotency_key="input-once")
        assert written["result"] == replayed["result"], replayed
        exited = session.call("execution.control", {
            "action": "continue", "wait": {"until": "exited", "timeout_ms": 5000},
        })
        assert any(inferior["status"] == "EXITED" and int(inferior["exit_code"]) == 0
                   for inferior in exited["state"]["inferiors"].values()), exited
        output = session.call("inferior_io.read", {"after_offset": 0, "max_bytes": 4096})
        assert output["truncated"] is False, output
        verify_output(client, session.session_id, output["result"], expected)
    finally:
        closed = session.close()
    verify_close(client, closed, expected)


def projected(client, program):
    launched = client.call_tool("gdb_session", {
        "action": "launch", "program": program, "stop": "none",
        "breakpoints": [{"function": "main"}, {"function": "report_input"}],
        "inspect": [{"view": "stack", "limit": 4}],
        "environment": {"GDB_AI_TEST_ENV": "sdk-世界"}})
    assert "api_version" not in launched and "revision" not in launched, launched
    created = launched["result"]["session"]
    assert "write_lease" not in created, created
    session_id = created["session_id"]
    assert created["controller"] == created["caller_identity"], created
    expected = "environment: sdk-世界\nmarker reached\ninput received: \0\n".encode()
    observer = Client(client.endpoint, protocol_version=client.protocol_version,
                      client_name="python-observer")
    readers = [Client(client.endpoint, protocol_version=client.protocol_version,
                      client_name=f"python-history-{index}", timeout=5) for index in range(8)]
    pool = ThreadPoolExecutor(max_workers=9)
    controller = client

    def call(name, **arguments):
        return controller.call_tool(name, {"session_id": session_id, **arguments})

    try:
        observer.connect()
        identities = set()
        for reader in readers:
            reader.connect()
            status = reader.call_tool("gdb_session", {"action": "status", "session_id": session_id})
            identities.add(status["result"]["caller_identity"])
        assert len(identities) == len(readers) and created["controller"] not in identities, identities
        assert launched["state"]["stop_id"], launched
        assert len(launched["result"]["created_breakpoints"]) == 2, launched
        assert launched["result"]["observations"]["stack"]["frames"][0]["function"] == "main", launched
        assert "backend" not in launched["state"], launched
        stack = call("gdb_inspect", view="stack", limit=4)
        assert stack["result"]["frames"], stack
        assert stack["context"]["stop_id"] == launched["state"]["stop_id"], stack
        assert stack["complete"] and stack["evidence"], stack
        memory = call("gdb_memory", action="read", address_expression="&large_buffer", length=4)["result"]
        assert memory["data_hex"] == "5a000000" and "data_base64" not in memory, memory
        binary = call("gdb_memory", action="read", address=memory["address"], length=4,
                      encoding="base64")["result"]
        assert binary["data_base64"] == "WgAAAA==" and "data_hex" not in binary, binary
        status_uri = f"gdbai://session/{session_id}/status"
        assert status_uri in {resource["uri"] for resource in client.list_resources()}
        status = json.loads(client.read_resource(status_uri)[0]["text"])
        assert status["stop_id"] == launched["state"]["stop_id"], status
        try:
            call("gdb_inspect", view="stack", stop_id="stale")
        except ApiError as error:
            assert error.code == "STALE_CONTEXT", error.response
            assert "revision" not in error.response, error.response
        else:
            raise AssertionError("stale projected stop was accepted")
        read_plan = [
            {"view": "registers", "roles": ["pc", "sp"]},
            {"view": "evaluate", "expression": "$pc"},
            {"name": "missing", "view": "evaluate", "expression": "gdb_ai_missing_sdk_symbol"},
            {"view": "stack", "limit": 4, "include_locals": True},
            {"name": "values", "view": "evaluate", "expressions": ["global_value", "global_pair"]},
            {"view": "memory", "address_expression": "&large_buffer", "length": 4},
        ]
        capture_response = call("gdb_batch", requests=read_plan)
        assert not capture_response["complete"], capture_response
        captured = capture_response["result"]
        assert captured["failures"]["missing"]["code"] == "GDB_ERROR", captured
        assert captured["availability"]["missing"] == "failed", captured
        assert captured["results"]["evaluate"]["status"] == "available", captured
        assert "command" not in captured["results"]["evaluate"], captured
        assert "record" not in captured["failures"]["missing"].get("details", {}), captured
        assert [item["value"] for item in captured["results"]["values"]["results"]] == [
            "7", "{left = 1, right = 2}"]
        assert captured["results"]["stack"]["frames"][0]["function"] == "main", captured
        assert isinstance(captured["results"]["stack"]["frames"][0]["locals"], list), captured
        assert captured["results"]["memory"]["data_hex"] == "5a000000", captured
        assert "data_base64" not in captured["results"]["memory"], captured
        observation_id = capture_response["context"]["observation_id"]
        evidence = capture_response["evidence"]
        assert len(evidence) == 1 and evidence[0]["kind"] == "journal-entries", evidence
        evidence_uri = evidence[0]["uri"]
        contents = observer.read_resource(evidence_uri)[0]
        assert contents["uri"] == evidence_uri, contents
        entries = json.loads(contents["text"])["entries"]
        snapshot_uri = f"gdbai://session/{session_id}/snapshot/{observation_id}"
        snapshot = json.loads(observer.read_resource(snapshot_uri)[0]["text"])
        original_entries = [json.loads(observer.read_resource(item["uri"])[0]["text"])
                            for item in snapshot["evidence"]]
        assert entries == sorted(original_entries, key=lambda entry: entry["seq"]), entries
        assert {entry["seq"] for entry in entries} == {
            int(sequence) for sequence in evidence_uri.rsplit("/", 1)[1].split(",")}, entries
        try:
            observer.read_resource(evidence_uri + ",18446744073709551615")
        except RpcError as error:
            assert error.data["gdb_ai_code"] == "NOT_FOUND", error.data
        else:
            raise AssertionError("missing evidence returned a successful partial batch")
        lookup = {"session_id": session_id, "view": "observation", "snapshot_id": observation_id}
        shared_response = observer.call_tool("gdb_inspect", lookup)
        assert shared_response["historical"], shared_response
        assert shared_response["context"]["observation_id"] == observation_id, shared_response
        shared = shared_response["result"]
        assert shared["results"] == captured["results"], shared
        assert shared["failures"] == captured["failures"], shared
        waiting = pool.submit(call, "gdb_run", action="continue", inspect=read_plan,
                              wait={"until": "settled", "timeout_ms": 10000})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            running = observer.call_tool("gdb_session", {"action": "status", "session_id": session_id})
            if running["result"].get("status") == "RUNNING":
                break
            assert not waiting.done(), waiting.result()
            time.sleep(0.01)
        else:
            raise AssertionError("controller never reached a running target")
        assert json.loads(observer.read_resource(evidence_uri)[0]["text"])["entries"] == entries
        assert not waiting.done(), "journal evidence must not release the pending controller"
        verify_history_readers(pool, readers, lookup, shared_response, waiting)
        # The independent status read proves continue was admitted before
        # submitting another request through the controller's HTTP client.
        released = time.perf_counter()
        call("gdb_io", action="write", data_base64="AAo=")
        stopped = waiting.result(timeout=10)
        after_input_seconds = time.perf_counter() - released
        assert stopped["context"]["stop_id"] != capture_response["context"]["stop_id"], stopped
        assert (stopped["context"]["execution_epoch"]
                > capture_response["context"]["execution_epoch"]), stopped
        fresh = stopped["result"]["observations"]
        assert fresh["stack"]["frames"][0]["function"] == "report_input", stopped
        assert [item["value"] for item in fresh["values"]["results"]] == [
            "42", "{left = 1, right = 2}"]
        assert observer.call_tool("gdb_inspect", lookup)["result"] == shared
        new_lookup = {**lookup, "snapshot_id": stopped["context"]["observation_id"]}
        retained = observer.call_tool("gdb_inspect", new_lookup)
        assert retained["historical"] and retained["context"] == stopped["context"], retained
        assert retained["result"]["results"] == fresh, retained
        print(json.dumps({"mixed_control": {
            "protocol": client.protocol_version, "after_input_seconds": after_input_seconds,
            "before": capture_response["context"], "after": stopped["context"],
            "historical_results_unchanged": True,
        }}), flush=True)
        peer_status = observer.call_tool("gdb_session", {"action": "status", "session_id": session_id})
        peer_identity = peer_status["result"]["caller_identity"]
        assert peer_identity != created["controller"], peer_status
        transferred = call("gdb_session", action="handoff", to=peer_identity)
        assert transferred["result"]["controller"] == peer_identity, transferred
        controller = observer
        try:
            client.call_tool("gdb_run", {"action": "continue", "session_id": session_id})
        except ApiError as error:
            assert error.code == "WRITE_LEASE_REQUIRED", error.response
        else:
            raise AssertionError("former controller retained mutation authority")
        exited = call("gdb_run", action="continue")
        assert exited["result"]["settled_by"] == "exited", exited
        assert exited["state"]["exit_code"] == 0, exited
        output = call("gdb_io", action="read", after_offset=0, max_bytes=4096)
        assert not output.get("truncated", False), output
        verify_output(client, session_id, output["result"], expected)
        assert client.call_tool("gdb_inspect", lookup)["result"] == shared
    finally:
        try:
            closed = call("gdb_session", action="close")
        finally:
            # Close the target first so a failed assertion cannot leave pool
            # shutdown waiting behind the controller's input-blocked request.
            pool.shutdown(wait=True, cancel_futures=True)
            for reader in readers:
                reader.disconnect()
            observer.disconnect()
    verify_close(client, closed, expected)
    assert client.call_tool("gdb_inspect", lookup)["result"] == shared
    closed_retained = client.call_tool("gdb_inspect", new_lookup)
    assert closed_retained["context"] == retained["context"], closed_retained
    assert closed_retained["result"] == retained["result"], closed_retained
    assert json.loads(client.read_resource(evidence_uri)[0]["text"])["entries"] == entries


def main():
    endpoint, program, version = sys.argv[1:]
    client = Client(endpoint, protocol_version=version, client_name="python-controller")
    try:
        client.connect()
        names = {tool["name"] for tool in client.list_tools()}
        assert {"gdb_session", "gdb_run", "gdb_inspect", "gdb_io"} <= names, names
        assert "gdb_raw" not in names, names
        assert client.list_resource_templates()
        try:
            client.call_tool("not_a_tool")
        except RpcError as error:
            assert error.code == -32601, error
        else:
            raise AssertionError("unknown tool was accepted")
        canonical(client, program)
        projected(client, program)
    finally:
        client.disconnect()
    print(f"Python {version}: canonical, projected, resources and output artifacts passed")


if __name__ == "__main__":
    main()
