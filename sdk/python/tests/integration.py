# SPDX-License-Identifier: GPL-3.0-or-later
"""Real HTTP/GDB SDK contract check, launched by sdk/verify.py."""

import base64
import hashlib
import json
import sys

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


def canonical(client, program):
    session = Session.create(client)
    expected = "environment: sdk-世界\nmarker reached\ninput received: Q\n".encode()
    try:
        session.renew()
        launched = session.call("target.launch", {
            "program": program, "environment": {"GDB_AI_TEST_ENV": "sdk-世界"},
            "stop": "first_instruction", "wait": {"until": "snapshot", "timeout_ms": 5000},
        })
        stop_id = launched["state"]["stop_id"]
        context = session.call("inspection.get", {"view": "stop_context"})
        assert context["result"]["stop_id"] == stop_id, context
        stack = session.call("inspection.get", {"view": "stack", "stop_id": stop_id, "limit": 4})
        assert stack["result"]["frames"], stack
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
    created = client.call_tool("gdb_session", {"action": "create"})
    assert "api_version" not in created and "revision" not in created, created
    assert "write_lease" not in created["result"], created
    session_id = created["result"]["session_id"]
    assert created["result"]["controller"] == created["result"]["caller_identity"], created
    expected = "environment: sdk-世界\nmarker reached\ninput received: \0\n".encode()
    observer = Client(client.endpoint, protocol_version=client.protocol_version,
                      client_name="python-observer")
    controller = client

    def call(name, **arguments):
        return controller.call_tool(name, {"session_id": session_id, **arguments})

    try:
        observer.connect()
        launched = call("gdb_session", action="launch", program=program,
                        environment={"GDB_AI_TEST_ENV": "sdk-世界"}, stop="first_instruction")
        assert launched["state"]["stop_id"], launched
        assert "backend" not in launched["state"], launched
        stack = call("gdb_inspect", view="stack", limit=4)
        assert stack["result"]["frames"], stack
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
        captured = call("gdb_batch", requests=[
            {"view": "registers", "roles": ["pc", "sp"]},
            {"view": "evaluate", "expression": "$pc"},
            {"name": "missing", "view": "evaluate", "expression": "gdb_ai_missing_sdk_symbol"},
        ])["result"]
        assert not captured["complete"], captured
        assert captured["failures"]["missing"]["code"] == "GDB_ERROR", captured
        assert "command" not in captured["results"]["evaluate"], captured
        assert "record" not in captured["failures"]["missing"].get("details", {}), captured
        observation_id = captured["observation_id"]
        lookup = {"session_id": session_id, "view": "observation", "snapshot_id": observation_id}
        shared = observer.call_tool("gdb_inspect", lookup)["result"]
        assert shared["historical"] and shared["observation_id"] == observation_id, shared
        assert shared["results"]["evaluate"] == captured["results"]["evaluate"], shared
        assert shared["failures"] == captured["failures"], shared
        peer_status = observer.call_tool("gdb_session", {"action": "status", "session_id": session_id})
        peer_identity = peer_status["result"]["caller_identity"]
        assert peer_identity != created["result"]["controller"], peer_status
        transferred = call("gdb_session", action="handoff", to=peer_identity)
        assert transferred["result"]["controller"] == peer_identity, transferred
        controller = observer
        try:
            client.call_tool("gdb_run", {"action": "continue", "session_id": session_id})
        except ApiError as error:
            assert error.code == "WRITE_LEASE_REQUIRED", error.response
        else:
            raise AssertionError("former controller retained mutation authority")
        exited = call("gdb_run", action="continue", input={"data_base64": "AAo="})
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
            observer.disconnect()
    verify_close(client, closed, expected)
    assert client.call_tool("gdb_inspect", lookup)["result"] == shared


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
