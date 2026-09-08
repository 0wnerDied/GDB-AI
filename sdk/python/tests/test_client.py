# SPDX-License-Identifier: GPL-3.0-or-later

import io
import json
import unittest
from urllib.error import HTTPError
from unittest.mock import patch

from gdb_ai import ApiError, Client, RpcError, Session


class Response(io.BytesIO):
    def __init__(self, payload: dict, headers: dict[str, str] | None = None) -> None:
        super().__init__(json.dumps(payload).encode())
        self.headers = headers or {}

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class ClientTest(unittest.TestCase):
    def test_session_uses_mutation_capable_default(self) -> None:
        calls = []

        class FakeClient:
            def call(self, method, parameters):
                calls.append((method, parameters))
                return {
                    "revision": 1,
                    "result": {
                        "session_id": "sess_test",
                        "write_lease": {"lease_id": "lease_test"},
                    },
                }

        Session.create(FakeClient())

        self.assertEqual(calls, [("session.create", {"profile": "lab_mutation"})])

    def test_calls_preserve_structured_results_errors_and_raw_opt_in(self) -> None:
        client = Client("http://127.0.0.1:8080")
        with patch.object(
            client,
            "_request",
            return_value=(
                {
                    "content": [{"type": "text", "text": "ok"}],
                    "structuredContent": {"result": {"written": 4}},
                },
                {},
            ),
        ) as request:
            result = client.call_tool("gdb_io", {"action": "write", "text": "test"})

        self.assertEqual(result, {"result": {"written": 4}})
        request.assert_called_once_with(
            "tools/call",
            {"name": "gdb_io", "arguments": {"action": "write", "text": "test"}},
        )
        with patch.object(client, "_request") as request:
            for method in ("raw.mi", "raw.console"):
                with self.assertRaises(ValueError):
                    client.call(method)
            with self.assertRaises(ValueError):
                client.call_tool("gdb_raw", {"action": "console", "command": "help"})
            request.assert_not_called()

        failure = {"error": {"code": "STALE_CONTEXT", "message": "stale", "retryable": False}}
        with patch.object(client, "_request", return_value=(
            {"structuredContent": failure, "isError": True}, {}
        )):
            with self.assertRaises(ApiError) as raised:
                client.call_tool("gdb_inspect", {"view": "stack"})
            self.assertIs(raised.exception.response, failure)
            self.assertFalse(raised.exception.retryable)

        rpc_error = {"code": -32001, "message": "deadline", "data": {"operation_id": "op_wait"}}
        for status in (200, 400):
            with self.subTest(status=status):
                def open_fault(*_args, **_kwargs):
                    payload = {"error": rpc_error}
                    if status == 400:
                        raise HTTPError(client.endpoint, 400, "Bad Request",
                                        {"Content-Type": "application/json"}, Response(payload))
                    return Response(payload)

                with patch("gdb_ai.client.urlopen", side_effect=open_fault):
                    stateless = Client(client.endpoint, protocol_version="2026-07-28")
                    with self.assertRaises(RpcError) as raised:
                        stateless.call("session.get", session_id="sess_test")
                self.assertEqual(raised.exception.code, -32001)
                self.assertEqual(raised.exception.data, {"operation_id": "op_wait"})

        with patch("gdb_ai.client.urlopen", side_effect=HTTPError(
            client.endpoint, 401, "Unauthorized", {"Content-Type": "text/plain"}, io.BytesIO(b"denied")
        )):
            with self.assertRaises(HTTPError) as raised:
                stateless.list_tools()
            with raised.exception as error:
                self.assertEqual(error.read(), b"denied")

    def test_http_protocols_and_transport_session_lifetime(self) -> None:
        requests = []

        def open_request(request, **_):
            requests.append(request)
            if request.get_method() == "DELETE":
                return Response({})
            if len(requests) == 1:
                return Response(
                    {"result": {"protocolVersion": "2025-11-25"}},
                    {"Mcp-Session-Id": "mcp_test"},
                )
            return Response({})

        with patch("gdb_ai.client.urlopen", side_effect=open_request):
            client = Client("http://127.0.0.1:8080", client_name="analysis-agent")
            client.connect()
            client.connect()
            client.disconnect()
            client.disconnect()

        self.assertEqual(requests[-1].get_method(), "DELETE")
        self.assertEqual(
            json.loads(requests[0].data)["params"]["clientInfo"]["name"],
            "analysis-agent",
        )
        self.assertEqual(requests[-1].get_header("Mcp-session-id"), "mcp_test")
        for request in requests[1:]:
            self.assertEqual(
                request.get_header("Mcp-protocol-version"), "2025-11-25"
            )
        for request in requests[:-1]:
            self.assertEqual(
                request.get_header("Accept"),
                "application/json, text/event-stream",
            )

        with patch("gdb_ai.client.urlopen", side_effect=HTTPError(
            client.endpoint, 404, "Not Found", {}, io.BytesIO()
        )):
            client._mcp_session = "mcp_evicted"
            client.disconnect()
        self.assertIsNone(client._mcp_session)
        for name in ("", "\N{SNOWMAN}" * 43):
            with self.assertRaises(ValueError):
                Client(client.endpoint, client_name=name)

        requests.clear()
        def open_stateless(request, **_):
            requests.append(request)
            method = json.loads(request.data)["method"]
            key = {
                "server/discover": "supportedVersions",
                "tools/list": "tools",
                "resources/list": "resources",
                "resources/templates/list": "resourceTemplates",
                "resources/read": "contents",
            }[method]
            return Response({"result": {key: []}})

        with patch("gdb_ai.client.urlopen", side_effect=open_stateless):
            client = Client("http://127.0.0.1:8080/mcp/", protocol_version="2026-07-28")
            self.assertEqual(client.list_tools(), [])
            client.connect()
            self.assertEqual(client.list_resources(), [])
            self.assertEqual(client.list_resource_templates(), [])
            self.assertEqual(client.read_resource("gdbai://session/sess_test/status"), [])
            client.disconnect()
        for request in requests:
            self.assertEqual(request.full_url, "http://127.0.0.1:8080/mcp")
            self.assertIsNone(request.get_header("Mcp-session-id"))
            self.assertIsNone(request.get_header("Mcp-protocol-version"))
            self.assertEqual(json.loads(request.data)["params"]["_meta"], {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            })

        requests.clear()
        with patch("gdb_ai.client.urlopen", side_effect=open_stateless):
            Client(
                client.endpoint,
                protocol_version="2026-07-28",
                client_name="analysis-agent",
            ).connect()
        self.assertEqual(
            json.loads(requests[0].data)["params"]["_meta"]["gdb-ai.dev/clientName"],
            "analysis-agent",
        )

    def test_renew_accepts_the_latest_revision(self) -> None:
        calls = []

        class FakeClient:
            def call(self, method, parameters, **envelope):
                calls.append((method, parameters, envelope))
                return {"revision": 9, "result": {"lease_id": "lease_new"}}

        session = Session(FakeClient(), "sess_test", 7, "lease_old")
        session.renew()

        self.assertNotIn("expected_revision", calls[0][2])
        self.assertEqual(session.revision, 9)
        self.assertEqual(session.lease_id, "lease_new")
        session.handoff("principal/mcp:next-agent")
        self.assertEqual(calls[-1][0], "session.handoff")
        self.assertEqual(calls[-1][1], {
            "to": "principal/mcp:next-agent",
            "lease_id": "lease_new",
        })
        self.assertEqual(calls[-1][2]["expected_revision"], 9)

    def test_session_retries_once_after_managed_lease_expiry(self) -> None:
        calls = []

        class FakeClient:
            def call(self, method, parameters=None, **envelope):
                calls.append((method, dict(parameters or {}), envelope))
                if method == "target.kill" and len(calls) == 1:
                    raise ApiError(
                        {"code": "WRITE_LEASE_EXPIRED", "message": "expired"},
                        {"revision": 8},
                    )
                if method == "session.acquire_write_lease":
                    return {"revision": 9, "result": {"lease_id": "lease_new"}}
                return {"revision": 10, "result": {"killed": True}}

        session = Session(FakeClient(), "sess_test", 7, "lease_old")
        parameters = {}
        result = session.call("target.kill", parameters)

        self.assertTrue(result["result"]["killed"])
        self.assertEqual([call[0] for call in calls], [
            "target.kill",
            "session.acquire_write_lease",
            "target.kill",
        ])
        self.assertEqual(calls[-1][1]["lease_id"], "lease_new")
        self.assertEqual(calls[-1][2]["expected_revision"], 9)
        self.assertEqual(parameters, {})
        self.assertEqual(session.revision, 10)

        class RejectingClient:
            def call(self, method, parameters=None, **envelope):
                calls.append((method, dict(parameters or {}), envelope))
                if method == "session.acquire_write_lease":
                    return {"revision": 9, "result": {"lease_id": "lease_new"}}
                raise ApiError({"code": "WRITE_LEASE_EXPIRED", "message": "expired"})

        for parameters, key, expected in (
            ({}, None, 3), ({"lease_id": "lease_explicit"}, None, 1), ({}, "kill-once", 1)
        ):
            with self.subTest(parameters=parameters, key=key):
                calls.clear()
                session = Session(RejectingClient(), "sess_test", 7, "lease_old")
                with self.assertRaises(ApiError):
                    session.call("target.kill", parameters, idempotency_key=key)
                self.assertEqual(len(calls), expected)
                self.assertEqual(calls[-1][2]["idempotency_key"], key)

    def test_session_keeps_revision_from_rejected_response(self) -> None:
        class FakeClient:
            def call(self, *_args, **_kwargs):
                raise ApiError(
                    {"code": "STALE_REVISION", "message": "stale"},
                    {"revision": 11},
                )

        session = Session(FakeClient(), "sess_test", 7, "lease_old")
        with self.assertRaises(ApiError):
            session.call("target.kill")
        self.assertEqual(session.revision, 11)
        with patch.object(session.client, "call", return_value={"revision": 8, "result": {}}):
            session.call("session.get", idempotency_key="cached-status")
        self.assertEqual(session.revision, 11)
        with patch.object(session.client, "call", side_effect=ApiError(
            {"code": "STALE_REVISION", "message": "cached rejection"}, {"revision": 9}
        )):
            with self.assertRaises(ApiError):
                session.call("target.kill", idempotency_key="cached-error")
        self.assertEqual(session.revision, 11)

    def test_session_cleanup_returns_results_without_stale_coordination(self) -> None:
        calls = []

        class FakeClient:
            def call(self, method, parameters=None, **envelope):
                calls.append((method, parameters, envelope))
                return {"result": {"closed": True, "clean_shutdown": False}}

        response = Session(FakeClient(), "sess_test", 7, "lease_expired").force_abort()

        self.assertEqual(calls, [("session.force_abort", None, {"session_id": "sess_test"})])
        self.assertFalse(response["result"]["clean_shutdown"])

        class ClosingClient:
            def call(self, method, parameters, **envelope):
                calls.append((method, parameters, envelope))
                return {"revision": 12, "result": {"closed": True, "clean_shutdown": True}}

        session = Session(ClosingClient(), "sess_test", 7, "lease_old")
        self.assertTrue(session.close()["result"]["closed"])
        self.assertIsNone(calls[-1][2]["expected_revision"])
        self.assertTrue(calls[-1][1]["accept_latest_revision"])
        self.assertEqual(session.revision, 12)


if __name__ == "__main__":
    unittest.main()
