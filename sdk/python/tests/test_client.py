# SPDX-License-Identifier: GPL-3.0-or-later

import io
import json
import unittest
from unittest.mock import patch

from gdb_ai.client import ApiError, Client, Session


class Response(io.BytesIO):
    def __init__(self, payload: dict, headers: dict[str, str] | None = None) -> None:
        super().__init__(json.dumps(payload).encode())
        self.headers = headers or {}

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class ClientTest(unittest.TestCase):
    def test_projected_tool_call_returns_only_structured_content(self) -> None:
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

    def test_disconnect_deletes_transport_session(self) -> None:
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
            client = Client("http://127.0.0.1:8080")
            client.connect()
            client.disconnect()

        self.assertEqual(requests[-1].get_method(), "DELETE")
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
        result = session.call("target.kill")

        self.assertTrue(result["result"]["killed"])
        self.assertEqual([call[0] for call in calls], [
            "target.kill",
            "session.acquire_write_lease",
            "target.kill",
        ])
        self.assertEqual(calls[-1][1]["lease_id"], "lease_new")
        self.assertEqual(calls[-1][2]["expected_revision"], 9)
        self.assertEqual(session.revision, 10)

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

    def test_force_abort_does_not_require_the_business_lease(self) -> None:
        calls = []

        class FakeClient:
            def call(self, method, parameters=None, **envelope):
                calls.append((method, parameters, envelope))
                return {"result": {"closed": True, "clean_shutdown": False}}

        Session(FakeClient(), "sess_test", 7, "lease_expired").force_abort()

        self.assertEqual(calls, [("session.force_abort", None, {"session_id": "sess_test"})])


if __name__ == "__main__":
    unittest.main()
