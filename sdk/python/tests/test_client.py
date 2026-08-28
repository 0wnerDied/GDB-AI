# SPDX-License-Identifier: GPL-3.0-or-later

import io
import json
import unittest
from unittest.mock import patch

from gdb_ai.client import Client


class Response(io.BytesIO):
    def __init__(self, payload: dict, headers: dict[str, str] | None = None) -> None:
        super().__init__(json.dumps(payload).encode())
        self.headers = headers or {}

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class ClientTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
