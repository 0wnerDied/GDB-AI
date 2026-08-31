# SPDX-License-Identifier: GPL-3.0-or-later
"""Dependency-free HTTP client for canonical and projected GDB/AI calls."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.request import Request, urlopen

MCP_VERSION = "2025-11-25"


class ApiError(RuntimeError):
    def __init__(self, error: dict[str, Any], response: dict[str, Any] | None = None) -> None:
        self.code = str(error.get("code", "INTERNAL"))
        self.details = error.get("details")
        self.response = response or {}
        super().__init__(f"{self.code}: {error.get('message', 'request failed')}")


class Client:
    def __init__(
        self,
        endpoint: str,
        *,
        token: str | None = None,
        allow_raw: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self.endpoint = endpoint.rstrip("/") + "/mcp"
        self.token = token
        self.allow_raw = allow_raw
        self.timeout = timeout
        self._mcp_session: str | None = None
        self._mcp_version: str | None = None
        self._next_id = 1

    def connect(self) -> None:
        result, headers = self._request(
            "initialize",
            {
                "protocolVersion": MCP_VERSION,
                "clientInfo": {"name": "gdb-ai-python", "version": "1.1.1"},
            },
            include_session=False,
        )
        if result.get("protocolVersion") != MCP_VERSION:
            raise RuntimeError("server returned an unsupported MCP protocol version")
        self._mcp_version = MCP_VERSION
        self._mcp_session = headers.get("Mcp-Session-Id")
        if not self._mcp_session:
            raise RuntimeError("server returned no MCP session ID")
        self._notify("notifications/initialized", {})

    # 2026-08-28: Clients could create HTTP transport sessions but had no
    # matching DELETE operation, leaving server state until idle eviction.
    def disconnect(self) -> None:
        if not self._mcp_session:
            return
        headers = {"Mcp-Session-Id": self._mcp_session}
        headers["Mcp-Protocol-Version"] = self._mcp_version or MCP_VERSION
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        with urlopen(
            Request(self.endpoint, headers=headers, method="DELETE"),
            timeout=self.timeout,
        ):
            self._mcp_session = None
            self._mcp_version = None

    def call(
        self,
        method: str,
        parameters: dict[str, Any] | None = None,
        *,
        session_id: str | None = None,
        expected_revision: int | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        if method.startswith("raw.") and not self.allow_raw:
            raise ValueError("raw methods require allow_raw=True")
        envelope = {
            "api_version": "gdb.ai/v1",
            "request_id": f"py_{self._next_id}",
            "session_id": session_id,
            "method": method,
            "expected_revision": expected_revision,
            "idempotency_key": idempotency_key,
            "parameters": parameters or {},
        }
        result, _ = self._request("gdb.ai/call", envelope)
        if result.get("error"):
            # 2026-08-31: Discarding the failed envelope also discarded its
            # current revision, so clients reacquired a lease merely to learn
            # state the server had already returned.
            raise ApiError(result["error"], result)
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        result, _ = self._request("tools/list", {})
        return result["tools"]

    def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        result, _ = self._request(
            "tools/call", {"name": name, "arguments": arguments or {}}
        )
        structured = result.get("structuredContent")
        if not isinstance(structured, dict):
            raise RuntimeError("tool returned no structuredContent")
        if structured.get("error"):
            raise ApiError(structured["error"], structured)
        return structured

    def _request(
        self,
        method: str,
        params: dict[str, Any],
        *,
        include_session: bool = True,
    ) -> tuple[dict[str, Any], Any]:
        request_id = self._next_id
        self._next_id += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        ).encode()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if include_session:
            if not self._mcp_session:
                raise RuntimeError("connect() must be called first")
            headers["Mcp-Session-Id"] = self._mcp_session
            # 2026-08-29: HTTP clients previously omitted the negotiated
            # version, so the server could not bind later requests to it.
            headers["Mcp-Protocol-Version"] = self._mcp_version or MCP_VERSION
        with urlopen(
            Request(self.endpoint, data=payload, headers=headers, method="POST"),
            timeout=self.timeout,
        ) as response:
            message = json.load(response)
            if message.get("error"):
                raise RuntimeError(message["error"])
            return message["result"], response.headers

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params}).encode()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self._mcp_session:
            headers["Mcp-Session-Id"] = self._mcp_session
            headers["Mcp-Protocol-Version"] = self._mcp_version or MCP_VERSION
        with urlopen(
            Request(self.endpoint, data=payload, headers=headers, method="POST"),
            timeout=self.timeout,
        ):
            pass


@dataclass
class Session:
    client: Client
    session_id: str
    revision: int
    lease_id: str

    @classmethod
    def create(cls, client: Client, profile: str = "debug_control") -> "Session":
        response = client.call("session.create", {"profile": profile})
        result = response["result"]
        return cls(
            client=client,
            session_id=result["session_id"],
            revision=response["revision"],
            lease_id=result["write_lease"]["lease_id"],
        )

    def call(self, method: str, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
        parameters = dict(parameters or {})
        managed_lease = "lease_id" not in parameters
        if managed_lease:
            parameters["lease_id"] = self.lease_id
        if method in {
            "session.close",
            "inferior_io.write",
            "inferior_io.close_stdin",
            "inferior_io.send_eof",
            "inferior_io.resize",
        } or method == "execution.control" and parameters.get("action") == "interrupt":
            parameters.setdefault("accept_latest_revision", True)

        renewed = False
        while True:
            accept_latest = parameters.get("accept_latest_revision") is True
            try:
                response = self.client.call(
                    method,
                    parameters,
                    session_id=self.session_id,
                    expected_revision=None if accept_latest else self.revision,
                )
                break
            except ApiError as error:
                if error.response.get("revision") is not None:
                    self.revision = error.response["revision"]
                # 2026-08-31: An expired lease rejects the mutation before its
                # target effect. Renew and retry that one managed request once.
                if error.code != "WRITE_LEASE_EXPIRED" or not managed_lease or renewed:
                    raise
                self.renew()
                parameters["lease_id"] = self.lease_id
                renewed = True
        if response.get("revision") is not None:
            self.revision = response["revision"]
        return response

    def renew(self) -> None:
        # 2026-08-28: Inferior output can advance the revision while an Agent
        # is reasoning. Sending that stale revision defeated accept_latest.
        response = self.client.call(
            "session.acquire_write_lease",
            {"accept_latest_revision": True},
            session_id=self.session_id,
        )
        self.revision = response["revision"]
        self.lease_id = response["result"]["lease_id"]

    def close(self) -> None:
        self.call("session.close")

    def force_abort(self) -> None:
        self.client.call("session.force_abort", session_id=self.session_id)
