# SPDX-License-Identifier: GPL-3.0-or-later
"""Dependency-free HTTP client for canonical and projected GDB/AI calls."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal, TypedDict
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ProtocolVersion = Literal["2025-11-25", "2026-07-28"]
MCP_VERSION: ProtocolVersion = "2025-11-25"
STATELESS_MCP_VERSION: ProtocolVersion = "2026-07-28"

ValueStatus = Literal["available", "unavailable", "not_collected", "failed", "invalid", "unknown"]


class _ObservationContextRequired(TypedDict):
    stop_id: str
    captured_revision: int
    execution_epoch: int


class ObservationContext(_ObservationContextRequired, total=False):
    observation_id: str
    inferior_id: str
    thread_id: str
    frame_id: str


class _ResultSemanticsRequired(TypedDict):
    complete: bool
    historical: bool
    projection: Literal["detailed", "compact"]


class ResultSemantics(_ResultSemanticsRequired, total=False):
    context: ObservationContext
    state: Any


class _ValueChildRequired(TypedDict):
    path: str
    status: ValueStatus


class ValueChild(_ValueChildRequired, total=False):
    name: str
    type: Any
    value: Any
    children_count: int
    has_children: bool
    dynamic: bool
    display_hint: str
    has_more: bool


class _ValueChangeRequired(TypedDict):
    path: str
    status: ValueStatus


class ValueChange(_ValueChangeRequired, total=False):
    value_id: str
    type: Any
    value: Any
    type_changed: bool
    children_count: int
    has_children: bool
    dynamic: bool
    display_hint: str
    has_more: bool
    new_children: list[ValueChild]


class ApiError(RuntimeError):
    def __init__(self, error: dict[str, Any], response: dict[str, Any] | None = None) -> None:
        self.code = str(error.get("code", "INTERNAL"))
        self.details = error.get("details")
        self.retryable = bool(error.get("retryable", False))
        self.response = response or {}
        super().__init__(f"{self.code}: {error.get('message', 'request failed')}")


class RpcError(RuntimeError):
    def __init__(self, error: dict[str, Any]) -> None:
        # 2026-09-06: Flattening RPC faults lost the operation_id needed to
        # inspect a timed-out waiter without repeating the target mutation.
        self.code = int(error["code"])
        self.data = error.get("data")
        super().__init__(f"{self.code}: {error['message']}")


class Client:
    def __init__(
        self,
        endpoint: str,
        *,
        token: str | None = None,
        allow_raw: bool = False,
        timeout: float = 30.0,
        protocol_version: ProtocolVersion = MCP_VERSION,
        client_name: str | None = None,
    ) -> None:
        if protocol_version not in {MCP_VERSION, STATELESS_MCP_VERSION}:
            raise ValueError("unsupported MCP protocol version")
        explicit_client_name = client_name is not None
        if client_name is None:
            client_name = "gdb-ai-python"
        if not client_name or len(client_name.encode()) > 128:
            raise ValueError("client_name must contain 1 to 128 bytes")
        # 2026-09-06: A documented /mcp endpoint used to become /mcp/mcp.
        self.endpoint = endpoint.rstrip("/")
        if not self.endpoint.endswith("/mcp"):
            self.endpoint += "/mcp"
        self.token = token
        self.allow_raw = allow_raw
        self.timeout = timeout
        self.protocol_version = protocol_version
        self.client_name = client_name
        self._explicit_client_name = explicit_client_name
        self._mcp_session: str | None = None
        self._mcp_version: str | None = None
        self._next_id = 1

    def connect(self) -> None:
        if self.protocol_version == STATELESS_MCP_VERSION:
            self._request("server/discover", {})
            return
        if self._mcp_session:
            # 2026-09-06: Repeated connect replaced an existing HTTP session
            # without deleting it. Reuse it and finish a pending handshake.
            self._notify("notifications/initialized", {})
            return
        result, headers = self._request(
            "initialize",
            {
                "protocolVersion": MCP_VERSION,
                "clientInfo": {"name": self.client_name, "version": "1.3.1"},
            },
            include_session=False,
        )
        if result.get("protocolVersion") != MCP_VERSION:
            raise RuntimeError("server returned an unsupported MCP protocol version")
        self._mcp_session = headers.get("Mcp-Session-Id")
        if not self._mcp_session:
            raise RuntimeError("server returned no MCP session ID")
        self._mcp_version = MCP_VERSION
        self._notify("notifications/initialized", {})

    # 2026-08-28: Clients could create HTTP transport sessions but had no
    # matching DELETE operation, leaving server state until idle eviction.
    def disconnect(self) -> None:
        if not self._mcp_session:
            return
        try:
            with urlopen(
                Request(self.endpoint, headers=self._headers(True), method="DELETE"),
                timeout=self.timeout,
            ):
                pass
        except HTTPError as error:
            # 2026-09-06: Idle eviction already deletes the transport session;
            # a 404 must clear local state just like a successful DELETE.
            if error.code != 404:
                raise
            error.close()
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
        # 2026-09-06: Projected raw calls bypassed the canonical opt-in guard.
        if name == "gdb_raw" and not self.allow_raw:
            raise ValueError("raw tools require allow_raw=True")
        result, _ = self._request(
            "tools/call", {"name": name, "arguments": arguments or {}}
        )
        structured = result.get("structuredContent")
        if not isinstance(structured, dict):
            raise RuntimeError("tool returned no structuredContent")
        if structured.get("error"):
            raise ApiError(structured["error"], structured)
        if result.get("isError"):
            raise RuntimeError("tool failed without a structured error")
        return structured

    def list_resources(self) -> list[dict[str, Any]]:
        result, _ = self._request("resources/list", {})
        return result["resources"]

    def list_resource_templates(self) -> list[dict[str, Any]]:
        result, _ = self._request("resources/templates/list", {})
        return result["resourceTemplates"]

    def read_resource(self, uri: str) -> list[dict[str, Any]]:
        result, _ = self._request("resources/read", {"uri": uri})
        return result["contents"]

    def _request(
        self,
        method: str,
        params: dict[str, Any],
        *,
        include_session: bool = True,
    ) -> tuple[dict[str, Any], Any]:
        request_id = self._next_id
        self._next_id += 1
        if self.protocol_version == STATELESS_MCP_VERSION:
            metadata: dict[str, Any] = {
                "io.modelcontextprotocol/protocolVersion": STATELESS_MCP_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            }
            if self._explicit_client_name:
                metadata["gdb-ai.dev/clientName"] = self.client_name
            params = {
                **params,
                "_meta": metadata,
            }
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        ).encode()
        headers = self._headers(include_session)
        try:
            response = urlopen(
                Request(self.endpoint, data=payload, headers=headers, method="POST"),
                timeout=self.timeout,
            )
        except HTTPError as error:
            # Protocol faults may carry an HTTP 400 status as well as JSON-RPC
            # data. Authentication and other non-JSON failures remain HTTPError.
            if "application/json" not in error.headers.get("Content-Type", ""):
                raise
            with error:
                message = json.load(error)
                if message.get("error"):
                    raise RpcError(message["error"]) from error
            raise
        with response:
            message = json.load(response)
            if message.get("error"):
                raise RpcError(message["error"])
            return message["result"], response.headers

    def _headers(self, include_session: bool) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if include_session and self.protocol_version == MCP_VERSION:
            if not self._mcp_session:
                raise RuntimeError("connect() must be called first")
            headers["Mcp-Session-Id"] = self._mcp_session
            # 2026-08-29: HTTP clients previously omitted the negotiated
            # version, so the server could not bind later requests to it.
            headers["Mcp-Protocol-Version"] = self._mcp_version or MCP_VERSION
        return headers

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params}).encode()
        with urlopen(
            Request(self.endpoint, data=payload, headers=self._headers(True), method="POST"),
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
    def create(cls, client: Client, profile: str = "lab_mutation") -> "Session":
        response = client.call("session.create", {"profile": profile})
        result = response["result"]
        return cls(
            client=client,
            session_id=result["session_id"],
            revision=response["revision"],
            lease_id=result["write_lease"]["lease_id"],
        )

    def call(
        self,
        method: str,
        parameters: dict[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
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
                    idempotency_key=idempotency_key,
                )
                break
            except ApiError as error:
                self._observe_revision(error.response)
                # 2026-08-31: An expired lease rejects the mutation before its
                # target effect. Renew and retry that one managed request once.
                # A keyed response is cached with its revision and lease;
                # renewing would change that request's fingerprint.
                if (
                    error.code != "WRITE_LEASE_EXPIRED"
                    or not managed_lease
                    or idempotency_key is not None
                    or renewed
                ):
                    raise
                self.renew()
                parameters["lease_id"] = self.lease_id
                renewed = True
        self._observe_revision(response)
        return response

    def renew(self) -> None:
        # 2026-08-28: Inferior output can advance the revision while an Agent
        # is reasoning. Sending that stale revision defeated accept_latest.
        response = self.client.call(
            "session.acquire_write_lease",
            {"accept_latest_revision": True},
            session_id=self.session_id,
        )
        self._observe_revision(response)
        self.lease_id = response["result"]["lease_id"]

    def handoff(self, to: str) -> dict[str, Any]:
        return self.call("session.handoff", {"to": to})

    def close(self) -> dict[str, Any]:
        # 2026-09-06: Discarding close replies hid finalized output artifacts
        # and completeness metadata that callers need to retain evidence.
        return self.call("session.close")

    def force_abort(self) -> dict[str, Any]:
        response = self.client.call("session.force_abort", session_id=self.session_id)
        self._observe_revision(response)
        return response

    def _observe_revision(self, response: dict[str, Any]) -> None:
        # 2026-09-06: Cached idempotent responses can precede newer observations.
        # Never roll back the revision already learned for this session.
        if response.get("revision") is not None:
            self.revision = max(self.revision, response["revision"])
