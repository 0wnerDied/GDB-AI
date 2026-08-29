// SPDX-License-Identifier: GPL-3.0-or-later

const MCP_VERSION = "2025-11-25";

export interface ApiResponse<T = unknown> {
  api_version: "gdb.ai/v1";
  request_id: string;
  session_id?: string;
  revision?: number;
  state?: unknown;
  result?: T;
  warnings: Array<{ code: string; message: string }>;
  truncated: boolean;
  continuation?: unknown;
  artifacts: string[];
  evidence: Array<{ kind: string; uri: string }>;
  error?: { code: string; message: string; retryable: boolean; details?: unknown };
}

export class ApiError extends Error {
  constructor(public readonly response: ApiResponse) {
    super(`${response.error?.code ?? "INTERNAL"}: ${response.error?.message ?? "request failed"}`);
  }
}

export class Client {
  private nextId = 1;
  private mcpSession?: string;
  private mcpVersion?: string;

  constructor(
    private readonly endpoint: string,
    private readonly token?: string,
    private readonly allowRaw = false,
  ) {}

  async connect(): Promise<void> {
    const { result, response } = await this.rpc("initialize", {
      protocolVersion: MCP_VERSION,
      clientInfo: { name: "gdb-ai-typescript", version: "0.1.0" },
    }, false);
    if ((result as { protocolVersion?: string }).protocolVersion !== MCP_VERSION) {
      throw new Error("server returned an unsupported MCP protocol version");
    }
    this.mcpVersion = MCP_VERSION;
    this.mcpSession = response.headers.get("Mcp-Session-Id") ?? undefined;
    if (!this.mcpSession) throw new Error("server returned no MCP session ID");
    await this.notify("notifications/initialized", {});
  }

  // 2026-08-28: Clients could create HTTP transport sessions but had no
  // matching DELETE operation, leaving server state until idle eviction.
  async disconnect(): Promise<void> {
    if (!this.mcpSession) return;
    const response = await fetch(`${this.endpoint.replace(/\/$/, "")}/mcp`, {
      method: "DELETE",
      headers: this.headers(true),
    });
    if (!response.ok && response.status !== 404) {
      throw new Error(`HTTP ${response.status}`);
    }
    this.mcpSession = undefined;
    this.mcpVersion = undefined;
  }

  async call<T = unknown>(
    method: string,
    parameters: Record<string, unknown> = {},
    options: { sessionId?: string; expectedRevision?: number; idempotencyKey?: string } = {},
  ): Promise<ApiResponse<T>> {
    if (method.startsWith("raw.") && !this.allowRaw) {
      throw new Error("raw methods require allowRaw=true");
    }
    const requestId = `ts_${this.nextId}`;
    const { result } = await this.rpc("gdb.ai/call", {
      api_version: "gdb.ai/v1",
      request_id: requestId,
      session_id: options.sessionId,
      method,
      expected_revision: options.expectedRevision,
      idempotency_key: options.idempotencyKey,
      parameters,
    });
    const response = result as ApiResponse<T>;
    if (response.error) throw new ApiError(response);
    return response;
  }

  private async rpc(
    method: string,
    params: unknown,
    includeSession = true,
  ): Promise<{ result: unknown; response: Response }> {
    const id = this.nextId++;
    const response = await fetch(`${this.endpoint.replace(/\/$/, "")}/mcp`, {
      method: "POST",
      headers: this.headers(includeSession),
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const message = await response.json() as { result?: unknown; error?: unknown };
    if (message.error) throw new Error(JSON.stringify(message.error));
    return { result: message.result, response };
  }

  private async notify(method: string, params: unknown): Promise<void> {
    const response = await fetch(`${this.endpoint.replace(/\/$/, "")}/mcp`, {
      method: "POST",
      headers: this.headers(true),
      body: JSON.stringify({ jsonrpc: "2.0", method, params }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
  }

  private headers(includeSession: boolean): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    if (includeSession) {
      if (!this.mcpSession) throw new Error("connect() must be called first");
      headers["Mcp-Session-Id"] = this.mcpSession;
      // 2026-08-29: Bind every HTTP request to the negotiated MCP version.
      headers["Mcp-Protocol-Version"] = this.mcpVersion ?? MCP_VERSION;
    }
    return headers;
  }
}

export class Session {
  private constructor(
    private readonly client: Client,
    readonly sessionId: string,
    private revision: number,
    private leaseId: string,
  ) {}

  static async create(client: Client, profile = "debug_control"): Promise<Session> {
    const response = await client.call<{
      session_id: string;
      write_lease: { lease_id: string };
    }>("session.create", { profile });
    const result = response.result!;
    return new Session(client, result.session_id, response.revision!, result.write_lease.lease_id);
  }

  async call<T = unknown>(
    method: string,
    parameters: Record<string, unknown> = {},
  ): Promise<ApiResponse<T>> {
    const response = await this.client.call<T>(method, {
      lease_id: this.leaseId,
      ...parameters,
    }, {
      sessionId: this.sessionId,
      expectedRevision: this.revision,
    });
    if (response.revision !== undefined) this.revision = response.revision;
    return response;
  }

  async renew(): Promise<void> {
    // 2026-08-28: Asynchronous target events can make the cached revision
    // stale. Supplying it here defeated accept_latest_revision.
    const response = await this.client.call<{ lease_id: string }>(
      "session.acquire_write_lease",
      { accept_latest_revision: true },
      { sessionId: this.sessionId },
    );
    this.revision = response.revision!;
    this.leaseId = response.result!.lease_id;
  }

  async close(): Promise<void> {
    await this.call("session.close");
  }
}
