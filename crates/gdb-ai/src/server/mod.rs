use super::*;

mod http;
mod resources;
mod stream;

pub(super) use http::serve_http;
pub(super) use stream::{serve_stdio, serve_unix};

use resources::{list_resources, read_resource, resource_templates};

pub(super) const MCP_VERSION: &str = "2025-11-25";
pub(super) const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_PENDING_REQUESTS: usize = 128;
const MAX_HTTP_PENDING_DURATION: Duration = Duration::from_secs(5 * 60);

type RpcOutput = (Option<String>, Value);

#[derive(Clone, Copy)]
enum CancelMode {
    DetachWaiter,
    InterruptTarget,
    CloseSession,
}

#[derive(Clone)]
struct RequestCancellation {
    mode: CancelMode,
    session_id: Option<String>,
    lease_id: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    New,
    AwaitingInitialized,
    Ready,
}

#[derive(Debug)]
struct RpcFault {
    code: i64,
    message: String,
    data: Option<Value>,
}

impl RpcFault {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
            data: None,
        }
    }
}

const AGENT_INSTRUCTIONS: &str = "Use tools/list schemas as authoritative. Start with \
gdb_session create, retain session_id, lease_id, and the latest revision, then launch; \
argv contains arguments only, not the program path. debug_control permits reads and \
run control; inferior PTY input and exploit experiments require a server configured \
for lab_mutation or an administrative caller selecting it. Renew an expired lease \
with acquire_write_lease and accept_latest_revision=true, omitting expected_revision. \
Read inferior output from stream=pty. Use each returned stop_id for stop-scoped \
inspection; resuming invalidates old frames and values. For stripped PIEs, set \
module-offset breakpoints with names shown by inspection mappings; a local \
explicit-loader breakpoint rebinds when its executable mapping appears. Read large evidence through \
gdbai:// resources and close the session when finished.";

fn initialize(params: &Value, phase: &mut Phase, caller: &mut Caller) -> Result<Value, RpcFault> {
    if *phase != Phase::New {
        return Err(RpcFault::invalid("initialize may only be called once"));
    }
    let requested = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcFault::invalid("protocolVersion is required"))?;
    let client_name = params
        .get("clientInfo")
        .and_then(|info| info.get("name"))
        .and_then(Value::as_str)
        .ok_or_else(|| RpcFault::invalid("clientInfo.name is required"))?;
    if client_name.is_empty() || client_name.len() > 128 {
        return Err(RpcFault::invalid(
            "clientInfo.name must contain 1 to 128 bytes",
        ));
    }
    caller.identity = format!("{}/mcp:{client_name}", caller.identity);
    *phase = Phase::AwaitingInitialized;
    let supported = [MCP_VERSION, "2025-06-18", "2025-03-26", "2024-11-05"];
    let version = if supported.contains(&requested) {
        requested
    } else {
        MCP_VERSION
    };
    Ok(json!({
        "protocolVersion": version,
        "capabilities": {
            "tools": {"listChanged": false},
            "resources": {"subscribe": false, "listChanged": false}
        },
        "serverInfo": {"name": "gdb-ai", "version": env!("CARGO_PKG_VERSION")},
        "instructions": AGENT_INSTRUCTIONS
    }))
}

fn apply_cancel_mode(
    gateway: Arc<Gateway>,
    caller: Caller,
    sequence: Arc<AtomicU64>,
    cancellation: RequestCancellation,
) {
    // 2026-08-28: MCP cancellation only aborted the response waiter while
    // presenting no explicit way to interrupt or close the target operation.
    let Some(session_id) = cancellation.session_id else {
        return;
    };
    let Some(lease_id) = cancellation.lease_id else {
        return;
    };
    let (method, parameters) = match cancellation.mode {
        CancelMode::DetachWaiter => return,
        CancelMode::InterruptTarget => (
            CanonicalMethod::ExecutionControl,
            json!({
                "action": "interrupt",
                "lease_id": lease_id,
                "accept_latest_revision": true
            }),
        ),
        CancelMode::CloseSession => (
            CanonicalMethod::SessionClose,
            json!({"lease_id": lease_id, "accept_latest_revision": true}),
        ),
    };
    tokio::spawn(async move {
        let response = gateway
            .dispatch(
                ApiRequest {
                    api_version: API_VERSION.into(),
                    request_id: format!("cancel_{}", sequence.fetch_add(1, Ordering::Relaxed)),
                    session_id: Some(session_id),
                    method,
                    expected_revision: None,
                    idempotency_key: None,
                    parameters,
                },
                &caller,
            )
            .await;
        if let Some(error) = response.error {
            tracing::warn!(code = ?error.code, message = %error.message, "request cancellation action failed");
        }
    });
}

fn request_cancellation(method: &str, params: &Value) -> Result<RequestCancellation, RpcFault> {
    let parameters = match method {
        "tools/call" => params.get("arguments").unwrap_or(&Value::Null),
        "gdb.ai/call" => params,
        _ => &Value::Null,
    };
    let mode = match parameters
        .get("cancel_mode")
        .and_then(Value::as_str)
        .unwrap_or("detach_waiter")
    {
        "detach_waiter" => CancelMode::DetachWaiter,
        "interrupt_target" => CancelMode::InterruptTarget,
        "close_session" => CancelMode::CloseSession,
        _ => return Err(RpcFault::invalid("unsupported cancel_mode")),
    };
    let session_id = parameters
        .get("session_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let lease_id = parameters
        .get("lease_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if !matches!(mode, CancelMode::DetachWaiter) && (session_id.is_none() || lease_id.is_none()) {
        return Err(RpcFault::invalid(
            "interrupt_target and close_session require session_id and lease_id",
        ));
    }
    Ok(RequestCancellation {
        mode,
        session_id,
        lease_id,
    })
}

fn progress_token(params: &Value) -> Result<Option<Value>, RpcFault> {
    let Some(token) = params
        .get("_meta")
        .and_then(|metadata| metadata.get("progressToken"))
    else {
        return Ok(None);
    };
    if token.is_string() || token.is_number() {
        Ok(Some(token.clone()))
    } else {
        Err(RpcFault::invalid(
            "_meta.progressToken must be a string or number",
        ))
    }
}

fn progress_notification(token: Value, progress: u64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {
            "progressToken": token,
            "progress": progress,
            "total": 1,
            "message": message
        }
    })
}

async fn dispatch_rpc(
    gateway: &Gateway,
    caller: &Caller,
    advanced_tools: bool,
    sequence: &AtomicU64,
    method: &str,
    params: Value,
) -> Result<Value, RpcFault> {
    match method {
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools(advanced_tools, caller.admin)})),
        "tools/call" => call_tool(gateway, caller, advanced_tools, sequence, params).await,
        "resources/list" => list_resources(gateway, caller, sequence).await,
        "resources/templates/list" => Ok(resource_templates()),
        "resources/read" => read_resource(gateway, caller, sequence, &params).await,
        "gdb.ai/call" => {
            let request: ApiRequest = serde_json::from_value(params)
                .map_err(|error| RpcFault::invalid(error.to_string()))?;
            Ok(
                serde_json::to_value(gateway.dispatch(request, caller).await)
                    .map_err(|error| RpcFault::invalid(error.to_string()))?,
            )
        }
        _ => Err(RpcFault {
            code: -32601,
            message: format!("method not found: {method}"),
            data: None,
        }),
    }
}

async fn call_tool(
    gateway: &Gateway,
    caller: &Caller,
    advanced_tools: bool,
    sequence: &AtomicU64,
    params: Value,
) -> Result<Value, RpcFault> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcFault::invalid("tools/call requires name"))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let request = map_tool(
        name,
        arguments,
        advanced_tools,
        caller.admin,
        sequence.fetch_add(1, Ordering::Relaxed),
    )?;
    let response = gateway.dispatch(request, caller).await;
    Ok(tool_result(response))
}

fn map_tool(
    name: &str,
    arguments: Value,
    advanced_tools: bool,
    raw_admin: bool,
    sequence: u64,
) -> Result<ApiRequest, RpcFault> {
    let mut parameters = arguments
        .as_object()
        .cloned()
        .ok_or_else(|| RpcFault::invalid("tool arguments must be an object"))?;
    let session_id = take_string(&mut parameters, "session_id")?;
    let expected_revision = take_u64(&mut parameters, "expected_revision")?;
    let idempotency_key = take_string(&mut parameters, "idempotency_key")?;
    let _ = take_string(&mut parameters, "cancel_mode")?;
    let discriminator = discriminator_for_tool(name);
    let action = discriminator
        .map(|field| take_required_string(&mut parameters, field))
        .transpose()?;
    let method =
        method_for_tool(name, action.as_deref(), advanced_tools, raw_admin).ok_or_else(|| {
            if tool_exists(name, advanced_tools, raw_admin) {
                RpcFault::invalid(format!(
                    "unsupported {name} action {}",
                    action.as_deref().unwrap_or_default()
                ))
            } else {
                RpcFault {
                    code: -32601,
                    message: format!("tool not found: {name}"),
                    data: None,
                }
            }
        })?;
    match (name, method, action.as_deref()) {
        ("gdb_run", CanonicalMethod::ExecutionControl, Some(action)) => {
            parameters.insert("action".into(), Value::String(action.into()));
        }
        ("gdb_breakpoints", CanonicalMethod::BreakpointUpdate, Some("enable" | "disable")) => {
            parameters.insert(
                "enabled".into(),
                Value::Bool(action.as_deref() == Some("enable")),
            );
        }
        ("gdb_inspect", CanonicalMethod::InspectionGet, Some(view)) => {
            parameters.insert("view".into(), Value::String(view.into()));
        }
        _ => {}
    }
    Ok(ApiRequest {
        api_version: API_VERSION.into(),
        request_id: format!("mcp_{sequence}"),
        session_id,
        method,
        expected_revision,
        idempotency_key,
        parameters: Value::Object(parameters),
    })
}

fn tool_result(response: ApiResponse) -> Value {
    let is_error = response.error.is_some();
    let summary = match &response.error {
        Some(error) => format!("{}: {}", error.code.code_name(), error.message),
        None => match response.revision {
            Some(revision) => format!("request completed at revision {revision}"),
            None => "request completed".into(),
        },
    };
    let structured = serde_json::to_value(response).unwrap_or_else(
        |error| json!({"error": {"code": "INTERNAL", "message": error.to_string()}}),
    );
    json!({
        "content": [{"type": "text", "text": summary}],
        "structuredContent": structured,
        "isError": is_error
    })
}

fn canonical_request(
    sequence: &AtomicU64,
    session_id: Option<String>,
    method: CanonicalMethod,
    parameters: Value,
) -> ApiRequest {
    ApiRequest {
        api_version: API_VERSION.into(),
        request_id: format!("rpc_{}", sequence.fetch_add(1, Ordering::Relaxed)),
        session_id,
        method,
        expected_revision: None,
        idempotency_key: None,
        parameters,
    }
}

fn take_required_string(object: &mut Map<String, Value>, name: &str) -> Result<String, RpcFault> {
    take_string(object, name)?.ok_or_else(|| RpcFault::invalid(format!("{name} is required")))
}

fn take_string(object: &mut Map<String, Value>, name: &str) -> Result<Option<String>, RpcFault> {
    match object.remove(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(RpcFault::invalid(format!("{name} must be a string"))),
    }
}

fn take_u64(object: &mut Map<String, Value>, name: &str) -> Result<Option<u64>, RpcFault> {
    match object.remove(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| RpcFault::invalid(format!("{name} must be unsigned"))),
        Some(_) => Err(RpcFault::invalid(format!("{name} must be unsigned"))),
    }
}

fn core_fault(code: impl Into<String>, message: impl Into<String>) -> RpcFault {
    RpcFault {
        code: -32001,
        message: message.into(),
        data: Some(json!({"gdb_ai_code": code.into()})),
    }
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn rpc_fault(id: Value, fault: RpcFault) -> Value {
    let mut error = json!({"code": fault.code, "message": fault.message});
    if let Some(data) = fault.data {
        error["data"] = data;
    }
    json!({"jsonrpc": "2.0", "id": id, "error": error})
}

fn rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    rpc_fault(
        id,
        RpcFault {
            code,
            message: message.into(),
            data: None,
        },
    )
}

fn valid_request_id(id: &Value) -> bool {
    id.as_str().is_some_and(|id| id.len() <= 128) || id.as_i64().is_some() || id.as_u64().is_some()
}

fn request_key(id: &Value) -> String {
    serde_json::to_string(id).unwrap_or_default()
}

pub(super) async fn read_line_bounded<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    maximum: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let buffer = reader.fill_buf().await?;
        if buffer.is_empty() {
            return Ok((!line.is_empty()).then_some(line));
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(buffer.len(), |index| index + 1);
        if line.len() + consumed > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("JSON-RPC message exceeds {maximum} bytes"),
            ));
        }
        line.extend_from_slice(&buffer[..consumed]);
        reader.consume(consumed);
        if newline.is_some() {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
    }
}

pub(super) async fn write_rpc<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    response: Value,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(&response)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await
}

pub(super) trait ErrorCodeName {
    fn code_name(&self) -> String;
}

impl ErrorCodeName for gdb_ai_core::ErrorCode {
    fn code_name(&self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "INTERNAL".into())
    }
}

#[cfg(test)]
mod tests;
