use std::{
    collections::HashMap,
    error::Error as StdError,
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use clap::{Parser, Subcommand};
use gdb_ai_core::{
    config::Config,
    domain::SessionId,
    gateway::{Caller, Gateway},
    protocol::{API_VERSION, ApiRequest, ApiResponse},
};
use serde_json::{Map, Value, json};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::mpsc,
    task::JoinHandle,
};

const MCP_VERSION: &str = "2025-11-25";
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

type AnyError = Box<dyn StdError + Send + Sync>;
type RpcOutput = (Option<String>, Value);

#[derive(Parser)]
#[command(name = "gdb-ai", version, about)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long)]
        stdio: bool,
        #[arg(long)]
        raw_admin: bool,
    },
    Doctor,
    Replay {
        journal: PathBuf,
        #[arg(long, default_value = "sess_replay")]
        session_id: String,
    },
    Schema {
        #[command(subcommand)]
        command: SchemaCommand,
    },
    Capabilities,
}

#[derive(Subcommand)]
enum SchemaCommand {
    Export,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("gdb-ai: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), AnyError> {
    let cli = Cli::parse();
    let config = Config::load(cli.config)?;
    match cli.command {
        Command::Serve {
            stdio: true,
            raw_admin,
        } => serve_stdio(config, raw_admin).await,
        Command::Serve { stdio: false, .. } => {
            Err(io::Error::other("the vertical slice supports only `gdb-ai serve --stdio`").into())
        }
        Command::Doctor => doctor(config).await,
        Command::Replay {
            journal,
            session_id,
        } => {
            let report = gdb_ai_core::replay::replay(journal, SessionId(session_id))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::Schema {
            command: SchemaCommand::Export,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&schemars::schema_for!(ApiRequest))?
            );
            Ok(())
        }
        Command::Capabilities => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "api_version": API_VERSION,
                    "mcp_protocol_version": MCP_VERSION,
                    "transports": ["stdio"],
                    "tools": tool_names(false),
                }))?
            );
            Ok(())
        }
    }
}

async fn doctor(config: Config) -> Result<(), AnyError> {
    let gateway = Gateway::new(config)?;
    let caller = Caller::local("doctor");
    let created = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "doctor-create".into(),
                session_id: None,
                method: "session.create".into(),
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &caller,
        )
        .await;
    if let Some(error) = &created.error {
        return Err(
            io::Error::other(format!("{}: {}", error.code.code_name(), error.message)).into(),
        );
    }
    let session_id = created
        .session_id
        .clone()
        .ok_or_else(|| io::Error::other("session.create returned no session_id"))?;
    let report = json!({
        "status": "ok",
        "session_id": session_id,
        "revision": created.revision,
        "backend": created.result.as_ref().and_then(|value| value.get("backend")),
        "capabilities": created.result.as_ref().and_then(|value| value.get("capabilities")),
    });
    let _ = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "doctor-close".into(),
                session_id: Some(session_id),
                method: "session.close".into(),
                expected_revision: created.revision,
                idempotency_key: None,
                parameters: json!({}),
            },
            &caller,
        )
        .await;
    gateway.shutdown().await;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn serve_stdio(config: Config, raw_admin: bool) -> Result<(), AnyError> {
    let gateway = Arc::new(Gateway::new(config)?);
    let mut caller = Caller {
        identity: "mcp-stdio".into(),
        admin: raw_admin,
    };
    let sequence = Arc::new(AtomicU64::new(1));
    let mut phase = Phase::New;
    let mut pending: HashMap<String, JoinHandle<()>> = HashMap::new();
    let mut input_open = true;
    let (responses, mut response_rx) = mpsc::channel::<RpcOutput>(128);
    let mut input = BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();

    loop {
        if !input_open && pending.is_empty() {
            break;
        }
        tokio::select! {
            line = read_line_bounded(&mut input, MAX_MESSAGE_BYTES), if input_open => {
                let Some(line) = line? else {
                    input_open = false;
                    continue;
                };
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                let message = match serde_json::from_slice::<Value>(&line) {
                    Ok(message) => message,
                    Err(error) => {
                        write_rpc(&mut output, rpc_error(Value::Null, -32700, error.to_string())).await?;
                        continue;
                    }
                };
                let Some(object) = message.as_object() else {
                    write_rpc(&mut output, rpc_error(Value::Null, -32600, "request must be an object")).await?;
                    continue;
                };
                let id = object.get("id").cloned();
                if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
                    write_rpc(&mut output, rpc_error(id.unwrap_or(Value::Null), -32600, "jsonrpc must be 2.0")).await?;
                    continue;
                }
                let Some(method) = object.get("method").and_then(Value::as_str) else {
                    if id.is_some() {
                        write_rpc(&mut output, rpc_error(id.unwrap_or(Value::Null), -32600, "method is required")).await?;
                    }
                    continue;
                };
                let params = object.get("params").cloned().unwrap_or_else(|| json!({}));

                if id.is_none() {
                    handle_notification(method, &params, &mut phase, &mut pending);
                    continue;
                }
                let id = id.unwrap();
                if !valid_request_id(&id) {
                    write_rpc(&mut output, rpc_error(Value::Null, -32600, "id must be a string or integer")).await?;
                    continue;
                }
                if method == "initialize" {
                    let response = initialize(&params, &mut phase, &mut caller)
                        .map_or_else(|error| rpc_fault(id.clone(), error), |result| rpc_result(id.clone(), result));
                    write_rpc(&mut output, response).await?;
                    continue;
                }
                if method != "ping" && phase != Phase::Ready {
                    write_rpc(&mut output, rpc_error(id, -32002, "server is not initialized")).await?;
                    continue;
                }

                let key = request_key(&id);
                let gateway = gateway.clone();
                let caller = caller.clone();
                let responses = responses.clone();
                let sequence = sequence.clone();
                let method = method.to_owned();
                let task_key = key.clone();
                let handle = tokio::spawn(async move {
                    let response = dispatch_rpc(&gateway, &caller, &sequence, &method, params)
                        .await
                        .map_or_else(|error| rpc_fault(id.clone(), error), |result| rpc_result(id.clone(), result));
                    let _ = responses.send((Some(task_key), response)).await;
                });
                pending.insert(key, handle);
            }
            Some((key, response)) = response_rx.recv() => {
                if let Some(key) = key {
                    pending.remove(&key);
                }
                write_rpc(&mut output, response).await?;
            }
        }
    }

    for task in pending.into_values() {
        task.abort();
    }
    gateway.shutdown().await;
    Ok(())
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
    caller.identity = format!("mcp:{client_name}");
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
        "instructions": "Create a session, launch a local target, and pass revision and stop_id on state-sensitive calls. Observations are bounded; large data is returned as a gdbai:// artifact."
    }))
}

fn handle_notification(
    method: &str,
    params: &Value,
    phase: &mut Phase,
    pending: &mut HashMap<String, JoinHandle<()>>,
) {
    match method {
        "notifications/initialized" if *phase == Phase::AwaitingInitialized => {
            *phase = Phase::Ready;
        }
        "notifications/cancelled" => {
            if let Some(id) = params.get("requestId")
                && let Some(task) = pending.remove(&request_key(id))
            {
                task.abort();
            }
        }
        _ => {}
    }
}

async fn dispatch_rpc(
    gateway: &Gateway,
    caller: &Caller,
    sequence: &AtomicU64,
    method: &str,
    params: Value,
) -> Result<Value, RpcFault> {
    match method {
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools(caller.admin)})),
        "tools/call" => call_tool(gateway, caller, sequence, params).await,
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
    let request = map_tool(name, arguments, sequence.fetch_add(1, Ordering::Relaxed))?;
    let response = gateway.dispatch(request, caller).await;
    Ok(tool_result(response))
}

fn map_tool(name: &str, arguments: Value, sequence: u64) -> Result<ApiRequest, RpcFault> {
    let mut parameters = arguments
        .as_object()
        .cloned()
        .ok_or_else(|| RpcFault::invalid("tool arguments must be an object"))?;
    let session_id = take_string(&mut parameters, "session_id")?;
    let expected_revision = take_u64(&mut parameters, "expected_revision")?;
    let idempotency_key = take_string(&mut parameters, "idempotency_key")?;
    let method = match name {
        "gdb_session" => match take_required_string(&mut parameters, "action")?.as_str() {
            "create" => "session.create",
            "launch" => "target.launch",
            "status" => "session.get",
            "list" => "session.list",
            "capabilities" => "session.capabilities",
            "close" => "session.close",
            action => {
                return Err(RpcFault::invalid(format!(
                    "unsupported session action {action}"
                )));
            }
        },
        "gdb_run" => {
            let action = take_required_string(&mut parameters, "action")?;
            if action == "wait" {
                "execution.wait"
            } else {
                parameters.insert("action".into(), Value::String(action));
                "execution.control"
            }
        }
        "gdb_breakpoints" => {
            let action = take_required_string(&mut parameters, "action")?;
            match action.as_str() {
                "create" => "breakpoint.create",
                "update" => "breakpoint.update",
                "enable" | "disable" => {
                    parameters.insert("enabled".into(), Value::Bool(action == "enable"));
                    "breakpoint.update"
                }
                "delete" => "breakpoint.delete",
                "list" => "breakpoint.list",
                _ => {
                    return Err(RpcFault::invalid(format!(
                        "unsupported breakpoint action {action}"
                    )));
                }
            }
        }
        "gdb_inspect" => "inspection.get",
        "gdb_evaluate" => "value.evaluate",
        "gdb_memory" => match take_required_string(&mut parameters, "action")?.as_str() {
            "read" => "memory.read",
            action => {
                return Err(RpcFault::invalid(format!(
                    "unsupported memory action {action}"
                )));
            }
        },
        "gdb_disassemble" => "disassembly.read",
        "gdb_io" => match take_required_string(&mut parameters, "action")?.as_str() {
            "read" => "inferior_io.read",
            "write" => "inferior_io.write",
            "close_stdin" => "inferior_io.close_stdin",
            "resize" => "inferior_io.resize",
            action => {
                return Err(RpcFault::invalid(format!(
                    "unsupported I/O action {action}"
                )));
            }
        },
        "gdb_raw" => match take_required_string(&mut parameters, "action")?.as_str() {
            "console" => "raw.console",
            action => {
                return Err(RpcFault::invalid(format!(
                    "unsupported raw action {action}"
                )));
            }
        },
        _ => {
            return Err(RpcFault {
                code: -32601,
                message: format!("tool not found: {name}"),
                data: None,
            });
        }
    };
    Ok(ApiRequest {
        api_version: API_VERSION.into(),
        request_id: format!("mcp_{sequence}"),
        session_id,
        method: method.into(),
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
    let serialized = serde_json::to_string(&structured).unwrap_or_else(|_| summary.clone());
    let text = if serialized.len() <= 16 * 1024 {
        serialized
    } else {
        summary
    };
    json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured,
        "isError": is_error
    })
}

async fn list_resources(
    gateway: &Gateway,
    caller: &Caller,
    sequence: &AtomicU64,
) -> Result<Value, RpcFault> {
    let response = gateway
        .dispatch(
            canonical_request(sequence, None, "session.list", json!({})),
            caller,
        )
        .await;
    if let Some(error) = response.error {
        return Err(core_fault(error.code.code_name(), error.message));
    }
    let resources = response
        .result
        .and_then(|result| result.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|state| {
            let id = state.get("session_id")?.as_str()?;
            Some(json!({
                "uri": format!("gdbai://session/{id}/status"),
                "name": format!("Session {id} status"),
                "mimeType": "application/json"
            }))
        })
        .collect::<Vec<_>>();
    Ok(json!({"resources": resources}))
}

fn resource_templates() -> Value {
    json!({"resourceTemplates": [
        {
            "uriTemplate": "gdbai://session/{session_id}/status",
            "name": "Session status",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://artifact/sha256:{digest}",
            "name": "Content-addressed artifact",
            "mimeType": "application/octet-stream"
        }
    ]})
}

async fn read_resource(
    gateway: &Gateway,
    caller: &Caller,
    sequence: &AtomicU64,
    params: &Value,
) -> Result<Value, RpcFault> {
    let uri = params
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcFault::invalid("resources/read requires uri"))?;
    if uri.starts_with("gdbai://artifact/sha256:") {
        let response = gateway
            .dispatch(
                canonical_request(sequence, None, "artifact.get", json!({"uri": uri})),
                caller,
            )
            .await;
        if let Some(error) = response.error {
            return Err(core_fault(error.code.code_name(), error.message));
        }
        let blob = response
            .result
            .and_then(|result| result.get("data_base64").cloned())
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| RpcFault::invalid("artifact response contained no data"))?;
        return Ok(json!({"contents": [{
            "uri": uri,
            "mimeType": "application/octet-stream",
            "blob": blob
        }]}));
    }
    let session = uri
        .strip_prefix("gdbai://session/")
        .and_then(|path| path.strip_suffix("/status"))
        .filter(|id| !id.is_empty() && !id.contains('/'))
        .ok_or_else(|| RpcFault {
            code: -32002,
            message: "resource not found".into(),
            data: Some(json!({"uri": uri})),
        })?;
    let response = gateway
        .dispatch(
            canonical_request(sequence, Some(session.into()), "session.get", json!({})),
            caller,
        )
        .await;
    if let Some(error) = response.error {
        return Err(core_fault(error.code.code_name(), error.message));
    }
    let text = serde_json::to_string(&response.result.unwrap_or(Value::Null))
        .map_err(|error| RpcFault::invalid(error.to_string()))?;
    Ok(json!({"contents": [{
        "uri": uri,
        "mimeType": "application/json",
        "text": text
    }]}))
}

fn canonical_request(
    sequence: &AtomicU64,
    session_id: Option<String>,
    method: &str,
    parameters: Value,
) -> ApiRequest {
    ApiRequest {
        api_version: API_VERSION.into(),
        request_id: format!("rpc_{}", sequence.fetch_add(1, Ordering::Relaxed)),
        session_id,
        method: method.into(),
        expected_revision: None,
        idempotency_key: None,
        parameters,
    }
}

fn tools(include_raw: bool) -> Vec<Value> {
    let mut tools = vec![
        tool(
            "gdb_session",
            "Create, launch, inspect, or close a local GDB session.",
            schema(
                &["action"],
                [
                    (
                        "action",
                        enum_schema(&[
                            "create",
                            "launch",
                            "status",
                            "list",
                            "capabilities",
                            "close",
                        ]),
                    ),
                    ("program", json!({"type": "string"})),
                    (
                        "profile",
                        enum_schema(&[
                            "offline_core",
                            "live_observer",
                            "debug_control",
                            "lab_mutation",
                            "raw_admin",
                        ]),
                    ),
                    (
                        "argv",
                        json!({"type": "array", "items": {"type": "string"}}),
                    ),
                    ("cwd", json!({"type": "string"})),
                    (
                        "environment",
                        json!({"type": "object", "additionalProperties": {"type": "string"}}),
                    ),
                    ("environment_mode", enum_schema(&["clean"])),
                    ("aslr", enum_schema(&["preserve", "disable"])),
                    ("stop", enum_schema(&["entry", "none"])),
                    ("follow_fork", enum_schema(&["parent", "child"])),
                    ("detach_on_fork", json!({"type": "boolean"})),
                    ("wait", wait_schema()),
                ],
            ),
            false,
        ),
        tool(
            "gdb_run",
            "Continue, interrupt, step, or wait for explicit target state.",
            schema(
                &["action", "session_id"],
                [
                    (
                        "action",
                        enum_schema(&[
                            "continue",
                            "interrupt",
                            "step",
                            "next",
                            "finish",
                            "step_instruction",
                            "next_instruction",
                            "until",
                            "wait",
                        ]),
                    ),
                    ("stop_id", json!({"type": "string"})),
                    ("thread_id", json!({"type": "string"})),
                    ("frame_id", json!({"type": "string"})),
                    ("location", json!({"type": "string"})),
                    ("wait", wait_schema()),
                ],
            ),
            false,
        ),
        tool(
            "gdb_breakpoints",
            "Create and manage bounded, structured breakpoints and watchpoints.",
            schema(
                &["action", "session_id"],
                [
                    (
                        "action",
                        enum_schema(&["create", "update", "enable", "disable", "delete", "list"]),
                    ),
                    ("breakpoint_id", json!({"type": "string"})),
                    ("location", json!({"type": "object"})),
                    (
                        "kind",
                        enum_schema(&[
                            "software",
                            "hardware",
                            "watchpoint",
                            "read_watchpoint",
                            "access_watchpoint",
                        ]),
                    ),
                    ("condition", json!({"type": "string"})),
                    ("ignore_count", json!({"type": "integer", "minimum": 0})),
                    ("temporary", json!({"type": "boolean"})),
                    ("hardware", json!({"type": "boolean"})),
                    ("pending", json!({"type": "boolean"})),
                ],
            ),
            false,
        ),
        tool(
            "gdb_inspect",
            "Read one bounded debugger view with explicit stop context.",
            schema(
                &["session_id", "view"],
                [
                    (
                        "view",
                        enum_schema(&[
                            "stop_context",
                            "threads",
                            "stack",
                            "frame",
                            "locals",
                            "arguments",
                            "registers",
                            "modules",
                            "mappings",
                            "source",
                            "breakpoints",
                            "capabilities",
                            "target",
                        ]),
                    ),
                    ("stop_id", json!({"type": "string"})),
                    ("thread_id", json!({"type": "string"})),
                    ("frame_id", json!({"type": "string"})),
                    ("limit", json!({"type": "integer", "minimum": 1})),
                    (
                        "roles",
                        json!({"type": "array", "items": {"type": "string"}}),
                    ),
                ],
            ),
            true,
        ),
        tool(
            "gdb_evaluate",
            "Evaluate an expression while inferior calls and writes are disabled.",
            schema(
                &["session_id", "expression", "stop_id"],
                [
                    ("expression", json!({"type": "string", "maxLength": 4096})),
                    ("stop_id", json!({"type": "string"})),
                    ("thread_id", json!({"type": "string"})),
                    ("frame_id", json!({"type": "string"})),
                    ("side_effects", enum_schema(&["deny"])),
                ],
            ),
            true,
        ),
        tool(
            "gdb_memory",
            "Read a bounded memory range; large results become artifacts.",
            schema(
                &["action", "session_id", "address", "length", "stop_id"],
                [
                    ("action", enum_schema(&["read"])),
                    (
                        "address",
                        json!({"type": "string", "pattern": "^0x[0-9a-fA-F]+$"}),
                    ),
                    ("length", json!({"type": "integer", "minimum": 1})),
                    ("stop_id", json!({"type": "string"})),
                    ("allow_partial", json!({"type": "boolean"})),
                ],
            ),
            true,
        ),
        tool(
            "gdb_disassemble",
            "Read bounded disassembly around an expression or address range.",
            schema(
                &["session_id", "stop_id"],
                [
                    ("stop_id", json!({"type": "string"})),
                    ("around", json!({"type": "object"})),
                    ("range", json!({"type": "object"})),
                    ("include_bytes", json!({"type": "boolean"})),
                    ("include_source", json!({"type": "boolean"})),
                ],
            ),
            true,
        ),
        tool(
            "gdb_io",
            "Read or write the inferior PTY independently from GDB control output.",
            schema(
                &["action", "session_id"],
                [
                    (
                        "action",
                        enum_schema(&["read", "write", "close_stdin", "resize"]),
                    ),
                    ("stream", enum_schema(&["pty", "console", "log"])),
                    ("after_offset", json!({"type": "integer", "minimum": 0})),
                    (
                        "max_bytes",
                        json!({"type": "integer", "minimum": 1, "maximum": 65536}),
                    ),
                    ("text", json!({"type": "string"})),
                    ("data_base64", json!({"type": "string"})),
                    (
                        "rows",
                        json!({"type": "integer", "minimum": 1, "maximum": 65535}),
                    ),
                    (
                        "columns",
                        json!({"type": "integer", "minimum": 1, "maximum": 65535}),
                    ),
                ],
            ),
            false,
        ),
    ];
    if include_raw {
        let mut raw = tool(
            "gdb_raw",
            "Run an audited console command and taint unmanaged GDB state.",
            schema(
                &["action", "session_id", "command"],
                [
                    ("action", enum_schema(&["console"])),
                    ("command", json!({"type": "string"})),
                    ("timeout_ms", json!({"type": "integer", "minimum": 1})),
                ],
            ),
            false,
        );
        raw["annotations"]["destructiveHint"] = Value::Bool(true);
        tools.push(raw);
    }
    tools
}

fn tool(name: &str, description: &str, input_schema: Value, read_only: bool) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "annotations": {
            "readOnlyHint": read_only,
            "destructiveHint": false,
            "openWorldHint": false
        }
    })
}

fn schema<const N: usize>(required: &[&str], fields: [(&str, Value); N]) -> Value {
    let mut properties = Map::from_iter([
        ("session_id".into(), json!({"type": "string"})),
        (
            "expected_revision".into(),
            json!({"type": "integer", "minimum": 0}),
        ),
        ("accept_latest_revision".into(), json!({"type": "boolean"})),
        (
            "idempotency_key".into(),
            json!({"type": "string", "maxLength": 256}),
        ),
    ]);
    properties.extend(fields.into_iter().map(|(name, value)| (name.into(), value)));
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false
    })
}

fn enum_schema(values: &[&str]) -> Value {
    json!({"type": "string", "enum": values})
}

fn wait_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "until": {"type": "string", "enum": ["accepted", "running", "stopped", "snapshot", "exited"]},
            "timeout_ms": {"type": "integer", "minimum": 1}
        },
        "required": ["until"],
        "additionalProperties": false
    })
}

fn tool_names(include_raw: bool) -> Vec<&'static str> {
    let mut names = vec![
        "gdb_session",
        "gdb_run",
        "gdb_breakpoints",
        "gdb_inspect",
        "gdb_evaluate",
        "gdb_memory",
        "gdb_disassemble",
        "gdb_io",
    ];
    if include_raw {
        names.push("gdb_raw");
    }
    names
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
    id.is_string() || id.as_i64().is_some() || id.as_u64().is_some()
}

fn request_key(id: &Value) -> String {
    serde_json::to_string(id).unwrap_or_default()
}

async fn read_line_bounded<R: AsyncBufRead + Unpin>(
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

async fn write_rpc<W: AsyncWriteExt + Unpin>(writer: &mut W, response: Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(&response)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await
}

trait ErrorCodeName {
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
mod tests {
    use super::*;
    use gdb_ai_core::config::{ArtifactConfig, PersistenceConfig};
    use tempfile::tempdir;

    #[test]
    fn maps_tool_metadata_outside_canonical_parameters() {
        let request = map_tool(
            "gdb_run",
            json!({
                "action": "continue",
                "session_id": "sess_test",
                "expected_revision": 7,
                "stop_id": "stop_test",
                "wait": {"until": "snapshot", "timeout_ms": 1000}
            }),
            3,
        )
        .unwrap();
        assert_eq!(request.method, "execution.control");
        assert_eq!(request.session_id.as_deref(), Some("sess_test"));
        assert_eq!(request.expected_revision, Some(7));
        assert_eq!(request.parameters["action"], "continue");
        assert!(request.parameters.get("session_id").is_none());
        assert!(!tool_names(false).contains(&"gdb_raw"));
        assert!(tool_names(true).contains(&"gdb_raw"));
    }

    #[tokio::test]
    async fn bounds_stdio_messages() {
        let mut input = BufReader::new(&b"{\"ok\":true}\r\nnext\n"[..]);
        assert_eq!(
            read_line_bounded(&mut input, 32).await.unwrap().unwrap(),
            b"{\"ok\":true}"
        );
        assert_eq!(
            read_line_bounded(&mut input, 32).await.unwrap().unwrap(),
            b"next"
        );
        let mut oversized = BufReader::new(&b"12345\n"[..]);
        assert!(read_line_bounded(&mut oversized, 4).await.is_err());
    }

    #[tokio::test]
    async fn mcp_tool_gates_and_audits_raw_session() {
        if std::process::Command::new("gdb")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let directory = tempdir().unwrap();
        let config = Config {
            artifacts: ArtifactConfig {
                path: directory.path().join("artifacts"),
            },
            persistence: PersistenceConfig {
                sqlite: directory.path().join("state.sqlite"),
                sessions: directory.path().join("sessions"),
            },
            ..Config::default()
        };
        let gateway = Gateway::new(config).unwrap();
        let caller = Caller {
            identity: "mcp-test".into(),
            admin: true,
        };
        let sequence = AtomicU64::new(1);
        let created = call_tool(
            &gateway,
            &caller,
            &sequence,
            json!({
                "name": "gdb_session",
                "arguments": {"action": "create", "profile": "raw_admin"}
            }),
        )
        .await
        .unwrap();
        assert_eq!(created["isError"], false);
        let response = &created["structuredContent"];
        let session_id = response["session_id"].as_str().unwrap();
        let revision = response["revision"].as_u64().unwrap();
        let raw = call_tool(
            &gateway,
            &caller,
            &sequence,
            json!({
                "name": "gdb_raw",
                "arguments": {
                    "action": "console",
                    "session_id": session_id,
                    "expected_revision": revision,
                    "command": "show language"
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(raw["isError"], false);
        assert_eq!(raw["structuredContent"]["state"]["consistency"], "TAINTED");
        let revision = raw["structuredContent"]["revision"].as_u64().unwrap();
        let closed = call_tool(
            &gateway,
            &caller,
            &sequence,
            json!({
                "name": "gdb_session",
                "arguments": {
                    "action": "close",
                    "session_id": session_id,
                    "expected_revision": revision
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(closed["isError"], false);
    }
}
