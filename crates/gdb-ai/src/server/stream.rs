use std::{
    collections::HashMap,
    io,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use gdb_ai_core::{
    config::Config,
    gateway::{Caller, Gateway},
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader},
    net::UnixListener,
    sync::{Semaphore, mpsc},
    task::JoinHandle,
};

use super::{
    MAX_MESSAGE_BYTES, MAX_PENDING_REQUESTS, Phase, RequestCancellation, RpcOutput,
    admit_canonical_operation, apply_cancel_mode, canonical_rpc_request, dispatch_rpc, initialize,
    progress_notification, progress_token, read_line_bounded, request_cancellation, request_key,
    rpc_error, rpc_fault, rpc_result, stateless_request, stateless_result, valid_request_id,
    write_rpc,
};
use crate::AnyError;

struct StreamPending {
    generation: u64,
    waiter: JoinHandle<()>,
    cancellation: RequestCancellation,
    stateless: bool,
}

pub(crate) async fn serve_stdio(
    config: Config,
    raw_admin: bool,
    advanced_tools: bool,
) -> Result<(), AnyError> {
    let gateway = Arc::new(Gateway::new(config)?);
    let result = serve_stream(
        gateway.clone(),
        Caller {
            identity: "mcp-stdio".into(),
            admin: raw_admin,
        },
        advanced_tools,
        tokio::io::stdin(),
        tokio::io::stdout(),
    )
    .await;
    gateway.shutdown().await;
    result
}

async fn serve_stream<R, W>(
    gateway: Arc<Gateway>,
    mut caller: Caller,
    advanced_tools: bool,
    input: R,
    mut output: W,
) -> Result<(), AnyError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let sequence = Arc::new(AtomicU64::new(1));
    let mut phase = Phase::New;
    let mut pending: HashMap<String, StreamPending> = HashMap::new();
    let mut input_open = true;
    let (responses, mut response_rx) = mpsc::channel::<RpcOutput>(128);
    let mut input = BufReader::new(input);

    loop {
        // 2026-08-28: EOF ends input, not pending work. Drain completed RPC
        // responses so a final one-shot MCP request is not silently dropped.
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
                let mut message = match serde_json::from_slice::<Value>(&line) {
                    Ok(message) => message,
                    Err(error) => {
                        write_rpc(&mut output, rpc_error(Value::Null, -32700, error.to_string())).await?;
                        continue;
                    }
                };
                let Some(object) = message.as_object_mut() else {
                    write_rpc(&mut output, rpc_error(Value::Null, -32600, "request must be an object")).await?;
                    continue;
                };
                let id = object.remove("id");
                if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
                    write_rpc(&mut output, rpc_error(id.unwrap_or(Value::Null), -32600, "jsonrpc must be 2.0")).await?;
                    continue;
                }
                let Some(Value::String(method)) = object.remove("method") else {
                    if id.is_some() {
                        write_rpc(&mut output, rpc_error(id.unwrap_or(Value::Null), -32600, "method is required")).await?;
                    }
                    continue;
                };
                let mut params = object.remove("params").unwrap_or_else(|| json!({}));

                if id.is_none() {
                    handle_notification(
                        &method,
                        &params,
                        &mut phase,
                        &mut pending,
                        &gateway,
                        &caller,
                        &sequence,
                    );
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
                let stateless = match stateless_request(&params) {
                    Ok(stateless) => stateless,
                    Err(error) => {
                        write_rpc(&mut output, rpc_fault(id, error)).await?;
                        continue;
                    }
                };
                if method == "server/discover" && !stateless {
                    write_rpc(&mut output, rpc_error(id, -32602, "server/discover requires 2026-07-28 request metadata")).await?;
                    continue;
                }
                if !stateless && method != "ping" && phase != Phase::Ready {
                    write_rpc(&mut output, rpc_error(id, -32002, "server is not initialized")).await?;
                    continue;
                }

                let key = request_key(&id);
                // 2026-08-28: Duplicate IDs replaced cancellation handles and
                // unbounded pending tasks let one connection exhaust memory.
                if pending.contains_key(&key) || pending.len() >= MAX_PENDING_REQUESTS {
                    write_rpc(&mut output, rpc_error(id, -32600, "duplicate request id or too many pending requests")).await?;
                    continue;
                }
                let generation = sequence.fetch_add(1, Ordering::Relaxed);
                let mut cancellation = match request_cancellation(&method, &params) {
                    Ok(cancellation) => cancellation,
                    Err(error) => {
                        write_rpc(&mut output, rpc_fault(id, error)).await?;
                        continue;
                    }
                };
                let progress_token = match progress_token(&params) {
                    Ok(progress_token) => progress_token,
                    Err(error) => {
                        write_rpc(&mut output, rpc_fault(id, error)).await?;
                        continue;
                    }
                };
                if let Some(token) = &progress_token {
                    write_rpc(
                        &mut output,
                        progress_notification(token.clone(), 0, "request started"),
                    )
                    .await?;
                }
                let canonical = match canonical_rpc_request(
                    &method,
                    &mut params,
                    advanced_tools,
                    caller.admin,
                    &sequence,
                ) {
                    Ok(canonical) => canonical,
                    Err(error) => {
                        write_rpc(&mut output, rpc_fault(id, error)).await?;
                        continue;
                    }
                };
                let (operation_id, operation) = if let Some((request, presentation)) = canonical {
                    match admit_canonical_operation(
                        gateway.clone(),
                        caller.clone(),
                        request,
                        presentation,
                        None,
                    )
                    .await
                    {
                        Ok((operation_id, waiter)) => (Some(operation_id), waiter),
                        Err(error) => {
                            write_rpc(&mut output, rpc_fault(id, error)).await?;
                            continue;
                        }
                    }
                } else {
                    let dispatch_gateway = gateway.clone();
                    let dispatch_caller = caller.clone();
                    let dispatch_sequence = sequence.clone();
                    let method = method.clone();
                    (
                        None,
                        tokio::spawn(async move {
                            dispatch_rpc(
                                &dispatch_gateway,
                                &dispatch_caller,
                                advanced_tools,
                                &dispatch_sequence,
                                &method,
                                params,
                            )
                            .await
                        }),
                    )
                };
                let delivered_operation = operation_id.clone();
                cancellation.operation_id = operation_id;
                let responses = responses.clone();
                let task_key = key.clone();
                let response_method = method.to_owned();
                let response_gateway = gateway.clone();
                let response_caller = caller.clone();
                // Requests may wait for a target stop; separate tasks let
                // cancellation and inferior I/O reach the gateway meanwhile.
                // 2026-08-28: Cancelling the response task used to cancel the
                // Gateway future after a worker had accepted a mutation. Keep
                // dispatch detached so idempotency and audit still complete.
                let handle = tokio::spawn(async move {
                    let response = match operation.await {
                        Ok(result) => result.map_or_else(
                            |error| rpc_fault(id.clone(), error),
                            |result| {
                                let result = if stateless {
                                    stateless_result(&response_method, result)
                                } else {
                                    result
                                };
                                rpc_result(id.clone(), result)
                            },
                        ),
                        Err(error) => rpc_error(id, -32603, error.to_string()),
                    };
                    if let Some(operation_id) = delivered_operation {
                        response_gateway
                            .release_delivered_operation(&operation_id, &response_caller)
                            .await;
                    }
                    if let Some(token) = progress_token {
                        let _ = responses
                            .send((
                                None,
                                progress_notification(token, 1, "request completed"),
                            ))
                            .await;
                    }
                    let _ = responses
                        .send((Some((task_key, generation)), response))
                        .await;
                });
                pending.insert(
                    key,
                    StreamPending {
                        generation,
                        waiter: handle,
                        cancellation,
                        stateless,
                    },
                );
            }
            Some((reservation, response)) = response_rx.recv() => {
                if let Some((key, generation)) = reservation {
                    remove_stream_pending(&mut pending, &key, generation);
                }
                write_rpc(&mut output, response).await?;
            }
        }
    }

    for request in pending.into_values() {
        request.waiter.abort();
    }
    Ok(())
}

fn remove_stream_pending(pending: &mut HashMap<String, StreamPending>, key: &str, generation: u64) {
    // 2026-08-30: A completed response could remain queued while cancellation
    // freed and reused its request ID. Match the reservation generation so an
    // old response cannot remove the replacement request.
    if pending
        .get(key)
        .is_some_and(|request| request.generation == generation)
    {
        pending.remove(key);
    }
}

pub(crate) async fn serve_unix(
    config: Config,
    path: PathBuf,
    raw_admin: bool,
    advanced_tools: bool,
) -> Result<(), AnyError> {
    let max_clients = config.server.max_http_sessions;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "refusing to replace a non-socket Unix path",
            )
            .into());
        }
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let gateway = Arc::new(Gateway::new(config)?);
    let client_slots = Arc::new(Semaphore::new(max_clients));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                // 2026-08-30: One local caller could open unbounded Unix
                // connections and multiply the per-stream pending limit.
                let Ok(slot) = client_slots.clone().try_acquire_owned() else {
                    tracing::warn!("rejected Unix client at the transport limit");
                    continue;
                };
                // 2026-08-28: Falling back to unix:unknown made every
                // credential lookup failure share one authorization principal.
                let identity = match stream.peer_cred() {
                    Ok(credentials) => format!("unix:uid:{}", credentials.uid()),
                    Err(error) => {
                        tracing::warn!(%error, "rejected Unix client without peer credentials");
                        continue;
                    }
                };
                let (input, output) = stream.into_split();
                let gateway = gateway.clone();
                tokio::spawn(async move {
                    let _slot = slot;
                    if let Err(error) = serve_stream(
                        gateway,
                        Caller { identity, admin: raw_admin },
                        advanced_tools,
                        input,
                        output,
                    )
                    .await
                    {
                        tracing::warn!(%error, "Unix client disconnected with an error");
                    }
                });
            }
            result = tokio::signal::ctrl_c() => {
                result?;
                break;
            }
        }
    }
    gateway.shutdown().await;
    std::fs::remove_file(&path)?;
    Ok(())
}

fn handle_notification(
    method: &str,
    params: &Value,
    phase: &mut Phase,
    pending: &mut HashMap<String, StreamPending>,
    gateway: &Arc<Gateway>,
    caller: &Caller,
    sequence: &Arc<AtomicU64>,
) {
    match method {
        "notifications/initialized" if *phase == Phase::AwaitingInitialized => {
            *phase = Phase::Ready;
        }
        "notifications/cancelled" => {
            if let Some(id) = params.get("requestId") {
                let key = request_key(id);
                // 2026-08-30: Stateless stdio cancellation only terminates
                // subscription streams; it must not interrupt tool calls.
                if pending.get(&key).is_some_and(|request| request.stateless) {
                    return;
                }
                if let Some(request) = pending.remove(&key) {
                    request.waiter.abort();
                    apply_cancel_mode(
                        gateway.clone(),
                        caller.clone(),
                        sequence.clone(),
                        request.cancellation,
                    );
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read_json_line;
    use gdb_ai_core::config::{ArtifactConfig, PersistenceConfig};
    use tempfile::tempdir;
    use tokio::io::AsyncWriteExt;

    use super::super::{MCP_VERSION, call_tool};

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
        let gdb_available = std::process::Command::new("gdb")
            .arg("--version")
            .output()
            .is_ok();
        if !gdb_available {
            // 2026-08-29: This server test bypassed the integration helper,
            // allowing required CI to pass without exercising MCP over GDB.
            if std::env::var_os("GDB_AI_REQUIRE_INTEGRATION").is_some() {
                panic!("required GDB executable is unavailable");
            }
            eprintln!("skipped MCP GDB test; GDB is unavailable");
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
            false,
            &sequence,
            json!({
                "name": "gdb_session",
                "arguments": {"action": "create", "profile": "raw_admin"}
            }),
        )
        .await
        .unwrap();
        assert_eq!(created["isError"], false, "{created}");
        let response = &created["structuredContent"];
        let session_id = response["session_id"].as_str().unwrap();
        let revision = response["revision"].as_u64().unwrap();
        let lease_id = response["result"]["write_lease"]["lease_id"]
            .as_str()
            .unwrap();
        let invalid = call_tool(
            &gateway,
            &caller,
            false,
            &sequence,
            json!({
                "name": "gdb_raw",
                "arguments": {
                    "action": "console",
                    "session_id": session_id,
                    "expected_revision": revision,
                    "lease_id": lease_id,
                    "command": "show language",
                    "timeout_ms": 0
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(invalid["isError"], true);
        assert_eq!(
            invalid["structuredContent"]["state"]["consistency"],
            "CLEAN"
        );
        assert_eq!(invalid["structuredContent"]["revision"], revision);
        let raw = call_tool(
            &gateway,
            &caller,
            false,
            &sequence,
            json!({
                "name": "gdb_raw",
                "arguments": {
                    "action": "console",
                    "session_id": session_id,
                    "expected_revision": revision,
                    "lease_id": lease_id,
                    "command": "show language"
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(raw["isError"], false);
        assert_eq!(raw["structuredContent"]["state"]["consistency"], "TAINTED");
        assert_eq!(
            raw["structuredContent"]["state"]["reconciliation_required"],
            false
        );
        let console = call_tool(
            &gateway,
            &caller,
            false,
            &sequence,
            json!({
                "name": "gdb_io",
                "arguments": {
                    "action": "read",
                    "session_id": session_id,
                    "stream": "console",
                    "after_offset": 0
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(console["isError"], false);
        assert!(
            console["structuredContent"]["result"]["text"]
                .as_str()
                .is_some_and(|text| text.contains("source language"))
        );
        let revision = raw["structuredContent"]["revision"].as_u64().unwrap();
        let denied = call_tool(
            &gateway,
            &caller,
            false,
            &sequence,
            json!({
                "name": "gdb_raw",
                "arguments": {
                    "action": "mi",
                    "session_id": session_id,
                    "expected_revision": revision,
                    "lease_id": lease_id,
                    "command": "-target-select",
                    "arguments": ["remote", "203.0.113.1:1"]
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(denied["isError"], true);
        assert_eq!(
            denied["structuredContent"]["error"]["code"],
            "POLICY_DENIED"
        );
        let closed = call_tool(
            &gateway,
            &caller,
            false,
            &sequence,
            json!({
                "name": "gdb_session",
                "arguments": {
                    "action": "close",
                    "session_id": session_id,
                    "expected_revision": revision,
                    "lease_id": lease_id
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(closed["isError"], false);
    }

    #[tokio::test]
    async fn queued_response_preserves_a_reused_request_id() {
        let mut pending = HashMap::from([(
            "same-id".into(),
            StreamPending {
                generation: 2,
                waiter: tokio::spawn(async {}),
                cancellation: RequestCancellation {
                    mode: super::super::CancelMode::DetachWaiter,
                    operation_id: None,
                },
                stateless: false,
            },
        )]);

        remove_stream_pending(&mut pending, "same-id", 1);
        assert!(pending.contains_key("same-id"));
        remove_stream_pending(&mut pending, "same-id", 2);
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn stream_protocol_runs_over_a_unix_compatible_byte_stream() {
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
        let gateway = Arc::new(Gateway::new(config).unwrap());
        let (client, server) = tokio::io::duplex(128 * 1024);
        let (client_input, mut client_output) = tokio::io::split(client);
        let (server_input, server_output) = tokio::io::split(server);
        let serving = tokio::spawn(serve_stream(
            gateway.clone(),
            Caller::local("stream-test"),
            false,
            server_input,
            server_output,
        ));
        let mut client_input = BufReader::new(client_input);
        write_rpc(
            &mut client_output,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_VERSION,
                    "clientInfo": {"name": "stream-test", "version": "1"}
                }
            }),
        )
        .await
        .unwrap();
        let initialized = read_json_line(&mut client_input).await.unwrap();
        assert_eq!(initialized["result"]["protocolVersion"], MCP_VERSION);
        write_rpc(
            &mut client_output,
            json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
        )
        .await
        .unwrap();
        write_rpc(
            &mut client_output,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {"_meta": {"progressToken": "list-progress"}}
            }),
        )
        .await
        .unwrap();
        let started = read_json_line(&mut client_input).await.unwrap();
        assert_eq!(started["method"], "notifications/progress");
        assert_eq!(started["params"]["progressToken"], "list-progress");
        assert_eq!(started["params"]["progress"], 0);
        let completed = read_json_line(&mut client_input).await.unwrap();
        assert_eq!(completed["method"], "notifications/progress");
        assert_eq!(completed["params"]["progress"], 1);
        let tools = read_json_line(&mut client_input).await.unwrap();
        assert!(tools["result"]["tools"].as_array().is_some());
        client_output.shutdown().await.unwrap();
        drop(client_output);
        serving.await.unwrap().unwrap();
        gateway.shutdown().await;
    }

    #[tokio::test]
    async fn stream_accepts_stateless_mcp_without_initialization() {
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
        let gateway = Arc::new(Gateway::new(config).unwrap());
        let (client, server) = tokio::io::duplex(128 * 1024);
        let (client_input, mut client_output) = tokio::io::split(client);
        let (server_input, server_output) = tokio::io::split(server);
        let serving = tokio::spawn(serve_stream(
            gateway.clone(),
            Caller::local("stateless-stream-test"),
            false,
            server_input,
            server_output,
        ));
        let mut client_input = BufReader::new(client_input);
        let metadata = json!({
            "io.modelcontextprotocol/protocolVersion": super::super::STATELESS_MCP_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}
        });
        write_rpc(
            &mut client_output,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "server/discover",
                "params": {"_meta": metadata}
            }),
        )
        .await
        .unwrap();
        let discovered = read_json_line(&mut client_input).await.unwrap();
        assert_eq!(discovered["result"]["resultType"], "complete");
        assert_eq!(
            discovered["result"]["supportedVersions"][0],
            super::super::STATELESS_MCP_VERSION
        );
        write_rpc(
            &mut client_output,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {"_meta": metadata}
            }),
        )
        .await
        .unwrap();
        let listed = read_json_line(&mut client_input).await.unwrap();
        assert_eq!(listed["result"]["resultType"], "complete");
        assert_eq!(listed["result"]["ttlMs"], 86_400_000_u64);
        assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 9);
        write_rpc(
            &mut client_output,
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "gdb.ai/call",
                "params": {
                    "api_version": gdb_ai_core::protocol::API_VERSION,
                    "request_id": "stateless-list",
                    "method": "session.list",
                    "parameters": {},
                    "_meta": metadata
                }
            }),
        )
        .await
        .unwrap();
        let called = read_json_line(&mut client_input).await.unwrap();
        assert_eq!(called["result"]["resultType"], "complete");
        assert!(called["result"]["result"].as_array().is_some());
        client_output.shutdown().await.unwrap();
        drop(client_output);
        serving.await.unwrap().unwrap();
        gateway.shutdown().await;
    }
}
