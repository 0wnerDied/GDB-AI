use super::*;
use gdb_ai_core::config::{ArtifactConfig, PersistenceConfig};
use tempfile::tempdir;

fn detached_http_pending(waiter: oneshot::Sender<()>, deadline: Instant) -> HttpPending {
    HttpPending {
        cancel_waiter: Some(waiter),
        cancellation: RequestCancellation {
            mode: CancelMode::DetachWaiter,
            session_id: None,
            lease_id: None,
        },
        deadline,
    }
}

#[test]
fn initialize_teaches_agents_the_stateful_workflow() {
    let mut phase = Phase::New;
    let mut caller = Caller::local("test");
    let result = initialize(
        &json!({
            "protocolVersion": MCP_VERSION,
            "clientInfo": {"name": "test-agent"}
        }),
        &mut phase,
        &mut caller,
    )
    .unwrap();
    let instructions = result["instructions"].as_str().unwrap();
    for required in [
        "tools/list",
        "argv",
        "lab_mutation",
        "accept_latest_revision",
        "stream=pty",
        "stop_id",
        "inspection mappings",
    ] {
        assert!(instructions.contains(required), "missing {required}");
    }
}

#[test]
fn maps_tool_metadata_outside_canonical_parameters() {
    let request = map_tool(
        "gdb_run",
        json!({
            "action": "continue",
            "session_id": "sess_test",
            "expected_revision": 7,
            "cancel_mode": "interrupt_target",
            "stop_id": "stop_test",
            "wait": {"until": "snapshot", "timeout_ms": 1000}
        }),
        false,
        false,
        3,
    )
    .unwrap();
    assert_eq!(request.method, "execution.control");
    assert_eq!(request.session_id.as_deref(), Some("sess_test"));
    assert_eq!(request.expected_revision, Some(7));
    assert_eq!(request.parameters["action"], "continue");
    assert!(request.parameters.get("session_id").is_none());
    assert!(request.parameters.get("cancel_mode").is_none());
    let cancellation = request_cancellation(
        "tools/call",
        &json!({
            "arguments": {
                "session_id": "sess_test",
                "lease_id": "lease_test",
                "cancel_mode": "interrupt_target"
            }
        }),
    )
    .unwrap();
    assert!(matches!(cancellation.mode, CancelMode::InterruptTarget));
    assert_eq!(cancellation.session_id.as_deref(), Some("sess_test"));
    assert!(!tool_names(false, false).contains(&"gdb_raw"));
    assert!(tool_names(false, true).contains(&"gdb_raw"));
    assert_eq!(
        map_tool("gdb_values", json!({"action": "create"}), false, false, 4,)
            .unwrap_err()
            .code,
        -32601
    );
    assert!(!valid_request_id(&Value::String("x".repeat(129))));
}

#[test]
fn artifact_resources_are_manifests_or_exact_ranges() {
    let digest = "a".repeat(64);
    let uri = format!("gdbai://artifact/sha256:{digest}");
    let result = json!({
        "size": 8,
        "sensitivity": "target-memory",
        "max_page_bytes": 4,
        "offset": 0,
        "next_offset": 1,
        "data_base64": "AA==",
        "truncated": true
    });
    let manifest =
        artifact_resource_contents(parse_artifact_resource(&uri).unwrap(), result.clone()).unwrap();
    assert_eq!(
        manifest["contents"][0]["mimeType"],
        "application/vnd.gdb-ai.artifact-manifest+json"
    );
    let manifest: Value =
        serde_json::from_str(manifest["contents"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(manifest["sha256"], digest);
    assert_eq!(manifest["size"], 8);
    assert_eq!(manifest["page_size"], 4);

    let range_uri = format!("{uri}?offset=4&length=4");
    let range = artifact_resource_contents(
        parse_artifact_resource(&range_uri).unwrap(),
        json!({
            "size": 8,
            "sensitivity": "target-memory",
            "max_page_bytes": 4,
            "offset": 4,
            "next_offset": 8,
            "data_base64": "BAUGBw==",
            "truncated": false
        }),
    )
    .unwrap();
    assert_eq!(range["contents"][0]["uri"], range_uri);
    assert_eq!(range["contents"][0]["blob"], "BAUGBw==");
    assert_eq!(range["contents"][0]["_meta"]["offset"], 4);
    assert_eq!(range["contents"][0]["_meta"]["length"], 4);

    assert!(
        artifact_resource_contents(
            parse_artifact_resource(&format!("{uri}?offset=4&length=4")).unwrap(),
            result,
        )
        .is_err()
    );
}

#[test]
fn artifact_resource_ranges_reject_ambiguous_or_invalid_bounds() {
    let uri = format!("gdbai://artifact/sha256:{}", "b".repeat(64));
    for invalid in [
        format!("{uri}?length=1&offset=0"),
        format!("{uri}?offset=00&length=1"),
        format!("{uri}?offset=0&length=0"),
        format!("{uri}?offset=0&length=1&extra=1"),
    ] {
        assert!(parse_artifact_resource(&invalid).is_err(), "{invalid}");
    }
    let response = json!({
        "size": 8,
        "sensitivity": "target-memory",
        "max_page_bytes": 4,
        "offset": 7,
        "next_offset": 8,
        "data_base64": "AA==",
        "truncated": false
    });
    assert!(
        artifact_resource_contents(
            parse_artifact_resource(&format!("{uri}?offset=7&length=2")).unwrap(),
            response.clone(),
        )
        .is_err()
    );
    assert!(
        artifact_resource_contents(
            parse_artifact_resource(&format!("{uri}?offset=0&length=5")).unwrap(),
            response,
        )
        .is_err()
    );
}

#[test]
fn resource_templates_describe_session_scoped_pty_output() {
    let templates = resource_templates().to_string();
    assert!(templates.contains("gdbai://session/{session_id}/output/pty"));
    assert!(!templates.contains("/inferior/{inferior_id}/output"));
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
async fn streamable_http_authenticates_and_tracks_mcp_sessions() {
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
    let state = HttpState {
        gateway: gateway.clone(),
        sessions: Arc::new(RwLock::new(HashMap::new())),
        sequence: Arc::new(AtomicU64::new(1)),
        raw_admin: false,
        advanced_tools: false,
        auth_token: Some(Arc::from("test-token")),
        trusted_origins: parse_trusted_origins(&["https://agent.example".into()]).unwrap(),
        max_sessions: 1,
        idle_timeout: Duration::from_secs(1),
    };
    let unauthorized = http_mcp(
        State(state.clone()),
        HeaderMap::new(),
        Json(json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})),
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer test-token"),
    );
    let mut forbidden_headers = headers.clone();
    forbidden_headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://evil.example"),
    );
    let forbidden = http_mcp(
        State(state.clone()),
        forbidden_headers,
        Json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_VERSION,
                "clientInfo": {"name": "http-evil", "version": "1"}
            }
        })),
    )
    .await;
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    let unsupported = http_mcp(
        State(state.clone()),
        headers.clone(),
        Json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "clientInfo": {"name": "http-old", "version": "1"}
            }
        })),
    )
    .await;
    assert_eq!(unsupported.status(), StatusCode::BAD_REQUEST);
    assert!(state.sessions.read().await.is_empty());
    let initialized = http_mcp(
        State(state.clone()),
        headers.clone(),
        Json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_VERSION,
                "clientInfo": {"name": "http-test", "version": "1"}
            }
        })),
    )
    .await;
    assert_eq!(initialized.status(), StatusCode::OK);
    let session = initialized.headers().get("mcp-session-id").unwrap().clone();
    headers.insert("mcp-session-id", session);
    let missing_version = http_mcp(
        State(state.clone()),
        headers.clone(),
        Json(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        })),
    )
    .await;
    assert_eq!(missing_version.status(), StatusCode::BAD_REQUEST);
    headers.insert(
        "mcp-protocol-version",
        HeaderValue::from_static(MCP_VERSION),
    );
    let ready = http_mcp(
        State(state.clone()),
        headers.clone(),
        Json(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        })),
    )
    .await;
    assert_eq!(ready.status(), StatusCode::ACCEPTED);
    let mut wrong_version = headers.clone();
    wrong_version.insert(
        "mcp-protocol-version",
        HeaderValue::from_static("2025-06-18"),
    );
    let rejected = http_mcp(
        State(state.clone()),
        wrong_version,
        Json(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        })),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    let listed = http_mcp(
        State(state.clone()),
        headers.clone(),
        Json(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        })),
    )
    .await;
    let bytes = axum::body::to_bytes(listed.into_body(), MAX_MESSAGE_BYTES)
        .await
        .unwrap();
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    let tools = response["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 9);
    assert!(!tools.iter().any(|tool| tool["name"] == "gdb_values"));
    let limited = http_mcp(
        State(state.clone()),
        headers.clone(),
        Json(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_VERSION,
                "clientInfo": {"name": "http-test-2", "version": "1"}
            }
        })),
    )
    .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    for client in state.sessions.write().await.values_mut() {
        client.last_active = Instant::now() - Duration::from_secs(2);
    }
    let replaced = http_mcp(
        State(state.clone()),
        headers,
        Json(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_VERSION,
                "clientInfo": {"name": "http-test-3", "version": "1"}
            }
        })),
    )
    .await;
    assert_eq!(replaced.status(), StatusCode::OK);
    assert_eq!(state.sessions.read().await.len(), 1);
    gateway.shutdown().await;
}

#[tokio::test]
async fn http_completion_cleans_pending_after_disconnect_and_panic() {
    async fn panic_operation() -> Result<Value, RpcFault> {
        panic!("operation panic")
    }

    let sessions = Arc::new(RwLock::new(HashMap::new()));
    let caller = Caller::local("http-cleanup-test");
    let deadline = Instant::now() + Duration::from_secs(1);
    let (cancel_waiter, _cancelled) = oneshot::channel();
    sessions.write().await.insert(
        "mcp_test".into(),
        HttpClient {
            phase: Phase::Ready,
            protocol_version: MCP_VERSION.into(),
            caller: caller.clone(),
            pending: HashMap::from([("1".into(), detached_http_pending(cancel_waiter, deadline))]),
            last_active: Instant::now(),
        },
    );

    let (release, released) = oneshot::channel();
    let operation = tokio::spawn(async move {
        released.await.unwrap();
        Ok(json!({"ok": true}))
    });
    let (response, disconnected) = oneshot::channel();
    drop(disconnected);
    let completion = tokio::spawn(complete_http_operation(
        sessions.clone(),
        "mcp_test".into(),
        "1".into(),
        json!(1),
        deadline,
        operation,
        response,
    ));
    release.send(()).unwrap();
    completion.await.unwrap();
    assert!(sessions.read().await["mcp_test"].pending.is_empty());

    let (cancel_waiter, _cancelled) = oneshot::channel();
    sessions
        .write()
        .await
        .get_mut("mcp_test")
        .unwrap()
        .pending
        .insert("2".into(), detached_http_pending(cancel_waiter, deadline));
    let (response, received) = oneshot::channel();
    complete_http_operation(
        sessions.clone(),
        "mcp_test".into(),
        "2".into(),
        json!(2),
        deadline,
        tokio::spawn(panic_operation()),
        response,
    )
    .await;
    assert_eq!(received.await.unwrap()["error"]["code"], -32603);
    assert!(sessions.read().await["mcp_test"].pending.is_empty());

    let deadline = Instant::now() - Duration::from_millis(1);
    let (cancel_waiter, _cancelled) = oneshot::channel();
    sessions
        .write()
        .await
        .get_mut("mcp_test")
        .unwrap()
        .pending
        .insert("3".into(), detached_http_pending(cancel_waiter, deadline));
    let operation = tokio::spawn(async {
        std::future::pending::<()>().await;
        Ok(json!({"unreachable": true}))
    });
    let abort = operation.abort_handle();
    let (response, received) = oneshot::channel();
    complete_http_operation(
        sessions.clone(),
        "mcp_test".into(),
        "3".into(),
        json!(3),
        deadline,
        operation,
        response,
    )
    .await;
    assert_eq!(received.await.unwrap()["error"]["code"], -32001);
    assert!(sessions.read().await["mcp_test"].pending.is_empty());
    abort.abort();
}

#[tokio::test]
async fn http_deadlines_and_delete_release_pending_waiters() {
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
    let state = HttpState {
        gateway: gateway.clone(),
        sessions: Arc::new(RwLock::new(HashMap::new())),
        sequence: Arc::new(AtomicU64::new(1)),
        raw_admin: false,
        advanced_tools: false,
        auth_token: None,
        trusted_origins: Arc::from([]),
        max_sessions: 1,
        idle_timeout: Duration::from_secs(60),
    };
    let (expired_waiter, expired) = oneshot::channel();
    state.sessions.write().await.insert(
        "mcp_test".into(),
        HttpClient {
            phase: Phase::Ready,
            protocol_version: MCP_VERSION.into(),
            caller: Caller::local("http-deadline-test"),
            pending: HashMap::from([(
                "expired".into(),
                detached_http_pending(expired_waiter, Instant::now() - Duration::from_millis(1)),
            )]),
            last_active: Instant::now(),
        },
    );
    evict_http_sessions(&state).await;
    expired.await.unwrap();
    assert!(state.sessions.read().await["mcp_test"].pending.is_empty());

    let (delete_waiter, deleted) = oneshot::channel();
    state
        .sessions
        .write()
        .await
        .get_mut("mcp_test")
        .unwrap()
        .pending
        .insert(
            "delete".into(),
            detached_http_pending(delete_waiter, Instant::now() + Duration::from_secs(60)),
        );
    let mut headers = HeaderMap::new();
    headers.insert("mcp-session-id", HeaderValue::from_static("mcp_test"));
    let rejected = http_delete(State(state.clone()), headers.clone()).await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert!(state.sessions.read().await.contains_key("mcp_test"));
    headers.insert(
        "mcp-protocol-version",
        HeaderValue::from_static(MCP_VERSION),
    );
    let response = http_delete(State(state.clone()), headers).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    deleted.await.unwrap();
    assert!(state.sessions.read().await.is_empty());
    gateway.shutdown().await;
}

#[test]
fn http_origin_and_binding_policy_fail_closed() {
    assert!(validate_http_address("127.0.0.1:8080".parse().unwrap()).is_ok());
    assert!(validate_http_address("[::1]:8080".parse().unwrap()).is_ok());
    assert!(validate_http_address("0.0.0.0:8080".parse().unwrap()).is_err());
    assert!(parse_trusted_origins(&["https://agent.example/path".into()]).is_err());

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
    let state = HttpState {
        gateway: Arc::new(Gateway::new(config).unwrap()),
        sessions: Arc::new(RwLock::new(HashMap::new())),
        sequence: Arc::new(AtomicU64::new(1)),
        raw_admin: false,
        advanced_tools: false,
        auth_token: None,
        trusted_origins: parse_trusted_origins(&["https://agent.example".into()]).unwrap(),
        max_sessions: 1,
        idle_timeout: Duration::from_secs(60),
    };
    assert!(allow_http_origin(&state, &HeaderMap::new()));
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://agent.example"),
    );
    assert!(allow_http_origin(&state, &headers));
    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://evil.example"),
    );
    assert!(!allow_http_origin(&state, &headers));
    headers.append(
        header::ORIGIN,
        HeaderValue::from_static("https://agent.example"),
    );
    assert!(!allow_http_origin(&state, &headers));
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
