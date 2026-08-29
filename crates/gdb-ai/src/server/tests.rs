use super::*;
use gdb_ai_core::config::{ArtifactConfig, PersistenceConfig};
use tempfile::tempdir;

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
