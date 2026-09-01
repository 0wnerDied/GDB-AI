use super::*;
use crate::tool_catalog::tool_names;
use gdb_ai_core::{
    config::{ArtifactConfig, Config, PersistenceConfig},
    domain::{
        BreakpointState, FrameSummary, InferiorId, InferiorState, InferiorStatus, SessionId,
        SessionState, SnapshotRef, SnapshotStatus, StopId, ThreadId, ThreadState,
    },
    protocol::ApiResponse,
};
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
        "MCP manages leases and revisions",
        "stop_id",
        "byte-exact PTY",
        "waits for stop/exit",
        "restart",
        "gdb_batch",
        "gdb_run action=probe",
        "gdb_inspect view=crash profile=brief",
    ] {
        assert!(instructions.contains(required), "missing {required}");
    }
    assert!(instructions.len() < 700);
}

#[test]
fn bounds_caller_controlled_faults_and_progress_tokens() {
    for fault in [
        RpcFault {
            code: -32601,
            message: "x".repeat(64 * 1024),
            data: None,
        },
        RpcFault {
            code: -32002,
            message: "resource not found".into(),
            data: Some(json!({"uri": "x".repeat(64 * 1024)})),
        },
    ] {
        let response = rpc_fault(json!(1), fault);
        let encoded = serde_json::to_vec(&response).unwrap();
        assert!(encoded.len() < 5 * 1024);
        assert_eq!(
            serde_json::from_slice::<Value>(&encoded).unwrap()["error"]["code"],
            response["error"]["code"]
        );
    }

    let fault = stateless_request(&json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "x".repeat(1024),
            "io.modelcontextprotocol/clientCapabilities": {}
        }
    }))
    .unwrap_err();
    let response = rpc_fault(json!(2), fault);
    assert!(serde_json::to_vec(&response).unwrap().len() < 1024);
    assert!(response["error"]["data"].get("requested").is_none());

    assert!(
        progress_token(&json!({
            "_meta": {"progressToken": "x".repeat(MAX_PROGRESS_TOKEN_BYTES + 1)}
        }))
        .is_err()
    );
    assert!(
        progress_token(&json!({
            "_meta": {"progressToken": "x".repeat(MAX_PROGRESS_TOKEN_BYTES)}
        }))
        .is_ok()
    );
    assert!(progress_token(&json!({"_meta": {"progressToken": 7}})).is_ok());

    let request = ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "large-error".into(),
        session_id: Some("sess_test".into()),
        method: CanonicalMethod::SessionList,
        expected_revision: None,
        idempotency_key: None,
        parameters: json!({}),
    };
    let result = tool_result(
        ApiResponse::failure(
            &request,
            gdb_ai_core::Error::new(
                gdb_ai_core::ErrorCode::InvalidArgument,
                "x".repeat(64 * 1024),
            )
            .with_details(json!({"evidence_seq": 9})),
            None,
        ),
        CanonicalMethod::SessionList,
    );
    assert!(result["content"][0]["text"].as_str().unwrap().len() <= MAX_TOOL_SUMMARY_BYTES);
    assert_eq!(
        result["structuredContent"]["error"]["message"]
            .as_str()
            .unwrap()
            .len(),
        64 * 1024
    );
    assert_eq!(
        result["structuredContent"]["evidence"][0]["kind"],
        "journal-entry"
    );
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
    assert_eq!(request.parameters["wait"]["until"], "snapshot");

    let blocking_run = map_tool(
        "gdb_run",
        json!({
            "action": "next",
            "session_id": "sess_test",
            "inspect": [{"view": "registers", "roles": ["pc", "sp"]}]
        }),
        false,
        false,
        4,
    )
    .unwrap();
    assert_eq!(blocking_run.parameters["wait"]["until"], "settled");
    assert_eq!(blocking_run.parameters["inspect"][0]["view"], "registers");

    let observed_wait = map_tool(
        "gdb_run",
        json!({
            "action": "wait",
            "session_id": "sess_test",
            "wait": {"until": "settled"},
            "inspect": [{"view": "stack", "limit": 4}]
        }),
        false,
        false,
        5,
    )
    .unwrap();
    assert_eq!(observed_wait.method, CanonicalMethod::ExecutionWait);
    assert_eq!(observed_wait.parameters["inspect"][0]["view"], "stack");

    let current_probe = map_tool(
        "gdb_run",
        json!({
            "action": "probe",
            "session_id": "sess_test",
            "function": "malloc"
        }),
        false,
        false,
        6,
    )
    .unwrap();
    assert_eq!(current_probe.method, CanonicalMethod::AgentProbe);
    assert_eq!(current_probe.parameters["accept_current_stop"], true);
    assert!(current_probe.parameters.get("action").is_none());

    let pinned_batch = map_tool(
        "gdb_batch",
        json!({
            "session_id": "sess_test",
            "stop_id": "stop_test",
            "requests": [{"name": "regs", "view": "registers"}]
        }),
        false,
        false,
        7,
    )
    .unwrap();
    assert!(pinned_batch.parameters.get("accept_current_stop").is_none());
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
    assert!(cancellation.operation_id.is_none());
    let read = map_tool(
        "gdb_io",
        json!({"action": "read", "session_id": "sess_test"}),
        false,
        false,
        4,
    )
    .unwrap();
    assert_eq!(read.parameters["max_bytes"], DEFAULT_MCP_IO_READ_BYTES);
    assert_eq!(
        map_tool(
            "gdb_session",
            json!({"action": "create", "session_id": "sess_invented"}),
            false,
            false,
            5,
        )
        .unwrap_err()
        .code,
        -32602
    );
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
fn current_stop_binding_matches_canonical_context() {
    for method in CanonicalMethod::ALL {
        let contextual = method.parameter_schema()["properties"]
            .get("accept_current_stop")
            .is_some()
            && *method != CanonicalMethod::ExecutionControl;
        assert_eq!(binds_current_stop(*method), contextual, "{method}");
    }
}

#[tokio::test]
async fn projected_tools_hide_and_recover_mutation_coordination() {
    if std::process::Command::new("gdb")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let directory = tempdir().unwrap();
    let mut config = Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    };
    config.security.workspace_roots = vec![std::path::PathBuf::from("/")];
    // 2026-09-01: A 1 ms recovered lease could expire again between the
    // projected preflight and dispatch on a loaded CI runner. Keep expiry
    // deliberate while leaving the mutation itself a bounded scheduling window.
    config.server.write_lease_ms = 1_000;
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("projected-coordination-test");
    let sequence = AtomicU64::new(1);
    let created = call_tool(
        &gateway,
        &caller,
        false,
        &sequence,
        json!({"name": "gdb_session", "arguments": {"action": "create"}}),
    )
    .await
    .unwrap();
    let result = created["structuredContent"]["result"].as_object().unwrap();
    assert_eq!(result.len(), 2);
    assert!(result.get("write_lease").is_none());
    let session_id = result["session_id"].as_str().unwrap();

    let launched = call_tool(
        &gateway,
        &caller,
        false,
        &sequence,
        json!({
            "name": "gdb_session",
            "arguments": {
                "action": "launch",
                "session_id": session_id,
                "program": "/bin/true",
                "stop": "first_instruction"
            }
        }),
    )
    .await
    .unwrap();
    assert_eq!(launched["isError"], false);
    let observed = call_tool(
        &gateway,
        &caller,
        false,
        &sequence,
        json!({
            "name": "gdb_batch",
            "arguments": {
                "session_id": session_id,
                "requests": [{"name": "context", "view": "stop_context"}]
            }
        }),
    )
    .await
    .unwrap();
    assert_eq!(observed["isError"], false);
    assert!(
        observed["structuredContent"]["result"]["stop_id"]
            .as_str()
            .is_some()
    );
    let turned = call_tool(
        &gateway,
        &caller,
        false,
        &sequence,
        json!({
            "name": "gdb_run",
            "arguments": {
                "action": "step_instruction",
                "session_id": session_id,
                "inspect": [{"view": "registers", "roles": ["pc", "sp"]}]
            }
        }),
    )
    .await
    .unwrap();
    assert_eq!(turned["isError"], false);
    let result = &turned["structuredContent"]["result"];
    assert!(result["stop_id"].as_str().is_some());
    assert!(result["observations"]["registers"].is_object());
    assert!(result["observations"]["registers"].get("stop_id").is_none());
    assert!(result.get("operation_id").is_none());
    let waited = call_tool(
        &gateway,
        &caller,
        false,
        &sequence,
        json!({
            "name": "gdb_run",
            "arguments": {
                "action": "wait",
                "session_id": session_id,
                "wait": {"until": "settled"},
                "inspect": [{"view": "stack", "limit": 1}]
            }
        }),
    )
    .await
    .unwrap();
    assert_eq!(waited["isError"], false);
    let result = &waited["structuredContent"]["result"];
    assert!(result["observations"]["stack"].is_object());
    assert!(result.get("operation").is_none());

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let closed = call_tool(
        &gateway,
        &caller,
        false,
        &sequence,
        json!({
            "name": "gdb_session",
            "arguments": {"action": "close", "session_id": session_id}
        }),
    )
    .await
    .unwrap();
    assert_eq!(closed["isError"], false);
    assert!(closed["structuredContent"].get("revision").is_none());
    assert!(closed["structuredContent"].get("session_id").is_none());
    gateway.shutdown().await;
}

#[test]
fn tool_results_compact_status_and_preserve_explicit_target_state() {
    let mut state = SessionState::creating(SessionId::parse("sess_test").unwrap());
    state.revision = 7;
    state.event_seq = 19;
    state.stop_id = Some(StopId("stop_test".into()));
    state.stopped_inferior_id = Some(InferiorId("inf_test".into()));
    state.stopped_thread_id = Some(ThreadId("thread_test".into()));
    state.inferiors.insert(
        "1".into(),
        InferiorState {
            id: InferiorId("inf_test".into()),
            backend_id: "1".into(),
            pid: Some(7),
            generation: 1,
            status: InferiorStatus::Stopped,
            exit_code: None,
            threads: std::collections::BTreeMap::from([(
                "1".into(),
                ThreadState {
                    id: ThreadId("thread_test".into()),
                    backend_id: "1".into(),
                    running: false,
                    frame: Some(FrameSummary {
                        level: 0,
                        address: Some("0x1234".into()),
                        function: Some("main".into()),
                        source: Some("main.c".into()),
                        line: Some(7),
                    }),
                },
            )]),
        },
    );
    for index in 0..64 {
        let id = format!("bp_{index}");
        state.breakpoints.insert(
            id.clone(),
            BreakpointState {
                id: gdb_ai_core::domain::BreakpointId(id),
                backend_number: index.to_string(),
                enabled: true,
                pending: false,
                locations: Vec::new(),
            },
        );
    }
    state.limitations.push("large repeated diagnostic".into());
    let request = ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "test".into(),
        session_id: Some("sess_test".into()),
        method: CanonicalMethod::SessionGet,
        expected_revision: None,
        idempotency_key: None,
        parameters: json!({}),
    };
    let response = ApiResponse::success(
        &request,
        Some(state.clone()),
        serde_json::to_value(&state).unwrap(),
    );
    let canonical_bytes = serde_json::to_vec(&response).unwrap().len();
    let result = tool_result(response, CanonicalMethod::SessionGet);
    let compact_bytes = serde_json::to_vec(&result["structuredContent"])
        .unwrap()
        .len();
    let structured = &result["structuredContent"];
    assert_eq!(result["content"][0]["text"], "ok");
    assert!(structured.get("state").is_none());
    assert_eq!(structured["result"]["event_seq"], 19);
    assert_eq!(structured["result"]["pid"], 7);
    assert_eq!(structured["result"]["frame"]["function"], "main");
    assert!(structured["result"].get("breakpoints").is_none());
    assert!(structured["result"].get("limitations").is_none());
    assert!(structured["result"].get("inferiors").is_none());
    assert!(structured.get("api_version").is_none());
    assert!(structured.get("request_id").is_none());
    assert!(compact_bytes < canonical_bytes);

    let historical = tool_result(
        ApiResponse::success(&request, None, serde_json::to_value(&state).unwrap()),
        CanonicalMethod::SessionGet,
    );
    assert!(historical["structuredContent"].get("session_id").is_none());
    assert_eq!(historical["structuredContent"]["result"]["event_seq"], 19);
    assert!(
        historical["structuredContent"]["result"]
            .get("breakpoints")
            .is_none()
    );

    let target = tool_result(
        ApiResponse::success(
            &request,
            Some(state.clone()),
            serde_json::to_value(&state).unwrap(),
        ),
        CanonicalMethod::InspectionGet,
    );
    assert_eq!(
        target["structuredContent"]["result"]["breakpoints"]
            .as_object()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        target["structuredContent"]["result"]["inferiors"]["1"]["threads"]["1"]["frame"]["function"],
        "main"
    );

    let launch = tool_result(
        ApiResponse::success(
            &request,
            Some(state.clone()),
            json!({"state": state.clone(), "start_policy": "main"}),
        ),
        CanonicalMethod::TargetLaunch,
    );
    assert!(launch["structuredContent"]["result"].get("state").is_none());
    assert_eq!(
        launch["structuredContent"]["state"]["frame"]["function"],
        "main"
    );
    assert!(
        launch["structuredContent"]["state"]
            .get("breakpoints")
            .is_none()
    );

    let listed = tool_result(
        ApiResponse::success(
            &ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "list".into(),
                session_id: None,
                method: CanonicalMethod::SessionList,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            None,
            json!([state]),
        ),
        CanonicalMethod::SessionList,
    );
    let listed = &listed["structuredContent"]["result"][0];
    assert_eq!(listed["session_id"], "sess_test");
    assert_eq!(listed["revision"], 7);
    assert_eq!(listed["breakpoints"].as_object().unwrap().len(), 64);
    assert_eq!(listed["limitations"][0], "large repeated diagnostic");
}

#[test]
fn tool_results_omit_incidental_metadata_but_preserve_explicit_discovery() {
    let request = ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "test".into(),
        session_id: Some("sess_test".into()),
        method: CanonicalMethod::InspectionGet,
        expected_revision: None,
        idempotency_key: None,
        parameters: json!({}),
    };
    let response = ApiResponse::success(
        &request,
        Some(SessionState::creating(
            SessionId::parse("sess_test").unwrap(),
        )),
        json!({
            "stop_id": "stop_test",
            "command": {
                "record": {},
                "stream_records": [],
                "evidence_seq": 9
            },
            "capabilities": {"unused": true},
            "frames": [{"function": "main", "evidence_seq": 8}],
            "evidence_seq": 9
        }),
    );
    let result = tool_result(response, CanonicalMethod::TargetLaunch);
    let structured = &result["structuredContent"];
    assert!(structured.get("state").is_none());
    assert!(structured["result"].get("command").is_none());
    assert!(structured["result"].get("capabilities").is_none());
    assert!(structured["result"].get("evidence_seq").is_none());
    assert!(
        structured["result"]["frames"][0]
            .get("evidence_seq")
            .is_none()
    );
    assert!(structured.get("evidence").is_none());

    let lifecycle = ApiResponse::success(
        &request,
        Some(SessionState::creating(
            SessionId::parse("sess_test").unwrap(),
        )),
        json!({
            "state": {"lifecycle": "ACTIVE", "snapshot": {"status": "BUILDING"}},
            "start_policy": "first_instruction"
        }),
    );
    let lifecycle = tool_result(lifecycle, CanonicalMethod::TargetLaunch);
    assert!(lifecycle["structuredContent"]["state"].is_object());
    assert!(
        lifecycle["structuredContent"]["result"]
            .get("state")
            .is_none()
    );

    let running = ApiResponse::success(
        &request,
        Some(SessionState::creating(
            SessionId::parse("sess_test").unwrap(),
        )),
        json!({"stop_id": null}),
    );
    let running = tool_result(running, CanonicalMethod::InspectionGet);
    assert!(running["structuredContent"].get("state").is_some());

    let capabilities = ApiResponse::success(
        &request,
        None,
        json!({
            "commands": ["-data-read-memory-bytes"],
            "capabilities": {"memory.read": {"status": "supported"}}
        }),
    );
    let capabilities = tool_result(capabilities, CanonicalMethod::InspectionGet);
    assert!(capabilities["structuredContent"]["result"]["capabilities"].is_object());
    assert_eq!(
        capabilities["structuredContent"]["result"]["commands"][0],
        "-data-read-memory-bytes"
    );

    let session_capabilities = ApiResponse::success(
        &request,
        None,
        json!({
            "commands": ["-exec-run"],
            "capabilities": {"execution": {"status": "supported"}}
        }),
    );
    let session_capabilities =
        tool_result(session_capabilities, CanonicalMethod::SessionCapabilities);
    assert!(session_capabilities["structuredContent"]["result"]["capabilities"].is_object());
    assert_eq!(
        session_capabilities["structuredContent"]["result"]["commands"][0],
        "-exec-run"
    );

    let raw = ApiResponse::success(&request, None, json!({"command": {"record": "raw MI"}}));
    let raw = tool_result(raw, CanonicalMethod::RawMi);
    assert!(raw["structuredContent"]["result"].get("command").is_some());
}

#[test]
fn completed_agent_operations_omit_recovery_bookkeeping() {
    let request = ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "compact".into(),
        session_id: Some("sess_test".into()),
        method: CanonicalMethod::ExecutionControl,
        expected_revision: None,
        idempotency_key: None,
        parameters: json!({}),
    };
    let completed = tool_result(
        ApiResponse::success(
            &request,
            None,
            json!({
                "operation_id": "op_done",
                "wait_status": "COMPLETED",
                "settled_by": "stop",
                "stop_id": "stop_test",
                "observations": {
                    "stack": {"stop_id": "stop_test", "frames": []}
                }
            }),
        ),
        CanonicalMethod::ExecutionControl,
    );
    let result = &completed["structuredContent"]["result"];
    assert_eq!(result["settled_by"], "stop");
    assert!(result.get("operation_id").is_none());
    assert!(result.get("wait_status").is_none());
    assert!(result["observations"]["stack"].get("stop_id").is_none());

    let asynchronous = tool_result(
        ApiResponse::success(
            &request,
            None,
            json!({"operation_id": "op_live", "wait_status": "ACCEPTED"}),
        ),
        CanonicalMethod::ExecutionControl,
    );
    assert_eq!(
        asynchronous["structuredContent"]["result"]["operation_id"],
        "op_live"
    );

    let waited = tool_result(
        ApiResponse::success(
            &request,
            None,
            json!({
                "operation": {"operation_id": "op_done", "status": "COMPLETED"},
                "stop_id": "stop_test",
                "observations": {"stack": {"stop_id": "stop_test", "frames": []}}
            }),
        ),
        CanonicalMethod::ExecutionWait,
    );
    let waited = &waited["structuredContent"]["result"];
    assert!(waited.get("operation").is_none());
    assert!(waited["observations"]["stack"].get("stop_id").is_none());

    let batch = tool_result(
        ApiResponse::success(
            &request,
            None,
            json!({
                "stop_id": "stop_test",
                "revision": 9,
                "results": {"registers": {"stop_id": "stop_test", "values": []}}
            }),
        ),
        CanonicalMethod::InspectionBatch,
    );
    assert_eq!(batch["structuredContent"]["result"]["stop_id"], "stop_test");
    assert!(
        batch["structuredContent"]["result"]
            .get("revision")
            .is_none()
    );
    assert!(
        batch["structuredContent"]["result"]["results"]["registers"]
            .get("stop_id")
            .is_none()
    );

    let probe = tool_result(
        ApiResponse::success(
            &request,
            None,
            json!({
                "captures": [],
                "capture_count": 0,
                "operation": {"operation_id": "op_probe", "status": "COMPLETED"}
            }),
        ),
        CanonicalMethod::AgentProbe,
    );
    assert_eq!(probe["structuredContent"]["result"]["capture_count"], 0);
    assert!(
        probe["structuredContent"]["result"]
            .get("operation")
            .is_none()
    );
}

#[test]
fn projected_mappings_keep_only_agent_address_semantics() {
    let request = ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "mappings".into(),
        session_id: Some("sess_test".into()),
        method: CanonicalMethod::InspectionGet,
        expected_revision: None,
        idempotency_key: None,
        parameters: json!({}),
    };
    let response = ApiResponse::success(
        &request,
        None,
        json!({"mappings": [{
            "start": "0x1000",
            "end": "0x2000",
            "offset": "0x0",
            "permissions": "r-xp",
            "path": "/target",
            "device": "00:01",
            "inode": 7,
            "source": "linux-proc"
        }]}),
    );

    let result = tool_result(response, CanonicalMethod::InspectionGet);
    let mapping = &result["structuredContent"]["result"]["mappings"][0];
    assert_eq!(mapping["start"], "0x1000");
    assert_eq!(mapping["path"], "/target");
    assert!(mapping.get("device").is_none());
    assert!(mapping.get("inode").is_none());
    assert!(mapping.get("source").is_none());
}

#[test]
fn coalesced_events_preserve_the_complete_resynchronization_state() {
    let request = ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "events".into(),
        session_id: Some("sess_test".into()),
        method: CanonicalMethod::EventsWait,
        expected_revision: None,
        idempotency_key: None,
        parameters: json!({}),
    };
    let mut state = SessionState::creating(SessionId::parse("sess_test").unwrap());
    state.limitations.push("resynchronization detail".into());
    let response = ApiResponse::success(
        &request,
        Some(state.clone()),
        json!({"coalesced": true, "state": state}),
    );

    let result = tool_result(response, CanonicalMethod::EventsWait);

    assert_eq!(
        result["structuredContent"]["state"]["limitations"][0],
        "resynchronization detail"
    );
    assert!(result["structuredContent"]["result"].get("state").is_none());
}

#[test]
fn execution_wait_preserves_a_distinct_matched_state() {
    let request = ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "wait".into(),
        session_id: Some("sess_test".into()),
        method: CanonicalMethod::ExecutionWait,
        expected_revision: None,
        idempotency_key: None,
        parameters: json!({}),
    };
    let mut matched = SessionState::creating(SessionId::parse("sess_test").unwrap());
    matched.revision = 7;
    matched.event_seq = 7;
    matched.inferiors.insert(
        "1".into(),
        InferiorState {
            id: InferiorId("inf_test".into()),
            backend_id: "1".into(),
            pid: Some(7),
            generation: 1,
            status: InferiorStatus::Running,
            exit_code: None,
            threads: std::collections::BTreeMap::new(),
        },
    );
    matched.stop_id = Some(StopId("stop_wait".into()));
    matched.snapshot = Some(SnapshotRef {
        snapshot_id: "snap_wait".into(),
        stop_id: StopId("stop_wait".into()),
        status: SnapshotStatus::Building,
        partial: false,
    });
    let mut current = matched.clone();
    current.revision = 8;
    current.event_seq = 8;
    current.snapshot.as_mut().unwrap().status = SnapshotStatus::Ready;
    let coordination_only = ApiResponse::success(
        &request,
        Some(current.clone()),
        json!({"state": matched.clone(), "operation": {"status": "COMPLETED"}}),
    );
    let coordination_only = tool_result(coordination_only, CanonicalMethod::ExecutionWait);
    assert!(
        coordination_only["structuredContent"]["result"]
            .get("state")
            .is_none()
    );

    current.inferiors.get_mut("1").unwrap().status = InferiorStatus::Stopped;
    let response = ApiResponse::success(
        &request,
        Some(current),
        json!({"state": matched, "operation": {"status": "COMPLETED"}}),
    );

    let result = tool_result(response, CanonicalMethod::ExecutionWait);

    assert!(result["structuredContent"].get("revision").is_none());
    assert_eq!(
        result["structuredContent"]["result"]["state"]["status"],
        "RUNNING"
    );
    assert!(
        result["structuredContent"]["result"]["state"]
            .get("revision")
            .is_none()
    );
    assert_eq!(result["structuredContent"]["state"]["status"], "STOPPED");
}

#[tokio::test]
async fn resource_listing_does_not_serialize_complete_session_state() {
    if std::process::Command::new("gdb")
        .arg("--version")
        .output()
        .is_err()
    {
        if std::env::var_os("GDB_AI_REQUIRE_INTEGRATION").is_some() {
            panic!("required GDB executable is unavailable");
        }
        eprintln!("skipped MCP resource test; GDB is unavailable");
        return;
    }
    let directory = tempdir().unwrap();
    let mut config = Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    };
    config.limits.tool_response_bytes = 1_024;
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("resource-test");
    let created = gateway
        .dispatch(
            canonical_request(
                &AtomicU64::new(1),
                None,
                CanonicalMethod::SessionCreate,
                json!({}),
            ),
            &caller,
        )
        .await;
    let session_id = created.session_id.unwrap();
    let listed = list_resources(&gateway, &caller).await.unwrap();

    assert_eq!(listed["resources"].as_array().unwrap().len(), 1);
    assert_eq!(
        listed["resources"][0]["uri"],
        format!("gdbai://session/{session_id}/status")
    );
    gateway.shutdown().await;
}

#[test]
fn breakpoint_tool_results_return_only_the_affected_breakpoint() {
    let request = ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "breakpoint".into(),
        session_id: Some("sess_test".into()),
        method: CanonicalMethod::BreakpointCreate,
        expected_revision: None,
        idempotency_key: None,
        parameters: json!({}),
    };
    let response = ApiResponse::success(
        &request,
        Some(SessionState::creating(
            SessionId::parse("sess_test").unwrap(),
        )),
        json!({
            "breakpoint": {"id": "bp_64", "backend_number": "64"},
            "breakpoints": (0..64)
                .map(|index| (index.to_string(), json!({"id": format!("bp_{index}")})))
                .collect::<Map<String, Value>>()
        }),
    );
    let result = tool_result(response, CanonicalMethod::BreakpointCreate);
    let structured = &result["structuredContent"];
    assert_eq!(structured["result"]["breakpoint"]["id"], "bp_64");
    assert!(structured["result"].get("breakpoints").is_none());
    assert!(structured.get("state").is_none());
}
