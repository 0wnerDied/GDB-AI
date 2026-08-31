use super::*;
use crate::tool_catalog::tool_names;
use gdb_ai_core::{
    domain::{
        BreakpointState, FrameSummary, InferiorId, InferiorState, InferiorStatus, SessionId,
        SessionState, StopId, ThreadId, ThreadState,
    },
    protocol::ApiResponse,
};

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
        session_id: None,
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
            ),
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
    assert!(cancellation.operation_id.is_none());
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
fn tool_results_keep_only_agent_coordination_state() {
    let mut state = SessionState::creating(SessionId::parse("sess_test").unwrap());
    state.revision = 7;
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
    assert_eq!(structured["state"]["lifecycle"], "CREATING");
    assert_eq!(structured["state"]["frame"]["function"], "main");
    assert!(structured.get("result").is_none());
    assert!(structured["state"].get("breakpoints").is_none());
    assert!(structured["state"].get("limitations").is_none());
    assert!(structured.get("api_version").is_none());
    assert!(structured.get("request_id").is_none());
    assert!(compact_bytes * 4 < canonical_bytes);

    let historical = tool_result(
        ApiResponse::success(&request, None, serde_json::to_value(&state).unwrap()),
        CanonicalMethod::SessionGet,
    );
    assert_eq!(historical["structuredContent"]["session_id"], "sess_test");
    assert_eq!(historical["structuredContent"]["revision"], 7);
    assert!(
        historical["structuredContent"]["state"]
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
    assert!(target["structuredContent"].get("result").is_none());

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
    assert!(listed["state"].get("breakpoints").is_none());
    assert!(serde_json::to_vec(listed).unwrap().len() < 2 * 1024);
}

#[test]
fn tool_results_omit_on_demand_evidence_and_repeated_stop_state() {
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
            "command": {"record": "raw MI"},
            "capabilities": {"unused": true},
            "frames": []
        }),
    );
    let result = tool_result(response, CanonicalMethod::TargetLaunch);
    let structured = &result["structuredContent"];
    assert!(structured.get("state").is_none());
    assert!(structured["result"].get("command").is_none());
    assert!(structured["result"].get("capabilities").is_none());

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
        json!({"capabilities": {"memory.read": {"status": "supported"}}}),
    );
    let capabilities = tool_result(capabilities, CanonicalMethod::InspectionGet);
    assert!(capabilities["structuredContent"]["result"]["capabilities"].is_object());

    let raw = ApiResponse::success(&request, None, json!({"command": {"record": "raw MI"}}));
    let raw = tool_result(raw, CanonicalMethod::RawMi);
    assert!(raw["structuredContent"]["result"].get("command").is_some());
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
