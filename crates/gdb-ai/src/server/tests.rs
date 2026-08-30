use super::*;
use crate::tool_catalog::tool_names;
use gdb_ai_core::{
    domain::{BreakpointState, SessionId, SessionState},
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
    let response = ApiResponse::success(&request, Some(state), json!({"status": "ready"}));
    let canonical_bytes = serde_json::to_vec(&response).unwrap().len();
    let result = tool_result(response);
    let compact_bytes = serde_json::to_vec(&result["structuredContent"])
        .unwrap()
        .len();
    let structured = &result["structuredContent"];
    assert_eq!(structured["state"]["lifecycle"], "CREATING");
    assert_eq!(structured["result"]["status"], "ready");
    assert!(structured["state"].get("breakpoints").is_none());
    assert!(structured["state"].get("limitations").is_none());
    assert!(structured.get("api_version").is_none());
    assert!(structured.get("request_id").is_none());
    assert!(compact_bytes * 4 < canonical_bytes);
}
