use std::{path::PathBuf, process::Command};

use gdb_ai_core::{
    ErrorCode,
    config::{ArtifactConfig, Config, PersistenceConfig},
    gateway::{Caller, Gateway},
    policy::Profile,
    protocol::{API_VERSION, ApiRequest, ApiResponse},
};
use serde_json::{Value, json};
use tempfile::tempdir;

mod support;

fn request(
    id: &str,
    session_id: Option<&str>,
    method: &str,
    revision: Option<u64>,
    parameters: Value,
) -> ApiRequest {
    ApiRequest {
        api_version: API_VERSION.into(),
        request_id: id.into(),
        session_id: session_id.map(str::to_owned),
        method: method.parse().unwrap(),
        expected_revision: revision,
        idempotency_key: None,
        parameters,
    }
}

fn successful(response: ApiResponse) -> ApiResponse {
    assert!(
        response.error.is_none(),
        "response error: {:?}",
        response.error
    );
    response
}

#[tokio::test]
async fn local_debugging_vertical_slice() {
    if !support::require_commands(&["gdb", "cc"]) {
        return;
    }

    let directory = tempdir().unwrap();
    let executable = directory.path().join("vertical");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/c/vertical.c");
    let compiled = Command::new("cc")
        .args(["-g", "-O0", "-fno-omit-frame-pointer"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .status()
        .unwrap();
    assert!(compiled.success());

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
    config.security.workspace_roots = vec![directory.path().to_owned()];
    config.security.default_profile = Profile::LabMutation;
    config.limits.inline_memory_bytes = 1;
    // 2026-08-29: Use the exact checksum-pinned GDB under qualification;
    // relying on a system PATH can silently exercise a different release.
    if let Some(path) = std::env::var_os("GDB_AI_GDB_PATH") {
        config.gdb.path = path.into();
    }
    // 2026-08-29: The full vertical path exceeds the production lease default
    // under TCG. Keep this qualification focused on debugger semantics.
    config.server.write_lease_ms = 5 * 60 * 1_000;
    // 2026-08-29: AArch64 TCG can use one GDB deadline for cancelled-probe
    // cleanup and another for the assertion's breakpoint reconciliation.
    let cleanup_timeout = config.server.command_timeout().saturating_mul(2);
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("integration-test");

    let created = successful(
        gateway
            .dispatch(
                request("create", None, "session.create", None, json!({})),
                &caller,
            )
            .await,
    );
    let session_id = created
        .result
        .as_ref()
        .and_then(|result| result.get("session_id"))
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    if let Ok(expected) = std::env::var("GDB_AI_EXPECTED_MI") {
        assert_eq!(
            created.result.as_ref().unwrap()["backend"]["mi_version"].as_str(),
            Some(expected.as_str())
        );
    }
    assert_eq!(created.session_id.as_deref(), Some(session_id.as_str()));
    assert!(created.revision.is_some());
    let lease_id = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap()
        .to_owned();
    // 2026-08-28: Batch validation must happen before the first signal policy
    // reaches GDB, otherwise a later malformed name leaves a partial mutation.
    let invalid_signals = gateway
        .dispatch(
            request(
                "invalid-signals",
                Some(&session_id),
                "signal.update",
                created.revision,
                json!({
                    "lease_id": lease_id,
                    "signals": {
                        "SIGUSR1": {"stop": true, "print": true, "pass": false},
                        "invalid": {"stop": false, "print": false, "pass": true}
                    }
                }),
            ),
            &caller,
        )
        .await;
    assert_eq!(
        invalid_signals.error.unwrap().code,
        ErrorCode::InvalidArgument
    );
    let signals = successful(
        gateway
            .dispatch(
                request(
                    "signals-after-invalid-update",
                    Some(&session_id),
                    "signal.get",
                    None,
                    json!({}),
                ),
                &caller,
            )
            .await,
    );
    assert!(
        signals
            .result
            .as_ref()
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty()
    );
    let partial_signals = gateway
        .dispatch(
            request(
                "partially-applied-signals",
                Some(&session_id),
                "signal.update",
                signals.revision,
                json!({
                    "lease_id": lease_id,
                    "signals": {
                        "SIGUSR1": {"stop": true, "print": true, "pass": false},
                        "SIGZZZ": {"stop": false, "print": false, "pass": true}
                    }
                }),
            ),
            &caller,
        )
        .await;
    let partial_error = partial_signals.error.as_ref().unwrap();
    assert_eq!(partial_error.code, ErrorCode::GdbError);
    assert_eq!(
        partial_error.details.as_ref().unwrap()["partial"],
        Value::Bool(true)
    );
    assert!(
        partial_error.details.as_ref().unwrap()["applied"]
            .get("SIGUSR1")
            .is_some()
    );

    let launched = successful(
        gateway
            .dispatch(
                request(
                    "launch",
                    Some(&session_id),
                    "target.launch",
                    partial_signals.revision,
                    json!({
                        "program": "vertical",
                        "lease_id": lease_id,
                        "cwd": directory.path(),
                        "environment": {"GDB_AI_TEST_ENV": "preserved"},
                        "stop": "first_instruction",
                        "wait": {"until": "snapshot", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    let first_stop = launched
        .state
        .as_ref()
        .and_then(|state| state.stop_id.as_ref())
        .unwrap()
        .0
        .clone();
    let minimal_snapshot_id = launched
        .state
        .as_ref()
        .unwrap()
        .snapshot
        .as_ref()
        .unwrap()
        .snapshot_id
        .clone();
    let minimal_snapshot = successful(
        gateway
            .dispatch(
                request(
                    "minimal-snapshot",
                    Some(&session_id),
                    "inspection.snapshot_get",
                    None,
                    json!({"snapshot_id": minimal_snapshot_id}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(minimal_snapshot.result.unwrap()["stop_id"], first_stop);
    let stop_context = successful(
        gateway
            .dispatch(
                request(
                    "stop-context",
                    Some(&session_id),
                    "inspection.get",
                    None,
                    json!({"view": "stop_context"}),
                ),
                &caller,
            )
            .await,
    );
    let stop_context = stop_context.result.unwrap();
    assert_eq!(stop_context["stop_id"], first_stop);
    assert!(stop_context.get("inferiors").is_none());
    assert!(stop_context.get("breakpoints").is_none());

    let event_wait = gateway.dispatch(
        request(
            "event-wait",
            Some(&session_id),
            "events.wait",
            None,
            json!({
                "after_event_seq": launched.state.as_ref().unwrap().event_seq,
                "timeout_ms": 1000
            }),
        ),
        &caller,
    );
    let resize = async {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        gateway
            .dispatch(
                request(
                    "resize",
                    Some(&session_id),
                    "inferior_io.resize",
                    launched.revision,
                    json!({
                        "lease_id": lease_id,
                        "rows": 40,
                        "columns": 120
                    }),
                ),
                &caller,
            )
            .await
    };
    let (event, resized) = tokio::join!(event_wait, resize);
    let event = successful(event);
    let resized = successful(resized);
    assert!(
        event.result.as_ref().unwrap()["event_seq"]
            .as_u64()
            .is_some_and(|seq| seq > launched.state.as_ref().unwrap().event_seq)
    );
    assert_eq!(resized.result.as_ref().unwrap()["rows"], 40);

    let breakpoint = successful(
        gateway
            .dispatch(
                request(
                    "breakpoint",
                    Some(&session_id),
                    "breakpoint.create",
                    resized.revision,
                    json!({"lease_id": lease_id, "location": {"function": "marker"}}),
                ),
                &caller,
            )
            .await,
    );
    let breakpoint_id = breakpoint.result.as_ref().unwrap()["breakpoints"]
        .as_object()
        .and_then(|breakpoints| breakpoints.values().next())
        .and_then(|breakpoint| breakpoint["id"].as_str())
        .unwrap()
        .to_owned();
    assert_eq!(
        breakpoint.result.as_ref().unwrap()["breakpoint"]["id"],
        breakpoint_id
    );
    let breakpoint = successful(
        gateway
            .dispatch(
                request(
                    "breakpoint-update",
                    Some(&session_id),
                    "breakpoint.update",
                    breakpoint.revision,
                    json!({
                        "lease_id": lease_id,
                        "breakpoint_id": breakpoint_id,
                        "enabled": true,
                        "condition": "global_value >= 0",
                        "ignore_count": 0
                    }),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(
        breakpoint.result.as_ref().unwrap()["commands"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
    let listed = successful(
        gateway
            .dispatch(
                request(
                    "breakpoint-list",
                    Some(&session_id),
                    "breakpoint.list",
                    None,
                    json!({}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(listed.revision, breakpoint.revision);
    assert_eq!(
        listed.result.as_ref().unwrap()["breakpoints"]
            .as_object()
            .map(serde_json::Map::len),
        Some(1)
    );
    let catchpoint = successful(
        gateway
            .dispatch(
                request(
                    "catchpoint",
                    Some(&session_id),
                    "breakpoint.create",
                    listed.revision,
                    json!({
                        "lease_id": lease_id,
                        "kind": "catchpoint",
                        "catch": "exec"
                    }),
                ),
                &caller,
            )
            .await,
    );
    let catchpoint_id = catchpoint.result.as_ref().unwrap()["breakpoints"]
        .as_object()
        .unwrap()
        .values()
        .find_map(|candidate| {
            let id = candidate["id"].as_str()?;
            (id != breakpoint_id).then(|| id.to_owned())
        })
        .unwrap();
    let breakpoint = successful(
        gateway
            .dispatch(
                request(
                    "catchpoint-delete",
                    Some(&session_id),
                    "breakpoint.delete",
                    catchpoint.revision,
                    json!({"lease_id": lease_id, "breakpoint_id": catchpoint_id}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(
        breakpoint.result.as_ref().unwrap()["breakpoints"]
            .as_object()
            .map(serde_json::Map::len),
        Some(1)
    );
    let invalid_wait = gateway
        .dispatch(
            request(
                "invalid-wait",
                Some(&session_id),
                "execution.control",
                breakpoint.revision,
                json!({
                    "action": "continue",
                    "lease_id": lease_id,
                    "stop_id": first_stop,
                    "wait": {"until": "unknown", "timeout_ms": 5000}
                }),
            ),
            &caller,
        )
        .await;
    assert_eq!(
        invalid_wait.error.unwrap().code,
        gdb_ai_core::ErrorCode::InvalidArgument
    );
    assert_eq!(
        invalid_wait
            .state
            .as_ref()
            .unwrap()
            .stop_id
            .as_ref()
            .unwrap()
            .0,
        first_stop
    );
    assert_eq!(invalid_wait.revision, breakpoint.revision);
    let racing_inspection = gateway
        .dispatch(
            request(
                "racing-inspection",
                Some(&session_id),
                "execution.control",
                breakpoint.revision,
                json!({
                    "action": "continue",
                    "lease_id": lease_id,
                    "stop_id": first_stop,
                    "wait": {"until": "running", "timeout_ms": 5000},
                    "inspect": [{"view": "stack", "limit": 2}]
                }),
            ),
            &caller,
        )
        .await;
    assert_eq!(
        racing_inspection.error.unwrap().code,
        gdb_ai_core::ErrorCode::InvalidArgument
    );
    assert_eq!(
        racing_inspection.state.unwrap().stop_id.unwrap().0,
        first_stop
    );
    let accepted = successful(
        gateway
            .dispatch(
                request(
                    "continue",
                    Some(&session_id),
                    "execution.control",
                    breakpoint.revision,
                    json!({
                        "action": "continue",
                        "lease_id": lease_id,
                        "stop_id": first_stop,
                        "wait": {"until": "accepted", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    let continued_operation = accepted.result.as_ref().unwrap()["operation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let continued = successful(
        gateway
            .dispatch(
                request(
                    "continue-wait",
                    Some(&session_id),
                    "execution.wait",
                    None,
                    json!({
                        "operation_id": continued_operation,
                        "wait": {"until": "snapshot", "timeout_ms": 5000},
                        "inspect": [
                            {"view": "stack", "limit": 2},
                            {"view": "registers", "roles": ["pc", "sp"]}
                        ]
                    }),
                ),
                &caller,
            )
            .await,
    );
    let second_stop = continued
        .state
        .as_ref()
        .and_then(|state| state.stop_id.as_ref())
        .unwrap()
        .0
        .clone();
    assert_eq!(continued.result.as_ref().unwrap()["stop_id"], second_stop);
    assert!(continued.result.as_ref().unwrap()["observations"]["stack"].is_object());
    assert!(continued.result.as_ref().unwrap()["observations"]["registers"].is_object());
    assert_ne!(first_stop, second_stop);
    let invalid_snapshot = gateway
        .dispatch(
            request(
                "invalid-snapshot",
                Some(&session_id),
                "inspection.snapshot",
                None,
                json!({"profile": "unknown", "stop_id": second_stop}),
            ),
            &caller,
        )
        .await;
    assert_eq!(
        invalid_snapshot.error.unwrap().code,
        gdb_ai_core::ErrorCode::InvalidArgument
    );
    assert_eq!(
        invalid_snapshot.state.unwrap().snapshot.unwrap().status,
        gdb_ai_core::domain::SnapshotStatus::Ready
    );

    for (id, view) in [
        ("stack", "stack"),
        ("locals", "locals"),
        ("registers", "registers"),
    ] {
        successful(
            gateway
                .dispatch(
                    request(
                        id,
                        Some(&session_id),
                        "inspection.get",
                        None,
                        json!({"view": view, "stop_id": second_stop, "limit": 8}),
                    ),
                    &caller,
                )
                .await,
        );
    }
    let batch = successful(
        gateway
            .dispatch(
                request(
                    "inspection-batch",
                    Some(&session_id),
                    "inspection.batch",
                    None,
                    json!({
                        "stop_id": second_stop,
                        "requests": [
                            {"name": "stack", "view": "stack", "limit": 2},
                            {"name": "registers", "view": "registers", "roles": ["pc", "sp"]}
                        ]
                    }),
                ),
                &caller,
            )
            .await,
    );
    assert!(batch.result.as_ref().unwrap()["results"]["stack"].is_object());
    assert!(batch.result.as_ref().unwrap()["results"]["registers"].is_object());
    let mappings = successful(
        gateway
            .dispatch(
                request(
                    "mappings",
                    Some(&session_id),
                    "inspection.get",
                    None,
                    json!({"view": "mappings", "limit": 1}),
                ),
                &caller,
            )
            .await,
    );
    let mappings = mappings.result.unwrap();
    assert_eq!(mappings["partial"], false);
    assert_eq!(mappings["mappings"].as_array().map(Vec::len), Some(1));
    assert_eq!(mappings["truncated"], true);
    assert_eq!(mappings["continuation"]["offset"], 1);
    let unavailable_register = successful(
        gateway
            .dispatch(
                request(
                    "unavailable-register",
                    Some(&session_id),
                    "register.read",
                    None,
                    json!({"roles": [], "stop_id": second_stop}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(
        unavailable_register.result.unwrap()["roles"]
            .as_object()
            .map(serde_json::Map::len),
        Some(0)
    );

    let address = successful(
        gateway
            .dispatch(
                request(
                    "address",
                    Some(&session_id),
                    "value.evaluate",
                    None,
                    json!({
                        "expression": "&global_value",
                        "stop_id": second_stop,
                        "side_effects": "deny"
                    }),
                ),
                &caller,
            )
            .await,
    )
    .result
    .unwrap()["value"]
        .as_str()
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    let hypothesis = successful(
        gateway
            .dispatch(
                request(
                    "hypothesis",
                    Some(&session_id),
                    "agent.hypothesis_check",
                    None,
                    json!({
                        "claim": "global_value is initialized before marker",
                        "expression": "global_value",
                        "operator": "equals",
                        "expected": "7",
                        "stop_id": second_stop
                    }),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(hypothesis.result.as_ref().unwrap()["verdict"], "confirmed");

    let memory = successful(
        gateway
            .dispatch(
                request(
                    "memory",
                    Some(&session_id),
                    "memory.read",
                    None,
                    json!({"address": address, "length": 4, "stop_id": second_stop}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(memory.result.as_ref().unwrap()["stop_id"], second_stop);
    let unmapped = gateway
        .dispatch(
            request(
                "unmapped-memory",
                Some(&session_id),
                "memory.read",
                None,
                json!({"address": "0x410", "length": 32, "accept_current_stop": true}),
            ),
            &caller,
        )
        .await;
    assert_eq!(unmapped.error.unwrap().code, ErrorCode::GdbError);
    let search = successful(
        gateway
            .dispatch(
                request(
                    "memory-search",
                    Some(&session_id),
                    "memory.search",
                    None,
                    json!({
                        "start": address,
                        "length": 4,
                        "pattern": {"hex": "07000000"},
                        "stop_id": second_stop
                    }),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(search.result.as_ref().unwrap()["stop_id"], second_stop);
    assert_eq!(search.result.as_ref().unwrap()["partial"], false);
    assert_eq!(
        search.result.as_ref().unwrap()["matches"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    let memory_artifact = memory.result.as_ref().unwrap()["artifact"]
        .as_str()
        .unwrap()
        .to_owned();
    let evidence_seq = memory.evidence[0]
        .uri
        .rsplit('/')
        .next()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let evidence = successful(
        gateway
            .dispatch(
                request(
                    "memory-evidence",
                    Some(&session_id),
                    "session.event",
                    None,
                    json!({"event_seq": evidence_seq}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(evidence.result.unwrap()["type"], "mi.output");
    let large_address = successful(
        gateway
            .dispatch(
                request(
                    "large-address",
                    Some(&session_id),
                    "value.evaluate",
                    None,
                    json!({
                        "expression": "&large_buffer",
                        "stop_id": second_stop,
                        "side_effects": "deny"
                    }),
                ),
                &caller,
            )
            .await,
    )
    .result
    .unwrap()["value"]
        .as_str()
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    let large_memory = successful(
        gateway
            .dispatch(
                request(
                    "large-memory",
                    Some(&session_id),
                    "memory.read",
                    None,
                    json!({
                        "address": large_address,
                        "length": 65537,
                        "stop_id": second_stop
                    }),
                ),
                &caller,
            )
            .await,
    );
    let large_result = large_memory.result.unwrap();
    assert_eq!(large_result["read_length"], 65537);
    let large_artifact = large_result["artifact"].as_str().unwrap();
    let first_page = successful(
        gateway
            .dispatch(
                request(
                    "artifact-page-1",
                    None,
                    "artifact.get",
                    None,
                    json!({"uri": large_artifact, "offset": 0, "max_bytes": 65536}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(first_page.result.as_ref().unwrap()["next_offset"], 65536);
    assert_eq!(first_page.result.as_ref().unwrap()["truncated"], true);
    let second_page = successful(
        gateway
            .dispatch(
                request(
                    "artifact-page-2",
                    None,
                    "artifact.get",
                    None,
                    json!({"uri": large_artifact, "offset": 65536, "max_bytes": 65536}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(second_page.result.as_ref().unwrap()["next_offset"], 65537);
    assert_eq!(second_page.result.as_ref().unwrap()["truncated"], false);
    let original_bytes = "BwAAAA==".to_owned();
    let unauthorized = gateway
        .dispatch(
            request(
                "artifact-other-owner",
                None,
                "artifact.get",
                None,
                json!({"uri": memory_artifact}),
            ),
            &Caller::local("other-agent"),
        )
        .await;
    assert_eq!(
        unauthorized.error.unwrap().code,
        gdb_ai_core::ErrorCode::PolicyDenied
    );
    let compared = successful(
        gateway
            .dispatch(
                request(
                    "memory-compare",
                    Some(&session_id),
                    "memory.compare",
                    None,
                    json!({
                        "address": address,
                        "length": 4,
                        "stop_id": second_stop,
                        "expected": {"bytes_base64": original_bytes}
                    }),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(compared.result.as_ref().unwrap()["stop_id"], second_stop);
    let value = successful(
        gateway
            .dispatch(
                request(
                    "value-create",
                    Some(&session_id),
                    "value.create",
                    continued.revision,
                    json!({
                        "lease_id": lease_id,
                        "expression": "global_pair",
                        "stop_id": second_stop
                    }),
                ),
                &caller,
            )
            .await,
    );
    let value_id = value.result.as_ref().unwrap()["value_id"]
        .as_str()
        .unwrap()
        .to_owned();
    successful(
        gateway
            .dispatch(
                request(
                    "value-update",
                    Some(&session_id),
                    "value.update",
                    None,
                    json!({"value_id": value_id, "stop_id": second_stop}),
                ),
                &caller,
            )
            .await,
    );
    successful(
        gateway
            .dispatch(
                request(
                    "value-children",
                    Some(&session_id),
                    "value.children",
                    None,
                    json!({
                        "value_id": value_id,
                        "stop_id": second_stop,
                        "offset": 0,
                        "limit": 8
                    }),
                ),
                &caller,
            )
            .await,
    );
    let tracking = successful(
        gateway
            .dispatch(
                request(
                    "tracking-add",
                    Some(&session_id),
                    "tracking.add_expression",
                    value.revision,
                    json!({
                        "lease_id": lease_id,
                        "expression": "global_value"
                    }),
                ),
                &caller,
            )
            .await,
    );
    let written = successful(
        gateway
            .dispatch(
                request(
                    "memory-write",
                    Some(&session_id),
                    "memory.write",
                    tracking.revision,
                    json!({
                        "lease_id": lease_id,
                        "address": address,
                        "data_base64": "CQAAAA==",
                        "expected": {"bytes_base64": original_bytes},
                        "stop_id": second_stop
                    }),
                ),
                &caller,
            )
            .await,
    );
    let _register = successful(
        gateway
            .dispatch(
                request(
                    "register-write",
                    Some(&session_id),
                    "register.write",
                    written.revision,
                    json!({
                        "lease_id": lease_id,
                        "register": "return",
                        "value": "0",
                        "reason": "integration test",
                        "stop_id": second_stop
                    }),
                ),
                &caller,
            )
            .await,
    );
    let snapshot = successful(
        gateway
            .dispatch(
                request(
                    "tracked-snapshot",
                    Some(&session_id),
                    "inspection.snapshot",
                    None,
                    json!({"profile": "brief", "stop_id": second_stop}),
                ),
                &caller,
            )
            .await,
    );
    // 2026-08-30: Keep the response bound to this request; the original
    // regression assertion accidentally inspected the earlier memory result.
    let disassembly = successful(
        gateway
            .dispatch(
                request(
                    "disassembly",
                    Some(&session_id),
                    "disassembly.read",
                    None,
                    json!({
                        "around": {"expression": "$pc", "before_instructions": 2, "after_instructions": 4},
                        "include_source": false,
                        "include_bytes": false,
                        "stop_id": second_stop
                    }),
                ),
                &caller,
            )
            .await,
    );
    assert!(
        disassembly.result.as_ref().unwrap()["instructions"]
            .as_array()
            .is_some_and(|instructions| instructions.len() <= 7)
    );
    assert_eq!(disassembly.result.as_ref().unwrap()["stop_id"], second_stop);
    assert!(
        disassembly.result.as_ref().unwrap()["instructions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|instruction| instruction.get("source").is_none()
                && instruction.get("bytes").is_none())
    );

    let stable_memory = gateway.dispatch(
        request(
            "stable-memory",
            Some(&session_id),
            "memory.read",
            None,
            json!({
                "address": large_address,
                "length": 4 * 1024 * 1024,
                "stop_id": second_stop
            }),
        ),
        &caller,
    );
    let resume_and_interrupt = async {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        successful(
            gateway
                .dispatch(
                    request(
                        "race-resume",
                        Some(&session_id),
                        "execution.control",
                        snapshot.revision,
                        json!({
                            "action": "continue",
                            "lease_id": lease_id,
                            "stop_id": second_stop
                        }),
                    ),
                    &caller,
                )
                .await,
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        successful(
            gateway
                .dispatch(
                    request(
                        "race-interrupt",
                        Some(&session_id),
                        "execution.control",
                        None,
                        json!({
                            "action": "interrupt",
                            "lease_id": lease_id,
                            "accept_latest_revision": true,
                            "wait": {"until": "snapshot", "timeout_ms": 5000}
                        }),
                    ),
                    &caller,
                )
                .await,
        )
    };
    let (stable_memory, stable_stop) = tokio::join!(stable_memory, resume_and_interrupt);
    assert_eq!(
        successful(stable_memory).result.unwrap()["read_length"],
        4 * 1024 * 1024
    );
    let second_stop = stable_stop
        .state
        .as_ref()
        .and_then(|state| state.stop_id.as_ref())
        .unwrap()
        .0
        .clone();
    let stable_revision = stable_stop.revision;

    let resume = gateway.dispatch(
        request(
            "resume-to-input",
            Some(&session_id),
            "execution.control",
            stable_revision,
            json!({
                "action": "continue",
                "lease_id": lease_id,
                "stop_id": second_stop,
                "wait": {"until": "snapshot", "timeout_ms": 5000}
            }),
        ),
        &caller,
    );
    let interrupt = async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        gateway
            .dispatch(
                request(
                    "interrupt",
                    Some(&session_id),
                    "execution.control",
                    None,
                    json!({
                        "action": "interrupt",
                        "lease_id": lease_id,
                        "accept_latest_revision": true,
                        "wait": {"until": "snapshot", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await
    };
    let (resumed, interrupted) = tokio::join!(resume, interrupt);
    successful(resumed);
    let interrupted = successful(interrupted);
    let third_stop = interrupted
        .state
        .as_ref()
        .and_then(|state| state.stop_id.as_ref())
        .unwrap()
        .0
        .clone();
    let superseded_wait = gateway
        .dispatch(
            request(
                "superseded-operation-wait",
                Some(&session_id),
                "execution.wait",
                None,
                json!({
                    "operation_id": continued_operation,
                    "wait": {"until": "snapshot", "timeout_ms": 100}
                }),
            ),
            &caller,
        )
        .await;
    assert_eq!(
        superseded_wait.error.unwrap().code,
        gdb_ai_core::ErrorCode::StaleContext
    );
    let stale_value = gateway
        .dispatch(
            request(
                "stale-value",
                Some(&session_id),
                "value.update",
                None,
                json!({"value_id": value_id, "stop_id": third_stop}),
            ),
            &caller,
        )
        .await;
    assert_eq!(
        stale_value.error.unwrap().code,
        gdb_ai_core::ErrorCode::StaleContext
    );
    let changed = successful(
        gateway
            .dispatch(
                request(
                    "changed-snapshot",
                    Some(&session_id),
                    "inspection.snapshot",
                    None,
                    json!({"profile": "brief", "stop_id": third_stop}),
                ),
                &caller,
            )
            .await,
    );
    assert!(
        changed.result.as_ref().unwrap()["changes"]
            .as_object()
            .is_some_and(|changes| !changes.is_empty())
    );

    let output = successful(
        gateway
            .dispatch(
                request(
                    "output",
                    Some(&session_id),
                    "inferior_io.read",
                    None,
                    json!({"stream": "pty", "after_offset": 0, "max_bytes": 4096}),
                ),
                &caller,
            )
            .await,
    );
    let output = output.result.unwrap();
    let output = output["text"].as_str().unwrap();
    assert!(output.contains("marker reached"));
    assert!(output.contains("environment: preserved"), "{output:?}");
    let deleted = successful(
        gateway
            .dispatch(
                request(
                    "delete-before-restart",
                    Some(&session_id),
                    "breakpoint.delete",
                    changed.revision,
                    json!({"lease_id": lease_id, "breakpoint_id": breakpoint_id}),
                ),
                &caller,
            )
            .await,
    );
    let queued = successful(
        gateway
            .dispatch(
                request(
                    "queue-stale-input",
                    Some(&session_id),
                    "inferior_io.write",
                    deleted.revision,
                    json!({"lease_id": lease_id, "text": "stale"}),
                ),
                &caller,
            )
            .await,
    );
    let restarted = successful(
        gateway
            .dispatch(
                request(
                    "restart-with-stale-input",
                    Some(&session_id),
                    "target.restart",
                    queued.revision,
                    json!({
                        "lease_id": lease_id,
                        "stop": "main",
                        "wait": {"until": "snapshot", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    let restarted_stop = restarted
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    let exited = successful(
        gateway
            .dispatch(
                request(
                    "exit",
                    Some(&session_id),
                    "execution.control",
                    restarted.revision,
                    json!({
                        "action": "continue",
                        "lease_id": lease_id,
                        "stop_id": restarted_stop,
                        "input": {"text": "x"},
                        "wait": {"until": "exited", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    assert!(exited.state.as_ref().unwrap().stop_id.is_none());
    assert!(exited.result.as_ref().unwrap().get("input").is_none());
    assert!(
        exited.result.as_ref().unwrap()["output"]["text"]
            .as_str()
            .unwrap()
            .contains("input received: x")
    );

    successful(
        gateway
            .dispatch(
                request(
                    "close",
                    Some(&session_id),
                    "session.close",
                    exited.revision,
                    json!({"lease_id": lease_id}),
                ),
                &caller,
            )
            .await,
    );

    let created = successful(
        gateway
            .dispatch(
                request("close-create", None, "session.create", None, json!({})),
                &caller,
            )
            .await,
    );
    let close_session = created.session_id.clone().unwrap();
    let close_lease = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let launched = successful(
        gateway
            .dispatch(
                request(
                    "close-launch",
                    Some(&close_session),
                    "target.launch",
                    created.revision,
                    json!({
                        "lease_id": close_lease,
                        "program": executable,
                        "stop": "first_instruction",
                        "wait": {"until": "snapshot", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    let close_stop = launched
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    // 2026-08-28: A timed-out probe must remove its temporary breakpoint even
    // though the inferior remains running until the caller interrupts it.
    let timed_out_probe = gateway
        .dispatch(
            request(
                "timed-out-probe",
                Some(&close_session),
                "agent.probe",
                launched.revision,
                json!({
                    "lease_id": close_lease,
                    "stop_id": close_stop,
                    "location": {"function": "never_called_by_vertical_target"},
                    "budget": {"wall_time_ms": 50}
                }),
            ),
            &caller,
        )
        .await;
    assert_eq!(timed_out_probe.error.unwrap().code, ErrorCode::Timeout);
    let timed_out_interrupted = successful(
        gateway
            .dispatch(
                request(
                    "timed-out-probe-interrupt",
                    Some(&close_session),
                    "execution.control",
                    None,
                    json!({
                        "action": "interrupt",
                        "lease_id": close_lease,
                        "accept_latest_revision": true,
                        "wait": {"until": "snapshot", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    let listed = successful(
        gateway
            .dispatch(
                request(
                    "timed-out-probe-breakpoints",
                    Some(&close_session),
                    "breakpoint.list",
                    None,
                    json!({}),
                ),
                &caller,
            )
            .await,
    );
    assert!(
        listed.result.unwrap()["breakpoints"]
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
    );
    let close_stop = timed_out_interrupted
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    {
        let probe = gateway.dispatch(
            request(
                "cancelled-probe",
                Some(&close_session),
                "agent.probe",
                timed_out_interrupted.revision,
                json!({
                    "lease_id": close_lease,
                    "stop_id": close_stop,
                    "location": {"function": "never_called_by_vertical_target"},
                    "budget": {"wall_time_ms": 5000}
                }),
            ),
            &caller,
        );
        tokio::pin!(probe);
        // 2026-08-29: A fixed delay could cancel before slow TCG finished
        // breakpoint insertion, so no cleanup guard owned the late side
        // effect. The probe installs its guard before resuming; cancel only
        // after the target is observably running.
        tokio::time::timeout(cleanup_timeout, async {
            loop {
                let status = gateway.dispatch(
                    request(
                        "cancelled-probe-status",
                        Some(&close_session),
                        "session.get",
                        None,
                        json!({}),
                    ),
                    &caller,
                );
                let status = tokio::select! {
                    response = &mut probe => {
                        panic!("probe completed before cancellation: {response:?}")
                    }
                    status = status => successful(status),
                };
                let state = status.result.as_ref().unwrap();
                let running = state["inferiors"].as_object().is_some_and(|inferiors| {
                    inferiors
                        .values()
                        .any(|inferior| inferior["status"] == "RUNNING")
                });
                if running {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("probe did not become cancellable before its deadline");
    }
    let interrupted = successful(
        gateway
            .dispatch(
                request(
                    "cancelled-probe-interrupt",
                    Some(&close_session),
                    "execution.control",
                    None,
                    json!({
                        "action": "interrupt",
                        "lease_id": close_lease,
                        "accept_latest_revision": true,
                        "wait": {"until": "snapshot", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    tokio::time::timeout(cleanup_timeout, async {
        loop {
            let listed = successful(
                gateway
                    .dispatch(
                        request(
                            "cancelled-probe-breakpoints",
                            Some(&close_session),
                            "breakpoint.list",
                            None,
                            json!({}),
                        ),
                        &caller,
                    )
                    .await,
            );
            if listed.result.unwrap()["breakpoints"]
                .as_object()
                .is_some_and(serde_json::Map::is_empty)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("cancelled probe retained its temporary breakpoint");
    let close_stop = interrupted
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    let waiter = gateway.dispatch(
        request(
            "close-waiter",
            Some(&close_session),
            "execution.control",
            interrupted.revision,
            json!({
                "action": "continue",
                "lease_id": close_lease,
                "stop_id": close_stop,
                "wait": {"until": "snapshot", "timeout_ms": 5000}
            }),
        ),
        &caller,
    );
    let closer = async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        gateway
            .dispatch(
                request(
                    "close-running",
                    Some(&close_session),
                    "session.close",
                    None,
                    json!({"lease_id": close_lease, "accept_latest_revision": true}),
                ),
                &caller,
            )
            .await
    };
    let (waited, closed) = tokio::join!(waiter, closer);
    successful(closed);
    assert!(waited.error.is_some());
}
