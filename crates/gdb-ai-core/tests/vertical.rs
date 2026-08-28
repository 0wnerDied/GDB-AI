use std::{path::PathBuf, process::Command};

use gdb_ai_core::{
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
    assert_eq!(created.session_id.as_deref(), Some(session_id.as_str()));
    assert!(created.revision.is_some());
    let lease_id = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let launched = successful(
        gateway
            .dispatch(
                request(
                    "launch",
                    Some(&session_id),
                    "target.launch",
                    created.revision,
                    json!({
                        "program": executable,
                        "lease_id": lease_id,
                        "cwd": directory.path(),
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

    let breakpoint = successful(
        gateway
            .dispatch(
                request(
                    "breakpoint",
                    Some(&session_id),
                    "breakpoint.create",
                    launched.revision,
                    json!({"lease_id": lease_id, "location": {"function": "marker"}}),
                ),
                &caller,
            )
            .await,
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
    let continued = successful(
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
                        "wait": {"until": "snapshot", "timeout_ms": 5000}
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
    let continued_operation = continued.result.as_ref().unwrap()["operation_id"]
        .as_str()
        .unwrap()
        .to_owned();
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
    let mappings = successful(
        gateway
            .dispatch(
                request(
                    "mappings",
                    Some(&session_id),
                    "inspection.get",
                    None,
                    json!({"view": "mappings"}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(mappings.result.unwrap()["partial"], false);
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
    successful(
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
    successful(
        gateway
            .dispatch(
                request(
                    "disassembly",
                    Some(&session_id),
                    "disassembly.read",
                    None,
                    json!({
                        "around": {"expression": "$pc", "before_instructions": 2, "after_instructions": 4},
                        "stop_id": second_stop
                    }),
                ),
                &caller,
            )
            .await,
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
    assert!(
        output.result.unwrap()["text"]
            .as_str()
            .unwrap()
            .contains("marker reached")
    );
    let input = successful(
        gateway
            .dispatch(
                request(
                    "input",
                    Some(&session_id),
                    "inferior_io.write",
                    changed.revision,
                    json!({"lease_id": lease_id, "text": "\n"}),
                ),
                &caller,
            )
            .await,
    );
    let exited = successful(
        gateway
            .dispatch(
                request(
                    "exit",
                    Some(&session_id),
                    "execution.control",
                    input.revision,
                    json!({
                        "action": "continue",
                        "lease_id": lease_id,
                        "stop_id": third_stop,
                        "wait": {"until": "exited", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    assert!(exited.state.as_ref().unwrap().stop_id.is_none());

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
    {
        let probe = gateway.dispatch(
            request(
                "cancelled-probe",
                Some(&close_session),
                "agent.probe",
                launched.revision,
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
        tokio::select! {
            response = &mut probe => panic!("probe completed before cancellation: {response:?}"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
        }
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
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
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
