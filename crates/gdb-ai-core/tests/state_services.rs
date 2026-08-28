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

async fn call(gateway: &Gateway, caller: &Caller, request: ApiRequest) -> ApiResponse {
    let response = gateway.dispatch(request, caller).await;
    assert!(
        response.error.is_none(),
        "response error: {:?}",
        response.error
    );
    response
}

#[tokio::test]
async fn tracked_state_lifecycle_round_trips() {
    if !support::require_commands(&["gdb", "cc"]) {
        return;
    }

    let directory = tempdir().unwrap();
    let executable = directory.path().join("state-services");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/c/vertical.c");
    assert!(
        Command::new("cc")
            .args(["-g", "-O0", "-fno-omit-frame-pointer"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );

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
    config.security.default_profile = Profile::LabMutation;
    config.security.workspace_roots = vec![
        directory.path().to_owned(),
        source.parent().unwrap().to_owned(),
    ];
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("state-services-test");

    let created = call(
        &gateway,
        &caller,
        request("create", None, "session.create", None, json!({})),
    )
    .await;
    let session_id = created.session_id.as_ref().unwrap().clone();
    let lease_id = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let launched = call(
        &gateway,
        &caller,
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
    )
    .await;
    let first_stop = launched
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();

    let marker = call(
        &gateway,
        &caller,
        request(
            "marker-breakpoint",
            Some(&session_id),
            "breakpoint.create",
            launched.revision,
            json!({"lease_id": lease_id, "location": {"function": "marker"}}),
        ),
    )
    .await;
    let marker_id = marker.result.as_ref().unwrap()["breakpoints"]
        .as_object()
        .and_then(|breakpoints| breakpoints.values().next())
        .and_then(|breakpoint| breakpoint["id"].as_str())
        .unwrap()
        .to_owned();
    let after_marker = call(
        &gateway,
        &caller,
        request(
            "after-marker-breakpoint",
            Some(&session_id),
            "breakpoint.create",
            marker.revision,
            json!({
                "lease_id": lease_id,
                "location": {"source": {"path": source, "line": 19}}
            }),
        ),
    )
    .await;
    let stopped = call(
        &gateway,
        &caller,
        request(
            "continue-to-marker",
            Some(&session_id),
            "execution.control",
            after_marker.revision,
            json!({
                "action": "continue",
                "lease_id": lease_id,
                "stop_id": first_stop,
                "wait": {"until": "snapshot", "timeout_ms": 5000}
            }),
        ),
    )
    .await;
    let marker_stop = stopped
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();

    let expression = call(
        &gateway,
        &caller,
        request(
            "track-expression",
            Some(&session_id),
            "tracking.add_expression",
            stopped.revision,
            json!({"lease_id": lease_id, "expression": "global_value"}),
        ),
    )
    .await;
    let expression_id = expression.result.as_ref().unwrap()["tracking_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let memory = call(
        &gateway,
        &caller,
        request(
            "track-memory",
            Some(&session_id),
            "tracking.add_memory",
            expression.revision,
            json!({
                "lease_id": lease_id,
                "address_expression": "&global_value",
                "length": 4,
                "max_history": 2
            }),
        ),
    )
    .await;
    let memory_id = memory.result.as_ref().unwrap()["tracking_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let listed = call(
        &gateway,
        &caller,
        request(
            "tracking-list",
            Some(&session_id),
            "tracking.list",
            None,
            json!({}),
        ),
    )
    .await;
    assert_eq!(listed.result.unwrap().as_array().map(Vec::len), Some(2));

    let value = call(
        &gateway,
        &caller,
        request(
            "value-create",
            Some(&session_id),
            "value.create",
            memory.revision,
            json!({
                "lease_id": lease_id,
                "expression": "global_pair",
                "stop_id": marker_stop
            }),
        ),
    )
    .await;
    let value_id = value.result.as_ref().unwrap()["value_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let released = call(
        &gateway,
        &caller,
        request(
            "value-release",
            Some(&session_id),
            "value.release",
            value.revision,
            json!({
                "lease_id": lease_id,
                "value_id": value_id,
                "stop_id": marker_stop
            }),
        ),
    )
    .await;
    assert_eq!(released.result.as_ref().unwrap()["released"], value_id);

    let before = call(
        &gateway,
        &caller,
        request(
            "before-snapshot",
            Some(&session_id),
            "inspection.snapshot",
            None,
            json!({"profile": "brief", "stop_id": marker_stop}),
        ),
    )
    .await;
    let before_id = before.result.as_ref().unwrap()["snapshot_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        before.result.as_ref().unwrap()["tracked"]
            .as_object()
            .map(serde_json::Map::len),
        Some(2)
    );

    let input = call(
        &gateway,
        &caller,
        request(
            "input",
            Some(&session_id),
            "inferior_io.write",
            before.revision,
            json!({"lease_id": lease_id, "text": "x\n"}),
        ),
    )
    .await;
    let legacy_eof = call(
        &gateway,
        &caller,
        request(
            "legacy-eof",
            Some(&session_id),
            "inferior_io.close_stdin",
            input.revision,
            json!({"lease_id": lease_id}),
        ),
    )
    .await;
    assert_eq!(
        legacy_eof.result.as_ref().unwrap(),
        &json!({"sent": true, "closed": false, "mechanism": "pty_veof"})
    );
    let next_stop = call(
        &gateway,
        &caller,
        request(
            "continue-after-marker",
            Some(&session_id),
            "execution.control",
            legacy_eof.revision,
            json!({
                "action": "continue",
                "lease_id": lease_id,
                "stop_id": marker_stop,
                "wait": {"until": "snapshot", "timeout_ms": 5000}
            }),
        ),
    )
    .await;
    let next_stop_id = next_stop
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    let after = call(
        &gateway,
        &caller,
        request(
            "after-snapshot",
            Some(&session_id),
            "inspection.snapshot",
            None,
            json!({"profile": "brief", "stop_id": next_stop_id}),
        ),
    )
    .await;
    let after_id = after.result.as_ref().unwrap()["snapshot_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let diff = call(
        &gateway,
        &caller,
        request(
            "snapshot-diff",
            Some(&session_id),
            "inspection.diff",
            None,
            json!({
                "before_snapshot_id": before_id,
                "after_snapshot_id": after_id
            }),
        ),
    )
    .await;
    assert!(diff.result.unwrap()["changes"].get("tracked").is_some());

    let removed_expression = call(
        &gateway,
        &caller,
        request(
            "remove-expression",
            Some(&session_id),
            "tracking.remove",
            after.revision,
            json!({"lease_id": lease_id, "tracking_id": expression_id}),
        ),
    )
    .await;
    let removed_memory = call(
        &gateway,
        &caller,
        request(
            "remove-memory",
            Some(&session_id),
            "tracking.remove",
            removed_expression.revision,
            json!({"lease_id": lease_id, "tracking_id": memory_id}),
        ),
    )
    .await;
    let listed = call(
        &gateway,
        &caller,
        request(
            "tracking-list-empty",
            Some(&session_id),
            "tracking.list",
            None,
            json!({}),
        ),
    )
    .await;
    assert!(listed.result.unwrap().as_array().unwrap().is_empty());

    let deleted = call(
        &gateway,
        &caller,
        request(
            "delete-breakpoint",
            Some(&session_id),
            "breakpoint.delete",
            removed_memory.revision,
            json!({"lease_id": lease_id, "breakpoint_id": marker_id}),
        ),
    )
    .await;
    assert_eq!(
        deleted.result.as_ref().unwrap()["breakpoints"]
            .as_object()
            .map(serde_json::Map::len),
        Some(1)
    );
    let killed = call(
        &gateway,
        &caller,
        request(
            "kill",
            Some(&session_id),
            "target.kill",
            deleted.revision,
            json!({
                "lease_id": lease_id,
                "wait": {"until": "exited", "timeout_ms": 5000}
            }),
        ),
    )
    .await;
    assert!(killed.state.as_ref().unwrap().stop_id.is_none());
    call(
        &gateway,
        &caller,
        request(
            "close",
            Some(&session_id),
            "session.close",
            killed.revision,
            json!({"lease_id": lease_id}),
        ),
    )
    .await;
}
