use std::{path::PathBuf, process::Command};

use gdb_ai_core::{
    config::{ArtifactConfig, Config, PersistenceConfig},
    gateway::{Caller, Gateway},
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

fn stop_id(response: &ApiResponse) -> String {
    response
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone()
}

#[tokio::test]
async fn probe_and_experiment_capture_and_clean_up() {
    if !support::require_commands(&["gdb", "cc"]) {
        return;
    }

    let directory = tempdir().unwrap();
    let executable = directory.path().join("agent-semantics");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/c/vertical.c");
    assert!(
        Command::new("cc")
            .args([
                "-g",
                "-O0",
                "-fno-omit-frame-pointer",
                "-DGDB_AI_REPEAT_MARKER",
            ])
            .arg(source)
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
    config.security.workspace_roots = vec![directory.path().to_owned()];
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("agent-semantics-test");

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
                "stop": "first_instruction"
            }),
        ),
    )
    .await;

    let probe = call(
        &gateway,
        &caller,
        request(
            "probe",
            Some(&session_id),
            "agent.probe",
            launched.revision,
            json!({
                "lease_id": lease_id,
                "stop_id": stop_id(&launched),
                "location": {"function": "marker"},
                "ignore_count": 1,
                "input": {"text": "x"},
                "capture": [
                    {"expression": "global_value"},
                    {"memory": {"address_expression": "&global_value", "length": 4}}
                ],
                "budget": {
                    "max_calls": 8,
                    "max_values": 3,
                    "wall_time_ms": 5000
                }
            }),
        ),
    )
    .await;
    assert_eq!(probe.result.as_ref().unwrap()["capture_count"], 1);
    assert_eq!(
        probe.result.as_ref().unwrap()["operation"]["kind"],
        "agent.probe"
    );
    assert_eq!(
        probe.result.as_ref().unwrap()["captures"][0]["observation"]["observations"][0]["value"],
        "8"
    );
    assert_eq!(
        probe.result.as_ref().unwrap()["captures"][0]["observation"]["observations"][1]["memory"]["hex"],
        "08000000"
    );

    let exited = call(
        &gateway,
        &caller,
        request(
            "continue-after-probe",
            Some(&session_id),
            "execution.control",
            probe.revision,
            json!({
                "action": "continue",
                "lease_id": lease_id,
                "stop_id": stop_id(&probe),
                "wait": {"until": "exited", "timeout_ms": 5000}
            }),
        ),
    )
    .await;
    assert!(
        exited.result.as_ref().unwrap()["output"]["text"]
            .as_str()
            .unwrap()
            .contains("input received: x")
    );

    let restarted = call(
        &gateway,
        &caller,
        request(
            "restart",
            Some(&session_id),
            "target.restart",
            exited.revision,
            json!({
                "lease_id": lease_id,
                "stop": "first_instruction"
            }),
        ),
    )
    .await;
    let experiment = call(
        &gateway,
        &caller,
        request(
            "experiment",
            Some(&session_id),
            "agent.experiment",
            restarted.revision,
            json!({
                "lease_id": lease_id,
                "stop_id": stop_id(&restarted),
                "location": {"function": "marker"},
                "capture": [
                    {"expression": "global_value"},
                    {"stack": {"limit": 2}}
                ],
                "budget": {
                    "max_calls": 8,
                    "max_frames": 2,
                    "max_values": 2,
                    "wall_time_ms": 5000
                }
            }),
        ),
    )
    .await;
    assert_eq!(experiment.result.as_ref().unwrap()["capture_count"], 1);
    assert_eq!(
        experiment.result.as_ref().unwrap()["operation"]["kind"],
        "agent.experiment"
    );
    assert_eq!(
        experiment.result.as_ref().unwrap()["captures"][0]["observation"]["observations"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );

    let breakpoints = call(
        &gateway,
        &caller,
        request(
            "breakpoints",
            Some(&session_id),
            "breakpoint.list",
            None,
            json!({}),
        ),
    )
    .await;
    assert!(
        breakpoints.result.unwrap()["breakpoints"]
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
    );
    call(
        &gateway,
        &caller,
        request(
            "close",
            Some(&session_id),
            "session.close",
            breakpoints.revision,
            json!({"lease_id": lease_id}),
        ),
    )
    .await;
}
