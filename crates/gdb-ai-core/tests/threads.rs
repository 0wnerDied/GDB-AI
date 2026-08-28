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

fn successful(response: ApiResponse) -> ApiResponse {
    assert!(
        response.error.is_none(),
        "{} response error: {:?}; state: {:?}; result: {:?}",
        response.request_id,
        response.error,
        response.state,
        response.result
    );
    response
}

#[tokio::test]
async fn frame_handles_select_their_owning_thread() {
    if !support::require_commands(&["gdb", "cc"]) {
        return;
    }

    let directory = tempdir().unwrap();
    let executable = directory.path().join("threads");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/c/threads.c");
    assert!(
        Command::new("cc")
            .args(["-g", "-O0", "-pthread"])
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
    let caller = Caller::local("thread-test");

    let created = successful(
        gateway
            .dispatch(
                request("create", None, "session.create", None, json!({})),
                &caller,
            )
            .await,
    );
    let session = created.result.as_ref().unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let lease = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let launched = successful(
        gateway
            .dispatch(
                request(
                    "launch",
                    Some(&session),
                    "target.launch",
                    created.revision,
                    json!({
                        "program": executable,
                        "lease_id": lease,
                        "stop": "main",
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
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    let breakpoint = successful(
        gateway
            .dispatch(
                request(
                    "breakpoint",
                    Some(&session),
                    "breakpoint.create",
                    launched.revision,
                    json!({
                        "lease_id": lease,
                        "location": {"function": "worker"},
                        "temporary": true
                    }),
                ),
                &caller,
            )
            .await,
    );
    let stopped = successful(
        gateway
            .dispatch(
                request(
                    "continue",
                    Some(&session),
                    "execution.control",
                    breakpoint.revision,
                    json!({
                        "action": "continue",
                        "lease_id": lease,
                        "stop_id": first_stop,
                        "wait": {"until": "snapshot", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    let state = stopped.state.as_ref().unwrap();
    let stop = state.stop_id.as_ref().unwrap().0.clone();
    let stopped_thread = state.stopped_thread_id.as_ref().unwrap().0.clone();
    let stack = successful(
        gateway
            .dispatch(
                request(
                    "stack",
                    Some(&session),
                    "inspection.get",
                    None,
                    json!({"view": "stack", "stop_id": stop, "limit": 2}),
                ),
                &caller,
            )
            .await,
    );
    let frame = stack.result.as_ref().unwrap()["frames"][0]["frame_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(frame.starts_with(&format!("frm_{stopped_thread}_")));

    let other_thread = state
        .inferiors
        .values()
        .flat_map(|inferior| inferior.threads.values())
        .find(|thread| thread.id.0 != stopped_thread)
        .unwrap()
        .id
        .0
        .clone();
    let mismatch = gateway
        .dispatch(
            request(
                "mismatch",
                Some(&session),
                "inspection.get",
                None,
                json!({
                    "view": "frame",
                    "stop_id": stop,
                    "thread_id": other_thread,
                    "frame_id": frame
                }),
            ),
            &caller,
        )
        .await;
    assert_eq!(
        mismatch.error.unwrap().code,
        gdb_ai_core::ErrorCode::StaleContext
    );

    let restarted = successful(
        gateway
            .dispatch(
                request(
                    "restart",
                    Some(&session),
                    "target.restart",
                    mismatch.revision,
                    json!({
                        "lease_id": lease,
                        "stop": "main",
                        "wait": {"until": "snapshot", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    let restart_stop = restarted
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    let probe = successful(
        gateway
            .dispatch(
                request(
                    "probe",
                    Some(&session),
                    "agent.probe",
                    restarted.revision,
                    json!({
                        "lease_id": lease,
                        "stop_id": restart_stop,
                        "location": {"function": "worker"},
                        "capture": [{"stack": {"limit": 2}}],
                        "budget": {"wall_time_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    let probe_state = probe.state.as_ref().unwrap();
    let probe_thread = &probe_state.stopped_thread_id.as_ref().unwrap().0;
    let probe_frame = &probe.result.as_ref().unwrap()["captures"][0]["observation"]["observations"]
        [0]["stack"][0];
    assert_eq!(probe_frame["function"], "worker");
    assert!(
        probe_frame["frame_id"]
            .as_str()
            .unwrap()
            .starts_with(&format!("frm_{probe_thread}_"))
    );

    successful(
        gateway
            .dispatch(
                request(
                    "close",
                    Some(&session),
                    "session.close",
                    probe.revision,
                    json!({"lease_id": lease}),
                ),
                &caller,
            )
            .await,
    );
}
