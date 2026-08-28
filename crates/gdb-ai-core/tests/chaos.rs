use std::{path::PathBuf, process::Command, time::Duration};

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
        "response error: {:?}",
        response.error
    );
    response
}

#[tokio::test]
async fn noisy_pty_does_not_starve_mi_stop() {
    if !support::require_commands(&["gdb", "cc"]) {
        return;
    }

    let directory = tempdir().unwrap();
    let executable = directory.path().join("noisy");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/c/noisy.c");
    assert!(
        Command::new("cc")
            .args(["-g", "-O0"])
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
    config.limits.inferior_output_ring_bytes = 64 * 1024;
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("chaos-test");
    let created = successful(
        gateway
            .dispatch(
                request("create", None, "session.create", None, json!({})),
                &caller,
            )
            .await,
    );
    let session_id = created.session_id.as_deref().unwrap();
    let lease_id = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap();
    let launched = successful(
        gateway
            .dispatch(
                request(
                    "launch",
                    Some(session_id),
                    "target.launch",
                    created.revision,
                    json!({
                        "program": executable,
                        "lease_id": lease_id,
                        "stop": "main",
                        "wait": {"until": "snapshot", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    let breakpoint = successful(
        gateway
            .dispatch(
                request(
                    "breakpoint",
                    Some(session_id),
                    "breakpoint.create",
                    launched.revision,
                    json!({"lease_id": lease_id, "location": {"function": "marker"}}),
                ),
                &caller,
            )
            .await,
    );

    let started = std::time::Instant::now();
    let stopped = successful(
        gateway
            .dispatch(
                request(
                    "continue",
                    Some(session_id),
                    "execution.control",
                    breakpoint.revision,
                    json!({
                        "action": "continue",
                        "lease_id": lease_id,
                        "wait": {"until": "snapshot", "timeout_ms": 10000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(stopped.state.as_ref().unwrap().stop_id.is_some());

    let output = successful(
        gateway
            .dispatch(
                request(
                    "output",
                    Some(session_id),
                    "inferior_io.read",
                    None,
                    json!({"stream": "pty", "after_offset": 0, "max_bytes": 65536}),
                ),
                &caller,
            )
            .await,
    );
    assert_eq!(output.result.as_ref().unwrap()["gap"], true);
    assert!(
        output.result.as_ref().unwrap()["available_from"]
            .as_u64()
            .unwrap()
            > 0
    );
    gateway.shutdown().await;
}
