use std::{path::PathBuf, process::Command};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use gdb_ai_core::{
    ErrorCode,
    config::{ArtifactConfig, Config, OutputEvidenceMode, PersistenceConfig},
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
    assert!(response.error.is_none(), "{:?}", response.error);
    response
}

#[tokio::test]
async fn preserves_binary_pty_input_and_eof_in_an_owned_artifact() {
    if !support::require_commands(&["gdb", "cc"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let executable = directory.path().join("output-target");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/c/io.c");
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
    config.security.default_profile = Profile::LabMutation;
    config.output.evidence = OutputEvidenceMode::Artifact;
    config.output.max_bytes = 1024 * 1024;
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("output-evidence-test");

    let created = successful(
        gateway
            .dispatch(
                request("create", None, "session.create", None, json!({})),
                &caller,
            )
            .await,
    );
    let session_id = created.session_id.clone().unwrap();
    let lease = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap();
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
                        "lease_id": lease,
                        "stop": "none",
                        "wait": {"until": "running", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    let running_eof = gateway
        .dispatch(
            request(
                "running-eof",
                Some(&session_id),
                "inferior_io.send_eof",
                launched.revision,
                json!({"lease_id": lease}),
            ),
            &caller,
        )
        .await;
    assert_eq!(running_eof.error.unwrap().code, ErrorCode::TargetRunning);
    let interrupted = successful(
        gateway
            .dispatch(
                request(
                    "interrupt",
                    Some(&session_id),
                    "execution.control",
                    running_eof.revision,
                    json!({
                        "action": "interrupt",
                        "lease_id": lease,
                        "wait": {"until": "snapshot", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    let stop_id = interrupted
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    let input = successful(
        gateway
            .dispatch(
                request(
                    "input",
                    Some(&session_id),
                    "inferior_io.write",
                    interrupted.revision,
                    json!({"lease_id": lease, "data_base64": "E0FCQw=="}),
                ),
                &caller,
            )
            .await,
    );
    let eof = successful(
        gateway
            .dispatch(
                request(
                    "eof",
                    Some(&session_id),
                    "inferior_io.send_eof",
                    input.revision,
                    json!({"lease_id": lease}),
                ),
                &caller,
            )
            .await,
    );
    let exited = successful(
        gateway
            .dispatch(
                request(
                    "run",
                    Some(&session_id),
                    "execution.control",
                    eof.revision,
                    json!({
                        "action": "continue",
                        "lease_id": lease,
                        "stop_id": stop_id,
                        "wait": {"until": "exited", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    let closed = successful(
        gateway
            .dispatch(
                request(
                    "close",
                    Some(&session_id),
                    "session.close",
                    exited.revision,
                    json!({"lease_id": lease}),
                ),
                &caller,
            )
            .await,
    );
    let evidence = &closed.result.as_ref().unwrap()["inferior_output_evidence"];
    assert_eq!(evidence["durability"], "artifact");
    assert_eq!(evidence["complete"], true);
    let uri = evidence["artifact_uri"].as_str().unwrap();
    let artifact = successful(
        gateway
            .dispatch(
                request("artifact", None, "artifact.get", None, json!({"uri": uri})),
                &caller,
            )
            .await,
    );
    let artifact = artifact.result.unwrap();
    let bytes = BASE64
        .decode(artifact["data_base64"].as_str().unwrap())
        .unwrap();
    assert!(bytes.windows(4).any(|window| window == b"\x13ABC"));
    assert!(bytes.windows(4).any(|window| window == b"EOF\n"));
}
