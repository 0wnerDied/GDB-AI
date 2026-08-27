use std::{path::PathBuf, process::Command};

use gdb_ai_core::{
    config::{ArtifactConfig, Config, PersistenceConfig},
    gateway::{Caller, Gateway},
    protocol::{API_VERSION, ApiRequest, ApiResponse},
};
use serde_json::{Value, json};
use tempfile::tempdir;

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
        method: method.into(),
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
    if Command::new("gdb").arg("--version").output().is_err()
        || Command::new("cc").arg("--version").output().is_err()
    {
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
                        "cwd": directory.path(),
                        "stop": "entry",
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

    let breakpoint = successful(
        gateway
            .dispatch(
                request(
                    "breakpoint",
                    Some(&session_id),
                    "breakpoint.create",
                    launched.revision,
                    json!({"location": {"function": "marker"}}),
                ),
                &caller,
            )
            .await,
    );
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
    assert_ne!(first_stop, second_stop);

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

    successful(
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

    let resume = gateway.dispatch(
        request(
            "resume-to-input",
            Some(&session_id),
            "execution.control",
            continued.revision,
            json!({
                "action": "continue",
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

    successful(
        gateway
            .dispatch(
                request(
                    "close",
                    Some(&session_id),
                    "session.close",
                    interrupted.revision,
                    json!({}),
                ),
                &caller,
            )
            .await,
    );
}
