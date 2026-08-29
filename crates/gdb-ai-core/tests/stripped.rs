use std::{path::PathBuf, process::Command};

use gdb_ai_core::{
    ErrorCode,
    config::{ArtifactConfig, Config, PersistenceConfig},
    domain::SessionId,
    gateway::{Caller, Gateway},
    protocol::{API_VERSION, ApiRequest},
    replay::replay,
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

#[tokio::test]
async fn rebinds_module_offset_after_explicit_loader_exec() {
    if !support::require_commands(&["gdb", "cc", "nm", "readelf", "strip"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let executable = directory.path().join("stripped");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/c/vertical.c");
    assert!(
        Command::new("cc")
            .args(["-fPIE", "-pie", "-O2"])
            .arg(source)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    let symbols = Command::new("nm").arg(&executable).output().unwrap();
    assert!(symbols.status.success());
    let marker_offset = String::from_utf8(symbols.stdout)
        .unwrap()
        .lines()
        .find_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.get(1) == Some(&"t") && fields.get(2) == Some(&"marker"))
                .then(|| u64::from_str_radix(fields[0], 16).unwrap())
        })
        .unwrap();
    let headers = Command::new("readelf")
        .args(["-l"])
        .arg(&executable)
        .output()
        .unwrap();
    assert!(headers.status.success());
    let loader = String::from_utf8(headers.stdout)
        .unwrap()
        .lines()
        .find_map(|line| {
            line.split_once("Requesting program interpreter:")
                .map(|(_, path)| path.trim().trim_end_matches(']').to_owned())
        })
        .map(std::fs::canonicalize)
        .unwrap()
        .unwrap();
    assert!(
        Command::new("strip")
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
    config.security.workspace_roots = vec![
        directory.path().to_owned(),
        loader.parent().unwrap().to_owned(),
    ];
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("stripped-test");
    let created = gateway
        .dispatch(
            request("create", None, "session.create", None, json!({})),
            &caller,
        )
        .await;
    assert!(created.error.is_none(), "{:?}", created.error);
    let session_id = created.session_id.clone().unwrap();
    let lease_id = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap();
    let launched = gateway
        .dispatch(
            request(
                "launch",
                Some(&session_id),
                "target.launch",
                created.revision,
                json!({
                    "lease_id": lease_id,
                    "program": loader,
                    "argv": [executable],
                    "cwd": directory.path(),
                    "stop": "first_instruction",
                    "wait": {"until": "snapshot", "timeout_ms": 5000}
                }),
            ),
            &caller,
        )
        .await;
    assert!(launched.error.is_none(), "{:?}", launched.error);
    let state = launched.state.as_ref().unwrap();
    let stop_id = state.stop_id.as_ref().unwrap().clone();
    let unresolved_probe = gateway
        .dispatch(
            request(
                "unresolved-probe",
                Some(&session_id),
                "agent.probe",
                launched.revision,
                json!({
                    "lease_id": lease_id,
                    "stop_id": stop_id,
                    "module_offset": {
                        "module": "stripped",
                        "offset": format!("0x{marker_offset:x}")
                    }
                }),
            ),
            &caller,
        )
        .await;
    assert_eq!(
        unresolved_probe.error.unwrap().code,
        ErrorCode::InvalidState
    );
    let breakpoint = gateway
        .dispatch(
            request(
                "module-offset-breakpoint",
                Some(&session_id),
                "breakpoint.create",
                launched.revision,
                json!({
                    "lease_id": lease_id,
                    "module_offset": {
                        "module": "stripped",
                        "offset": format!("0x{marker_offset:x}")
                    }
                }),
            ),
            &caller,
        )
        .await;
    assert!(breakpoint.error.is_none(), "{:?}", breakpoint.error);
    let pending = breakpoint.result.as_ref().unwrap()["breakpoints"]
        .as_object()
        .unwrap()
        .values()
        .find(|breakpoint| breakpoint["pending"] == true)
        .unwrap();
    let public_id = pending["id"].as_str().unwrap().to_owned();
    let stopped = gateway
        .dispatch(
            request(
                "continue-to-module-offset",
                Some(&session_id),
                "execution.control",
                breakpoint.revision,
                json!({
                    "action": "continue",
                    "lease_id": lease_id,
                    "stop_id": stop_id,
                    "wait": {"until": "snapshot", "timeout_ms": 5000}
                }),
            ),
            &caller,
        )
        .await;
    assert!(stopped.error.is_none(), "{:?}", stopped.error);
    let state = stopped.state.as_ref().unwrap();
    let rebound = state
        .breakpoints
        .values()
        .find(|breakpoint| breakpoint.id.0 == public_id)
        .unwrap();
    assert!(!rebound.pending);
    // 2026-08-29: GDB may omit the optional frame from an async stop record.
    // Query the stopped frame explicitly before comparing the rebound PC.
    let frame = gateway
        .dispatch(
            request(
                "rebound-frame",
                Some(&session_id),
                "inspection.get",
                None,
                json!({
                    "view": "frame",
                    "stop_id": state.stop_id.as_ref().unwrap()
                }),
            ),
            &caller,
        )
        .await;
    assert!(frame.error.is_none(), "{:?}", frame.error);
    let pc = frame.result.as_ref().unwrap()["frame"]["address"]
        .as_str()
        .unwrap();
    assert_eq!(rebound.locations[0].address.as_deref(), Some(pc));
    gateway.shutdown().await;
    let replayed = replay(
        directory
            .path()
            .join("sessions")
            .join(&session_id)
            .join("journal.jsonl"),
        SessionId(session_id),
    )
    .unwrap();
    assert!(
        replayed
            .state
            .breakpoints
            .values()
            .any(|breakpoint| breakpoint.id.0 == public_id && !breakpoint.pending)
    );
}
