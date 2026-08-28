use std::{path::PathBuf, process::Command};

use gdb_ai_core::{
    config::{ArtifactConfig, Config, PersistenceConfig},
    gateway::{Caller, Gateway},
    protocol::{API_VERSION, ApiRequest},
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
async fn stops_at_the_first_instruction_without_symbols() {
    if !support::require_commands(&["gdb", "cc"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let executable = directory.path().join("stripped");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/c/vertical.c");
    assert!(
        Command::new("cc")
            .args(["-s", "-O2"])
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
                    "program": executable,
                    "stop": "first_instruction",
                    "wait": {"until": "snapshot", "timeout_ms": 5000}
                }),
            ),
            &caller,
        )
        .await;
    assert!(launched.error.is_none(), "{:?}", launched.error);
    let state = launched.state.as_ref().unwrap();
    let stop_id = state.stop_id.as_ref().unwrap();
    let pc = state
        .inferiors
        .values()
        .flat_map(|inferior| inferior.threads.values())
        .find_map(|thread| thread.frame.as_ref()?.address.as_deref())
        .map(|address| u64::from_str_radix(address.trim_start_matches("0x"), 16).unwrap())
        .unwrap();
    let mappings = gateway
        .dispatch(
            request(
                "mappings",
                Some(&session_id),
                "inspection.get",
                None,
                json!({"view": "mappings", "stop_id": stop_id}),
            ),
            &caller,
        )
        .await;
    assert!(mappings.error.is_none(), "{:?}", mappings.error);
    let base = mappings.result.as_ref().unwrap()["mappings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|mapping| mapping["path"] == executable.to_string_lossy().as_ref())
        .map(|mapping| {
            let start = u64::from_str_radix(
                mapping["start"].as_str().unwrap().trim_start_matches("0x"),
                16,
            )
            .unwrap();
            let offset = u64::from_str_radix(
                mapping["offset"].as_str().unwrap().trim_start_matches("0x"),
                16,
            )
            .unwrap();
            start - offset
        })
        .unwrap();
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
                        "offset": format!("0x{:x}", pc - base)
                    }
                }),
            ),
            &caller,
        )
        .await;
    assert!(breakpoint.error.is_none(), "{:?}", breakpoint.error);
    assert!(
        breakpoint.result.as_ref().unwrap()["breakpoints"]
            .as_object()
            .unwrap()
            .values()
            .any(|breakpoint| {
                !breakpoint["pending"].as_bool().unwrap()
                    && breakpoint["locations"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|location| location["address"] == format!("0x{pc:016x}"))
            })
    );
    gateway.shutdown().await;
}
