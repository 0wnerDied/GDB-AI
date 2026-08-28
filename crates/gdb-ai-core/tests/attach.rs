use std::{path::PathBuf, process::Command};

use gdb_ai_core::{
    config::{ArtifactConfig, Config, PersistenceConfig, SandboxMode},
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
async fn attaches_and_detaches_allowlisted_process() {
    if !support::require_commands(&["gdb", "cc"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let executable = directory.path().join("attach");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/c/attach.c");
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
    let mut target = Command::new(&executable).spawn().unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let pid = u64::from(target.id());

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
    config.security.attach_allowlist = vec![pid];
    config.security.sandbox = SandboxMode::Disabled;
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("attach-test");
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
    let attached = gateway
        .dispatch(
            request(
                "attach",
                Some(&session_id),
                "target.attach",
                created.revision,
                json!({"lease_id": lease_id, "pid": pid}),
            ),
            &caller,
        )
        .await;
    assert!(attached.error.is_none(), "{:?}", attached.error);
    assert!(attached.state.as_ref().unwrap().stop_id.is_some());
    let detached = gateway
        .dispatch(
            request(
                "detach",
                Some(&session_id),
                "target.detach",
                attached.revision,
                json!({"lease_id": lease_id}),
            ),
            &caller,
        )
        .await;
    assert!(detached.error.is_none(), "{:?}", detached.error);
    gateway.shutdown().await;
    let _ = target.kill();
    let _ = target.wait();
}
