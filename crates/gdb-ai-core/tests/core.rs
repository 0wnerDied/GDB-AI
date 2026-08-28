use std::{path::PathBuf, process::Command};

use gdb_ai_core::{
    config::{ArtifactConfig, Config, PersistenceConfig},
    gateway::{Caller, Gateway},
    policy::Profile,
    protocol::{API_VERSION, ApiRequest},
};
use serde_json::{Value, json};
use tempfile::Builder;

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

#[tokio::test]
async fn opens_and_inspects_core_without_execution() {
    if Command::new("gdb").arg("--version").output().is_err()
        || Command::new("cc").arg("--version").output().is_err()
    {
        return;
    }
    let directory = Builder::new().prefix("gdb ai core ").tempdir().unwrap();
    let executable = directory.path().join("crash");
    let core = directory.path().join("crash.core");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/c/crash.c");
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
    let generated = Command::new("gdb")
        .args(["-q", "-nx", "-batch", "-ex", "run"])
        .arg("-ex")
        .arg(format!("generate-core-file {}", core.display()))
        .arg(&executable)
        .status()
        .unwrap();
    if !generated.success() || !core.is_file() {
        return;
    }

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
    config.security.default_profile = Profile::OfflineCore;
    config.security.workspace_roots = vec![directory.path().to_owned()];
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("core-test");
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
    let opened = gateway
        .dispatch(
            request(
                "open-core",
                Some(&session_id),
                "target.open_core",
                created.revision,
                json!({
                    "lease_id": lease_id,
                    "executable": executable,
                    "core": core
                }),
            ),
            &caller,
        )
        .await;
    assert!(opened.error.is_none(), "{:?}", opened.error);
    let stop_id = opened
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    let stack = gateway
        .dispatch(
            request(
                "stack",
                Some(&session_id),
                "inspection.get",
                None,
                json!({"view": "stack", "stop_id": stop_id, "limit": 8}),
            ),
            &caller,
        )
        .await;
    assert!(stack.error.is_none(), "{:?}", stack.error);
    gateway.shutdown().await;
}
