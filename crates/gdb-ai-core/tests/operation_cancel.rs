use std::{path::PathBuf, process::Command, sync::Arc, time::Duration};

use gdb_ai_core::{
    ErrorCode,
    config::{ArtifactConfig, Config, PersistenceConfig},
    gateway::{Caller, Gateway, RequestOperationStatus},
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

async fn wait_running(gateway: &Gateway, caller: &Caller, session_id: &str) -> u64 {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status = gateway
                .dispatch(
                    request("status", Some(session_id), "session.get", None, json!({})),
                    caller,
                )
                .await;
            if let Some(state) = status.state
                && state
                    .inferiors
                    .values()
                    .any(|inferior| inferior.status == gdb_ai_core::domain::InferiorStatus::Running)
            {
                break state.revision;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn cancellation_stays_scoped_and_close_releases_the_session() {
    if !support::require_commands(&["gdb", "cc"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let executable = directory.path().join("io");
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
    config.server.max_sessions = 1;
    if let Some(path) = std::env::var_os("GDB_AI_GDB_PATH") {
        config.gdb.path = path.into();
    }
    let gateway = Arc::new(Gateway::new(config).unwrap());
    let caller = Caller::local("operation-cancel-test");
    let created = gateway
        .dispatch(
            request("create", None, "session.create", None, json!({})),
            &caller,
        )
        .await;
    assert!(created.error.is_none(), "{:?}", created.error);
    let session_id = created.session_id.unwrap();
    let lease_id = created.result.unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let launched = gateway
        .dispatch(
            request(
                "launch",
                Some(&session_id),
                "target.launch",
                created.revision,
                json!({
                    "program": executable,
                    "lease_id": lease_id,
                    "stop": "first_instruction",
                    "wait": {"until": "snapshot", "timeout_ms": 5000}
                }),
            ),
            &caller,
        )
        .await;
    assert!(launched.error.is_none(), "{:?}", launched.error);

    let run = |id: &str, revision| {
        request(
            id,
            Some(&session_id),
            "execution.control",
            Some(revision),
            json!({
                "action": "continue",
                "lease_id": lease_id,
                "wait": {"until": "exited", "timeout_ms": 500}
            }),
        )
    };
    let first = gateway
        .admit_operation(
            run("first", launched.revision.unwrap()),
            caller.clone(),
            None,
        )
        .await
        .unwrap();
    wait_running(&gateway, &caller, &session_id).await;
    let cancelled = gateway
        .dispatch(
            request(
                "cancel-first",
                None,
                "operation.cancel",
                None,
                json!({
                    "operation_id": first.operation_id,
                    "mode": "interrupt_target"
                }),
            ),
            &caller,
        )
        .await;
    assert!(cancelled.error.is_none(), "{:?}", cancelled.error);
    assert_eq!(
        gateway
            .wait_operation(&first.operation_id.0, &caller)
            .await
            .unwrap()
            .status,
        RequestOperationStatus::Aborted
    );

    let revision = gateway
        .dispatch(
            request("stopped", Some(&session_id), "session.get", None, json!({})),
            &caller,
        )
        .await
        .revision
        .unwrap();
    let second = gateway
        .admit_operation(run("second", revision), caller.clone(), None)
        .await
        .unwrap();
    wait_running(&gateway, &caller, &session_id).await;
    let stale = gateway
        .dispatch(
            request(
                "stale-cancel",
                None,
                "operation.cancel",
                None,
                json!({
                    "operation_id": first.operation_id,
                    "mode": "interrupt_target"
                }),
            ),
            &caller,
        )
        .await;
    assert_eq!(stale.error.unwrap().code, ErrorCode::Conflict);
    wait_running(&gateway, &caller, &session_id).await;

    let closed = gateway
        .dispatch(
            request(
                "cancel-second",
                None,
                "operation.cancel",
                None,
                json!({
                    "operation_id": second.operation_id,
                    "mode": "close_session"
                }),
            ),
            &caller,
        )
        .await;
    assert!(closed.error.is_none(), "{:?}", closed.error);
    assert_eq!(
        gateway
            .wait_operation(&second.operation_id.0, &caller)
            .await
            .unwrap()
            .status,
        RequestOperationStatus::Aborted
    );
    let already_closed = gateway
        .dispatch(
            request(
                "close-again",
                Some(&session_id),
                "session.close",
                None,
                json!({"lease_id": lease_id, "accept_latest_revision": true}),
            ),
            &caller,
        )
        .await;
    assert_eq!(already_closed.error.unwrap().code, ErrorCode::NotFound);
    let replacement = gateway
        .dispatch(
            request("replacement", None, "session.create", None, json!({})),
            &caller,
        )
        .await;
    assert!(replacement.error.is_none(), "{:?}", replacement.error);
    gateway.shutdown().await;
}
