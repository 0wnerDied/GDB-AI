use std::{net::TcpListener, path::PathBuf, process::Command, time::Duration};

use gdb_ai_core::{
    config::{ArtifactConfig, Config, PersistenceConfig},
    gateway::{Caller, Gateway},
    policy::Profile,
    protocol::{API_VERSION, ApiRequest},
};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::sync::Mutex;

mod support;

// 2026-08-29: The tests release their ephemeral port before gdbserver binds
// it, so parallel fixtures could select the same port and strand one client.
static GDBSERVER_TEST_LOCK: Mutex<()> = Mutex::const_new(());

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
async fn connects_to_allowlisted_gdbserver() {
    if !support::require_commands(&["gdbserver", "gdb", "cc"]) {
        return;
    }
    let _server_guard = GDBSERVER_TEST_LOCK.lock().await;
    let directory = tempdir().unwrap();
    let executable = directory.path().join("remote");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/c/vertical.c");
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
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = probe.local_addr().unwrap().to_string();
    drop(probe);
    let mut server = Command::new("gdbserver")
        .args(["--once", &endpoint])
        .arg(&executable)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

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
    config.security.default_profile = Profile::RawAdmin;
    config.security.workspace_roots = vec![directory.path().to_owned()];
    config.security.remote_allowlist = vec![endpoint.clone()];
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller {
        identity: "remote-test".into(),
        admin: true,
    };
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
    let connected = gateway
        .dispatch(
            request(
                "connect",
                Some(&session_id),
                "target.connect_remote",
                created.revision,
                json!({
                    "lease_id": lease_id,
                    "mode": "remote",
                    "endpoint": endpoint,
                    "executable": executable,
                    "wait": {"until": "snapshot", "timeout_ms": 5000}
                }),
            ),
            &caller,
        )
        .await;
    assert!(connected.error.is_none(), "{:?}", connected.error);
    assert!(connected.state.as_ref().unwrap().stop_id.is_some());
    let symbols = gateway
        .dispatch(
            request(
                "relative-symbols",
                Some(&session_id),
                "raw.console",
                None,
                json!({
                    "accept_latest_revision": true,
                    "lease_id": lease_id,
                    "command": "add-symbol-file ./remote 0"
                }),
            ),
            &caller,
        )
        .await;
    assert!(symbols.error.is_none(), "{:?}", symbols.error);
    let mappings = gateway
        .dispatch(
            request(
                "mappings",
                Some(&session_id),
                "inspection.get",
                None,
                json!({"view": "mappings"}),
            ),
            &caller,
        )
        .await;
    assert!(mappings.error.is_none(), "{:?}", mappings.error);
    assert_eq!(mappings.result.unwrap()["partial"], true);
    gateway.shutdown().await;
    let _ = server.kill();
    let _ = server.wait();
}

#[tokio::test]
async fn default_remote_connection_invalidates_state_on_disconnect() {
    if !support::require_commands(&["gdb", "gdbserver", "cc"]) {
        return;
    }
    let _server_guard = GDBSERVER_TEST_LOCK.lock().await;
    let directory = tempdir().unwrap();
    let executable = directory.path().join("remote-disconnect");
    // 2026-08-29: Remote inferiors do not use GDB's local PTY, so the old
    // getchar fixture could consume CI stdin EOF and exit before disconnect.
    // Keep this target alive until the test kills gdbserver.
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
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = probe.local_addr().unwrap().to_string();
    drop(probe);
    let mut server = Command::new("gdbserver")
        .args(["--once", &endpoint])
        .arg(&executable)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

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
    // 2026-08-29: Loaded CI runners can deliver GDB's disconnect notification
    // after five seconds, so observe it for the configured command deadline.
    let disconnect_timeout = config.server.command_timeout();
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller {
        identity: "disconnect-test".into(),
        admin: false,
    };
    let created = gateway
        .dispatch(
            request("create", None, "session.create", None, json!({})),
            &caller,
        )
        .await;
    assert!(created.error.is_none(), "{:?}", created.error);
    let session_id = created.session_id.as_deref().unwrap();
    let lease_id = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap();
    let connected = gateway
        .dispatch(
            request(
                "connect",
                Some(session_id),
                "target.connect_remote",
                created.revision,
                json!({
                    "lease_id": lease_id,
                    "mode": "remote",
                    "endpoint": endpoint,
                    "executable": executable,
                    "wait": {"until": "snapshot", "timeout_ms": 5000}
                }),
            ),
            &caller,
        )
        .await;
    assert!(connected.error.is_none(), "{:?}", connected.error);
    let continued = gateway
        .dispatch(
            request(
                "continue",
                Some(session_id),
                "execution.control",
                None,
                json!({
                    "action": "continue",
                    "lease_id": lease_id,
                    "accept_latest_revision": true,
                    "wait": {"until": "running", "timeout_ms": 5000}
                }),
            ),
            &caller,
        )
        .await;
    assert!(continued.error.is_none(), "{:?}", continued.error);

    server.kill().unwrap();
    server.wait().unwrap();
    tokio::time::timeout(disconnect_timeout, async {
        loop {
            let state = gateway
                .dispatch(
                    request("status", Some(session_id), "session.get", None, json!({})),
                    &caller,
                )
                .await;
            assert!(state.error.is_none(), "{:?}", state.error);
            let disconnected = state.result.as_ref().unwrap()["inferiors"]
                .as_object()
                .unwrap()
                .values()
                .all(|inferior| inferior["status"] == "DISCONNECTED");
            if disconnected {
                assert!(state.result.as_ref().unwrap()["stop_id"].is_null());
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("remote disconnect did not invalidate target state");
    gateway.shutdown().await;
}
