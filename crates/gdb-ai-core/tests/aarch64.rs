use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use gdb_ai_core::{
    config::{ArtifactConfig, Config, PersistenceConfig},
    gateway::{Caller, Gateway},
    policy::Profile,
    protocol::{API_VERSION, ApiRequest, ApiResponse},
};
use serde_json::{Value, json};
use tempfile::tempdir;

mod support;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

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

async fn call(gateway: &Gateway, caller: &Caller, request: ApiRequest) -> ApiResponse {
    let response = gateway.dispatch(request, caller).await;
    assert!(
        response.error.is_none(),
        "response error: {:?}",
        response.error
    );
    response
}

#[tokio::test]
async fn debugs_aarch64_over_qemu_rsp() {
    if !support::require_commands(&["aarch64-linux-gnu-gcc", "gdb-multiarch", "qemu-aarch64"]) {
        return;
    }

    let directory = tempdir().unwrap();
    let executable = directory.path().join("vertical-aarch64");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/c/vertical.c");
    assert!(
        Command::new("aarch64-linux-gnu-gcc")
            .args(["-g", "-O0", "-static"])
            .arg(source)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = format!("127.0.0.1:{port}");
    drop(listener);
    let _qemu = ChildGuard(
        Command::new("qemu-aarch64")
            .args(["-g", &port.to_string()])
            .arg(&executable)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
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
    config.gdb.path = "gdb-multiarch".into();
    config.security.default_profile = Profile::RawAdmin;
    config.security.workspace_roots = vec![directory.path().to_owned()];
    config.security.remote_allowlist = vec![endpoint.clone()];
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller {
        identity: "aarch64-test".into(),
        admin: true,
    };

    let created = call(
        &gateway,
        &caller,
        request("create", None, "session.create", None, json!({})),
    )
    .await;
    let session_id = created.session_id.as_ref().unwrap().clone();
    let lease_id = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let connected = call(
        &gateway,
        &caller,
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
                "wait": {"until": "snapshot", "timeout_ms": 10000}
            }),
        ),
    )
    .await;
    let first_stop = connected
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();

    let breakpoint = call(
        &gateway,
        &caller,
        request(
            "breakpoint",
            Some(&session_id),
            "breakpoint.create",
            connected.revision,
            json!({"lease_id": lease_id, "location": {"function": "marker"}}),
        ),
    )
    .await;
    let stopped = call(
        &gateway,
        &caller,
        request(
            "continue",
            Some(&session_id),
            "execution.control",
            breakpoint.revision,
            json!({
                "action": "continue",
                "lease_id": lease_id,
                "stop_id": first_stop,
                "wait": {"until": "snapshot", "timeout_ms": 10000}
            }),
        ),
    )
    .await;
    let stop_id = stopped
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    assert_ne!(stop_id, first_stop);

    let registers = call(
        &gateway,
        &caller,
        request(
            "registers",
            Some(&session_id),
            "register.read",
            None,
            json!({
                "roles": ["pc", "sp", "fp", "return", "argument_0"],
                "stop_id": stop_id
            }),
        ),
    )
    .await;
    let result = registers.result.as_ref().unwrap();
    assert_eq!(result["architecture"], "aarch64");
    for role in ["pc", "sp", "fp", "return", "argument_0"] {
        assert!(result["roles"][role].as_str().is_some(), "missing {role}");
    }

    let disassembly = call(
        &gateway,
        &caller,
        request(
            "disassembly",
            Some(&session_id),
            "disassembly.read",
            None,
            json!({
                "around": {
                    "expression": "$pc",
                    "before_instructions": 2,
                    "after_instructions": 4
                },
                "include_source": false,
                "stop_id": stop_id
            }),
        ),
    )
    .await;
    let result = disassembly.result.as_ref().unwrap();
    assert!(
        result["architecture"].as_str().unwrap().contains("aarch64"),
        "unexpected disassembly architecture: {}",
        result["architecture"]
    );
    assert!(!result["instructions"].as_array().unwrap().is_empty());

    gateway.shutdown().await;
}
