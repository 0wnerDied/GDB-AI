use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use gdb_ai_core::{
    config::{ArtifactConfig, Config, PersistenceConfig},
    domain::Consistency,
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

fn kernel_artifacts() -> Option<(PathBuf, PathBuf)> {
    let image = std::env::var_os("GDB_AI_KERNEL_IMAGE").map(PathBuf::from);
    let symbols = std::env::var_os("GDB_AI_KERNEL_VMLINUX").map(PathBuf::from);
    if let (Some(image), Some(symbols)) = (image, symbols)
        && image.is_file()
        && symbols.is_file()
    {
        return Some((image, symbols));
    }
    if std::env::var_os("GDB_AI_REQUIRE_KERNEL_INTEGRATION").is_some() {
        panic!("GDB_AI_KERNEL_IMAGE and GDB_AI_KERNEL_VMLINUX must name files");
    }
    eprintln!("skipped kernel integration; Debian kernel artifacts are not configured");
    None
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
async fn inspects_a_public_debian_kernel_over_qemu_rsp() {
    let Some((kernel_image, vmlinux)) = kernel_artifacts() else {
        return;
    };
    if !support::require_commands(&["gdb", "qemu-system-x86_64"]) {
        return;
    }

    let directory = tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    drop(listener);
    let _qemu = ChildGuard(
        Command::new("qemu-system-x86_64")
            .args(["-accel", "tcg", "-m", "512M", "-smp", "1", "-S"])
            .arg("-kernel")
            .arg(&kernel_image)
            .args(["-append", "console=ttyS0 nokaslr", "-gdb"])
            .arg(format!("tcp:{endpoint}"))
            .args(["-display", "none", "-serial", "none", "-monitor", "none"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

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
    config.security.workspace_roots = vec![
        directory.path().to_owned(),
        vmlinux.parent().unwrap().to_owned(),
    ];
    config.security.remote_allowlist = vec![endpoint.clone()];
    config.security.kernel_enabled = true;
    config.security.monitor_allowlist = vec!["info".into()];
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller {
        identity: "kernel-provider-test".into(),
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
                "executable": vmlinux,
                "wait": {"until": "snapshot", "timeout_ms": 5000}
            }),
        ),
    )
    .await;
    let reset_stop = connected
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
            "start-kernel-breakpoint",
            Some(&session_id),
            "breakpoint.create",
            connected.revision,
            json!({"lease_id": lease_id, "location": {"function": "start_kernel"}}),
        ),
    )
    .await;
    let stopped = call(
        &gateway,
        &caller,
        request(
            "continue-to-start-kernel",
            Some(&session_id),
            "execution.control",
            breakpoint.revision,
            json!({
                "action": "continue",
                "lease_id": lease_id,
                "stop_id": reset_stop,
                "wait": {"until": "snapshot", "timeout_ms": 15000}
            }),
        ),
    )
    .await;
    let kernel_stop = stopped
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();

    let init_task = call(
        &gateway,
        &caller,
        request(
            "inspect-init-task",
            Some(&session_id),
            "kernel.inspect",
            None,
            json!({"view": "init_task", "stop_id": kernel_stop}),
        ),
    )
    .await;
    assert!(
        init_task.result.as_ref().unwrap()["value"]
            .as_str()
            .is_some_and(|value| value.contains("init_task"))
    );
    let current_task = call(
        &gateway,
        &caller,
        request(
            "inspect-current-task",
            Some(&session_id),
            "kernel.inspect",
            None,
            json!({"view": "current_task", "stop_id": kernel_stop}),
        ),
    )
    .await;
    assert!(
        current_task.result.as_ref().unwrap()["value"]
            .as_str()
            .is_some_and(|value| value.contains("init_task"))
    );
    assert_eq!(
        current_task.result.as_ref().unwrap()["source"]["provider"],
        "linux-kernel"
    );

    let monitored = call(
        &gateway,
        &caller,
        request(
            "monitor-registers",
            Some(&session_id),
            "kernel.monitor",
            current_task.revision,
            json!({"lease_id": lease_id, "command": "info registers"}),
        ),
    )
    .await;
    assert_eq!(
        monitored.state.as_ref().unwrap().consistency,
        Consistency::Tainted
    );
    assert_eq!(
        monitored.result.as_ref().unwrap()["reconciliation"]["status"],
        "tainted"
    );

    call(
        &gateway,
        &caller,
        request(
            "close",
            Some(&session_id),
            "session.close",
            monitored.revision,
            json!({"lease_id": lease_id}),
        ),
    )
    .await;
}
