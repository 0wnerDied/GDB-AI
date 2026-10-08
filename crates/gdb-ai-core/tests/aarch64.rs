use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use gdb_ai_core::{
    config::{ArtifactConfig, Config, PersistenceConfig},
    gateway::{Caller, Gateway},
    policy::Profile,
};
use serde_json::json;
use tempfile::tempdir;

mod support;

use support::{call, request, successful};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "firmware qualification: requires qemu-system-aarch64"]
async fn debugs_bare_metal_aarch64_over_rsp() {
    if !support::require_commands(&[
        "aarch64-linux-gnu-gcc",
        "gdb-multiarch",
        "qemu-system-aarch64",
    ]) {
        return;
    }
    let directory = tempdir().unwrap();
    let executable = directory.path().join("firmware");
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/aarch64/firmware.S");
    assert!(
        Command::new("aarch64-linux-gnu-gcc")
            .args([
                "-g",
                "-nostdlib",
                "-static",
                "-Wl,-Ttext=0x40080000,-e,_start"
            ])
            .arg(source)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    drop(listener);
    let _qemu = ChildGuard(
        Command::new("qemu-system-aarch64")
            .args([
                "-machine",
                "virt",
                "-cpu",
                "cortex-a57",
                "-display",
                "none",
                "-serial",
                "none",
                "-S",
                "-gdb",
            ])
            .arg(format!("tcp:{endpoint}"))
            .arg("-kernel")
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
    config.security.workspace_roots = vec![directory.path().to_owned()];
    config.security.remote_allowlist = vec![endpoint.clone()];
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("firmware/mcp:controller");
    let created = successful(
        gateway
            .dispatch_agent(
                request("create", None, "session.create", None, json!({})),
                &caller,
            )
            .await,
    );
    let session_id = created.session_id.as_deref().unwrap();
    macro_rules! agent_call {
        ($id:literal, $method:literal, $parameters:expr) => {
            successful(
                gateway
                    .dispatch_agent(
                        request($id, Some(session_id), $method, None, $parameters),
                        &caller,
                    )
                    .await,
            )
        };
    }
    let connected = agent_call!(
        "connect",
        "target.connect_remote",
        json!({
            "endpoint": endpoint, "executable": executable,
            "wait": {"until": "snapshot", "timeout_ms": 10000}
        })
    );
    assert_eq!(
        connected.state.as_ref().unwrap().target_origin,
        gdb_ai_core::domain::TargetOrigin::Remote
    );
    agent_call!(
        "breakpoint",
        "breakpoint.create",
        json!({"location": {"function": "checkpoint"}})
    );
    let stopped = agent_call!(
        "continue",
        "execution.control",
        json!({
            "action": "continue", "stop_id": connected.state.as_ref().unwrap().stop_id,
            "wait": {"until": "snapshot", "timeout_ms": 10000}
        })
    );
    assert_eq!(
        stopped.semantics.as_ref().unwrap().state.as_ref().unwrap()["status"],
        "STOPPED"
    );
    let stop_id = &stopped
        .semantics
        .as_ref()
        .unwrap()
        .context
        .as_ref()
        .unwrap()
        .stop_id;
    let value = agent_call!(
        "register",
        "value.evaluate",
        json!({"stop_id": stop_id, "expression": "$x0"})
    );
    assert_eq!(value.result.as_ref().unwrap()["value"], "42");
    let instructions = agent_call!(
        "disassembly",
        "disassembly.read",
        json!({
            "stop_id": stop_id, "around": {"expression": "$pc", "before_instructions": 0, "after_instructions": 1},
            "include_source": false
        })
    );
    assert!(
        !instructions.result.as_ref().unwrap()["instructions"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let memory = agent_call!(
        "memory",
        "memory.read",
        json!({"stop_id": stop_id, "address_expression": "$pc", "length": 4})
    );
    assert_eq!(memory.result.as_ref().unwrap()["data_hex"], "00000014");
    let maps = agent_call!(
        "mappings",
        "inspection.get",
        json!({"stop_id": stop_id, "view": "mappings"})
    );
    assert!(!maps.semantics.as_ref().unwrap().complete);
    assert!(
        maps.result.as_ref().unwrap()["mappings"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let stepped = agent_call!(
        "step",
        "execution.control",
        json!({
            "action": "step_instruction", "stop_id": stop_id,
            "wait": {"until": "snapshot", "timeout_ms": 10000}
        })
    );
    assert_ne!(
        stepped
            .semantics
            .as_ref()
            .unwrap()
            .context
            .as_ref()
            .unwrap()
            .stop_id,
        *stop_id
    );
    agent_call!("close", "session.close", json!({}));
    gateway.shutdown().await;
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
