use std::process::Command;

use gdb_ai_core::{
    config::{ArtifactConfig, Config, PersistenceConfig},
    domain::SessionId,
    gateway::{Caller, Gateway},
    protocol::{API_VERSION, ApiRequest, ApiResponse},
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

async fn call(gateway: &Gateway, caller: &Caller, request: ApiRequest) -> ApiResponse {
    let response = gateway.dispatch(request, caller).await;
    assert!(response.error.is_none(), "{:?}", response.error);
    response
}

#[tokio::test]
async fn rebinds_module_offset_for_probes_and_persistent_breakpoints() {
    if !support::require_commands(&["gdb", "cc", "nm", "readelf", "strip"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let executable = directory.path().join("stripped");
    let source = directory.path().join("stripped.c");
    std::fs::write(
        &source,
        "#include <unistd.h>\nvolatile int value;\n__attribute__((noinline)) static void marker(void) { value++; }\nint main(void) { sleep(1); marker(); return value != 1; }\n",
    )
    .unwrap();
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
    let probed = gateway
        .dispatch(
            request(
                "pending-probe",
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
    assert!(probed.error.is_none(), "{:?}", probed.error);
    assert_eq!(probed.result.as_ref().unwrap()["capture_count"], 1);
    assert!(
        probed.state.as_ref().unwrap().breakpoints.is_empty(),
        "{:?}",
        probed.state.as_ref().unwrap().breakpoints
    );
    let launched = gateway
        .dispatch(
            request(
                "restart-after-probe",
                Some(&session_id),
                "target.restart",
                probed.revision,
                json!({
                    "lease_id": lease_id,
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

    macro_rules! call {
        ($id:literal, $method:literal, $revision:expr, $parameters:expr) => {
            call(
                &gateway,
                &caller,
                request($id, Some(&session_id), $method, $revision, $parameters),
            )
            .await
        };
    }

    let deleted = call!(
        "delete-initial-module-offset",
        "breakpoint.delete",
        frame.revision,
        json!({"lease_id": lease_id, "breakpoint_id": public_id})
    );
    let materialized = call!(
        "materialized-module-offset",
        "breakpoint.create",
        deleted.revision,
        json!({"lease_id": lease_id, "module_offset": {
            "module": "stripped", "offset": format!("0x{marker_offset:x}")}})
    );
    let public_id = materialized.result.as_ref().unwrap()["breakpoint"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let disabled = call!(
        "disable-module-offset",
        "breakpoint.update",
        materialized.revision,
        json!({"lease_id": lease_id, "breakpoint_id": public_id, "enabled": false})
    );
    let restarted = call!(
        "restart-with-module-offset",
        "target.restart",
        disabled.revision,
        json!({"lease_id": lease_id, "stop": "first_instruction",
            "wait": {"until": "snapshot", "timeout_ms": 5000}})
    );
    let restart_stop_id = restarted.state.as_ref().unwrap().stop_id.clone().unwrap();
    let parked = restarted
        .state
        .as_ref()
        .unwrap()
        .breakpoints
        .values()
        .find(|breakpoint| breakpoint.id.0 == public_id)
        .unwrap();
    assert!(parked.pending && !parked.enabled);
    let enabled = call!(
        "enable-restarted-module-offset",
        "breakpoint.update",
        None,
        json!({"lease_id": lease_id, "accept_latest_revision": true,
            "breakpoint_id": public_id, "enabled": true})
    );
    let stopped_after_restart = call!(
        "continue-after-restart",
        "execution.control",
        enabled.revision,
        json!({"action": "continue", "lease_id": lease_id, "stop_id": restart_stop_id,
            "wait": {"until": "snapshot", "timeout_ms": 5000}})
    );
    assert_eq!(
        stopped_after_restart
            .state
            .as_ref()
            .unwrap()
            .stop_reason
            .as_deref(),
        Some("breakpoint-hit")
    );
    let killed = call!(
        "kill-before-relaunch",
        "target.kill",
        stopped_after_restart.revision,
        json!({"lease_id": lease_id, "wait": {"until": "exited", "timeout_ms": 5000}})
    );
    let relaunched = call!(
        "relaunch-with-module-offset",
        "target.launch",
        killed.revision,
        json!({"lease_id": lease_id, "program": loader, "argv": [executable],
            "cwd": directory.path(), "stop": "first_instruction",
            "wait": {"until": "snapshot", "timeout_ms": 5000}})
    );
    let relaunch_stop_id = relaunched.state.as_ref().unwrap().stop_id.clone().unwrap();
    let stopped_after_relaunch = call!(
        "continue-after-relaunch",
        "execution.control",
        None,
        json!({"action": "continue", "accept_latest_revision": true, "lease_id": lease_id,
            "stop_id": relaunch_stop_id,
            "wait": {"until": "snapshot", "timeout_ms": 5000}})
    );
    assert_eq!(
        stopped_after_relaunch
            .state
            .as_ref()
            .unwrap()
            .stop_reason
            .as_deref(),
        Some("breakpoint-hit"),
        "{:?}",
        stopped_after_relaunch.state
    );
    assert!(
        stopped_after_relaunch
            .state
            .as_ref()
            .unwrap()
            .breakpoints
            .values()
            .any(|breakpoint| breakpoint.id.0 == public_id && !breakpoint.pending)
    );
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

#[tokio::test]
async fn launches_a_complete_bundled_runtime_without_losing_pie_breakpoints() {
    if !support::require_commands(&["gdb", "cc", "ldd", "patchelf"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let executable = directory.path().join("bundled-pie");
    let source = directory.path().join("bundled-pie.c");
    std::fs::write(
        &source,
        "volatile int calls;\n__attribute__((noinline)) void marker(void) { calls++; }\nint main(void) { marker(); return calls != 1; }\n",
    )
    .unwrap();
    assert!(
        Command::new("cc")
            .args(["-fPIE", "-pie", "-O0", "-g"])
            .arg(source)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    let original = std::fs::read(&executable).unwrap();
    let interpreter = Command::new("patchelf")
        .arg("--print-interpreter")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(interpreter.status.success());
    let interpreter =
        std::fs::canonicalize(String::from_utf8(interpreter.stdout).unwrap().trim()).unwrap();
    let libraries = Command::new("ldd").arg(&executable).output().unwrap();
    assert!(libraries.status.success());
    let libc = String::from_utf8(libraries.stdout)
        .unwrap()
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("libc.so.6"))
                .then(|| fields.nth(1).map(std::path::PathBuf::from))
                .flatten()
        })
        .map(std::fs::canonicalize)
        .unwrap()
        .unwrap();
    let bundled_loader = directory.path().join("ld-bundled.so");
    let bundled_libc = directory.path().join("libc-bundled.so.6.999");
    std::fs::copy(interpreter, &bundled_loader).unwrap();
    std::fs::copy(libc, &bundled_libc).unwrap();

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
    let caller = Caller::local("bundled-runtime-test");
    let created = call(
        &gateway,
        &caller,
        request("create-bundled", None, "session.create", None, json!({})),
    )
    .await;
    let session_id = created.session_id.clone().unwrap();
    let lease_id = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap();
    macro_rules! invoke {
        ($id:literal, $method:literal, $revision:expr, $parameters:expr) => {
            call(
                &gateway,
                &caller,
                request($id, Some(&session_id), $method, $revision, $parameters),
            )
            .await
        };
    }
    let launched = invoke!(
        "launch-bundled",
        "target.launch",
        created.revision,
        json!({
            "lease_id": lease_id,
            "program": executable,
            "stop": "first_instruction",
            "wait": {"until": "snapshot", "timeout_ms": 5000}
        })
    );
    let runtime = &launched.result.as_ref().unwrap()["runtime"];
    assert_eq!(std::fs::read(&executable).unwrap(), original);
    assert_eq!(runtime["mode"], "bundled");
    assert_eq!(runtime["loader"].as_str(), bundled_loader.to_str());
    assert_eq!(runtime["libraries"], json!(["libc.so.6"]));
    assert_eq!(
        std::fs::canonicalize(
            std::path::Path::new(runtime["library_path"].as_str().unwrap()).join("libc.so.6")
        )
        .unwrap(),
        bundled_libc
    );
    assert!(
        runtime["prepared_program"]
            .as_str()
            .unwrap()
            .ends_with("/bundled-pie")
    );
    let breakpoint = invoke!(
        "break-bundled",
        "breakpoint.create",
        launched.revision,
        json!({"lease_id": lease_id, "function": "marker"})
    );
    let first = invoke!(
        "continue-bundled",
        "execution.control",
        breakpoint.revision,
        json!({
            "action": "continue",
            "lease_id": lease_id,
            "stop_id": launched.state.as_ref().unwrap().stop_id.clone(),
            "wait": {"until": "snapshot", "timeout_ms": 5000}
        })
    );
    assert_eq!(
        first.state.as_ref().unwrap().stop_reason.as_deref(),
        Some("breakpoint-hit")
    );
    let pid = first
        .state
        .as_ref()
        .unwrap()
        .inferiors
        .values()
        .find_map(|inferior| inferior.pid)
        .unwrap();
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
    assert!(
        maps.lines()
            .any(|line| line.ends_with(&format!(" {}", bundled_libc.display())))
    );
    let restarted = invoke!(
        "restart-bundled",
        "target.restart",
        first.revision,
        json!({
            "lease_id": lease_id,
            "stop": "first_instruction",
            "wait": {"until": "snapshot", "timeout_ms": 5000}
        })
    );
    let second = invoke!(
        "continue-restarted-bundled",
        "execution.control",
        restarted.revision,
        json!({
            "action": "continue",
            "lease_id": lease_id,
            "stop_id": restarted.state.as_ref().unwrap().stop_id.clone(),
            "wait": {"until": "snapshot", "timeout_ms": 5000}
        })
    );
    assert_eq!(
        second.state.as_ref().unwrap().stop_reason.as_deref(),
        Some("breakpoint-hit")
    );
    gateway.shutdown().await;
}
