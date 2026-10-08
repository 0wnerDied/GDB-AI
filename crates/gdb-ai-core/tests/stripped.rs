use std::process::Command;

use gdb_ai_core::{
    ErrorCode,
    config::{ArtifactConfig, Config, PersistenceConfig},
    domain::SessionId,
    gateway::{Caller, Gateway},
    replay::replay,
};
use serde_json::json;
use tempfile::tempdir;

mod support;

use support::{call, request, successful};

#[tokio::test]
async fn rejects_missing_main_before_running_but_keeps_explicit_pending_breakpoints() {
    if !support::require_commands(&["gdb", "cc", "strip"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let source = directory.path().join("main.c");
    let executable = directory.path().join("with-symbols");
    let stripped = directory.path().join("stripped");
    let marker = directory.path().join("executed");
    std::fs::write(
        &source,
        "#include <stdio.h>\nint main(int argc, char **argv) {\n\
         FILE *file = fopen(argv[1], \"w\"); fputs(\"executed\", file); fclose(file);\n\
         __builtin_trap(); return argc;\n}\n",
    )
    .unwrap();
    assert!(
        Command::new("cc")
            .args(["-g", "-O0", "-fPIE", "-pie"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    std::fs::copy(&executable, &stripped).unwrap();
    assert!(
        Command::new("strip")
            .arg(&stripped)
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
    if let Some(path) = std::env::var_os("GDB_AI_GDB_PATH") {
        config.gdb.path = path.into();
    }
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("stripped-main/mcp:writer");
    let rejected = gateway
        .dispatch_agent(
            request(
                "missing-main",
                None,
                "target.launch",
                None,
                json!({"program": stripped, "argv": [marker], "stop": "main"}),
            ),
            &caller,
        )
        .await;
    assert_eq!(
        rejected.error.as_ref().map(|error| error.code),
        Some(ErrorCode::GdbError)
    );
    assert!(rejected.error.as_ref().unwrap().message.contains("main"));
    assert_eq!(rejected.state.as_ref().unwrap().execution_epoch, 0);
    assert!(
        !marker.exists(),
        "a rejected main policy must not execute the program"
    );
    let session = rejected.session_id.as_deref().unwrap();
    let dispatch = |id: &str, method: &str, parameters| {
        gateway.dispatch_agent(
            request(id, Some(session), method, None, parameters),
            &caller,
        )
    };
    let first = successful(
        dispatch(
            "first-instruction",
            "target.launch",
            json!({"program": stripped, "argv": [marker], "stop": "first_instruction"}),
        )
        .await,
    );
    assert!(first.semantics.as_ref().unwrap().state.as_ref().unwrap()["stop_id"].is_string());
    assert!(!marker.exists());
    let restart = dispatch(
        "missing-main-restart",
        "target.restart",
        json!({"stop": "main"}),
    )
    .await;
    assert_eq!(restart.error.unwrap().code, ErrorCode::GdbError);
    assert!(!marker.exists());
    let ran = successful(
        dispatch(
            "run-to-stop",
            "target.restart",
            json!({"stop": "none", "inspect": [{"view": "stack", "limit": 1}]}),
        )
        .await,
    );
    assert_eq!(
        ran.semantics.as_ref().unwrap().state.as_ref().unwrap()["status"],
        "STOPPED"
    );
    assert!(marker.exists());
    successful(dispatch("close-stripped", "session.close", json!({})).await);

    let created = successful(
        gateway
            .dispatch_agent(
                request("pending-session", None, "session.create", None, json!({})),
                &caller,
            )
            .await,
    );
    let session = created.session_id.as_deref().unwrap();
    let dispatch = |id: &str, method: &str, parameters| {
        gateway.dispatch_agent(
            request(id, Some(session), method, None, parameters),
            &caller,
        )
    };
    let pending = successful(
        dispatch(
            "pending-main",
            "breakpoint.create",
            json!({"function": "main", "pending": true}),
        )
        .await,
    );
    assert_eq!(
        pending.result.as_ref().unwrap()["breakpoint"]["pending"],
        true
    );
    let launched = successful(dispatch(
        "bind-pending", "target.launch",
        json!({"program": executable, "argv": [marker], "stop": "none", "inspect": [{"view": "stack", "limit": 1}]}),
    ).await);
    assert_eq!(
        launched.result.as_ref().unwrap()["observations"]["stack"]["frames"][0]["function"],
        "main"
    );
    successful(dispatch("close-pending", "session.close", json!({})).await);
}

#[tokio::test]
async fn distinguishes_empty_locals_from_missing_frame_debug_information() {
    if !support::require_commands(&["gdb", "cc", "strip", "objcopy"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let source = directory.path().join("scope.c");
    let executable = directory.path().join("scope");
    let debug_file = directory.path().join("scope.debug");
    std::fs::write(
        &source,
        "__attribute__((noinline)) void empty(void) { __builtin_trap(); }\n\
         int main(void) { volatile int value = 7; empty(); return value != 7; }\n",
    )
    .unwrap();
    assert!(
        Command::new("cc")
            .args(["-g", "-O0", "-fPIE", "-pie"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("objcopy")
            .arg("--only-keep-debug")
            .arg(&executable)
            .arg(&debug_file)
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
    if let Some(path) = std::env::var_os("GDB_AI_GDB_PATH") {
        config.gdb.path = path.into();
    }
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("frame-debug-info/mcp:writer");
    for (name, strip, separate_debug, available) in [
        ("debug", None, false, true),
        ("symbols-only", Some("--strip-debug"), false, false),
        ("stripped", Some("--strip-all"), false, false),
        ("separate-debug", Some("--strip-all"), true, true),
    ] {
        let binary = directory.path().join(name);
        std::fs::copy(&executable, &binary).unwrap();
        if let Some(option) = strip {
            assert!(
                Command::new("strip")
                    .arg(option)
                    .arg(&binary)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        if separate_debug {
            assert!(
                Command::new("objcopy")
                    .arg(format!("--add-gnu-debuglink={}", debug_file.display()))
                    .arg(&binary)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let launched = successful(gateway.dispatch_agent(
            request(name, None, "target.launch", None, json!({
                "program": binary, "stop": "none", "inspect": [
                    {"view": "locals"}, {"view": "stack", "limit": 2, "include_locals": true},
                    {"view": "registers", "roles": ["pc"]}
                ]
            })), &caller,
        ).await);
        let facts = launched.result.as_ref().unwrap();
        assert_eq!(
            launched.semantics.as_ref().unwrap().complete,
            available,
            "{name}"
        );
        assert!(facts["observations"]["registers"]["roles"]["pc"].is_string());
        let frames = facts["observations"]["stack"]["frames"].as_array().unwrap();
        assert_eq!(frames.len(), 2, "{name}");
        if available {
            assert_eq!(facts["observations"]["locals"]["variables"], json!([]));
            assert_eq!(frames[0]["locals"], json!([]));
            assert!(
                frames[1]["locals"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|variable| variable["name"] == "value" && variable["value"] == "7")
            );
        } else {
            assert_eq!(
                facts["observation_failures"]["locals"]["code"],
                "CAPABILITY_MISSING"
            );
            assert_eq!(facts["observation_availability"]["locals"], "unavailable");
            assert!(
                frames
                    .iter()
                    .all(|frame| frame["variables_error"]["code"] == "CAPABILITY_MISSING")
            );
        }
        let session = launched.session_id.as_deref().unwrap();
        let stop_id = &launched
            .semantics
            .as_ref()
            .unwrap()
            .context
            .as_ref()
            .unwrap()
            .stop_id;
        let dispatch = |id: &str, method: &str, parameters| {
            gateway.dispatch_agent(
                request(id, Some(session), method, None, parameters),
                &caller,
            )
        };
        let before = gateway.metrics();
        let locals = dispatch(
            "caller-locals",
            "inspection.get",
            json!({"view": "locals", "frame_level": 1, "stop_id": stop_id}),
        )
        .await;
        if available {
            let locals = successful(locals);
            assert!(
                locals.result.as_ref().unwrap()["variables"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|variable| variable["name"] == "value" && variable["value"] == "7")
            );
            let commands = |metrics: &str| {
                metrics
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("gdbai_commands_total ")
                            .map(|value| value.parse::<u64>().unwrap())
                    })
                    .unwrap()
            };
            assert_eq!(
                commands(&gateway.metrics()) - commands(&before),
                1,
                "nonempty locals must stay one MI read"
            );
        } else {
            assert_eq!(locals.error.unwrap().code, ErrorCode::CapabilityMissing);
            assert!(!locals.evidence.is_empty());
        }
        let snapshot = successful(
            dispatch(
                "snapshot",
                "inspection.snapshot",
                json!({"profile": "brief", "stop_id": stop_id}),
            )
            .await,
        );
        assert_eq!(
            snapshot.semantics.as_ref().unwrap().complete,
            available,
            "{name}"
        );
        if !available {
            assert_eq!(
                snapshot.result.as_ref().unwrap()["failures"]["locals"]["code"],
                "CAPABILITY_MISSING"
            );
        }
        successful(dispatch("close", "session.close", json!({})).await);
    }
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
    // 2026-10-08: The version matrix qualified one GDB but this test started
    // an absent system binary. Use the same debugger as its prerequisite check.
    if let Some(path) = std::env::var_os("GDB_AI_GDB_PATH") {
        config.gdb.path = path.into();
    }
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
