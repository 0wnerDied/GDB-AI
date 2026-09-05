use std::{path::PathBuf, process::Command};

use gdb_ai_core::{
    config::{ArtifactConfig, Config, PersistenceConfig},
    gateway::{Caller, Gateway},
    protocol::{API_VERSION, ApiRequest, ApiResponse},
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

fn successful(response: ApiResponse) -> ApiResponse {
    assert!(
        response.error.is_none(),
        "{} response error: {:?}; state: {:?}; result: {:?}",
        response.request_id,
        response.error,
        response.state,
        response.result
    );
    response
}

#[tokio::test]
async fn thread_stacks_capture_a_deadlock_in_one_stop() {
    if !support::require_commands(&["gdb", "cc"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let executable = directory.path().join("deadlock");
    assert!(
        Command::new("cc")
            .args(["-g", "-O0", "-pthread"])
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/c/deadlock.c"))
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
    if let Some(path) = std::env::var_os("GDB_AI_GDB_PATH") {
        config.gdb.path = path.into();
    }
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("deadlock-test");
    let created = successful(
        gateway
            .dispatch(
                request("create", None, "session.create", None, json!({})),
                &caller,
            )
            .await,
    );
    let session = created.session_id.unwrap();
    let call = async |id: &str, method: &str, parameters: Value| {
        let mut request = request(id, Some(&session), method, None, parameters);
        gateway
            .prepare_agent_request(&mut request, &caller)
            .await
            .unwrap();
        gateway.dispatch(request, &caller).await
    };
    successful(
        call(
            "launch",
            "target.launch",
            json!({"program": executable, "stop": "main"}),
        )
        .await,
    );
    successful(
        call(
            "break",
            "breakpoint.create",
            json!({"function": "pthread_join", "temporary": true}),
        )
        .await,
    );
    let stopped = successful(
        call(
            "continue",
            "execution.control",
            json!({
                "action": "continue", "wait": {"until": "snapshot", "timeout_ms": 5000},
                "inspect": [{"view": "threads", "stack_depth": 8}]
            }),
        )
        .await,
    );
    let stop = stopped.state.as_ref().unwrap().stop_id.as_ref().unwrap();
    let threads = stopped.result.as_ref().unwrap()["observations"]["threads"]["threads"]
        .as_array()
        .unwrap();
    assert_eq!(threads.len(), 3);
    for thread in threads {
        assert!(thread["target_id"].as_str().unwrap().contains("LWP"));
        assert!(thread.get("error").is_none(), "{thread}");
        for frame in thread["frames"].as_array().unwrap() {
            assert!(frame["frame_id"].as_str().unwrap().starts_with(&format!(
                "f{}_{}_",
                thread["thread_id"].as_str().unwrap(),
                stop
            )));
        }
    }
    for worker in ["worker_left", "worker_right"] {
        assert!(threads.iter().any(|thread| {
            thread["frames"]
                .as_array()
                .unwrap()
                .iter()
                .any(|frame| frame["function"] == worker)
        }));
    }
    let (page, other) = tokio::join!(
        call(
            "page",
            "inspection.get",
            json!({"view": "threads", "stop_id": stop, "limit": 1, "offset": 1, "stack_depth": 1})
        ),
        call(
            "other",
            "inspection.get",
            json!({"view": "stack", "stop_id": stop, "thread_id": threads[0]["thread_id"], "limit": 2})
        ),
    );
    let page = successful(page).result.unwrap();
    assert_eq!(page["next_offset"], 2);
    assert_eq!(page["threads"][0]["thread_id"], threads[1]["thread_id"]);
    assert_eq!(page["threads"][0]["next_frame_offset"], 1);
    assert_eq!(page["threads"][0]["frames"].as_array().unwrap().len(), 1);
    let other = successful(other).result.unwrap();
    assert_eq!(
        other["frames"][0]["frame_id"],
        threads[0]["frames"][0]["frame_id"]
    );
    let invalid = call(
        "invalid",
        "inspection.get",
        json!({"view": "threads", "stop_id": stop, "stack_depth": 65}),
    )
    .await;
    assert_eq!(
        invalid.error.unwrap().code,
        gdb_ai_core::ErrorCode::InvalidArgument
    );
    successful(
        call(
            "resume",
            "execution.control",
            json!({"action": "continue", "wait": {"until": "running"}}),
        )
        .await,
    );
    let interrupted = successful(
        call(
            "interrupt",
            "execution.control",
            json!({
                "action": "interrupt", "wait": {"until": "snapshot", "timeout_ms": 5000},
                "inspect": [{"view": "threads", "stack_depth": 8}]
            }),
        )
        .await,
    );
    assert_eq!(
        interrupted.result.as_ref().unwrap()["observations"]["threads"]["threads"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let stale = call(
        "old-stop",
        "inspection.get",
        json!({"view": "threads", "stop_id": stop, "stack_depth": 8}),
    )
    .await;
    assert_eq!(
        stale.error.unwrap().code,
        gdb_ai_core::ErrorCode::StaleContext
    );
    successful(call("close", "session.close", json!({})).await);
}

#[tokio::test]
async fn frame_handles_select_their_owning_thread() {
    if !support::require_commands(&["gdb", "cc"]) {
        return;
    }

    let directory = tempdir().unwrap();
    let executable = directory.path().join("threads");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/c/threads.c");
    assert!(
        Command::new("cc")
            .args(["-g", "-O0", "-pthread"])
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
    let caller = Caller::local("thread-test");

    let created = successful(
        gateway
            .dispatch(
                request("create", None, "session.create", None, json!({})),
                &caller,
            )
            .await,
    );
    let session = created.result.as_ref().unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let lease = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let launched = successful(
        gateway
            .dispatch(
                request(
                    "launch",
                    Some(&session),
                    "target.launch",
                    created.revision,
                    json!({
                        "program": executable,
                        "lease_id": lease,
                        "stop": "main",
                        "wait": {"until": "snapshot", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    let first_stop = launched
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    let breakpoint = successful(
        gateway
            .dispatch(
                request(
                    "breakpoint",
                    Some(&session),
                    "breakpoint.create",
                    launched.revision,
                    json!({
                        "lease_id": lease,
                        "location": {"function": "worker"},
                        "temporary": true
                    }),
                ),
                &caller,
            )
            .await,
    );
    let stopped = successful(
        gateway
            .dispatch(
                request(
                    "continue",
                    Some(&session),
                    "execution.control",
                    breakpoint.revision,
                    json!({
                        "action": "continue",
                        "lease_id": lease,
                        "stop_id": first_stop,
                        "wait": {"until": "snapshot", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    let state = stopped.state.as_ref().unwrap();
    let stop = state.stop_id.as_ref().unwrap().0.clone();
    let stopped_thread = state.stopped_thread_id.as_ref().unwrap().0.clone();
    let stack = successful(
        gateway
            .dispatch(
                request(
                    "stack",
                    Some(&session),
                    "inspection.get",
                    None,
                    json!({"view": "stack", "stop_id": stop, "limit": 2}),
                ),
                &caller,
            )
            .await,
    );
    let frame = stack.result.as_ref().unwrap()["frames"][0]["frame_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(frame.starts_with(&format!("f{stopped_thread}_")));

    let other_thread = state
        .inferiors
        .values()
        .flat_map(|inferior| inferior.threads.values())
        .find(|thread| thread.id.0 != stopped_thread)
        .unwrap()
        .id
        .0
        .clone();
    let mismatch = gateway
        .dispatch(
            request(
                "mismatch",
                Some(&session),
                "inspection.get",
                None,
                json!({
                    "view": "frame",
                    "stop_id": stop,
                    "thread_id": other_thread,
                    "frame_id": frame
                }),
            ),
            &caller,
        )
        .await;
    assert_eq!(
        mismatch.error.unwrap().code,
        gdb_ai_core::ErrorCode::StaleContext
    );

    let restarted = successful(
        gateway
            .dispatch(
                request(
                    "restart",
                    Some(&session),
                    "target.restart",
                    mismatch.revision,
                    json!({
                        "lease_id": lease,
                        "stop": "main",
                        "wait": {"until": "snapshot", "timeout_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    let restart_stop = restarted
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    let probe = successful(
        gateway
            .dispatch(
                request(
                    "probe",
                    Some(&session),
                    "agent.probe",
                    restarted.revision,
                    json!({
                        "lease_id": lease,
                        "stop_id": restart_stop,
                        "location": {"function": "worker"},
                        "capture": [{"stack": {"limit": 2}}],
                        "budget": {"wall_time_ms": 5000}
                    }),
                ),
                &caller,
            )
            .await,
    );
    let probe_state = probe.state.as_ref().unwrap();
    let probe_thread = &probe_state.stopped_thread_id.as_ref().unwrap().0;
    let probe_frame = &probe.result.as_ref().unwrap()["captures"][0]["observation"]["observations"]
        [0]["stack"][0];
    assert_eq!(probe_frame["function"], "worker");
    assert!(
        probe_frame["frame_id"]
            .as_str()
            .unwrap()
            .starts_with(&format!("f{probe_thread}_"))
    );

    successful(
        gateway
            .dispatch(
                request(
                    "close",
                    Some(&session),
                    "session.close",
                    probe.revision,
                    json!({"lease_id": lease}),
                ),
                &caller,
            )
            .await,
    );
}
