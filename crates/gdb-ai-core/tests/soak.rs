use std::{path::PathBuf, process::Command, sync::Arc, time::Duration};

use gdb_ai_core::{
    config::{ArtifactConfig, Config, PersistenceConfig},
    gateway::{Caller, Gateway},
    protocol::{API_VERSION, ApiRequest},
};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::task::JoinSet;

mod support;

fn request(
    id: String,
    session_id: Option<&str>,
    method: &str,
    revision: Option<u64>,
    parameters: Value,
) -> ApiRequest {
    ApiRequest {
        api_version: API_VERSION.into(),
        request_id: id,
        session_id: session_id.map(str::to_owned),
        method: method.parse().unwrap(),
        expected_revision: revision,
        idempotency_key: None,
        parameters,
    }
}

fn metric(metrics: &str, name: &str) -> u64 {
    metrics
        .lines()
        .find_map(|line| {
            line.strip_prefix(name)
                .and_then(|value| value.trim().parse().ok())
        })
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "release gate: run explicitly to execute 10,000 real GDB lifecycles"]
async fn ten_thousand_session_lifecycles() {
    if !support::require_commands(&["gdb", "cc"]) {
        return;
    }
    let cycles = std::env::var("GDB_AI_SOAK_CYCLES")
        .map(|value| value.parse::<usize>().unwrap())
        .unwrap_or(10_000);
    let concurrency = std::env::var("GDB_AI_SOAK_CONCURRENCY")
        .map(|value| value.parse::<usize>().unwrap())
        .unwrap_or(8)
        .clamp(1, 32);

    let directory = tempdir().unwrap();
    let executable = directory.path().join("soak-target");
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
    config.server.max_sessions = concurrency;
    config.server.requests_per_second = 1_000_000;
    config.server.request_burst = 0;
    config.server.write_lease_ms = 60_000;
    config.security.workspace_roots = vec![directory.path().to_owned()];
    let gateway = Arc::new(Gateway::new(config).unwrap());
    let caller = Caller::local("lifecycle-soak");

    let started = std::time::Instant::now();
    for first in (0..cycles).step_by(concurrency) {
        let mut batch = JoinSet::new();
        for cycle in first..(first + concurrency).min(cycles) {
            let gateway = gateway.clone();
            let caller = caller.clone();
            let executable = executable.clone();
            batch.spawn(async move {
                tokio::time::timeout(Duration::from_secs(30), async {
                    let created = gateway
                        .dispatch(
                            request(
                                format!("create-{cycle}"),
                                None,
                                "session.create",
                                None,
                                json!({}),
                            ),
                            &caller,
                        )
                        .await;
                    assert!(
                        created.error.is_none(),
                        "cycle {cycle}: {:?}",
                        created.error
                    );
                    let session_id = created.session_id.as_deref().unwrap();
                    let lease_id = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
                        .as_str()
                        .unwrap();
                    let launched = gateway
                        .dispatch(
                            request(
                                format!("launch-{cycle}"),
                                Some(session_id),
                                "target.launch",
                                created.revision,
                                json!({
                                    "program": executable,
                                    "lease_id": lease_id,
                                    "stop": "main",
                                    "wait": {"until": "snapshot", "timeout_ms": 5000}
                                }),
                            ),
                            &caller,
                        )
                        .await;
                    assert!(
                        launched.error.is_none(),
                        "cycle {cycle}: {:?}",
                        launched.error
                    );
                    assert!(launched.state.as_ref().unwrap().stop_id.is_some());
                    let closed = gateway
                        .dispatch(
                            request(
                                format!("close-{cycle}"),
                                Some(session_id),
                                "session.close",
                                None,
                                json!({
                                    "lease_id": lease_id,
                                    "accept_latest_revision": true
                                }),
                            ),
                            &caller,
                        )
                        .await;
                    assert!(closed.error.is_none(), "cycle {cycle}: {:?}", closed.error);
                    assert_eq!(
                        closed.result.as_ref().unwrap()["state"]["lifecycle"],
                        "CLOSED"
                    );
                })
                .await
                .unwrap_or_else(|_| panic!("cycle {cycle} exceeded 30 seconds"));
            });
        }
        while let Some(result) = batch.join_next().await {
            result.unwrap();
        }
    }

    let metrics = gateway.metrics();
    assert_eq!(metric(&metrics, "gdbai_sessions_total"), cycles as u64);
    assert_eq!(metric(&metrics, "gdbai_sessions_active"), 0);
    assert_eq!(metric(&metrics, "gdbai_session_failures_total"), 0);
    assert_eq!(metric(&metrics, "gdbai_gdb_start_failures_total"), 0);
    assert_eq!(metric(&metrics, "gdbai_mi_parse_errors_total"), 0);
    assert_eq!(metric(&metrics, "gdbai_command_timeouts_total"), 0);
    assert_eq!(metric(&metrics, "gdbai_consistency_lost_total"), 0);
    eprintln!("completed {cycles} lifecycles in {:?}", started.elapsed());
    gateway.shutdown().await;
}
