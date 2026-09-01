use gdb_ai_mi::MiResult;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use super::*;
use crate::{
    config::{ArtifactConfig, PersistenceConfig},
    domain::JournaledEvent,
    reducer::StateReducer,
};

async fn control_test_session() -> Option<SessionHandle> {
    if !crate::test_support::require_commands(&["gdb"]) {
        return None;
    }
    let directory = tempdir().unwrap();
    let path = directory.keep();
    let config = Config {
        artifacts: ArtifactConfig {
            path: path.join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: path.join("state.sqlite"),
            sessions: path.join("sessions"),
        },
        ..Config::default()
    };
    let store = Arc::new(Store::open(&config.persistence.sqlite).unwrap());
    Some(
        SessionHandle::start(
            Arc::new(config),
            Profile::RawAdmin,
            store,
            Arc::new(Metrics::default()),
        )
        .await
        .unwrap(),
    )
}

#[test]
fn conditional_capability_is_not_unconditionally_supported() {
    let capabilities = SessionCapabilities {
        backend: BackendDescriptor {
            name: "gdb",
            mi_version: "mi4".into(),
            pty: "/dev/pts/test".into(),
            filesystem_hardened: false,
            network_isolated: false,
        },
        features: BTreeSet::new(),
        target_features: BTreeSet::new(),
        commands: BTreeSet::new(),
        capabilities: BTreeMap::from([(
            "conditional".into(),
            Capability {
                status: CapabilityStatus::Conditional,
                scope: "current_target",
                constraints: vec!["target must be stopped".into()],
                source: "probe",
                last_checked_revision: 1,
            },
        )]),
        limitations: Vec::new(),
    };

    assert!(!capabilities.supports("conditional"));
}

#[test]
fn exit_wait_ignores_an_already_terminal_inferior() {
    let mut reducer = StateReducer::new(SessionState::creating(SessionId("sess_wait".into())));
    for (seq, event) in [
        (1, DomainEvent::BackendStarted),
        (
            2,
            DomainEvent::InferiorAdded {
                backend_id: "i1".into(),
                pid: Some(1),
            },
        ),
        (
            3,
            DomainEvent::InferiorExited {
                backend_id: "i1".into(),
                exit_code: Some("0".into()),
                from_stop_record: true,
            },
        ),
    ] {
        reducer
            .apply(&JournaledEvent::for_replay(seq, event))
            .unwrap();
    }
    let baseline = WaitBaseline::from(reducer.state());
    reducer
        .apply(&JournaledEvent::for_replay(
            4,
            DomainEvent::InferiorAdded {
                backend_id: "i2".into(),
                pid: Some(2),
            },
        ))
        .unwrap();
    assert!(!wait_satisfied(
        reducer.state(),
        WaitUntil::Exited,
        Some(&baseline)
    ));
    assert!(!wait_satisfied(
        reducer.state(),
        WaitUntil::Settled,
        Some(&baseline)
    ));
    let mut stopped = reducer.state().clone();
    stopped.event_seq += 1;
    stopped.stop_id = Some(StopId("stop_new".into()));
    stopped.inferiors.get_mut("i2").unwrap().status = InferiorStatus::Stopped;
    assert_eq!(settled_by(&stopped, Some(&baseline)), Some("stopped"));
    reducer
        .apply(&JournaledEvent::for_replay(
            5,
            DomainEvent::InferiorExited {
                backend_id: "i2".into(),
                exit_code: Some("0".into()),
                from_stop_record: true,
            },
        ))
        .unwrap();
    assert!(wait_satisfied(
        reducer.state(),
        WaitUntil::Exited,
        Some(&baseline)
    ));
    assert!(wait_satisfied(
        reducer.state(),
        WaitUntil::Settled,
        Some(&baseline)
    ));
    assert_eq!(settled_by(reducer.state(), Some(&baseline)), Some("exited"));
}

#[tokio::test]
async fn starts_secure_gdb_and_closes_cleanly() {
    if !crate::test_support::require_commands(&["gdb"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let config = Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    };
    let store = Arc::new(Store::open(&config.persistence.sqlite).unwrap());
    let session = SessionHandle::start(
        Arc::new(config),
        Profile::DebugControl,
        store,
        Arc::new(Metrics::default()),
    )
    .await
    .unwrap();
    assert_eq!(
        session.state().lifecycle,
        crate::domain::SessionLifecycle::Ready
    );
    assert!(session.capabilities().supports("async_execution"));
    assert!(session.capabilities().supports("inferior_tty"));
    let memory_guard = session
        .command(
            MiCommand::new("-gdb-show")
                .unwrap()
                .bare("may-write-memory")
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        MiResult::find_str(memory_guard.record.results(), "value"),
        Some("on")
    );
    session.close().await.unwrap();
    assert_eq!(
        session.state().lifecycle,
        crate::domain::SessionLifecycle::Closed
    );
}

#[tokio::test]
async fn state_persistence_failure_fails_session() {
    if !crate::test_support::require_commands(&["gdb"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let sqlite = directory.path().join("state.sqlite");
    let config = Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: sqlite.clone(),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    };
    let store = Arc::new(Store::open(&sqlite).unwrap());
    let session = SessionHandle::start(
        Arc::new(config),
        Profile::RawAdmin,
        store,
        Arc::new(Metrics::default()),
    )
    .await
    .unwrap();
    rusqlite::Connection::open(sqlite)
        .unwrap()
        .execute("DROP TABLE sessions", [])
        .unwrap();

    assert!(
        session
            .record_event(DomainEvent::ControllerChanged {
                kind: "force_persistence_failure".into(),
            })
            .await
            .is_err()
    );
    assert_eq!(
        session.state().lifecycle,
        crate::domain::SessionLifecycle::Failed
    );
    assert_eq!(session.state().backend, crate::domain::BackendHealth::Dead);
}

#[tokio::test]
async fn timeout_fences_late_result() {
    if !crate::test_support::require_commands(&["gdb"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let config = Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    };
    let store = Arc::new(Store::open(&config.persistence.sqlite).unwrap());
    let session = SessionHandle::start(
        Arc::new(config),
        Profile::RawAdmin,
        store,
        Arc::new(Metrics::default()),
    )
    .await
    .unwrap();
    let slow = MiCommand::new("-interpreter-exec")
        .unwrap()
        .bare("console")
        .unwrap()
        .string("shell sleep 0.5");
    let timeout = session
        .command_with_timeout(slow, Duration::from_millis(10))
        .await
        .unwrap_err();
    assert_eq!(timeout.code, ErrorCode::Timeout);
    assert!(!session.state().outcome_unknown_tokens.is_empty());

    let fenced = session
        .command(MiCommand::new("-gdb-version").unwrap())
        .await
        .unwrap_err();
    assert_eq!(fenced.code, ErrorCode::GdbUnresponsive);

    tokio::time::timeout(Duration::from_secs(2), async {
        while !session.state().outcome_unknown_tokens.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(session.state().reconciliation_required);
    session.close().await.unwrap();
}

#[tokio::test]
async fn stalled_inferior_write_times_out_without_wedging_worker() {
    if !crate::test_support::require_commands(&["gdb", "cc"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let executable = directory.path().join("stalled-input");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/c/vertical.c");
    assert!(
        std::process::Command::new("cc")
            .args(["-g", "-O0"])
            .arg(source)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    let config = Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    };
    let store = Arc::new(Store::open(&config.persistence.sqlite).unwrap());
    let session = SessionHandle::start(
        Arc::new(config),
        Profile::RawAdmin,
        store,
        Arc::new(Metrics::default()),
    )
    .await
    .unwrap();
    session
        .command(
            MiCommand::new("-file-exec-and-symbols")
                .unwrap()
                .string(executable.as_os_str().as_encoded_bytes()),
        )
        .await
        .unwrap();
    let baseline = session.state();
    session
        .command(
            MiCommand::new("-exec-run")
                .unwrap()
                .bare("--start")
                .unwrap(),
        )
        .await
        .unwrap();
    session
        .wait_after(WaitUntil::Stopped, Duration::from_secs(5), &baseline)
        .await
        .unwrap();

    let started = std::time::Instant::now();
    let error = session
        .write_inferior_with_timeout(vec![b'A'; 64 * 1024], false, Duration::from_millis(100))
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Timeout);
    assert!(started.elapsed() < Duration::from_secs(2));
    let details = error.details.unwrap();
    assert_eq!(
        details["written"].as_u64().unwrap() + details["remaining"].as_u64().unwrap(),
        64 * 1024
    );
    session
        .command(MiCommand::new("-gdb-version").unwrap())
        .await
        .unwrap();
    session.close().await.unwrap();
}

#[tokio::test]
async fn late_execution_error_requires_reconciliation() {
    if !crate::test_support::require_commands(&["gdb", "cc"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let executable = directory.path().join("late-error");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/c/vertical.c");
    assert!(
        std::process::Command::new("cc")
            .args(["-g", "-O0"])
            .arg(source)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    let config = Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    };
    let store = Arc::new(Store::open(&config.persistence.sqlite).unwrap());
    let session = SessionHandle::start(
        Arc::new(config),
        Profile::RawAdmin,
        store,
        Arc::new(Metrics::default()),
    )
    .await
    .unwrap();
    session
        .command(
            MiCommand::new("-file-exec-and-symbols")
                .unwrap()
                .string(executable.as_os_str().as_encoded_bytes()),
        )
        .await
        .unwrap();
    session
        .command(
            MiCommand::new("-gdb-set")
                .unwrap()
                .bare("may-write-memory")
                .unwrap()
                .bare("off")
                .unwrap(),
        )
        .await
        .unwrap();
    let baseline = session.state();
    let run = session
        .command(
            MiCommand::new("-exec-run")
                .unwrap()
                .bare("--start")
                .unwrap(),
        )
        .await;
    if let Ok(reply) = run {
        assert_eq!(reply.class, "running");
        let started = std::time::Instant::now();
        let error = session
            .wait_after(WaitUntil::Snapshot, Duration::from_secs(5), &baseline)
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ConsistencyDirty);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(session.state().reconciliation_required);
    } else {
        assert_eq!(run.unwrap_err().code, ErrorCode::GdbError);
    }
    session.close().await.unwrap();
}

#[tokio::test]
async fn state_wait_returns_when_gdb_exits() {
    let Some(session) = control_test_session().await else {
        return;
    };
    let _ = session.command(MiCommand::new("-gdb-exit").unwrap()).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while session.state().lifecycle != crate::domain::SessionLifecycle::Failed {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let started = std::time::Instant::now();
    let error = session
        .wait(WaitUntil::Stopped, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::GdbExited);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn stopped_wait_returns_target_exit_without_timing_out() {
    let Some(session) = control_test_session().await else {
        return;
    };
    session
        .command(
            MiCommand::new("-file-exec-and-symbols")
                .unwrap()
                .string("/bin/false"),
        )
        .await
        .unwrap();
    let baseline = session.state();
    session
        .command(MiCommand::new("-exec-run").unwrap())
        .await
        .unwrap();

    let started = std::time::Instant::now();
    let error = session
        .wait_after(WaitUntil::Stopped, Duration::from_secs(5), &baseline)
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::TargetExited);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(error.details.unwrap()["exit_code"], "01");
    session.close().await.unwrap();
}

#[tokio::test]
async fn safe_evaluate_restores_settings_after_a_late_result() {
    if !crate::test_support::require_commands(&["gdb"]) {
        return;
    }
    let directory = tempdir().unwrap();
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
    config.server.command_timeout_ms = 500;
    let store = Arc::new(Store::open(&config.persistence.sqlite).unwrap());
    let session = SessionHandle::start(
        Arc::new(config),
        Profile::RawAdmin,
        store,
        Arc::new(Metrics::default()),
    )
    .await
    .unwrap();

    let error = session
        .safe_evaluate(
            MiCommand::new("-interpreter-exec")
                .unwrap()
                .bare("console")
                .unwrap()
                .string("shell sleep 1"),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Timeout);

    tokio::time::timeout(Duration::from_secs(2), async {
        while !session.state().outcome_unknown_tokens.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let restored = session
        .command(
            MiCommand::new("-gdb-show")
                .unwrap()
                .bare("may-write-memory")
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        MiResult::find_str(restored.record.results(), "value"),
        Some("on")
    );
    session.close().await.unwrap();
}

#[tokio::test]
async fn cancelled_operation_skips_queued_observation_commands() {
    let Some(session) = control_test_session().await else {
        return;
    };
    let operation = ActiveOperation::new(OperationId::new(), Arc::new(AtomicBool::new(true)));

    let evaluation = scope_operation(operation.clone(), async {
        session
            .safe_evaluate(
                MiCommand::new("-data-evaluate-expression")
                    .unwrap()
                    .string("1"),
            )
            .await
    })
    .await
    .unwrap_err();
    assert_eq!(evaluation.code, ErrorCode::Cancelled);

    let refresh = scope_operation(operation.clone(), session.refresh_target_capabilities())
        .await
        .unwrap_err();
    assert_eq!(refresh.code, ErrorCode::Cancelled);

    scope_operation(
        operation,
        session.cleanup_command(MiCommand::new("-gdb-version").unwrap()),
    )
    .await
    .unwrap();
    session.close().await.unwrap();
}

#[tokio::test]
async fn expired_capability_refresh_never_reaches_gdb() {
    let Some(session) = control_test_session().await else {
        return;
    };
    let (response, result) = oneshot::channel();
    session
        .requests
        .send(WorkerRequest::RefreshTargetCapabilities {
            operation: None,
            deadline: tokio::time::Instant::now() - Duration::from_millis(1),
            response,
        })
        .await
        .unwrap();

    let error = result.await.unwrap().unwrap_err();
    assert_eq!(error.code, ErrorCode::Timeout);
    session.close().await.unwrap();
}

#[tokio::test]
async fn stale_value_cleanup_does_not_consume_the_business_deadline() {
    if !crate::test_support::require_commands(&["gdb"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let config = Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    };
    let store = Arc::new(Store::open(&config.persistence.sqlite).unwrap());
    let session = SessionHandle::start(
        Arc::new(config),
        Profile::RawAdmin,
        store,
        Arc::new(Metrics::default()),
    )
    .await
    .unwrap();
    session
        .record_event(DomainEvent::InferiorAdded {
            backend_id: "i1".into(),
            pid: Some(1),
        })
        .await
        .unwrap();
    session
        .record_event(DomainEvent::TargetStopped {
            backend_inferior: Some("i1".into()),
            backend_thread: None,
            reason: "breakpoint-hit".into(),
            reason_detail: None,
            frame: None,
        })
        .await
        .unwrap();
    let stop_id = session.state().stop_id.unwrap();
    for index in 0..1_024 {
        session
            .register_value(ValueBinding {
                value_id: crate::domain::ValueId(format!("val_{stop_id}_{index}")),
                backend_name: format!("missing_{index}"),
                stop_id: stop_id.clone(),
                expression: "0".into(),
            })
            .await
            .unwrap();
    }
    session
        .record_event(DomainEvent::TargetRunning {
            backend_inferiors: vec!["i1".into()],
        })
        .await
        .unwrap();
    session
        .record_event(DomainEvent::TargetStopped {
            backend_inferior: Some("i1".into()),
            backend_thread: None,
            reason: "breakpoint-hit".into(),
            reason_detail: None,
            frame: None,
        })
        .await
        .unwrap();

    // 2026-09-01: Reusing this 200 ms business deadline for GDB startup made
    // the CI scheduler fail unrelated setup. Scope it to the command whose
    // stale-value maintenance ordering the test actually verifies.
    session
        .command_with_timeout(
            MiCommand::new("-gdb-version").unwrap(),
            Duration::from_millis(200),
        )
        .await
        .unwrap();
    session.close().await.unwrap();
}

#[tokio::test]
async fn queue_wait_counts_toward_command_deadline() {
    if !crate::test_support::require_commands(&["gdb"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let config = Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    };
    let store = Arc::new(Store::open(&config.persistence.sqlite).unwrap());
    let session = SessionHandle::start(
        Arc::new(config),
        Profile::RawAdmin,
        store,
        Arc::new(Metrics::default()),
    )
    .await
    .unwrap();
    let slow_session = session.clone();
    let slow = tokio::spawn(async move {
        slow_session
            .command_with_timeout(
                MiCommand::new("-interpreter-exec")
                    .unwrap()
                    .bare("console")
                    .unwrap()
                    .string("shell sleep 0.3"),
                Duration::from_secs(1),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let started = std::time::Instant::now();
    let expired = session
        .command_with_timeout(
            MiCommand::new("-gdb-version").unwrap(),
            Duration::from_millis(20),
        )
        .await
        .unwrap_err();
    assert_eq!(expired.code, ErrorCode::Timeout);
    assert!(started.elapsed() < Duration::from_millis(150));
    assert!(session.state().outcome_unknown_tokens.is_empty());
    slow.await.unwrap().unwrap();
    session
        .command(MiCommand::new("-gdb-version").unwrap())
        .await
        .unwrap();
    session.close().await.unwrap();
}

#[tokio::test]
async fn transaction_resume_is_owned_by_its_operation() {
    if !crate::test_support::require_commands(&["gdb", "cc"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let executable = directory.path().join("transaction-resume");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/targets/c/attach.c");
    assert!(
        std::process::Command::new("cc")
            .args(["-g", "-O0"])
            .arg(source)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    let Some(session) = control_test_session().await else {
        return;
    };
    session
        .command(
            MiCommand::new("-target-select")
                .unwrap()
                .bare("native")
                .unwrap(),
        )
        .await
        .unwrap();
    session
        .command(
            MiCommand::new("-file-exec-and-symbols")
                .unwrap()
                .bare(executable.to_string_lossy())
                .unwrap(),
        )
        .await
        .unwrap();

    let operation_id = OperationId::new();
    let operation = ActiveOperation::new(operation_id.clone(), Arc::new(AtomicBool::new(false)));
    let running = session.clone();
    scope_operation(operation, async move {
        running
            .transaction(Vec::new(), MiCommand::new("-exec-run").unwrap(), Vec::new())
            .await
    })
    .await
    .unwrap();

    session
        .cancel_operation(operation_id, OperationCancelMode::InterruptTarget)
        .await
        .unwrap();
    session
        .wait(WaitUntil::Stopped, Duration::from_secs(2))
        .await
        .unwrap();
    session.close().await.unwrap();
}

#[tokio::test]
async fn stable_observation_serializes_ordinary_commands() {
    let Some(session) = control_test_session().await else {
        return;
    };
    let expected = session.state();
    let observing_session = session.clone();
    let (entered_sender, entered) = oneshot::channel();
    let (release_sender, release) = oneshot::channel();
    let observation = tokio::spawn(async move {
        observing_session
            .stable_observation(
                &expected,
                Box::pin(async {
                    observing_session
                        .command(MiCommand::new("-gdb-version").unwrap())
                        .await?;
                    let _ = entered_sender.send(());
                    let _ = release.await;
                    Ok(())
                }),
            )
            .await
    });
    entered.await.unwrap();

    let competing_session = session.clone();
    let competing = tokio::spawn(async move {
        competing_session
            .command(MiCommand::new("-gdb-version").unwrap())
            .await
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!competing.is_finished());

    release_sender.send(()).unwrap();
    observation.await.unwrap().unwrap();
    competing.await.unwrap().unwrap();
    session.close().await.unwrap();
}

#[tokio::test]
async fn stable_observation_admission_obeys_command_deadline() {
    let Some(session) = control_test_session().await else {
        return;
    };
    let sequence = session.command_sequence.lock().await;
    let mut waiting = session.clone();
    waiting.command_timeout = Duration::from_millis(20);
    let expected = waiting.state();
    let started = std::time::Instant::now();

    let error = waiting
        .stable_observation(&expected, Box::pin(async { Ok(()) }))
        .await
        .unwrap_err();

    assert_eq!(error.code, ErrorCode::Timeout);
    assert!(started.elapsed() < Duration::from_millis(150));
    drop(sequence);
    session.close().await.unwrap();
}

#[tokio::test]
async fn stale_snapshot_commit_leaves_no_snapshot() {
    let Some(session) = control_test_session().await else {
        return;
    };
    let error = session
        .commit_snapshot(
            "snap_invalid".into(),
            serde_json::json!({"snapshot_id": "snap_invalid"}),
            StopId("stop_missing".into()),
            session.state().execution_epoch,
            false,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::StaleContext);
    assert_eq!(
        session
            .snapshot("snap_invalid".into())
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    session.close().await.unwrap();
}

#[tokio::test]
async fn stable_observation_rejects_a_preempting_state_change() {
    let Some(session) = control_test_session().await else {
        return;
    };
    let expected = session.state();
    let observing_session = session.clone();
    let (entered_sender, entered) = oneshot::channel();
    let (release_sender, release) = oneshot::channel();
    let observation = tokio::spawn(async move {
        observing_session
            .stable_observation(
                &expected,
                Box::pin(async {
                    let _ = entered_sender.send(());
                    let _ = release.await;
                    Ok(())
                }),
            )
            .await
    });
    entered.await.unwrap();
    session
        .record_event(DomainEvent::TargetRunning {
            backend_inferiors: vec![],
        })
        .await
        .unwrap();
    release_sender.send(()).unwrap();

    assert_eq!(
        observation.await.unwrap().unwrap_err().code,
        ErrorCode::StaleContext
    );
    session.close().await.unwrap();
}

#[tokio::test]
async fn interrupt_preempts_blocked_command() {
    let Some(session) = control_test_session().await else {
        return;
    };
    let slow_session = session.clone();
    let slow = tokio::spawn(async move {
        slow_session
            .command_with_timeout(
                MiCommand::new("-interpreter-exec")
                    .unwrap()
                    .bare("console")
                    .unwrap()
                    .string("shell sleep 5"),
                Duration::from_secs(10),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let started = std::time::Instant::now();
    let interrupt = session
        .interrupt(MiCommand::new("-exec-interrupt").unwrap())
        .await;
    assert!(started.elapsed() < Duration::from_secs(2));
    if let Err(error) = interrupt {
        assert_eq!(error.code, ErrorCode::GdbError);
    }
    tokio::time::timeout(Duration::from_secs(2), slow)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    session.close().await.unwrap();
}

#[tokio::test]
async fn close_preempts_blocked_command() {
    let Some(session) = control_test_session().await else {
        return;
    };
    let slow_session = session.clone();
    let slow = tokio::spawn(async move {
        slow_session
            .command_with_timeout(
                MiCommand::new("-interpreter-exec")
                    .unwrap()
                    .bare("console")
                    .unwrap()
                    .string("shell sleep 10"),
                Duration::from_secs(20),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let started = std::time::Instant::now();
    session.close().await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(
        session.state().lifecycle,
        crate::domain::SessionLifecycle::Closed
    );
    let error = tokio::time::timeout(Duration::from_secs(1), slow)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::GdbExited);
}

#[tokio::test]
async fn loads_hash_pinned_python_extension() {
    let python_enabled = std::process::Command::new("gdb")
        .arg("--configuration")
        .output()
        .ok()
        .is_some_and(|output| String::from_utf8_lossy(&output.stdout).contains("--with-python"));
    if !python_enabled {
        // 2026-08-29: Required CI previously skipped extension loading when
        // its GDB lacked Python, hiding a missing release prerequisite.
        if std::env::var_os("GDB_AI_REQUIRE_INTEGRATION").is_some() {
            panic!("required GDB Python support is unavailable");
        }
        eprintln!("skipped GDB Python extension test; Python support is unavailable");
        return;
    }
    let directory = tempdir().unwrap();
    let extension = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../gdb-extension/gdb_ai.py")
        .canonicalize()
        .unwrap();
    let digest = format!("{:x}", Sha256::digest(std::fs::read(&extension).unwrap()));
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
    config.gdb.python_extension = Some(extension);
    config.gdb.python_extension_sha256 = Some(digest);
    let store = Arc::new(Store::open(&config.persistence.sqlite).unwrap());
    let session = SessionHandle::start(
        Arc::new(config),
        Profile::DebugControl,
        store,
        Arc::new(Metrics::default()),
    )
    .await
    .unwrap();
    assert!(session.capabilities().supports("custom_extension"));
    session.close().await.unwrap();
}

#[tokio::test]
async fn starts_compatible_mi3_backend() {
    if !crate::test_support::require_commands(&["gdb"]) {
        return;
    }
    let directory = tempdir().unwrap();
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
    config.gdb.preferred_mi = "mi99".into();
    config.gdb.fallback_mi = "mi3".into();
    let store = Arc::new(Store::open(&config.persistence.sqlite).unwrap());
    let session = SessionHandle::start(
        Arc::new(config),
        Profile::DebugControl,
        store,
        Arc::new(Metrics::default()),
    )
    .await
    .unwrap();
    assert_eq!(session.capabilities().backend.mi_version, "mi3");
    session.close().await.unwrap();
}
