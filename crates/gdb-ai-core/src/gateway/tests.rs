use serde_json::json;
use tempfile::tempdir;

use super::*;
use crate::config::{ArtifactConfig, PersistenceConfig};

#[tokio::test]
async fn expired_lease_keeps_owner_cleanup_reachable() {
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
    config.server.write_lease_ms = 1;
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("lease-test");
    let created = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "create".into(),
                session_id: None,
                method: crate::protocol::CanonicalMethod::SessionCreate,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &caller,
        )
        .await;
    let session_id = created.session_id.clone().unwrap();
    let lease_id = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let rejected = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "close".into(),
                session_id: Some(session_id.clone()),
                method: crate::protocol::CanonicalMethod::SessionClose,
                expected_revision: created.revision,
                idempotency_key: None,
                parameters: json!({"lease_id": lease_id}),
            },
            &caller,
        )
        .await;
    assert_eq!(rejected.error.unwrap().code, ErrorCode::WriteLeaseExpired);

    gateway
        .entry(&session_id)
        .await
        .unwrap()
        .handle
        .record_event(crate::domain::DomainEvent::CommandOutcomeUnknown { token: 99 })
        .await
        .unwrap();
    let renewed = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "renew-unknown".into(),
                session_id: Some(session_id.clone()),
                method: crate::protocol::CanonicalMethod::SessionAcquireWriteLease,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({"accept_latest_revision": true}),
            },
            &caller,
        )
        .await;
    assert!(renewed.error.is_none(), "{:?}", renewed.error);

    let denied = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "foreign-abort".into(),
                session_id: Some(session_id.clone()),
                method: crate::protocol::CanonicalMethod::SessionForceAbort,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &Caller::local("different-owner"),
        )
        .await;
    assert_eq!(denied.error.unwrap().code, ErrorCode::PolicyDenied);

    let aborted = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "force-abort".into(),
                session_id: Some(session_id),
                method: crate::protocol::CanonicalMethod::SessionForceAbort,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &caller,
        )
        .await;
    assert!(aborted.error.is_none(), "{:?}", aborted.error);
    assert_eq!(aborted.result.unwrap()["clean_shutdown"], false);
    assert!(gateway.sessions.read().await.is_empty());
}

#[tokio::test]
async fn active_owner_mutation_refreshes_lease_near_half_life() {
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
    config.server.write_lease_ms = 10_000;
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("lease-refresh-test");
    let created = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "create-refresh-test".into(),
                session_id: None,
                method: crate::protocol::CanonicalMethod::SessionCreate,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &caller,
        )
        .await;
    let session_id = created.session_id.unwrap();
    let entry = gateway.entry(&session_id).await.unwrap();
    let shortened_expiry = now_unix_ms().saturating_add(1_000);
    let lease_id = {
        let mut lease = entry.lease.lock().await;
        let lease = lease.as_mut().unwrap();
        lease.expires_at_unix_ms = shortened_expiry;
        lease.lease_id.0.clone()
    };
    let state = entry.handle.state();
    gateway
        .require_mutation_preconditions(
            &ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "refresh-test".into(),
                session_id: Some(session_id.clone()),
                method: crate::protocol::CanonicalMethod::SessionClose,
                expected_revision: Some(state.revision),
                idempotency_key: None,
                parameters: json!({"lease_id": lease_id}),
            },
            &caller,
            &entry,
            &state,
        )
        .await
        .unwrap();
    assert!(
        entry
            .lease
            .lock()
            .await
            .as_ref()
            .unwrap()
            .expires_at_unix_ms
            > shortened_expiry
    );

    let aborted = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "abort-refresh-test".into(),
                session_id: Some(session_id),
                method: crate::protocol::CanonicalMethod::SessionForceAbort,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &caller,
        )
        .await;
    assert!(aborted.error.is_none(), "{:?}", aborted.error);
}

#[tokio::test]
async fn lost_session_recovery_does_not_require_a_business_lease() {
    if !crate::test_support::require_commands(&["gdb"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let gateway = Gateway::new(Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    })
    .unwrap();
    let caller = Caller::local("recovery-test");
    let created = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "create-recovery".into(),
                session_id: None,
                method: crate::protocol::CanonicalMethod::SessionCreate,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &caller,
        )
        .await;
    let session_id = created.session_id.unwrap();
    let entry = gateway.entry(&session_id).await.unwrap();
    entry.lease.lock().await.take();
    gateway.store.delete_lease(entry.handle.id()).unwrap();
    entry
        .handle
        .record_event(crate::domain::DomainEvent::ConsistencyLost {
            reason: "test recovery authority".into(),
        })
        .await
        .unwrap();

    let recovered = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "recover".into(),
                session_id: Some(session_id.clone()),
                method: crate::protocol::CanonicalMethod::SessionAttemptRecovery,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &caller,
        )
        .await;
    assert!(recovered.error.is_none(), "{:?}", recovered.error);

    let aborted = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "cleanup".into(),
                session_id: Some(session_id),
                method: crate::protocol::CanonicalMethod::SessionForceAbort,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &caller,
        )
        .await;
    assert!(aborted.error.is_none(), "{:?}", aborted.error);
}

#[tokio::test]
async fn lease_cleanup_failure_does_not_retain_a_closed_session() {
    if !crate::test_support::require_commands(&["gdb"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let sqlite = directory.path().join("state.sqlite");
    let mut config = Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: sqlite.clone(),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    };
    config.server.max_sessions = 1;
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("cleanup-test");
    let created = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "create-cleanup".into(),
                session_id: None,
                method: crate::protocol::CanonicalMethod::SessionCreate,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &caller,
        )
        .await;
    let session_id = created.session_id.unwrap();
    let retained = gateway.entry(&session_id).await.unwrap();
    rusqlite::Connection::open(sqlite)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_lease_cleanup BEFORE DELETE ON leases
             BEGIN SELECT RAISE(ABORT, 'injected lease cleanup failure'); END;",
        )
        .unwrap();

    let closed = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "force-cleanup".into(),
                session_id: Some(session_id),
                method: crate::protocol::CanonicalMethod::SessionForceAbort,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &caller,
        )
        .await;

    assert!(closed.error.is_none(), "{:?}", closed.error);
    assert_eq!(
        closed.result.unwrap()["warnings"][0]["code"],
        "LEASE_CLEANUP_FAILED"
    );
    assert!(gateway.sessions.read().await.is_empty());
    let replacement = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "replacement-after-cleanup".into(),
                session_id: None,
                method: crate::protocol::CanonicalMethod::SessionCreate,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &caller,
        )
        .await;
    assert!(replacement.error.is_none(), "{:?}", replacement.error);
    drop(retained);
    gateway.shutdown().await;
}

#[tokio::test]
async fn completion_audit_failure_preserves_an_executed_mutation() {
    if !crate::test_support::require_commands(&["gdb"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let sqlite = directory.path().join("state.sqlite");
    let gateway = Gateway::new(Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: sqlite.clone(),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    })
    .unwrap();
    let caller = Caller::local("audit-test");
    let created = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "create-audit".into(),
                session_id: None,
                method: crate::protocol::CanonicalMethod::SessionCreate,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &caller,
        )
        .await;
    let session_id = created.session_id.unwrap();
    rusqlite::Connection::open(sqlite)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_completion_audit BEFORE INSERT ON audit
             WHEN NEW.outcome = 'completed'
             BEGIN SELECT RAISE(ABORT, 'injected completion audit failure'); END;",
        )
        .unwrap();

    let renewed = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "renew-audit".into(),
                session_id: Some(session_id),
                method: crate::protocol::CanonicalMethod::SessionAcquireWriteLease,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({"accept_latest_revision": true}),
            },
            &caller,
        )
        .await;

    assert!(renewed.error.is_none(), "{:?}", renewed.error);
    assert!(
        renewed
            .warnings
            .iter()
            .any(|warning| warning.code == "AUDIT_COMPLETION_FAILED")
    );
    gateway.shutdown().await;
}

#[tokio::test]
async fn failed_lease_release_keeps_the_live_lease() {
    if !crate::test_support::require_commands(&["gdb"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let sqlite = directory.path().join("state.sqlite");
    let gateway = Gateway::new(Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: sqlite.clone(),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    })
    .unwrap();
    let caller = Caller::local("lease-release-test");
    let created = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "create-release-test".into(),
                session_id: None,
                method: crate::protocol::CanonicalMethod::SessionCreate,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &caller,
        )
        .await;
    let session_id = created.session_id.unwrap();
    let lease_id = created.result.unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap()
        .to_owned();
    rusqlite::Connection::open(sqlite)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_lease_delete BEFORE DELETE ON leases
             BEGIN SELECT RAISE(ABORT, 'injected lease delete failure'); END;",
        )
        .unwrap();

    let released = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "release-test".into(),
                session_id: Some(session_id.clone()),
                method: crate::protocol::CanonicalMethod::SessionReleaseWriteLease,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({
                    "accept_latest_revision": true,
                    "lease_id": lease_id
                }),
            },
            &caller,
        )
        .await;

    assert!(released.error.is_some());
    assert!(
        gateway
            .entry(&session_id)
            .await
            .unwrap()
            .lease
            .lock()
            .await
            .is_some()
    );
    gateway.shutdown().await;
}

#[tokio::test]
async fn concurrent_idempotent_create_runs_once() {
    if !crate::test_support::require_commands(&["gdb"]) {
        return;
    }
    let directory = tempdir().unwrap();
    let gateway = Gateway::new(Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    })
    .unwrap();
    let caller = Caller::local("idempotency-test");
    let request = ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "create".into(),
        session_id: None,
        method: crate::protocol::CanonicalMethod::SessionCreate,
        expected_revision: None,
        idempotency_key: Some("same-create".into()),
        parameters: json!({}),
    };
    let (first, second) = tokio::join!(
        gateway.dispatch(request.clone(), &caller),
        gateway.dispatch(request, &caller)
    );
    assert_eq!(first.session_id, second.session_id);
    assert_eq!(gateway.sessions.read().await.len(), 1);
    let conflicting = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "changed-retry".into(),
                session_id: None,
                method: crate::protocol::CanonicalMethod::SessionCreate,
                expected_revision: Some(99),
                idempotency_key: Some("same-create".into()),
                parameters: json!({}),
            },
            &caller,
        )
        .await;
    assert_eq!(conflicting.error.unwrap().code, ErrorCode::Conflict);
    assert_eq!(gateway.sessions.read().await.len(), 1);
    gateway.shutdown().await;
}

#[tokio::test]
async fn concurrent_creates_respect_the_session_limit() {
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
    config.server.max_sessions = 1;
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("limit-test");
    let create = |request_id: &str| ApiRequest {
        api_version: API_VERSION.into(),
        request_id: request_id.into(),
        session_id: None,
        method: crate::protocol::CanonicalMethod::SessionCreate,
        expected_revision: None,
        idempotency_key: None,
        parameters: json!({}),
    };
    let (first, second) = tokio::join!(
        gateway.dispatch(create("first"), &caller),
        gateway.dispatch(create("second"), &caller)
    );
    assert_eq!(gateway.sessions.read().await.len(), 1);
    assert_eq!(
        [first, second]
            .into_iter()
            .filter_map(|response| response.error)
            .map(|error| error.code)
            .collect::<Vec<_>>(),
        vec![ErrorCode::Conflict]
    );
    gateway.shutdown().await;
}

#[tokio::test]
async fn isolates_active_and_persisted_sessions_by_principal() {
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
    let gateway = Gateway::new(config.clone()).unwrap();
    let alice = Caller::local("alice");
    let bob = Caller::local("bob");
    let created = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "create-owned".into(),
                session_id: None,
                method: crate::protocol::CanonicalMethod::SessionCreate,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &alice,
        )
        .await;
    let session_id = created.session_id.clone().unwrap();
    let read = |request_id: &str| ApiRequest {
        api_version: API_VERSION.into(),
        request_id: request_id.into(),
        session_id: Some(session_id.clone()),
        method: crate::protocol::CanonicalMethod::SessionGet,
        expected_revision: None,
        idempotency_key: None,
        parameters: json!({}),
    };
    assert_eq!(
        gateway
            .dispatch(read("bob-active"), &bob)
            .await
            .error
            .unwrap()
            .code,
        ErrorCode::PolicyDenied
    );
    gateway.shutdown().await;
    drop(gateway);

    let reopened = Gateway::new(config).unwrap();
    assert!(
        reopened
            .dispatch(read("alice-closed"), &alice)
            .await
            .error
            .is_none()
    );
    let transcript = ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "alice-transcript".into(),
        session_id: Some(session_id.clone()),
        method: crate::protocol::CanonicalMethod::SessionTranscript,
        expected_revision: None,
        idempotency_key: None,
        parameters: json!({"max_bytes": 1024}),
    };
    assert!(reopened.dispatch(transcript, &alice).await.error.is_none());
    assert_eq!(
        reopened
            .dispatch(read("bob-closed"), &bob)
            .await
            .error
            .unwrap()
            .code,
        ErrorCode::PolicyDenied
    );
}

#[tokio::test]
async fn restart_marks_persisted_live_session_failed() {
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
    let session_id = crate::domain::SessionId("sess_abandoned".into());
    let mut state = crate::domain::SessionState::creating(session_id.clone());
    state.lifecycle = crate::domain::SessionLifecycle::Active;
    state.backend = crate::domain::BackendHealth::Healthy;
    let store = Store::open_with_storage(&config.persistence.sqlite, &config.storage).unwrap();
    store
        .upsert_session(&state, crate::policy::Profile::DebugControl)
        .unwrap();
    store
        .set_session_owner(&session_id, "restart-test")
        .unwrap();
    drop(store);

    let gateway = Gateway::new(config).unwrap();
    let response = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "list-after-restart".into(),
                session_id: None,
                method: crate::protocol::CanonicalMethod::SessionList,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &Caller::local("restart-test"),
        )
        .await;
    let state = &response.result.unwrap()[0];
    assert_eq!(state["lifecycle"], "FAILED");
    assert_eq!(state["backend"], "DEAD");
}

#[test]
fn bounds_the_complete_response_envelope() {
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
    config.limits.tool_response_bytes = 1_024;
    let gateway = Gateway::new(config).unwrap();
    gateway
        .store
        .set_session_owner(&crate::domain::SessionId("sess_bound".into()), "test")
        .unwrap();
    let request = ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "bounded".into(),
        session_id: Some("sess_bound".into()),
        method: crate::protocol::CanonicalMethod::SessionGet,
        expected_revision: None,
        idempotency_key: None,
        parameters: json!({}),
    };
    let mut state =
        crate::domain::SessionState::creating(crate::domain::SessionId("sess_bound".into()));
    state.limitations = vec!["x".repeat(1_024); 8];
    let mut response = ApiResponse::success(&request, Some(state), json!({"x": "y"}));
    gateway.bound_response(&request, &mut response);
    assert!(serde_json::to_vec(&response).unwrap().len() <= 1_024);
    assert!(response.truncated);
    assert_eq!(response.artifacts.len(), 1);
}

#[test]
fn removes_nested_exact_state_duplicates_before_bounding() {
    let directory = tempdir().unwrap();
    let mut request = ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "deduplicate".into(),
        session_id: Some("sess_deduplicate".into()),
        method: crate::protocol::CanonicalMethod::SessionGet,
        expected_revision: None,
        idempotency_key: None,
        parameters: json!({}),
    };
    let mut state =
        crate::domain::SessionState::creating(crate::domain::SessionId("sess_deduplicate".into()));
    state.limitations.push("x".repeat(2_048));
    let mut root = ApiResponse::success(&request, Some(state.clone()), json!(state.clone()));
    remove_repeated_state(&mut root);
    assert!(root.state.is_some());
    assert_eq!(root.result, Some(json!(state.clone())));

    request.method = crate::protocol::CanonicalMethod::TargetLaunch;
    let mut response = ApiResponse::success(
        &request,
        Some(state.clone()),
        json!({"state": state, "start_policy": "none"}),
    );
    let mut single = response.clone();
    single
        .result
        .as_mut()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("state");
    let inline_size = serde_json::to_vec(&single).unwrap().len() + 64;
    assert!(serde_json::to_vec(&response).unwrap().len() > inline_size);
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
    config.limits.tool_response_bytes = inline_size;
    let gateway = Gateway::new(config).unwrap();

    gateway.bound_response(&request, &mut response);

    assert!(response.state.is_some());
    assert!(response.result.as_ref().unwrap().get("state").is_none());
    assert_eq!(response.result.as_ref().unwrap()["start_policy"], "none");
    assert!(!response.truncated);
}

#[test]
fn bounds_the_fallback_when_artifact_publication_fails() {
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
    config.limits.tool_response_bytes = 1_024;
    config.limits.session_artifact_bytes = 1_024;
    config.limits.owner_artifact_bytes = 1_024;
    config.limits.total_artifact_bytes = 1_024;
    config.output.max_bytes = 1_024;
    let gateway = Gateway::new(config).unwrap();
    let request = ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "bounded-fallback".into(),
        session_id: None,
        method: crate::protocol::CanonicalMethod::SessionList,
        expected_revision: None,
        idempotency_key: None,
        parameters: json!({}),
    };
    let mut response = ApiResponse::success(&request, None, json!({"large": "x".repeat(2_048)}));
    response.artifacts = vec!["a".repeat(1_024); 4];

    gateway.bound_response(&request, &mut response);

    assert!(serde_json::to_vec(&response).unwrap().len() <= 1_024);
    assert!(response.artifacts.is_empty());
    assert!(response.truncated);
}

#[test]
fn rejects_unknown_or_wrong_typed_method_parameters() {
    let directory = tempdir().unwrap();
    let gateway = Gateway::new(Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    })
    .unwrap();
    let request = |parameters| ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "invalid-parameters".into(),
        session_id: Some("sess_test".into()),
        method: crate::protocol::CanonicalMethod::MemoryRead,
        expected_revision: None,
        idempotency_key: None,
        parameters,
    };
    assert!(
        gateway
            .validate_request(&request(json!({
                "address": "0x1000",
                "length": 16,
                "stop_id": "stop_test",
                "lenght": 16
            })))
            .is_err()
    );
    assert!(
        gateway
            .validate_request(&request(json!({
                "address": "0x1000",
                "length": "16",
                "stop_id": "stop_test"
            })))
            .is_err()
    );
}

#[test]
fn classifies_linux_memory_ranges_without_client_input() {
    let maps = concat!(
        "00400000-00410000 r-xp 00000000 08:01 1 /workspace/target\n",
        "00410000-00411000 r--p 00010000 08:01 1 /workspace/target\n",
        "70000000-70001000 rw-s 00000000 00:05 2 /dev/uio0\n",
        "70001000-70002000 rw-p 00000000 00:00 0\n",
    );
    assert_eq!(
        classify_linux_maps(maps, 0x0040_0100, 0x0040_0200),
        MemoryRangeEffect::Ordinary
    );
    assert_eq!(
        classify_linux_maps(maps, 0x7000_0000, 0x7000_0004),
        MemoryRangeEffect::Volatile
    );
    assert_eq!(
        classify_linux_maps(maps, 0x5000_0000, 0x5000_0004),
        MemoryRangeEffect::Unknown
    );
    assert_eq!(
        classify_linux_maps(maps, 0x0040_ffff, 0x0040_ffff),
        MemoryRangeEffect::Ordinary
    );
    assert_eq!(
        classify_linux_maps(maps, 0x0040_ffff, 0x0041_0000),
        MemoryRangeEffect::Ordinary
    );
    assert_eq!(
        classify_linux_maps(maps, 0x0041_1000, 0x0041_1000),
        MemoryRangeEffect::Unknown
    );
    assert_eq!(
        classify_linux_maps(maps, 0x7000_0fff, 0x7000_1000),
        MemoryRangeEffect::Volatile
    );

    let mut state = SessionState::creating(crate::domain::SessionId("sess_effect".into()));
    let request = ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "effect".into(),
        session_id: Some("sess_effect".into()),
        method: crate::protocol::CanonicalMethod::MemoryRead,
        expected_revision: None,
        idempotency_key: None,
        parameters: json!({"address": "0x400000", "length": 4}),
    };
    state.target_origin = TargetOrigin::Remote;
    assert_eq!(
        classify_memory_range(&state, &request).unwrap(),
        MemoryRangeEffect::Unknown
    );
    state.target_origin = TargetOrigin::Core;
    assert_eq!(
        classify_memory_range(&state, &request).unwrap(),
        MemoryRangeEffect::Ordinary
    );
    let mut final_byte = request;
    final_byte.parameters = json!({"address": "0xffffffffffffffff", "length": 1});
    assert_eq!(
        classify_memory_range(&state, &final_byte).unwrap(),
        MemoryRangeEffect::Ordinary
    );
    final_byte.parameters["length"] = json!(2);
    assert_eq!(
        classify_memory_range(&state, &final_byte).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn inline_probe_input_is_a_target_mutation() {
    let mut request = ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "probe-effect".into(),
        session_id: Some("sess_effect".into()),
        method: crate::protocol::CanonicalMethod::AgentProbe,
        expected_revision: None,
        idempotency_key: None,
        parameters: json!({}),
    };
    assert_eq!(effect_for_request(&request), Effect::Control);
    request.parameters = json!({"input": {"text": "x"}});
    assert_eq!(effect_for_request(&request), Effect::TargetMutation);

    request.method = crate::protocol::CanonicalMethod::ValueEvaluate;
    request.parameters = json!({"expression": "$pc"});
    assert_eq!(effect_for_request(&request), Effect::Read);
    request.parameters["side_effects"] = json!("allow");
    assert_eq!(effect_for_request(&request), Effect::TargetMutation);
}

#[test]
fn every_session_method_rejects_a_missing_session_id() {
    let directory = tempdir().unwrap();
    let gateway = Gateway::new(Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    })
    .unwrap();

    for method in crate::protocol::CanonicalMethod::ALL
        .iter()
        .copied()
        .filter(|method| method.requires_session())
    {
        let error = gateway
            .validate_request(&ApiRequest {
                api_version: API_VERSION.into(),
                request_id: format!("missing-session-{method}"),
                session_id: None,
                method,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            })
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument, "{method}");
        assert_eq!(error.message, "method requires session_id", "{method}");
    }
}

#[tokio::test]
async fn idempotency_lock_cleanup_preserves_live_waiters_and_replacements() {
    let directory = tempdir().unwrap();
    let gateway = Gateway::new(Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    })
    .unwrap();
    let key = "same-request";
    let original = Arc::new(Mutex::new(()));
    gateway
        .idempotency_locks
        .lock()
        .await
        .insert(key.into(), original.clone());

    let waiter = original.clone();
    gateway.release_idempotency_lock(key, &original).await;
    assert!(gateway.idempotency_locks.lock().await.contains_key(key));
    drop(waiter);
    gateway.release_idempotency_lock(key, &original).await;
    assert!(!gateway.idempotency_locks.lock().await.contains_key(key));

    let replacement = Arc::new(Mutex::new(()));
    gateway
        .idempotency_locks
        .lock()
        .await
        .insert(key.into(), replacement.clone());
    gateway.release_idempotency_lock(key, &original).await;
    assert!(Arc::ptr_eq(
        &gateway.idempotency_locks.lock().await[key],
        &replacement
    ));
}

#[test]
fn borrowed_idempotency_fingerprint_preserves_the_wire_hash() {
    let request = ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "retry-2".into(),
        session_id: Some("sess_test".into()),
        method: crate::protocol::CanonicalMethod::MemoryWrite,
        expected_revision: Some(7),
        idempotency_key: Some("write-once".into()),
        parameters: json!({"address": "0x1000", "data_base64": "AA=="}),
    };
    let mut legacy = request.clone();
    legacy.request_id.clear();
    legacy.idempotency_key = None;
    let expected = format!("{:x}", Sha256::digest(serde_json::to_vec(&legacy).unwrap()));

    assert_eq!(idempotency_fingerprint(&request), expected);
}

#[tokio::test]
async fn shutdown_closes_session_admission() {
    let directory = tempdir().unwrap();
    let gateway = Gateway::new(Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    })
    .unwrap();
    gateway.shutdown().await;

    let response = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "create-after-shutdown".into(),
                session_id: None,
                method: crate::protocol::CanonicalMethod::SessionCreate,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &Caller::local("shutdown-test"),
        )
        .await;
    assert_eq!(response.error.unwrap().code, ErrorCode::InvalidState);
    assert!(gateway.sessions.read().await.is_empty());
}

#[tokio::test]
async fn stable_read_for_unknown_session_returns_not_found() {
    let directory = tempdir().unwrap();
    let gateway = Gateway::new(Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    })
    .unwrap();
    let response = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "unknown-session-read".into(),
                session_id: Some("sess_missing".into()),
                method: crate::protocol::CanonicalMethod::MemoryRead,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({
                    "address": "0x1000",
                    "length": 16,
                    "stop_id": "stop_missing"
                }),
            },
            &Caller::local("missing-session-test"),
        )
        .await;
    assert_eq!(response.error.unwrap().code, ErrorCode::NotFound);
}

#[tokio::test]
async fn mcp_client_labels_share_principal_limits_and_idempotency() {
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
    config.server.requests_per_second = 1;
    config.server.request_burst = 0;
    let gateway = Gateway::new(config).unwrap();
    let first = Caller::local("mcp-http/mcp:first");
    let second = Caller::local("mcp-http/mcp:second");

    gateway.check_rate(&first.identity).await.unwrap();
    assert_eq!(
        gateway.check_rate(&second.identity).await.unwrap_err().code,
        ErrorCode::Conflict
    );

    let request = ApiRequest {
        api_version: API_VERSION.into(),
        request_id: "principal-key".into(),
        session_id: None,
        method: crate::protocol::CanonicalMethod::SessionList,
        expected_revision: None,
        idempotency_key: Some("same".into()),
        parameters: json!({}),
    };
    assert_eq!(
        idempotency_key(&request, &first),
        idempotency_key(&request, &second)
    );
}

#[tokio::test]
async fn ordinary_reads_do_not_duplicate_journal_evidence_in_sqlite() {
    let directory = tempdir().unwrap();
    let gateway = Gateway::new(Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    })
    .unwrap();
    let response = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "list-without-audit".into(),
                session_id: None,
                method: crate::protocol::CanonicalMethod::SessionList,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &Caller::local("read-test"),
        )
        .await;

    assert!(response.error.is_none());
    assert_eq!(gateway.store.audit_counts().unwrap(), (0, 0));
}
