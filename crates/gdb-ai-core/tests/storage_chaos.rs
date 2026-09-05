use gdb_ai_core::{
    ErrorCode,
    config::{ArtifactConfig, Config, JournalDurability, PersistenceConfig},
    domain::SessionLifecycle,
    gateway::{Caller, Gateway},
    protocol::{API_VERSION, ApiRequest},
    replay::replay,
};
use serde_json::{Value, json};
use tempfile::tempdir;

mod support;

#[tokio::test]
async fn persistence_failures_preserve_debugging_unless_durability_is_required() {
    if !support::require_commands(&["gdb"]) {
        return;
    }

    for (durability, fill_journal) in [
        (JournalDurability::Performance, true),
        (JournalDurability::Durable, true),
        (JournalDurability::Performance, false),
    ] {
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
        config.security.workspace_roots = vec!["/".into()];
        config.limits.journal_bytes = 256 * 1024;
        config.journal.durability = durability;
        let gateway = Gateway::new(config).unwrap();
        let caller = Caller {
            identity: "history-test".into(),
            admin: true,
        };
        let call = async |session_id: Option<&str>, method: &str, parameters: Value| {
            gateway
                .dispatch_agent(
                    ApiRequest {
                        api_version: API_VERSION.into(),
                        request_id: method.into(),
                        session_id: session_id.map(str::to_owned),
                        method: method.parse().unwrap(),
                        expected_revision: None,
                        idempotency_key: None,
                        parameters,
                    },
                    &caller,
                )
                .await
        };
        let created = call(None, "session.create", json!({})).await;
        assert!(created.error.is_none(), "{:?}", created.error);
        let session_id = created.session_id.unwrap();
        let session = Some(session_id.as_str());
        let launched = call(
            session,
            "target.launch",
            json!({
                "program": "/bin/true", "stop": "first_instruction"
            }),
        )
        .await;
        assert!(launched.error.is_none(), "{:?}", launched.error);
        let stopped = launched.state.unwrap();
        let connection = rusqlite::Connection::open(directory.path().join("state.sqlite")).unwrap();
        if !fill_journal {
            connection.execute_batch(
                "CREATE TRIGGER fail_state BEFORE UPDATE ON sessions BEGIN SELECT RAISE(FAIL, 'storage fault'); END;
                 CREATE TRIGGER fail_snapshot BEFORE INSERT ON snapshots BEGIN SELECT RAISE(FAIL, 'storage fault'); END;
                 CREATE TRIGGER fail_operation BEFORE INSERT ON operations BEGIN SELECT RAISE(FAIL, 'storage fault'); END;"
            ).unwrap();
        }
        let recorded = if fill_journal {
            call(
                session,
                "raw.console",
                json!({"command": "printf \"%262144s\", \"x\""}),
            )
            .await
        } else {
            call(session, "session.transcript", json!({"max_bytes": 128})).await
        };
        if durability == JournalDurability::Durable {
            assert_eq!(recorded.error.unwrap().code, ErrorCode::OutputLimit);
            assert_eq!(recorded.state.unwrap().lifecycle, SessionLifecycle::Failed);
            gateway.shutdown().await;
            continue;
        }
        assert!(recorded.error.is_none(), "{:?}", recorded.error);
        let current = call(session, "session.get", json!({})).await.state.unwrap();
        assert_eq!(current.stop_id, stopped.stop_id);
        assert!(
            current
                .limitations
                .iter()
                .any(|reason| reason.starts_with("evidence gap: "))
        );
        let snapshot_id = current.snapshot.as_ref().unwrap().snapshot_id.clone();
        let snapshot = call(
            session,
            "inspection.snapshot_get",
            json!({"snapshot_id": snapshot_id}),
        )
        .await;
        assert!(snapshot.error.is_none(), "{:?}", snapshot.error);
        let continued = call(
            session,
            "execution.control",
            json!({
                "action": "continue", "wait": {"until": "accepted", "timeout_ms": 5000}
            }),
        )
        .await;
        assert!(continued.error.is_none(), "{:?}", continued.error);
        let waited = call(
            session,
            "execution.wait",
            json!({
                "operation_id": continued.result.unwrap()["operation_id"],
                "wait": {"until": "settled", "timeout_ms": 5000}
            }),
        )
        .await;
        assert!(waited.error.is_none(), "{:?}", waited.error);
        assert_eq!(waited.result.unwrap()["settled_by"], "exited");
        let final_seq = waited.state.unwrap().event_seq;
        assert!(final_seq > current.event_seq);
        let closed = call(session, "session.close", json!({})).await;
        assert!(closed.error.is_none(), "{:?}", closed.error);
        let retained = call(session, "session.get", json!({})).await;
        assert_eq!(retained.result.unwrap()["lifecycle"], "CLOSED");
        let listed = call(None, "session.list", json!({})).await;
        assert_eq!(listed.result.unwrap()[0]["lifecycle"], "CLOSED");
        let journal_path = directory
            .path()
            .join("sessions")
            .join(&session_id)
            .join("journal.jsonl");
        let replayed = replay(
            &journal_path,
            gdb_ai_core::domain::SessionId::parse(&session_id).unwrap(),
        )
        .unwrap();
        assert_eq!(replayed.complete, !fill_journal);
        assert_eq!(replayed.evidence_gap.is_some(), fill_journal);
        assert!(std::fs::metadata(&journal_path).unwrap().len() <= 256 * 1024);
        let transcript = call(session, "session.transcript", json!({"max_bytes": 128})).await;
        assert!(transcript.error.is_none(), "{:?}", transcript.error);
        assert!(
            transcript
                .warnings
                .iter()
                .any(|warning| warning.code == "EVIDENCE_GAP")
        );
        if let Some(gap) = replayed.evidence_gap {
            let first = call(session, "session.event", json!({"event_seq": 1})).await;
            assert_eq!(first.result.unwrap()["type"], "session.created");
            for seq in [gap.from_seq, final_seq] {
                let missing = call(session, "session.event", json!({"event_seq": seq})).await;
                assert_eq!(missing.error.unwrap().code, ErrorCode::EventGap);
            }
            let journal = std::fs::read_to_string(&journal_path).unwrap();
            let mut lines: Vec<_> = journal.lines().collect();
            lines.pop();
            std::fs::write(&journal_path, lines.join("\n") + "\n").unwrap();
            let missing = call(session, "session.event", json!({"event_seq": final_seq})).await;
            assert_eq!(missing.error.unwrap().code, ErrorCode::EventGap);
        }
        gateway.shutdown().await;
    }
}
