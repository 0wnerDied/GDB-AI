use std::{sync::Arc, time::Duration};

use gdb_ai_core::{
    ErrorCode,
    backend::MiCommand,
    config::{ArtifactConfig, Config, PersistenceConfig},
    domain::SessionLifecycle,
    metrics::Metrics,
    persistence::Store,
    policy::Profile,
    session::SessionHandle,
};
use tempfile::tempdir;

mod support;

#[tokio::test]
async fn journal_quota_failure_fails_closed() {
    if !support::require_commands(&["gdb"]) {
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
    config.limits.journal_bytes = 256 * 1024;
    let store = Arc::new(Store::open(&config.persistence.sqlite).unwrap());
    let session = SessionHandle::start(
        Arc::new(config),
        Profile::RawAdmin,
        store,
        Arc::new(Metrics::default()),
    )
    .await
    .unwrap();

    let mut failure = None;
    for _ in 0..1_000 {
        match session
            .command(MiCommand::new("-gdb-version").unwrap())
            .await
        {
            Ok(_) => {}
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }
    let failure = failure.expect("journal quota was not reached");
    assert!(matches!(
        failure.code,
        ErrorCode::OutputLimit | ErrorCode::GdbExited
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        while session.state().lifecycle != SessionLifecycle::Failed {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("journal failure did not publish terminal state");
    assert_eq!(
        session
            .command(MiCommand::new("-gdb-version").unwrap())
            .await
            .unwrap_err()
            .code,
        ErrorCode::GdbExited
    );
}
