use std::{os::unix::fs::PermissionsExt, path::Path, sync::Mutex, time::SystemTime};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;

use crate::{
    Error, ErrorCode, Result,
    domain::{OperationRecord, SessionId, SessionState, TrackingDefinition, WriteLease},
    policy::{Effect, Profile},
    protocol::ApiResponse,
};

pub struct Store {
    connection: Mutex<Connection>,
}

#[derive(Clone, Debug)]
pub struct ArtifactRecord {
    pub size: usize,
    pub sensitivity: String,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
            // 2026-08-28: SQLite, journals, and artifacts contain target
            // memory and audit data; default umask permissions were too broad.
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        // 2026-08-28: Borrow the path so it remains available for permission hardening.
        let connection = Connection::open(&path).map_err(sql_error)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA foreign_keys=ON;
                 CREATE TABLE IF NOT EXISTS sessions (
                     id TEXT PRIMARY KEY,
                     profile TEXT NOT NULL,
                     state_json TEXT NOT NULL,
                     created_unix_ms INTEGER NOT NULL,
                     updated_unix_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS audit (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     created_unix_ms INTEGER NOT NULL,
                     caller TEXT NOT NULL,
                     session_id TEXT,
                     method TEXT NOT NULL,
                     effect TEXT NOT NULL,
                     allowed INTEGER NOT NULL,
                     revision INTEGER,
                     request_json TEXT NOT NULL,
                     outcome TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS artifacts (
                     uri TEXT PRIMARY KEY,
                     session_id TEXT,
                     size INTEGER NOT NULL,
                     sensitivity TEXT NOT NULL,
                     created_unix_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS leases (
                     session_id TEXT PRIMARY KEY,
                     lease_json TEXT NOT NULL,
                     updated_unix_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS tracking (
                     session_id TEXT NOT NULL,
                     tracking_id TEXT NOT NULL,
                     definition_json TEXT NOT NULL,
                     updated_unix_ms INTEGER NOT NULL,
                     PRIMARY KEY (session_id, tracking_id)
                 );
                 CREATE TABLE IF NOT EXISTS snapshots (
                     session_id TEXT NOT NULL,
                     snapshot_id TEXT NOT NULL,
                     snapshot_json TEXT NOT NULL,
                     created_unix_ms INTEGER NOT NULL,
                     PRIMARY KEY (session_id, snapshot_id)
                 );
                 CREATE TABLE IF NOT EXISTS operations (
                     operation_id TEXT PRIMARY KEY,
                     session_id TEXT NOT NULL,
                     operation_json TEXT NOT NULL,
                     updated_unix_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS audit_results (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     created_unix_ms INTEGER NOT NULL,
                     session_id TEXT,
                     method TEXT NOT NULL,
                     result_json TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS session_owners (
                     session_id TEXT PRIMARY KEY,
                     owner TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS artifact_owners (
                     uri TEXT NOT NULL,
                     session_id TEXT NOT NULL,
                     PRIMARY KEY (uri, session_id)
                 );
                 CREATE TABLE IF NOT EXISTS idempotency (
                     cache_key TEXT PRIMARY KEY,
                     request_hash TEXT NOT NULL,
                     response_json TEXT NOT NULL,
                     updated_unix_ms INTEGER NOT NULL
                 );",
            )
            .map_err(sql_error)?;
        // 2026-08-28: A content digest may be produced by multiple sessions;
        // the single legacy artifacts.session_id column lost later owners.
        connection
            .execute(
                "INSERT OR IGNORE INTO artifact_owners (uri, session_id)
                 SELECT uri, session_id FROM artifacts WHERE session_id IS NOT NULL",
                [],
            )
            .map_err(sql_error)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T>,
    ) -> Result<T> {
        let run = || {
            let mut connection = self
                .connection
                .lock()
                .map_err(|_| Error::new(ErrorCode::Internal, "database mutex poisoned"))?;
            operation(&mut connection)
        };
        // 2026-08-28: Synchronous SQLite work ran directly on Tokio workers,
        // so a slow WAL write or connection lock stalled unrelated sessions.
        // Let the multithreaded runtime replace this worker while it blocks.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(run)
            }
            _ => run(),
        }
    }

    pub fn upsert_session(&self, state: &SessionState, profile: Profile) -> Result<()> {
        let now = unix_ms();
        let state_json = serde_json::to_string(state)?;
        self.with_connection(|connection| {
            connection
                .execute(
                    "INSERT INTO sessions
                 (id, profile, state_json, created_unix_ms, updated_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT(id) DO UPDATE SET
                   state_json=excluded.state_json,
                   updated_unix_ms=excluded.updated_unix_ms",
                    params![state.session_id.0, format!("{profile:?}"), state_json, now],
                )
                .map_err(sql_error)?;
            Ok(())
        })
    }

    pub fn get_session(&self, id: &SessionId) -> Result<Option<SessionState>> {
        let json: Option<String> = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT state_json FROM sessions WHERE id=?1",
                    params![id.0],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_error)
        })?;
        json.map(|json| serde_json::from_str(&json).map_err(Into::into))
            .transpose()
    }

    pub fn list_sessions(&self) -> Result<Vec<SessionState>> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare("SELECT state_json FROM sessions ORDER BY created_unix_ms, id")
                .map_err(sql_error)?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(sql_error)?;
            rows.map(|row| {
                let json = row.map_err(sql_error)?;
                serde_json::from_str(&json).map_err(Into::into)
            })
            .collect()
        })
    }

    pub fn set_session_owner(&self, session_id: &SessionId, owner: &str) -> Result<()> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "INSERT INTO session_owners (session_id, owner) VALUES (?1, ?2)
                 ON CONFLICT(session_id) DO NOTHING",
                    params![session_id.0, owner],
                )
                .map_err(sql_error)?;
            Ok(())
        })
    }

    pub fn session_owner(&self, session_id: &SessionId) -> Result<Option<String>> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT owner FROM session_owners WHERE session_id=?1",
                    params![session_id.0],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_error)
        })
    }

    pub fn list_session_owners(&self) -> Result<Vec<(SessionState, Option<String>)>> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare(
                    "SELECT sessions.state_json, session_owners.owner
                 FROM sessions
                 LEFT JOIN session_owners ON session_owners.session_id=sessions.id
                 ORDER BY sessions.created_unix_ms, sessions.id",
                )
                .map_err(sql_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
                })
                .map_err(sql_error)?;
            rows.map(|row| {
                let (json, owner) = row.map_err(sql_error)?;
                Ok((serde_json::from_str(&json)?, owner))
            })
            .collect()
        })
    }

    pub fn upsert_lease(&self, lease: &WriteLease) -> Result<()> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "INSERT INTO leases (session_id, lease_json, updated_unix_ms)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(session_id) DO UPDATE SET
                   lease_json=excluded.lease_json,
                   updated_unix_ms=excluded.updated_unix_ms",
                    params![lease.session_id.0, serde_json::to_string(lease)?, unix_ms()],
                )
                .map_err(sql_error)?;
            Ok(())
        })
    }

    pub fn delete_lease(&self, session_id: &SessionId) -> Result<()> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "DELETE FROM leases WHERE session_id=?1",
                    params![session_id.0],
                )
                .map_err(sql_error)?;
            Ok(())
        })
    }

    pub fn upsert_tracking(
        &self,
        session_id: &SessionId,
        definition: &TrackingDefinition,
    ) -> Result<()> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "INSERT INTO tracking
                 (session_id, tracking_id, definition_json, updated_unix_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(session_id, tracking_id) DO UPDATE SET
                   definition_json=excluded.definition_json,
                   updated_unix_ms=excluded.updated_unix_ms",
                    params![
                        session_id.0,
                        definition.id().0,
                        serde_json::to_string(definition)?,
                        unix_ms()
                    ],
                )
                .map_err(sql_error)?;
            Ok(())
        })
    }

    pub fn delete_tracking(&self, session_id: &SessionId, tracking_id: &str) -> Result<()> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "DELETE FROM tracking WHERE session_id=?1 AND tracking_id=?2",
                    params![session_id.0, tracking_id],
                )
                .map_err(sql_error)?;
            Ok(())
        })
    }

    pub fn upsert_snapshot(
        &self,
        session_id: &SessionId,
        snapshot_id: &str,
        snapshot: &Value,
    ) -> Result<()> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "INSERT INTO snapshots
                 (session_id, snapshot_id, snapshot_json, created_unix_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(session_id, snapshot_id) DO UPDATE SET
                   snapshot_json=excluded.snapshot_json",
                    params![
                        session_id.0,
                        snapshot_id,
                        serde_json::to_string(snapshot)?,
                        unix_ms()
                    ],
                )
                .map_err(sql_error)?;
            Ok(())
        })
    }

    pub fn get_snapshot(&self, session_id: &SessionId, snapshot_id: &str) -> Result<Option<Value>> {
        let json: Option<String> = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT snapshot_json FROM snapshots
                 WHERE session_id=?1 AND snapshot_id=?2",
                    params![session_id.0, snapshot_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_error)
        })?;
        json.map(|json| serde_json::from_str(&json).map_err(Into::into))
            .transpose()
    }

    pub fn upsert_operation(&self, operation: &OperationRecord) -> Result<()> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "INSERT INTO operations
                 (operation_id, session_id, operation_json, updated_unix_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(operation_id) DO UPDATE SET
                   operation_json=excluded.operation_json,
                   updated_unix_ms=excluded.updated_unix_ms",
                    params![
                        operation.operation_id.0,
                        operation.session_id.0,
                        serde_json::to_string(operation)?,
                        unix_ms()
                    ],
                )
                .map_err(sql_error)?;
            Ok(())
        })
    }

    pub fn get_operation(&self, operation_id: &str) -> Result<Option<OperationRecord>> {
        let json: Option<String> = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT operation_json FROM operations WHERE operation_id=?1",
                    params![operation_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_error)
        })?;
        json.map(|json| serde_json::from_str(&json).map_err(Into::into))
            .transpose()
    }

    pub fn register_artifact(
        &self,
        uri: &str,
        session_id: Option<&SessionId>,
        size: usize,
        sensitivity: &str,
    ) -> Result<()> {
        self.with_connection(|connection| {
            let transaction = connection.transaction().map_err(sql_error)?;
            transaction
                .execute(
                    "INSERT INTO artifacts
                 (uri, session_id, size, sensitivity, created_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(uri) DO UPDATE SET
                   sensitivity=excluded.sensitivity",
                    params![
                        uri,
                        session_id.map(|session_id| session_id.0.as_str()),
                        size,
                        sensitivity,
                        unix_ms()
                    ],
                )
                .map_err(sql_error)?;
            if let Some(session_id) = session_id {
                transaction
                    .execute(
                        "INSERT OR IGNORE INTO artifact_owners (uri, session_id)
                     VALUES (?1, ?2)",
                        params![uri, session_id.0],
                    )
                    .map_err(sql_error)?;
            }
            transaction.commit().map_err(sql_error)?;
            Ok(())
        })
    }

    pub fn artifact(&self, uri: &str) -> Result<Option<ArtifactRecord>> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT size, sensitivity FROM artifacts WHERE uri=?1",
                    params![uri],
                    |row| {
                        Ok(ArtifactRecord {
                            size: row.get::<_, i64>(0)?.max(0) as usize,
                            sensitivity: row.get(1)?,
                        })
                    },
                )
                .optional()
                .map_err(sql_error)
        })
    }

    pub fn artifact_sessions(&self, uri: &str) -> Result<Vec<String>> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare(
                    "SELECT session_id FROM artifact_owners
                 WHERE uri=?1 ORDER BY session_id",
                )
                .map_err(sql_error)?;
            let rows = statement
                .query_map(params![uri], |row| row.get(0))
                .map_err(sql_error)?;
            rows.map(|row| row.map_err(sql_error)).collect()
        })
    }

    pub fn artifact_bytes(&self, session_id: &SessionId) -> Result<usize> {
        let total = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT COALESCE(SUM(artifacts.size), 0)
                 FROM artifacts
                 JOIN artifact_owners ON artifact_owners.uri=artifacts.uri
                 WHERE artifact_owners.session_id=?1",
                    params![session_id.0],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(sql_error)
        })?;
        Ok(total.max(0) as usize)
    }

    pub fn get_idempotent_response(
        &self,
        key: &str,
        request_hash: &str,
    ) -> Result<Option<ApiResponse>> {
        let row: Option<(String, String)> = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT request_hash, response_json FROM idempotency WHERE cache_key=?1",
                    params![key],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(sql_error)
        })?;
        let Some((stored_hash, json)) = row else {
            return Ok(None);
        };
        if stored_hash != request_hash {
            return Err(Error::new(
                ErrorCode::Conflict,
                "idempotency key was already used with different parameters",
            ));
        }
        Ok(Some(serde_json::from_str(&json)?))
    }

    pub fn put_idempotent_response(
        &self,
        key: &str,
        request_hash: &str,
        response: &ApiResponse,
    ) -> Result<()> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "INSERT INTO idempotency
                 (cache_key, request_hash, response_json, updated_unix_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(cache_key) DO UPDATE SET
                   request_hash=excluded.request_hash,
                   response_json=excluded.response_json,
                   updated_unix_ms=excluded.updated_unix_ms",
                    params![
                        key,
                        request_hash,
                        serde_json::to_string(response)?,
                        unix_ms()
                    ],
                )
                .map_err(sql_error)?;
            connection
                .execute(
                    "DELETE FROM idempotency WHERE cache_key IN (
                   SELECT cache_key FROM idempotency
                   ORDER BY updated_unix_ms DESC LIMIT -1 OFFSET 4096
                 )",
                    [],
                )
                .map_err(sql_error)?;
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn audit(
        &self,
        caller: &str,
        session_id: Option<&SessionId>,
        method: &str,
        effect: Effect,
        allowed: bool,
        revision: Option<u64>,
        request: &Value,
        outcome: &str,
    ) -> Result<()> {
        let request = redact(request.clone());
        self.with_connection(|connection| {
            connection
                .execute(
                    "INSERT INTO audit
                 (created_unix_ms, caller, session_id, method, effect, allowed,
                  revision, request_json, outcome)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        unix_ms(),
                        caller,
                        session_id.map(|id| id.0.as_str()),
                        method,
                        format!("{effect:?}"),
                        allowed,
                        revision,
                        serde_json::to_string(&request)?,
                        outcome,
                    ],
                )
                .map_err(sql_error)?;
            Ok(())
        })
    }

    pub fn audit_result(
        &self,
        session_id: Option<&SessionId>,
        method: &str,
        result: &Value,
    ) -> Result<()> {
        let result = redact(result.clone());
        self.with_connection(|connection| {
            connection
                .execute(
                    "INSERT INTO audit_results
                 (created_unix_ms, session_id, method, result_json)
                 VALUES (?1, ?2, ?3, ?4)",
                    params![
                        unix_ms(),
                        session_id.map(|id| id.0.as_str()),
                        method,
                        serde_json::to_string(&result)?
                    ],
                )
                .map_err(sql_error)?;
            Ok(())
        })
    }
}

fn redact(mut value: Value) -> Value {
    match &mut value {
        Value::Object(object) => {
            for (key, child) in object {
                if matches!(
                    key.as_str(),
                    "environment"
                        | "argv"
                        | "data_base64"
                        | "bytes_base64"
                        | "stdin"
                        | "credentials"
                        | "expression"
                        | "address_expression"
                        | "value"
                        | "text"
                        | "actual"
                        | "expected"
                ) {
                    *child = Value::String("<redacted>".into());
                } else {
                    *child = redact(child.take());
                }
            }
        }
        Value::Array(array) => {
            for child in array {
                *child = redact(child.take());
            }
        }
        _ => {}
    }
    value
}

fn unix_ms() -> i64 {
    SystemTime::UNIX_EPOCH
        .elapsed()
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn sql_error(error: rusqlite::Error) -> Error {
    Error::new(ErrorCode::Internal, format!("SQLite: {error}"))
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, atomic::AtomicBool},
        time::Duration,
    };

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn sqlite_wal_round_trips_state() {
        let directory = tempdir().unwrap();
        let store = Store::open(directory.path().join("state.sqlite")).unwrap();
        let state = SessionState::creating(SessionId("sess_sql".into()));
        store.upsert_session(&state, Profile::DebugControl).unwrap();
        assert_eq!(store.get_session(&state.session_id).unwrap(), Some(state));
        let snapshot = serde_json::json!({"snapshot_id": "snap_test"});
        store
            .upsert_snapshot(&SessionId("sess_sql".into()), "snap_test", &snapshot)
            .unwrap();
        assert_eq!(
            store
                .get_snapshot(&SessionId("sess_sql".into()), "snap_test")
                .unwrap(),
            Some(snapshot)
        );
    }

    #[test]
    fn content_addressed_artifacts_retain_every_session_owner() {
        let directory = tempdir().unwrap();
        let store = Store::open(directory.path().join("state.sqlite")).unwrap();
        let first = SessionId("sess_first".into());
        let second = SessionId("sess_second".into());
        store
            .register_artifact("gdbai://artifact/sha256:test", Some(&first), 7, "test")
            .unwrap();
        store
            .register_artifact("gdbai://artifact/sha256:test", Some(&second), 7, "test")
            .unwrap();
        assert_eq!(
            store
                .artifact_sessions("gdbai://artifact/sha256:test")
                .unwrap(),
            vec!["sess_first", "sess_second"]
        );
        assert_eq!(store.artifact_bytes(&first).unwrap(), 7);
        assert_eq!(store.artifact_bytes(&second).unwrap(), 7);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn sqlite_lock_wait_does_not_stall_the_runtime_worker() {
        let directory = tempdir().unwrap();
        let store = Arc::new(Store::open(directory.path().join("state.sqlite")).unwrap());
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        let locked_store = store.clone();
        let holder = std::thread::spawn(move || {
            let _guard = locked_store.connection.lock().unwrap();
            ready_tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(250));
        });
        ready_rx.recv().unwrap();

        let progressed = Arc::new(AtomicBool::new(false));
        let marker = progressed.clone();
        tokio::spawn(async move {
            marker.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        store.list_sessions().unwrap();

        assert!(progressed.load(std::sync::atomic::Ordering::SeqCst));
        holder.join().unwrap();
    }
}
