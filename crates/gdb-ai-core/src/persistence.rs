use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    os::fd::AsRawFd,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::Mutex,
    time::SystemTime,
};

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::Value;

use crate::{
    Error, ErrorCode, Result,
    artifact::ArtifactStore,
    config::StorageConfig,
    domain::{OperationRecord, SessionId, SessionState, TrackingDefinition, WriteLease},
    policy::{Effect, Profile},
    protocol::ApiResponse,
};

pub struct Store {
    connection: Mutex<Connection>,
    storage: StorageConfig,
}

pub struct StorageLock {
    _file: File,
}

#[derive(Clone, Debug)]
pub struct ArtifactRecord {
    pub size: usize,
    pub sensitivity: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct StoredArtifact {
    pub uri: String,
    pub size: usize,
    pub sensitivity: String,
    pub owner_count: usize,
    pub global: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct ArtifactLimits {
    pub session_bytes: usize,
    pub owner_bytes: usize,
    pub total_bytes: usize,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_storage(path, &StorageConfig::default())
    }

    pub fn open_with_storage(path: impl AsRef<Path>, storage: &StorageConfig) -> Result<Self> {
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
                 );
                 CREATE INDEX IF NOT EXISTS audit_created_idx
                   ON audit(created_unix_ms, id);
                 CREATE INDEX IF NOT EXISTS audit_results_created_idx
                   ON audit_results(created_unix_ms, id);
                 CREATE INDEX IF NOT EXISTS snapshots_session_created_idx
                   ON snapshots(session_id, created_unix_ms);
                 CREATE INDEX IF NOT EXISTS operations_session_updated_idx
                   ON operations(session_id, updated_unix_ms);",
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
            storage: storage.clone(),
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

    pub fn retention_candidates(
        &self,
        now_unix_ms: i64,
        retention_ms: u64,
        maximum: usize,
        live_sessions: &BTreeSet<String>,
    ) -> Result<Vec<SessionId>> {
        let mut historical = self.with_connection(|connection| {
            let mut statement = connection
                .prepare("SELECT id, updated_unix_ms FROM sessions ORDER BY updated_unix_ms DESC")
                .map_err(sql_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(sql_error)?;
            rows.map(|row| row.map_err(sql_error))
                .collect::<Result<Vec<_>>>()
        })?;
        historical.retain(|(id, _)| !live_sessions.contains(id));
        let cutoff = now_unix_ms.saturating_sub(retention_ms.min(i64::MAX as u64) as i64);
        historical
            .into_iter()
            .enumerate()
            .filter(|(index, (_, updated))| *index >= maximum || *updated < cutoff)
            .map(|(_, (id, _))| SessionId::parse(id))
            .collect()
    }

    pub fn prune_session(
        &self,
        artifacts: &ArtifactStore,
        session_id: &SessionId,
    ) -> Result<usize> {
        self.with_connection(|connection| {
            let transaction = connection.transaction().map_err(sql_error)?;
            transaction
                .execute(
                    "DELETE FROM artifact_owners WHERE session_id=?1",
                    params![session_id.0],
                )
                .map_err(sql_error)?;
            let orphaned = {
                let mut statement = transaction
                    .prepare(
                        "SELECT uri FROM artifacts
                         WHERE session_id IS NOT NULL
                           AND NOT EXISTS (
                             SELECT 1 FROM artifact_owners
                             WHERE artifact_owners.uri=artifacts.uri
                           )
                         ORDER BY uri",
                    )
                    .map_err(sql_error)?;
                let rows = statement
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(sql_error)?;
                rows.map(|row| row.map_err(sql_error))
                    .collect::<Result<Vec<_>>>()?
            };
            for table in [
                "leases",
                "tracking",
                "snapshots",
                "operations",
                "session_owners",
            ] {
                transaction
                    .execute(
                        &format!("DELETE FROM {table} WHERE session_id=?1"),
                        params![session_id.0],
                    )
                    .map_err(sql_error)?;
            }
            transaction
                .execute("DELETE FROM sessions WHERE id=?1", params![session_id.0])
                .map_err(sql_error)?;
            for uri in &orphaned {
                transaction
                    .execute("DELETE FROM artifacts WHERE uri=?1", params![uri])
                    .map_err(sql_error)?;
            }
            transaction.commit().map_err(sql_error)?;
            // The connection mutex remains held until this closure returns,
            // so another registration cannot recreate metadata before unlink.
            for uri in &orphaned {
                artifacts.remove_if_exists(uri)?;
            }
            Ok(orphaned.len())
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
        let maximum = self.storage.max_snapshots_per_session;
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
            // 2026-08-29: Repeated stops retained every snapshot for a live
            // session, so enforce the configured bound at the shared writer.
            connection
                .execute(
                    "DELETE FROM snapshots WHERE rowid IN (
                       SELECT rowid FROM snapshots WHERE session_id=?1
                       ORDER BY created_unix_ms DESC, rowid DESC
                       LIMIT -1 OFFSET ?2
                     )",
                    params![session_id.0, maximum as i64],
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
        let maximum = self.storage.max_operations_per_session;
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
            // 2026-08-29: Completed operations accumulated for the lifetime
            // of a live session, so keep only its configured recent history.
            connection
                .execute(
                    "DELETE FROM operations WHERE operation_id IN (
                       SELECT operation_id FROM operations WHERE session_id=?1
                       ORDER BY updated_unix_ms DESC, operation_id DESC
                       LIMIT -1 OFFSET ?2
                     )",
                    params![operation.session_id.0, maximum as i64],
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

    pub fn put_artifact(
        &self,
        artifacts: &ArtifactStore,
        bytes: &[u8],
        session_id: Option<&SessionId>,
        sensitivity: &str,
        limits: ArtifactLimits,
    ) -> Result<String> {
        let incoming_rank = artifact_sensitivity_rank(sensitivity).ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("unknown artifact sensitivity {sensitivity}"),
            )
        })?;
        let uri = ArtifactStore::uri(bytes);
        self.with_connection(|connection| {
            let transaction = connection.transaction().map_err(sql_error)?;
            let existing = transaction
                .query_row(
                    "SELECT size, sensitivity FROM artifacts WHERE uri=?1",
                    params![&uri],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(sql_error)?;
            if let Some((size, _)) = &existing
                && *size != bytes.len() as i64
            {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "artifact metadata size does not match its digest content",
                ));
            }
            let already_owned = match session_id {
                Some(session_id) => transaction
                    .query_row(
                        "SELECT 1 FROM artifact_owners WHERE uri=?1 AND session_id=?2",
                        params![&uri, session_id.0],
                        |_| Ok(()),
                    )
                    .optional()
                    .map_err(sql_error)?
                    .is_some(),
                None => false,
            };
            if let Some(session_id) = session_id
                && !already_owned
            {
                let used = transaction
                    .query_row(
                        "SELECT COALESCE(SUM(artifacts.size), 0)
                         FROM artifacts
                         JOIN artifact_owners ON artifact_owners.uri=artifacts.uri
                         WHERE artifact_owners.session_id=?1",
                        params![session_id.0],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(sql_error)?;
                if (used.max(0) as usize).saturating_add(bytes.len()) > limits.session_bytes {
                    return Err(Error::new(
                        ErrorCode::OutputLimit,
                        "session artifact quota exceeded",
                    ));
                }
            }
            if let Some(session_id) = session_id {
                let owner = transaction
                    .query_row(
                        "SELECT owner FROM session_owners WHERE session_id=?1",
                        params![session_id.0],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(sql_error)?
                    .ok_or_else(|| {
                        Error::new(ErrorCode::Internal, "artifact session has no owner")
                    })?;
                let owner_has_artifact = transaction
                    .query_row(
                        "SELECT 1
                         FROM artifact_owners
                         JOIN session_owners USING (session_id)
                         WHERE artifact_owners.uri=?1 AND session_owners.owner=?2
                         LIMIT 1",
                        params![&uri, &owner],
                        |_| Ok(()),
                    )
                    .optional()
                    .map_err(sql_error)?
                    .is_some();
                if !owner_has_artifact {
                    let used = transaction
                        .query_row(
                            "SELECT COALESCE(SUM(size), 0)
                             FROM artifacts
                             WHERE uri IN (
                               SELECT DISTINCT artifact_owners.uri
                               FROM artifact_owners
                               JOIN session_owners USING (session_id)
                               WHERE session_owners.owner=?1
                             )",
                            params![owner],
                            |row| row.get::<_, i64>(0),
                        )
                        .map_err(sql_error)?;
                    if (used.max(0) as usize).saturating_add(bytes.len()) > limits.owner_bytes {
                        return Err(Error::new(
                            ErrorCode::OutputLimit,
                            "owner artifact quota exceeded",
                        ));
                    }
                }
            }
            if existing.is_none() {
                let used = transaction
                    .query_row("SELECT COALESCE(SUM(size), 0) FROM artifacts", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .map_err(sql_error)?;
                // 2026-08-29: Per-session limits allowed many sessions to
                // exhaust the shared artifact filesystem. Reserve global
                // capacity in the serialized metadata transaction first.
                if (used.max(0) as usize).saturating_add(bytes.len()) > limits.total_bytes {
                    return Err(Error::new(
                        ErrorCode::OutputLimit,
                        "global artifact quota exceeded",
                    ));
                }
            }
            artifacts.put(bytes)?;
            // 2026-08-29: A later registration unconditionally replaced the
            // sensitivity of a shared digest and could downgrade secret target
            // evidence to a public label. Global labels only move upward.
            let sensitivity = existing
                .as_ref()
                .map(|(_, sensitivity)| sensitivity.as_str())
                .filter(|existing| {
                    artifact_sensitivity_rank(existing).unwrap_or(u8::MAX) >= incoming_rank
                })
                .unwrap_or(sensitivity);
            transaction
                .execute(
                    "INSERT INTO artifacts
                 (uri, session_id, size, sensitivity, created_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(uri) DO UPDATE SET
                   sensitivity=excluded.sensitivity",
                    params![
                        &uri,
                        session_id.map(|session_id| session_id.0.as_str()),
                        bytes.len(),
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
                        params![&uri, session_id.0],
                    )
                    .map_err(sql_error)?;
            }
            transaction.commit().map_err(sql_error)?;
            Ok(uri)
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

    pub fn total_artifact_bytes(&self) -> Result<usize> {
        let total = self.with_connection(|connection| {
            connection
                .query_row("SELECT COALESCE(SUM(size), 0) FROM artifacts", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(sql_error)
        })?;
        Ok(total.max(0) as usize)
    }

    pub fn list_artifacts(&self) -> Result<Vec<StoredArtifact>> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare(
                    "SELECT artifacts.uri, artifacts.size, artifacts.sensitivity,
                            artifacts.session_id IS NULL,
                            COUNT(artifact_owners.session_id)
                     FROM artifacts
                     LEFT JOIN artifact_owners ON artifact_owners.uri=artifacts.uri
                     GROUP BY artifacts.uri
                     ORDER BY artifacts.uri",
                )
                .map_err(sql_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok(StoredArtifact {
                        uri: row.get(0)?,
                        size: row.get::<_, i64>(1)?.max(0) as usize,
                        sensitivity: row.get(2)?,
                        global: row.get(3)?,
                        owner_count: row.get::<_, i64>(4)?.max(0) as usize,
                    })
                })
                .map_err(sql_error)?;
            rows.map(|row| row.map_err(sql_error)).collect()
        })
    }

    pub fn delete_unowned_artifact(&self, uri: &str) -> Result<bool> {
        self.with_connection(|connection| {
            let deleted = connection
                .execute(
                    "DELETE FROM artifacts
                     WHERE uri=?1 AND session_id IS NOT NULL
                       AND NOT EXISTS (
                         SELECT 1 FROM artifact_owners WHERE artifact_owners.uri=artifacts.uri
                       )",
                    params![uri],
                )
                .map_err(sql_error)?;
            Ok(deleted == 1)
        })
    }

    pub fn quick_check(&self) -> Result<String> {
        self.with_connection(|connection| {
            connection
                .query_row("PRAGMA quick_check", [], |row| row.get(0))
                .map_err(sql_error)
        })
    }

    pub fn checkpoint_wal(&self) -> Result<()> {
        self.with_connection(|connection| {
            connection
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
                .map_err(sql_error)
        })
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
        let retention_ms = self.storage.audit_retention_ms;
        let maximum = self.storage.max_audit_rows;
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
            prune_time_series(connection, "audit", retention_ms, maximum)?;
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
        let retention_ms = self.storage.audit_retention_ms;
        let maximum = self.storage.max_audit_rows;
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
            prune_time_series(connection, "audit_results", retention_ms, maximum)?;
            Ok(())
        })
    }

    pub fn audit_counts(&self) -> Result<(usize, usize)> {
        self.with_connection(|connection| {
            let audit = connection
                .query_row("SELECT COUNT(*) FROM audit", [], |row| row.get::<_, i64>(0))
                .map_err(sql_error)?;
            let results = connection
                .query_row("SELECT COUNT(*) FROM audit_results", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(sql_error)?;
            Ok((audit.max(0) as usize, results.max(0) as usize))
        })
    }
}

fn prune_time_series(
    connection: &Connection,
    table: &str,
    retention_ms: u64,
    maximum: usize,
) -> Result<()> {
    let cutoff = unix_ms().saturating_sub(retention_ms.min(i64::MAX as u64) as i64);
    connection
        .execute(
            &format!("DELETE FROM {table} WHERE created_unix_ms < ?1"),
            params![cutoff],
        )
        .map_err(sql_error)?;
    // 2026-08-29: Audit and result rows grew without bound during a long-lived
    // daemon even though every individual value was size-limited.
    connection
        .execute(
            &format!(
                "DELETE FROM {table} WHERE id IN (
                   SELECT id FROM {table} ORDER BY id DESC LIMIT -1 OFFSET ?1
                 )"
            ),
            params![maximum as i64],
        )
        .map_err(sql_error)?;
    Ok(())
}

impl StorageLock {
    pub fn acquire(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        // 2026-08-29: Destructive GC could race a daemon registering the same
        // digest and unlink newly-owned evidence. One data directory has one
        // writer; maintenance uses this same non-blocking process lock.
        // SAFETY: flock only reads this live file descriptor and does not
        // retain it after the call.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(Error::new(
                ErrorCode::Conflict,
                "storage is already in use by another GDB/AI process",
            ));
        }
        Ok(Self { _file: file })
    }
}

pub fn prune_retained_sessions(
    store: &Store,
    artifacts: &ArtifactStore,
    session_root: &Path,
    now_unix_ms: i64,
    retention_ms: u64,
    maximum: usize,
    live_sessions: &BTreeSet<String>,
) -> Result<(usize, usize)> {
    let candidates =
        store.retention_candidates(now_unix_ms, retention_ms, maximum, live_sessions)?;
    let mut removed_artifacts = 0;
    for session_id in &candidates {
        removed_artifacts += store.prune_session(artifacts, session_id)?;
        remove_session_directory(session_root, session_id)?;
    }
    Ok((candidates.len(), removed_artifacts))
}

fn remove_session_directory(root: &Path, session_id: &SessionId) -> Result<bool> {
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_dir() {
        return Err(Error::new(
            ErrorCode::Internal,
            "session storage root is not a directory",
        ));
    }
    let root = std::fs::canonicalize(root)?;
    let candidate = root.join(&session_id.0);
    match std::fs::symlink_metadata(&candidate) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            let canonical = std::fs::canonicalize(&candidate)?;
            if canonical.parent() != Some(root.as_path()) {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "session directory escapes the storage root",
                ));
            }
            std::fs::remove_dir_all(canonical)?;
            Ok(true)
        }
        Ok(_) => Err(Error::new(
            ErrorCode::Internal,
            "session storage entry is not a directory",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn artifact_sensitivity_rank(sensitivity: &str) -> Option<u8> {
    Some(match sensitivity {
        "public" => 0,
        "source" => 1,
        "transcript" => 2,
        "target-io" => 3,
        "protocol-response" | "probe-observations" | "target-value" | "tracked-memory"
        | "target-memory" => 4,
        "secret" => 5,
        _ => return None,
    })
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

    const UNLIMITED_ARTIFACTS: ArtifactLimits = ArtifactLimits {
        session_bytes: usize::MAX,
        owner_bytes: usize::MAX,
        total_bytes: usize::MAX,
    };

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
        let artifacts = ArtifactStore::new(directory.path().join("artifacts")).unwrap();
        let first = SessionId("sess_first".into());
        let second = SessionId("sess_second".into());
        store.set_session_owner(&first, "first-owner").unwrap();
        store.set_session_owner(&second, "second-owner").unwrap();
        let uri = store
            .put_artifact(
                &artifacts,
                b"shared!",
                Some(&first),
                "target-memory",
                UNLIMITED_ARTIFACTS,
            )
            .unwrap();
        store
            .put_artifact(
                &artifacts,
                b"shared!",
                Some(&second),
                "public",
                UNLIMITED_ARTIFACTS,
            )
            .unwrap();
        assert_eq!(
            store.artifact_sessions(&uri).unwrap(),
            vec!["sess_first", "sess_second"]
        );
        assert_eq!(store.artifact_bytes(&first).unwrap(), 7);
        assert_eq!(store.artifact_bytes(&second).unwrap(), 7);
        assert_eq!(
            store.artifact(&uri).unwrap().unwrap().sensitivity,
            "target-memory"
        );
        store
            .put_artifact(&artifacts, b"u", None, "public", UNLIMITED_ARTIFACTS)
            .unwrap();
        let upgrade = store
            .put_artifact(&artifacts, b"u", None, "secret", UNLIMITED_ARTIFACTS)
            .unwrap();
        assert_eq!(
            store.artifact(&upgrade).unwrap().unwrap().sensitivity,
            "secret"
        );
        assert!(
            store
                .put_artifact(&artifacts, b"other", None, "unknown", UNLIMITED_ARTIFACTS,)
                .is_err()
        );
    }

    #[test]
    fn artifact_quotas_are_reserved_before_writing() {
        let directory = tempdir().unwrap();
        let store = Store::open(directory.path().join("state.sqlite")).unwrap();
        let artifacts = ArtifactStore::new(directory.path().join("artifacts")).unwrap();
        let first = SessionId("sess_first".into());
        let second = SessionId("sess_second".into());
        let sibling = SessionId("sess_sibling".into());
        store.set_session_owner(&first, "owner").unwrap();
        store.set_session_owner(&sibling, "owner").unwrap();
        store.set_session_owner(&second, "other").unwrap();
        let limits = ArtifactLimits {
            session_bytes: 4,
            owner_bytes: 4,
            total_bytes: 4,
        };
        store
            .put_artifact(&artifacts, b"1234", Some(&first), "public", limits)
            .unwrap();
        store
            .put_artifact(&artifacts, b"1234", Some(&second), "public", limits)
            .unwrap();
        assert_eq!(store.total_artifact_bytes().unwrap(), 4);
        let global = store
            .put_artifact(&artifacts, b"g", None, "public", limits)
            .unwrap_err();
        assert_eq!(global.code, ErrorCode::OutputLimit);
        let session = store
            .put_artifact(
                &artifacts,
                b"s",
                Some(&first),
                "public",
                ArtifactLimits {
                    total_bytes: 8,
                    ..limits
                },
            )
            .unwrap_err();
        assert_eq!(session.code, ErrorCode::OutputLimit);
        let owner = store
            .put_artifact(
                &artifacts,
                b"o",
                Some(&sibling),
                "public",
                ArtifactLimits {
                    session_bytes: 5,
                    total_bytes: 8,
                    ..limits
                },
            )
            .unwrap_err();
        assert_eq!(owner.code, ErrorCode::OutputLimit);
        assert!(artifacts.get(&ArtifactStore::uri(b"g"), 1).is_err());
        assert!(artifacts.get(&ArtifactStore::uri(b"s"), 1).is_err());
        assert!(artifacts.get(&ArtifactStore::uri(b"o"), 1).is_err());
    }

    #[test]
    fn storage_lock_excludes_concurrent_maintenance() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("storage.lock");
        let first = StorageLock::acquire(&path).unwrap();
        assert!(StorageLock::acquire(&path).is_err());
        drop(first);
        StorageLock::acquire(path).unwrap();
    }

    #[test]
    fn retention_prunes_only_non_live_session_ownership() {
        let directory = tempdir().unwrap();
        let store = Store::open(directory.path().join("state.sqlite")).unwrap();
        let artifacts = ArtifactStore::new(directory.path().join("artifacts")).unwrap();
        let sessions = directory.path().join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let live = SessionId("sess_live".into());
        let stale = SessionId("sess_stale".into());
        for session in [&live, &stale] {
            store
                .upsert_session(
                    &SessionState::creating(session.clone()),
                    Profile::DebugControl,
                )
                .unwrap();
            store.set_session_owner(session, "owner").unwrap();
            std::fs::create_dir(sessions.join(&session.0)).unwrap();
        }
        let uri = store
            .put_artifact(
                &artifacts,
                b"shared",
                Some(&live),
                "public",
                UNLIMITED_ARTIFACTS,
            )
            .unwrap();
        store
            .put_artifact(
                &artifacts,
                b"shared",
                Some(&stale),
                "public",
                UNLIMITED_ARTIFACTS,
            )
            .unwrap();
        let excluded = BTreeSet::from([live.0.clone()]);
        let future = unix_ms().saturating_add(10_000);
        assert_eq!(
            prune_retained_sessions(&store, &artifacts, &sessions, future, 1, 10, &excluded)
                .unwrap(),
            (1, 0)
        );
        assert!(sessions.join(&live.0).is_dir());
        assert!(!sessions.join(&stale.0).exists());
        assert_eq!(
            store.artifact_sessions(&uri).unwrap(),
            std::slice::from_ref(&live.0)
        );
        assert_eq!(
            prune_retained_sessions(
                &store,
                &artifacts,
                &sessions,
                future,
                1,
                10,
                &BTreeSet::new(),
            )
            .unwrap(),
            (1, 1)
        );
        assert!(!sessions.join(&live.0).exists());
        assert!(artifacts.verify(&uri).is_err());
    }

    #[test]
    fn sqlite_histories_stay_within_configured_limits() {
        let directory = tempdir().unwrap();
        let storage = StorageConfig {
            max_audit_rows: 2,
            max_snapshots_per_session: 2,
            max_operations_per_session: 2,
            ..StorageConfig::default()
        };
        let store =
            Store::open_with_storage(directory.path().join("state.sqlite"), &storage).unwrap();
        let session = SessionId("sess_bounded".into());
        for index in 0..3 {
            let snapshot_id = format!("snap_{index}");
            store
                .upsert_snapshot(&session, &snapshot_id, &serde_json::json!({"index": index}))
                .unwrap();
            store
                .upsert_operation(&OperationRecord {
                    operation_id: crate::domain::OperationId(format!("op_{index}")),
                    session_id: session.clone(),
                    kind: "test".into(),
                    status: crate::domain::OperationStatus::Completed,
                    created_revision: 0,
                    wait_baseline: None,
                    expected_execution_epoch: None,
                    accepted_event_seq: None,
                    completed_event_seq: None,
                    error: None,
                })
                .unwrap();
            store
                .audit(
                    "caller",
                    Some(&session),
                    "session.get",
                    Effect::Read,
                    true,
                    None,
                    &serde_json::json!({"index": index}),
                    "allowed",
                )
                .unwrap();
            store
                .audit_result(
                    Some(&session),
                    "session.get",
                    &serde_json::json!({"index": index}),
                )
                .unwrap();
        }
        assert!(store.get_snapshot(&session, "snap_0").unwrap().is_none());
        assert!(store.get_operation("op_0").unwrap().is_none());
        assert_eq!(store.audit_counts().unwrap(), (2, 2));
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
