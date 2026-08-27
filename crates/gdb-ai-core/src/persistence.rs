use std::{path::Path, sync::Mutex, time::SystemTime};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;

use crate::{
    Error, ErrorCode, Result,
    domain::{SessionId, SessionState},
    policy::{Effect, Profile},
};

pub struct Store {
    connection: Mutex<Connection>,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path).map_err(sql_error)?;
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
                 );",
            )
            .map_err(sql_error)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn upsert_session(&self, state: &SessionState, profile: Profile) -> Result<()> {
        let now = unix_ms();
        let state_json = serde_json::to_string(state)?;
        self.connection
            .lock()
            .map_err(|_| Error::new(ErrorCode::Internal, "database mutex poisoned"))?
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
    }

    pub fn get_session(&self, id: &SessionId) -> Result<Option<SessionState>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| Error::new(ErrorCode::Internal, "database mutex poisoned"))?;
        let json: Option<String> = connection
            .query_row(
                "SELECT state_json FROM sessions WHERE id=?1",
                params![id.0],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_error)?;
        json.map(|json| serde_json::from_str(&json).map_err(Into::into))
            .transpose()
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
        self.connection
            .lock()
            .map_err(|_| Error::new(ErrorCode::Internal, "database mutex poisoned"))?
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
    }
}

fn redact(mut value: Value) -> Value {
    match &mut value {
        Value::Object(object) => {
            for (key, child) in object {
                if matches!(
                    key.as_str(),
                    "environment" | "data_base64" | "bytes_base64" | "stdin" | "credentials"
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
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn sqlite_wal_round_trips_state() {
        let directory = tempdir().unwrap();
        let store = Store::open(directory.path().join("state.sqlite")).unwrap();
        let state = SessionState::creating(SessionId("sess_sql".into()));
        store.upsert_session(&state, Profile::DebugControl).unwrap();
        assert_eq!(store.get_session(&state.session_id).unwrap(), Some(state));
    }
}
