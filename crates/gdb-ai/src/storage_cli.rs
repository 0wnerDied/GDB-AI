use std::collections::{BTreeMap, BTreeSet};

use clap::Subcommand;
use gdb_ai_core::{
    Error, ErrorCode, Result,
    artifact::{ArtifactFile, ArtifactStore},
    config::Config,
    persistence::{StorageLock, Store, StoredArtifact, prune_retained_sessions},
};
use serde_json::{Value, json};

#[derive(Subcommand)]
pub enum StorageCommand {
    Status,
    Verify,
    Gc {
        #[arg(long)]
        execute: bool,
    },
}

struct StorageScan {
    database: Vec<StoredArtifact>,
    files: Vec<ArtifactFile>,
    invalid_entries: Vec<String>,
    untracked_files: Vec<String>,
    missing_files: Vec<String>,
    unowned_artifacts: Vec<String>,
    size_mismatches: Vec<String>,
    corrupt_artifacts: Vec<Value>,
    sqlite_quick_check: String,
    verified_artifacts: usize,
}

impl StorageScan {
    fn ok(&self) -> bool {
        self.sqlite_quick_check == "ok"
            && self.invalid_entries.is_empty()
            && self.untracked_files.is_empty()
            && self.missing_files.is_empty()
            && self.unowned_artifacts.is_empty()
            && self.size_mismatches.is_empty()
            && self.corrupt_artifacts.is_empty()
    }

    fn json(&self) -> Value {
        json!({
            "ok": self.ok(),
            "sqlite_quick_check": self.sqlite_quick_check,
            "database": {
                "artifacts": self.database.len(),
                "bytes": self.database.iter().map(|artifact| artifact.size).sum::<usize>()
            },
            "filesystem": {
                "artifacts": self.files.len(),
                "bytes": self.files.iter().map(|artifact| artifact.size).sum::<u64>()
            },
            "invalid_entries": self.invalid_entries,
            "untracked_files": self.untracked_files,
            "missing_files": self.missing_files,
            "unowned_artifacts": self.unowned_artifacts,
            "size_mismatches": self.size_mismatches,
            "corrupt_artifacts": self.corrupt_artifacts,
            "verified_artifacts": self.verified_artifacts,
        })
    }

    fn database_bytes(&self) -> usize {
        self.database.iter().map(|artifact| artifact.size).sum()
    }

    fn filesystem_bytes(&self) -> u64 {
        self.files.iter().map(|artifact| artifact.size).sum()
    }
}

pub fn run(config: Config, command: StorageCommand) -> Result<()> {
    let _lock = StorageLock::acquire(config.persistence.sqlite.with_extension("lock"))?;
    let store = Store::open_with_storage(&config.persistence.sqlite, &config.storage)?;
    let artifacts = ArtifactStore::new(&config.artifacts.path)?;
    match command {
        StorageCommand::Status => {
            let scan = scan(&store, &artifacts, false)?;
            let artifact_bytes = scan.database_bytes();
            let mut report = scan.json();
            report["retained_sessions"] = json!(store.list_sessions()?.len());
            let (audit, audit_results) = store.audit_counts()?;
            report["audit_rows"] = json!({"requests": audit, "results": audit_results});
            // 2026-08-29: Hard caps rejected writes safely but status omitted
            // their current watermarks, leaving operators unable to act early.
            report["watermarks"] = json!({
                "artifact_bytes": {
                    "used": artifact_bytes,
                    "hard_limit": config.limits.total_artifact_bytes,
                },
                "retained_sessions": {
                    "used": report["retained_sessions"],
                    "hard_limit": config.storage.max_closed_sessions,
                },
                "audit_rows": {
                    "requests": audit,
                    "results": audit_results,
                    "hard_limit_each": config.storage.max_audit_rows,
                }
            });
            report["limits"] = json!({
                "artifact_bytes_per_session": config.limits.session_artifact_bytes,
                "artifact_bytes_per_owner": config.limits.owner_artifact_bytes,
                "artifact_bytes_total": config.limits.total_artifact_bytes,
                "journal_bytes_per_session": config.limits.journal_bytes,
                "output_spool_bytes_per_session": config.output.max_bytes,
                "snapshots_per_session": config.storage.max_snapshots_per_session,
                "operations_per_session": config.storage.max_operations_per_session,
                "closed_session_retention_ms": config.storage.closed_session_retention_ms,
                "audit_retention_ms": config.storage.audit_retention_ms,
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        StorageCommand::Verify => {
            let report = scan(&store, &artifacts, true)?;
            println!("{}", serde_json::to_string_pretty(&report.json())?);
            if !report.ok() {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "storage verification found inconsistencies",
                ));
            }
        }
        StorageCommand::Gc { execute } => {
            let before = scan(&store, &artifacts, false)?;
            let bytes_before = before.filesystem_bytes();
            let session_candidates = store.retention_candidates(
                now_unix_ms(),
                config.storage.closed_session_retention_ms,
                config.storage.max_closed_sessions,
                &BTreeSet::new(),
            )?;
            let (removed_sessions, removed_session_artifacts, removed_orphans) = if execute {
                let (sessions, session_artifacts) = prune_retained_sessions(
                    &store,
                    &artifacts,
                    &config.persistence.sessions,
                    now_unix_ms(),
                    config.storage.closed_session_retention_ms,
                    config.storage.max_closed_sessions,
                    &BTreeSet::new(),
                )?;
                let refreshed = scan(&store, &artifacts, false)?;
                let orphans = collect_garbage(&store, &artifacts, &refreshed)?;
                (sessions, session_artifacts, orphans)
            } else {
                (0, 0, 0)
            };
            let after = execute
                .then(|| scan(&store, &artifacts, false))
                .transpose()?;
            // 2026-08-29: GC reported removed object counts but not reclaimed
            // artifact capacity, so storage pressure could not be verified.
            let reclaimed_artifact_bytes = after
                .as_ref()
                .map(|scan| bytes_before.saturating_sub(scan.filesystem_bytes()))
                .unwrap_or(0);
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "executed": execute,
                    "removed": {
                        "sessions": removed_sessions,
                        "session_artifacts": removed_session_artifacts,
                        "orphan_artifacts": removed_orphans,
                        "artifact_bytes": reclaimed_artifact_bytes,
                    },
                    "planned": {
                        "sessions": session_candidates,
                        "untracked_files": before.untracked_files,
                        "unowned_artifacts": before.unowned_artifacts,
                    },
                    "after": after.map(|scan| scan.json()),
                }))?
            );
        }
    }
    Ok(())
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::UNIX_EPOCH
        .elapsed()
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn scan(store: &Store, artifacts: &ArtifactStore, verify: bool) -> Result<StorageScan> {
    let database = store.list_artifacts()?;
    let inventory = artifacts.inventory()?;
    let database_by_uri = database
        .iter()
        .map(|artifact| (artifact.uri.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let files_by_uri = inventory
        .files
        .iter()
        .map(|artifact| (artifact.uri.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let database_uris = database_by_uri.keys().copied().collect::<BTreeSet<_>>();
    let file_uris = files_by_uri.keys().copied().collect::<BTreeSet<_>>();
    let untracked_files = file_uris
        .difference(&database_uris)
        .map(|uri| (*uri).to_owned())
        .collect();
    let missing_files = database_uris
        .difference(&file_uris)
        .map(|uri| (*uri).to_owned())
        .collect();
    let unowned_artifacts = database
        .iter()
        .filter(|artifact| !artifact.global && artifact.owner_count == 0)
        .map(|artifact| artifact.uri.clone())
        .collect();
    let size_mismatches = database_uris
        .intersection(&file_uris)
        .filter(|uri| database_by_uri[**uri].size as u64 != files_by_uri[**uri].size)
        .map(|uri| (*uri).to_owned())
        .collect();
    let mut corrupt_artifacts = Vec::new();
    let verified_artifacts = if verify {
        database_uris.intersection(&file_uris).count()
    } else {
        0
    };
    if verify {
        for uri in database_uris.intersection(&file_uris) {
            if let Err(error) = artifacts.verify(uri) {
                corrupt_artifacts.push(json!({"uri": uri, "error": error.to_string()}));
            }
        }
    }
    Ok(StorageScan {
        database,
        files: inventory.files,
        invalid_entries: inventory.invalid_entries,
        untracked_files,
        missing_files,
        unowned_artifacts,
        size_mismatches,
        corrupt_artifacts,
        sqlite_quick_check: store.quick_check()?,
        verified_artifacts,
    })
}

fn collect_garbage(store: &Store, artifacts: &ArtifactStore, scan: &StorageScan) -> Result<usize> {
    let mut removed = 0;
    for uri in &scan.unowned_artifacts {
        if store.delete_unowned_artifact(uri)? {
            if scan.files.iter().any(|file| &file.uri == uri) {
                artifacts.remove(uri)?;
            }
            removed += 1;
        }
    }
    for uri in &scan.untracked_files {
        artifacts.remove(uri)?;
        removed += 1;
    }
    store.checkpoint_wal()?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use gdb_ai_core::{domain::SessionId, persistence::ArtifactLimits};

    use super::*;

    #[test]
    fn garbage_collection_keeps_owned_artifacts() {
        let directory = tempdir().unwrap();
        let store = Store::open(directory.path().join("state.sqlite")).unwrap();
        let artifacts = ArtifactStore::new(directory.path().join("artifacts")).unwrap();
        let session = SessionId("sess_owned".into());
        store.set_session_owner(&session, "owner").unwrap();
        let owned = store
            .put_artifact(
                &artifacts,
                b"owned",
                Some(&session),
                "public",
                ArtifactLimits {
                    session_bytes: 1024,
                    owner_bytes: 1024,
                    total_bytes: 1024,
                },
            )
            .unwrap();
        let orphan = artifacts.put(b"orphan").unwrap();
        let before = scan(&store, &artifacts, false).unwrap();
        assert_eq!(before.untracked_files, std::slice::from_ref(&orphan));
        let bytes_before = before.filesystem_bytes();
        assert_eq!(collect_garbage(&store, &artifacts, &before).unwrap(), 1);
        assert!(artifacts.verify(&owned).is_ok());
        assert!(artifacts.verify(&orphan).is_err());
        let after = scan(&store, &artifacts, true).unwrap();
        assert_eq!(bytes_before - after.filesystem_bytes(), 6);
        assert_eq!(after.verified_artifacts, 1);
    }
}
