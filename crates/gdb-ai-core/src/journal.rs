use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    Error, ErrorCode, Result,
    config::JournalDurability,
    domain::{DomainEvent, JournaledEvent},
};

// 2026-08-28: Replay and inspection once accepted missing journal entries and
// could present an incomplete evidence chain as valid.
pub fn require_next_sequence(last: u64, next: u64) -> Result<()> {
    if next == last + 1 {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::InvalidArgument,
            "journal sequence must be contiguous and start at 1",
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JournalEntry {
    pub seq: u64,
    #[serde(rename = "type")]
    pub kind: String,
    pub data: Value,
}

#[derive(Serialize)]
struct EncodedJournalEntry<'a, T> {
    seq: u64,
    #[serde(rename = "type")]
    kind: &'a str,
    data: T,
}

#[derive(Serialize)]
struct StateRevision<'a, T> {
    revision: u64,
    state: &'a T,
}

#[derive(Serialize)]
struct SnapshotResult<'a, T> {
    snapshot_id: &'a str,
    snapshot: &'a T,
}

pub struct Journal {
    writer: BufWriter<File>,
    next_seq: u64,
    bytes_written: usize,
    max_bytes: usize,
    unflushed_records: usize,
    durability: JournalDurability,
}

impl Journal {
    pub fn create(path: impl AsRef<Path>, max_bytes: usize) -> Result<Self> {
        Self::create_with_durability(path, max_bytes, JournalDurability::Performance)
    }

    pub fn create_with_durability(
        path: impl AsRef<Path>,
        max_bytes: usize,
        durability: JournalDurability,
    ) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        Ok(Self {
            writer: BufWriter::new(file),
            next_seq: 1,
            bytes_written: 0,
            max_bytes,
            unflushed_records: 0,
            durability,
        })
    }

    pub fn append_session_created(&mut self, session_id: &str) -> Result<u64> {
        self.append(
            "session.created",
            serde_json::json!({"session_id": session_id}),
        )
    }

    pub fn append_api(&mut self, request: Value) -> Result<u64> {
        let sequence = self.append("api.request", request)?;
        self.flush_boundary(sequence)
    }

    pub fn append_mi_input(&mut self, token: u64, raw: &[u8]) -> Result<u64> {
        self.append(
            "mi.input",
            serde_json::json!({ "token": token, "raw_base64": BASE64.encode(raw) }),
        )
    }

    pub fn append_mi_output(&mut self, raw: &[u8]) -> Result<u64> {
        self.append(
            "mi.output",
            serde_json::json!({ "raw_base64": BASE64.encode(raw) }),
        )
    }

    pub fn append_gdb_stderr(&mut self, bytes: &[u8]) -> Result<u64> {
        self.append(
            "gdb.stderr",
            serde_json::json!({ "raw_base64": BASE64.encode(bytes) }),
        )
    }

    pub fn append_inferior_output(
        &mut self,
        offset: u64,
        length: usize,
        dropped_bytes: u64,
    ) -> Result<u64> {
        self.append(
            "inferior.output",
            serde_json::json!({
                "offset": offset,
                "length": length,
                "dropped_bytes": dropped_bytes
            }),
        )
    }

    pub fn append_inferior_input(&mut self, bytes: &[u8]) -> Result<u64> {
        self.append(
            "inferior.input",
            serde_json::json!({ "raw_base64": BASE64.encode(bytes) }),
        )
    }

    pub fn append_inferior_output_evidence(&mut self, evidence: Value) -> Result<u64> {
        self.append("inferior.output.evidence", evidence)
    }

    pub fn append_domain(&mut self, event: DomainEvent) -> Result<JournaledEvent> {
        let seq = self.append("normalized.event", &event)?;
        Ok(JournaledEvent::new(seq, event))
    }

    pub fn append_state<T: Serialize>(&mut self, revision: u64, state: &T) -> Result<u64> {
        let sequence = self.append("state.revision", StateRevision { revision, state })?;
        self.flush_boundary(sequence)
    }

    pub fn append_snapshot<T: Serialize>(
        &mut self,
        snapshot_id: &str,
        snapshot: &T,
    ) -> Result<u64> {
        let sequence = self.append(
            "snapshot.result",
            SnapshotResult {
                snapshot_id,
                snapshot,
            },
        )?;
        self.flush_boundary(sequence)
    }

    fn append<T: Serialize>(&mut self, kind: &str, data: T) -> Result<u64> {
        let seq = self.next_seq;
        // 2026-08-30: Domain events, snapshots, and large session states used
        // to allocate an intermediate JSON tree before the journal encoded
        // them. Serialize borrowed payloads directly without changing JSONL.
        let entry = EncodedJournalEntry { seq, kind, data };
        let mut encoded = serde_json::to_vec(&entry)?;
        encoded.push(b'\n');
        // 2026-08-28: Journals performed an fsync for every record and had no
        // total size bound, so noisy targets could exhaust I/O and disk space.
        if self.bytes_written.saturating_add(encoded.len()) > self.max_bytes {
            return Err(Error::new(
                ErrorCode::OutputLimit,
                "session journal byte limit reached",
            ));
        }
        self.writer.write_all(&encoded)?;
        self.bytes_written += encoded.len();
        self.unflushed_records += 1;
        if self.unflushed_records >= 64 {
            self.flush()?;
        }
        self.next_seq += 1;
        Ok(seq)
    }

    pub fn flush(&mut self) -> Result<()> {
        if self.unflushed_records == 0 {
            return Ok(());
        }
        self.writer.flush()?;
        // 2026-08-29: A buffered flush only made records visible to the OS;
        // it did not satisfy the documented crash-durable evidence mode.
        if self.durability == JournalDurability::Durable {
            self.writer.get_ref().sync_data()?;
        }
        self.unflushed_records = 0;
        Ok(())
    }

    fn flush_boundary(&mut self, sequence: u64) -> Result<u64> {
        if self.durability == JournalDurability::Durable {
            self.flush()?;
        }
        Ok(sequence)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn appends_monotonic_jsonl_before_returning_event() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("journal.jsonl");
        let mut journal = Journal::create(&path, 1024).unwrap();
        assert_eq!(journal.append_mi_output(b"*running").unwrap(), 1);
        let event = journal
            .append_domain(DomainEvent::TargetRunning {
                backend_inferiors: vec![],
            })
            .unwrap();
        assert_eq!(event.seq(), 2);
        journal.flush().unwrap();

        let entries: Vec<JournalEntry> = BufReader::new(File::open(path).unwrap())
            .lines()
            .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
            .collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].kind, "mi.output");
        assert_eq!(entries[1].kind, "normalized.event");
    }

    #[test]
    fn rejects_records_beyond_the_session_quota() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("journal.jsonl");
        let mut journal = Journal::create(&path, 64).unwrap();
        let error = journal.append_mi_output(&[0; 128]).unwrap_err();
        assert_eq!(error.code, ErrorCode::OutputLimit);
        journal.flush().unwrap();
        assert!(std::fs::metadata(path).unwrap().len() <= 64);
    }

    #[test]
    fn records_pty_offsets_without_copying_output_bytes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("journal.jsonl");
        let mut journal = Journal::create(&path, 1024).unwrap();
        journal.append_inferior_output(4096, 65_536, 128).unwrap();
        journal.flush().unwrap();

        let entry: JournalEntry =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(entry.kind, "inferior.output");
        assert_eq!(entry.data["offset"], 4096);
        assert_eq!(entry.data["length"], 65_536);
        assert_eq!(entry.data["dropped_bytes"], 128);
        assert!(entry.data.get("raw_base64").is_none());
    }

    #[test]
    fn durable_mode_flushes_evidence_boundaries() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("journal.jsonl");
        let mut journal =
            Journal::create_with_durability(&path, 4096, JournalDurability::Durable).unwrap();

        journal
            .append_api(serde_json::json!({"method": "test"}))
            .unwrap();
        assert_eq!(journal.unflushed_records, 0);
        journal
            .append_state(1, &serde_json::json!({"revision": 1}))
            .unwrap();
        assert_eq!(journal.unflushed_records, 0);
        assert_eq!(std::fs::read_to_string(path).unwrap().lines().count(), 2);
    }
}
