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

pub struct Journal {
    writer: BufWriter<File>,
    next_seq: u64,
    bytes_written: usize,
    max_bytes: usize,
    unflushed_records: usize,
}

impl Journal {
    pub fn create(path: impl AsRef<Path>, max_bytes: usize) -> Result<Self> {
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
        })
    }

    pub fn append_session_created(&mut self, session_id: &str) -> Result<u64> {
        self.append(
            "session.created",
            serde_json::json!({"session_id": session_id}),
        )
    }

    pub fn append_api(&mut self, request: &Value) -> Result<u64> {
        self.append("api.request", request.clone())
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

    pub fn append_domain(&mut self, event: DomainEvent) -> Result<JournaledEvent> {
        let data = serde_json::to_value(&event)?;
        let seq = self.append("normalized.event", data)?;
        Ok(JournaledEvent::new(seq, event))
    }

    pub fn append_state(&mut self, revision: u64, state: &Value) -> Result<u64> {
        self.append(
            "state.revision",
            serde_json::json!({ "revision": revision, "state": state }),
        )
    }

    pub fn append_snapshot(&mut self, snapshot_id: &str, snapshot: &Value) -> Result<u64> {
        self.append(
            "snapshot.result",
            serde_json::json!({ "snapshot_id": snapshot_id, "snapshot": snapshot }),
        )
    }

    fn append(&mut self, kind: &str, data: Value) -> Result<u64> {
        let seq = self.next_seq;
        let entry = JournalEntry {
            seq,
            kind: kind.to_owned(),
            data,
        };
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
        self.unflushed_records = 0;
        Ok(())
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
}
