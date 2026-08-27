use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    Result,
    domain::{DomainEvent, JournaledEvent},
};

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
}

impl Journal {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create_new(true).write(true).open(path)?;
        Ok(Self {
            writer: BufWriter::new(file),
            next_seq: 1,
        })
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

    pub fn append_inferior_output(&mut self, bytes: &[u8]) -> Result<u64> {
        self.append(
            "inferior.output",
            serde_json::json!({ "raw_base64": BASE64.encode(bytes) }),
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

    fn append(&mut self, kind: &str, data: Value) -> Result<u64> {
        let seq = self.next_seq;
        let entry = JournalEntry {
            seq,
            kind: kind.to_owned(),
            data,
        };
        serde_json::to_writer(&mut self.writer, &entry)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        self.writer.get_ref().sync_data()?;
        self.next_seq += 1;
        Ok(seq)
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
        let mut journal = Journal::create(&path).unwrap();
        assert_eq!(journal.append_mi_output(b"*running").unwrap(), 1);
        let event = journal
            .append_domain(DomainEvent::TargetRunning {
                backend_inferiors: vec![],
            })
            .unwrap();
        assert_eq!(event.seq(), 2);
        drop(journal);

        let entries: Vec<JournalEntry> = BufReader::new(File::open(path).unwrap())
            .lines()
            .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
            .collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].kind, "mi.output");
        assert_eq!(entries[1].kind, "normalized.event");
    }
}
