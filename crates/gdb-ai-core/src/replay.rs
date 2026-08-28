use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::Serialize;
use serde_json::Value;

use crate::{
    Error, ErrorCode, Result,
    domain::{DomainEvent, JournaledEvent, SessionId, SessionState},
    journal::{JournalEntry, require_next_sequence},
    normalize::normalize,
    reducer::StateReducer,
};

#[derive(Debug, Serialize)]
pub struct ReplayReport {
    pub entries: u64,
    pub parsed_mi_records: u64,
    pub applied_events: u64,
    pub snapshots: u64,
    pub latest_snapshot: Option<Value>,
    pub state: SessionState,
}

pub fn replay(path: impl AsRef<Path>, session_id: SessionId) -> Result<ReplayReport> {
    let mut reducer = StateReducer::new(SessionState::creating(session_id));
    let mut entries = 0;
    let mut parsed_mi_records = 0;
    let mut applied_events = 0;
    let mut saw_normalized = false;
    let mut derived = Vec::new();
    let mut snapshots = 0;
    let mut latest_snapshot = None;
    let mut last_seq = 0;

    for line in BufReader::new(File::open(path)?).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: JournalEntry = serde_json::from_str(&line)?;
        require_next_sequence(last_seq, entry.seq)?;
        last_seq = entry.seq;
        entries += 1;
        match entry.kind.as_str() {
            "session.created" if entries == 1 => {
                let recorded = entry
                    .data
                    .get("session_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        Error::new(ErrorCode::InvalidArgument, "missing recorded session_id")
                    })?;
                // 2026-08-28: Replay previously trusted a caller-supplied ID,
                // producing different public handles from the same journal.
                reducer = StateReducer::new(SessionState::creating(SessionId::parse(recorded)?));
            }
            "session.created" => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "session.created must be the first journal entry",
                ));
            }
            "mi.output" => {
                let raw = entry
                    .data
                    .get("raw_base64")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "missing raw_base64"))?;
                let raw = BASE64.decode(raw).map_err(|error| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid base64: {error}"),
                    )
                })?;
                let record = gdb_ai_mi::parse_record(&raw, gdb_ai_mi::MiLimits::default())?;
                parsed_mi_records += 1;
                if let Some(event) = normalize(&record) {
                    derived.push((entry.seq, event));
                }
            }
            "normalized.event" => {
                saw_normalized = true;
                let event: DomainEvent = serde_json::from_value(entry.data)?;
                reducer.apply(&JournaledEvent::for_replay(entry.seq, event))?;
                applied_events += 1;
            }
            "snapshot.result" => {
                snapshots += 1;
                latest_snapshot = entry.data.get("snapshot").cloned();
            }
            _ => {}
        }
    }

    if !saw_normalized {
        for (seq, event) in derived {
            reducer.apply(&JournaledEvent::for_replay(seq, event))?;
            applied_events += 1;
        }
    }

    Ok(ReplayReport {
        entries,
        parsed_mi_records,
        applied_events,
        snapshots,
        latest_snapshot,
        state: reducer.into_state(),
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn raw_transcript_replay_is_deterministic() {
        let mut transcript = NamedTempFile::new().unwrap();
        let created = JournalEntry {
            seq: 1,
            kind: "session.created".into(),
            data: serde_json::json!({"session_id": "sess_recorded"}),
        };
        writeln!(transcript, "{}", serde_json::to_string(&created).unwrap()).unwrap();
        for (seq, raw) in [
            (2, "=thread-group-added,id=\"i1\""),
            (
                3,
                "*stopped,reason=\"breakpoint-hit\",thread-group=\"i1\",thread-id=\"1\"",
            ),
            (4, "*running,thread-id=\"all\""),
        ] {
            let entry = JournalEntry {
                seq,
                kind: "mi.output".into(),
                data: serde_json::json!({ "raw_base64": BASE64.encode(raw) }),
            };
            writeln!(transcript, "{}", serde_json::to_string(&entry).unwrap()).unwrap();
        }
        let first = replay(transcript.path(), SessionId("sess_test".into())).unwrap();
        let second = replay(transcript.path(), SessionId("sess_test".into())).unwrap();
        assert_eq!(first.state, second.state);
        assert_eq!(first.state.session_id.0, "sess_recorded");
        assert_eq!(first.state.execution_epoch, 1);
        assert!(first.state.stop_id.is_none());
    }

    #[test]
    fn rejects_duplicate_journal_sequence() {
        let mut transcript = NamedTempFile::new().unwrap();
        let entry = JournalEntry {
            seq: 1,
            kind: "mi.output".into(),
            data: serde_json::json!({ "raw_base64": BASE64.encode("(gdb)") }),
        };
        writeln!(transcript, "{}", serde_json::to_string(&entry).unwrap()).unwrap();
        writeln!(transcript, "{}", serde_json::to_string(&entry).unwrap()).unwrap();
        assert!(matches!(
            replay(transcript.path(), SessionId("sess_test".into())),
            Err(Error {
                code: ErrorCode::InvalidArgument,
                ..
            })
        ));

        let mut gap = NamedTempFile::new().unwrap();
        let mut skipped = entry;
        skipped.seq = 2;
        writeln!(gap, "{}", serde_json::to_string(&skipped).unwrap()).unwrap();
        assert!(replay(gap.path(), SessionId("sess_test".into())).is_err());
    }
}
