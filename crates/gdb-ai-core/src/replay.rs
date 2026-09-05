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
    domain::{DomainEvent, JournaledEvent, SessionId, SessionLifecycle, SessionState},
    journal::{JournalEntry, JournalGap, require_next_sequence},
    normalize::normalize,
    reducer::StateReducer,
};

#[derive(Debug, Serialize)]
pub struct ReplayReport {
    pub complete: bool,
    pub evidence_gap: Option<JournalGap>,
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
    let mut complete = false;
    let mut evidence_gap: Option<JournalGap> = None;

    for line in BufReader::new(File::open(path)?).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: JournalEntry = serde_json::from_str(&line)?;
        if complete || evidence_gap.is_some() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "journal has records after its terminal marker",
            ));
        }
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
                    derived.push((entry.seq, event, false));
                }
            }
            "normalized.event" => {
                saw_normalized = true;
                let event: DomainEvent = serde_json::from_value(entry.data)?;
                // 2026-08-28: Complete journals carried both raw MI and
                // normalized events but replay trusted the latter blindly.
                // Verify adjacent MI-derived events before reducing them.
                if let Some((raw_seq, derived_event, matched)) = derived.last_mut()
                    && *raw_seq + 1 == entry.seq
                {
                    if *derived_event != event {
                        return Err(Error::new(
                            ErrorCode::InvalidArgument,
                            format!(
                                "normalized event {} differs from MI record {}",
                                entry.seq, raw_seq
                            ),
                        ));
                    }
                    *matched = true;
                }
                reducer.apply(&JournaledEvent::for_replay(entry.seq, event))?;
                applied_events += 1;
            }
            "state.revision" => {
                let revision = entry
                    .data
                    .get("revision")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        Error::new(ErrorCode::InvalidArgument, "missing state revision")
                    })?;
                let recorded: SessionState =
                    serde_json::from_value(entry.data.get("state").cloned().ok_or_else(|| {
                        Error::new(ErrorCode::InvalidArgument, "missing revision state")
                    })?)?;
                // 2026-08-28: Replay ignored persisted state checkpoints, so
                // reducer regressions and corrupted journals appeared valid.
                if !saw_normalized || revision != recorded.revision || reducer.state() != &recorded
                {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        format!("state checkpoint {} does not match replay", entry.seq),
                    ));
                }
            }
            "snapshot.result" => {
                snapshots += 1;
                latest_snapshot = entry.data.get("snapshot").cloned();
            }
            "journal.gap" => {
                let gap: JournalGap = serde_json::from_value(entry.data)?;
                if gap.from_seq != entry.seq {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "invalid journal gap",
                    ));
                }
                evidence_gap = Some(gap);
            }
            "journal.closed" => {
                // 2026-09-05: A storage failure can leave a valid prefix but
                // no writable gap marker. Only a clean close certifies that
                // the retained evidence covers the entire session.
                if reducer.state().lifecycle != SessionLifecycle::Closed {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "journal closed before the session",
                    ));
                }
                complete = true;
            }
            _ => {}
        }
    }

    if saw_normalized {
        if let Some((seq, _, _)) = derived.iter().find(|(seq, _, matched)| {
            !matched
                && evidence_gap
                    .as_ref()
                    .is_none_or(|gap| seq + 1 < gap.from_seq)
        }) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("MI record {seq} has no matching normalized event"),
            ));
        }
    } else {
        for (seq, event, _) in derived {
            reducer.apply(&JournaledEvent::for_replay(seq, event))?;
            applied_events += 1;
        }
    }

    Ok(ReplayReport {
        complete,
        evidence_gap,
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

    #[test]
    fn verifies_mi_events_and_state_checkpoints() {
        let mut transcript = NamedTempFile::new().unwrap();
        let session_id = SessionId("sess_recorded".into());
        let created = JournalEntry {
            seq: 1,
            kind: "session.created".into(),
            data: serde_json::json!({"session_id": session_id}),
        };
        let raw = b"*running,thread-id=\"all\"";
        let event =
            normalize(&gdb_ai_mi::parse_record(raw, gdb_ai_mi::MiLimits::default()).unwrap())
                .unwrap();
        let mut reducer = StateReducer::new(SessionState::creating(session_id));
        reducer
            .apply(&JournaledEvent::for_replay(3, event.clone()))
            .unwrap();
        let entries = [
            created,
            JournalEntry {
                seq: 2,
                kind: "mi.output".into(),
                data: serde_json::json!({"raw_base64": BASE64.encode(raw)}),
            },
            JournalEntry {
                seq: 3,
                kind: "normalized.event".into(),
                data: serde_json::to_value(event).unwrap(),
            },
            JournalEntry {
                seq: 4,
                kind: "state.revision".into(),
                data: serde_json::json!({
                    "revision": reducer.state().revision,
                    "state": reducer.state()
                }),
            },
        ];
        for entry in entries {
            writeln!(transcript, "{}", serde_json::to_string(&entry).unwrap()).unwrap();
        }

        let report = replay(transcript.path(), SessionId("ignored".into())).unwrap();
        assert_eq!(report.state, *reducer.state());
    }

    #[test]
    fn rejects_normalized_events_that_disagree_with_mi() {
        let mut transcript = NamedTempFile::new().unwrap();
        for entry in [
            JournalEntry {
                seq: 1,
                kind: "session.created".into(),
                data: serde_json::json!({"session_id": "sess_recorded"}),
            },
            JournalEntry {
                seq: 2,
                kind: "mi.output".into(),
                data: serde_json::json!({
                    "raw_base64": BASE64.encode("*running,thread-id=\"all\"")
                }),
            },
            JournalEntry {
                seq: 3,
                kind: "normalized.event".into(),
                data: serde_json::to_value(DomainEvent::BackendStarted).unwrap(),
            },
        ] {
            writeln!(transcript, "{}", serde_json::to_string(&entry).unwrap()).unwrap();
        }

        let error = replay(transcript.path(), SessionId("ignored".into())).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("differs from MI record"));
    }

    #[test]
    fn rejects_state_checkpoint_drift() {
        let mut transcript = NamedTempFile::new().unwrap();
        let mut state = SessionState::creating(SessionId("sess_recorded".into()));
        state.revision = 99;
        for entry in [
            JournalEntry {
                seq: 1,
                kind: "session.created".into(),
                data: serde_json::json!({"session_id": "sess_recorded"}),
            },
            JournalEntry {
                seq: 2,
                kind: "normalized.event".into(),
                data: serde_json::to_value(DomainEvent::BackendStarted).unwrap(),
            },
            JournalEntry {
                seq: 3,
                kind: "state.revision".into(),
                data: serde_json::json!({"revision": 99, "state": state}),
            },
        ] {
            writeln!(transcript, "{}", serde_json::to_string(&entry).unwrap()).unwrap();
        }

        let error = replay(transcript.path(), SessionId("ignored".into())).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("does not match replay"));
    }
}
