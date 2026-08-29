use gdb_ai_mi::{MiRecord, MiResult, MiValue};

use crate::{
    Error, ErrorCode, Result,
    domain::{DomainEvent, FrameSummary, OutputSource, StopReason},
};

pub fn normalize(record: &MiRecord) -> Option<DomainEvent> {
    match record {
        MiRecord::ExecAsync { class, results, .. } if class == "running" => {
            let groups = MiResult::find_str(results, "thread-group")
                .map(|group| vec![group.to_owned()])
                .unwrap_or_default();
            Some(DomainEvent::TargetRunning {
                backend_inferiors: groups,
            })
        }
        MiRecord::ExecAsync { class, results, .. } if class == "stopped" => stopped(results),
        MiRecord::ExecAsync { class, .. } => Some(DomainEvent::UnknownBackendEvent {
            class: format!("exec:{class}"),
        }),
        MiRecord::NotifyAsync { class, results, .. } => notification(class, results),
        MiRecord::ConsoleStream(bytes) => Some(DomainEvent::Output {
            source: OutputSource::GdbConsoleStream,
            bytes: bytes.clone(),
        }),
        MiRecord::TargetStream(bytes) => Some(DomainEvent::Output {
            source: OutputSource::MiTargetStream,
            bytes: bytes.clone(),
        }),
        MiRecord::LogStream(bytes) => Some(DomainEvent::Output {
            source: OutputSource::GdbLogStream,
            bytes: bytes.clone(),
        }),
        MiRecord::Result { .. } | MiRecord::StatusAsync { .. } | MiRecord::Prompt => None,
    }
}

pub(crate) fn breakpoint_number(record: &MiRecord) -> Result<String> {
    MiResult::find(record.results(), "bkpt")
        .and_then(MiValue::results)
        .and_then(|fields| MiResult::find_str(fields, "number"))
        .map(str::to_owned)
        .ok_or_else(|| Error::new(ErrorCode::GdbError, "GDB returned no breakpoint number"))
}

fn stopped(results: &[MiResult]) -> Option<DomainEvent> {
    let raw_reason = MiResult::find_str(results, "reason")
        .unwrap_or("unknown")
        .to_owned();
    let backend_inferior = MiResult::find_str(results, "thread-group").map(str::to_owned);
    if raw_reason.starts_with("exited") {
        return Some(DomainEvent::InferiorExited {
            backend_id: backend_inferior.unwrap_or_else(|| "i1".into()),
            exit_code: MiResult::find_str(results, "exit-code").map(str::to_owned),
            from_stop_record: true,
        });
    }
    Some(DomainEvent::TargetStopped {
        backend_inferior,
        backend_thread: MiResult::find_str(results, "thread-id").map(str::to_owned),
        reason: raw_reason.clone(),
        reason_detail: Some(stop_reason(results, raw_reason)),
        frame: MiResult::find(results, "frame").and_then(frame),
    })
}

// 2026-08-28: Keeping only GDB's reason string discarded bkptno and signal
// metadata, so Agent probes could treat any stop as evidence of their own hit.
fn stop_reason(results: &[MiResult], raw_reason: String) -> StopReason {
    match raw_reason.as_str() {
        "breakpoint-hit" => StopReason::Breakpoint {
            backend_number: text(results, "bkptno"),
            disposition: text(results, "disp"),
        },
        "watchpoint-trigger" | "read-watchpoint-trigger" | "access-watchpoint-trigger" => {
            let fields = ["wpt", "hw-rwpt", "hw-awpt"]
                .iter()
                .find_map(|name| MiResult::find(results, name).and_then(MiValue::results));
            StopReason::Watchpoint {
                backend_number: fields.and_then(|fields| text(fields, "number")),
                expression: fields.and_then(|fields| text(fields, "exp")),
                access: raw_reason,
            }
        }
        "signal-received" => StopReason::Signal {
            name: text(results, "signal-name"),
            meaning: text(results, "signal-meaning"),
        },
        "end-stepping-range" => StopReason::EndSteppingRange,
        "function-finished" => StopReason::FunctionFinished,
        "location-reached" => StopReason::LocationReached,
        "interrupt" => StopReason::Interrupt,
        _ => StopReason::Unknown { raw_reason },
    }
}

fn notification(class: &str, results: &[MiResult]) -> Option<DomainEvent> {
    match class {
        "thread-group-added" | "thread-group-started" => Some(DomainEvent::InferiorAdded {
            backend_id: text(results, "id").unwrap_or_else(|| "i1".into()),
            pid: MiResult::find_str(results, "pid").and_then(|pid| pid.parse().ok()),
        }),
        "thread-group-removed" => Some(DomainEvent::InferiorRemoved {
            backend_id: text(results, "id")?,
        }),
        "thread-group-exited" => Some(DomainEvent::InferiorExited {
            backend_id: text(results, "id")?,
            exit_code: text(results, "exit-code"),
            from_stop_record: false,
        }),
        "thread-created" => Some(DomainEvent::ThreadCreated {
            backend_inferior: text(results, "group-id").unwrap_or_else(|| "i1".into()),
            backend_thread: text(results, "id")?,
        }),
        "thread-exited" => Some(DomainEvent::ThreadExited {
            backend_inferior: text(results, "group-id"),
            backend_thread: text(results, "id")?,
        }),
        "breakpoint-created" => breakpoint(results, false),
        "breakpoint-modified" => breakpoint(results, true),
        "breakpoint-deleted" => Some(DomainEvent::BreakpointDeleted {
            backend_number: text(results, "id")?,
        }),
        "library-loaded" => Some(DomainEvent::LibraryLoaded {
            id: text(results, "id")?,
            target_name: text(results, "target-name"),
            host_name: text(results, "host-name"),
            symbols_loaded: text(results, "symbols-loaded").map(|value| value == "1"),
        }),
        "library-unloaded" => Some(DomainEvent::LibraryUnloaded {
            id: text(results, "id")?,
        }),
        "memory-changed" => Some(DomainEvent::MemoryChanged),
        // These notifications do not alter the canonical all-stop model.
        "thread-selected" | "cmd-param-changed" => None,
        // 2026-08-28: Future informational notifications permanently tainted
        // sessions. Preserve them separately so managed reconciliation can
        // recover without treating every new MI notification as a mutation.
        _ => Some(DomainEvent::UnknownBackendNotification {
            class: format!("notify:{class}"),
        }),
    }
}

fn breakpoint(results: &[MiResult], modified: bool) -> Option<DomainEvent> {
    let fields = MiResult::find(results, "bkpt")?.results()?;
    let backend_number = text(fields, "number")?;
    let enabled = text(fields, "enabled").is_none_or(|value| value == "y");
    let pending = text(fields, "pending").is_some_and(|value| value == "y")
        || text(fields, "addr").as_deref() == Some("<PENDING>");
    Some(if modified {
        DomainEvent::BreakpointModified {
            backend_number,
            enabled,
            pending,
        }
    } else {
        DomainEvent::BreakpointCreated {
            backend_number,
            enabled,
            pending,
        }
    })
}

fn frame(value: &MiValue) -> Option<FrameSummary> {
    let fields = value.results()?;
    Some(FrameSummary {
        level: MiResult::find_str(fields, "level")
            .and_then(|level| level.parse().ok())
            .unwrap_or(0),
        address: text(fields, "addr"),
        function: text(fields, "func"),
        source: text(fields, "fullname").or_else(|| text(fields, "file")),
        line: MiResult::find_str(fields, "line").and_then(|line| line.parse().ok()),
    })
}

fn text(results: &[MiResult], name: &str) -> Option<String> {
    MiResult::find_str(results, name).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use gdb_ai_mi::{MiLimits, parse_record};

    use super::*;

    #[test]
    fn normalizes_stop_without_losing_frame() {
        let record = parse_record(
            b"*stopped,reason=\"breakpoint-hit\",thread-id=\"1\",thread-group=\"i1\",frame={addr=\"0x401000\",func=\"main\",file=\"a.c\",line=\"7\"}",
            MiLimits::default(),
        )
        .unwrap();
        let DomainEvent::TargetStopped {
            reason,
            reason_detail,
            frame,
            ..
        } = normalize(&record).unwrap()
        else {
            panic!("wrong event");
        };
        assert_eq!(reason, "breakpoint-hit");
        assert_eq!(
            reason_detail,
            Some(StopReason::Breakpoint {
                backend_number: None,
                disposition: None
            })
        );
        assert_eq!(frame.unwrap().function.as_deref(), Some("main"));
    }

    #[test]
    fn preserves_stop_attribution_fields() {
        let record = parse_record(
            b"*stopped,reason=\"breakpoint-hit\",disp=\"keep\",bkptno=\"7.2\",thread-id=\"3\",thread-group=\"i1\"",
            MiLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            normalize(&record),
            Some(DomainEvent::TargetStopped {
                reason_detail: Some(StopReason::Breakpoint {
                    backend_number: Some(number),
                    disposition: Some(disposition),
                }),
                ..
            }) if number == "7.2" && disposition == "keep"
        ));
    }

    #[test]
    fn unknown_notification_requests_managed_reconciliation() {
        let record = parse_record(b"=future-event,x=\"1\"", MiLimits::default()).unwrap();
        assert!(matches!(
            normalize(&record),
            Some(DomainEvent::UnknownBackendNotification { .. })
        ));
    }

    #[test]
    fn unknown_exec_event_remains_unclassifiable() {
        let record = parse_record(b"*future-exec,x=\"1\"", MiLimits::default()).unwrap();
        assert!(matches!(
            normalize(&record),
            Some(DomainEvent::UnknownBackendEvent { .. })
        ));
    }
}
