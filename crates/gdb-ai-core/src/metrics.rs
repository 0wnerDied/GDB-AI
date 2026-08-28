use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    sessions_total: AtomicU64,
    sessions_active: AtomicU64,
    session_failures: AtomicU64,
    gdb_start_failures: AtomicU64,
    mi_records: AtomicU64,
    mi_parse_errors: AtomicU64,
    mi_unknown_classes: AtomicU64,
    commands: AtomicU64,
    command_latency_micros: AtomicU64,
    command_timeouts: AtomicU64,
    target_stops: AtomicU64,
    snapshots: AtomicU64,
    snapshot_partial: AtomicU64,
    raw_commands: AtomicU64,
    reconciliations: AtomicU64,
    consistency_lost: AtomicU64,
    response_truncations: AtomicU64,
    artifact_bytes: AtomicU64,
    inferior_output_dropped_bytes: AtomicU64,
}

impl Metrics {
    pub fn session_started(&self) {
        self.sessions_total.fetch_add(1, Ordering::Relaxed);
        self.sessions_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn session_closed(&self) {
        self.sessions_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn session_failed(&self) {
        self.session_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn gdb_start_failed(&self) {
        self.gdb_start_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mi_record(&self) {
        self.mi_records.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mi_parse_error(&self) {
        self.mi_parse_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mi_unknown_class(&self) {
        self.mi_unknown_classes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn command(&self, elapsed_micros: u64, timed_out: bool) {
        self.commands.fetch_add(1, Ordering::Relaxed);
        self.command_latency_micros
            .fetch_add(elapsed_micros, Ordering::Relaxed);
        if timed_out {
            self.command_timeouts.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn target_stop(&self) {
        self.target_stops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self, partial: bool) {
        self.snapshots.fetch_add(1, Ordering::Relaxed);
        if partial {
            self.snapshot_partial.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn raw_command(&self) {
        self.raw_commands.fetch_add(1, Ordering::Relaxed);
    }

    pub fn reconciliation(&self) {
        self.reconciliations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn consistency_lost(&self) {
        self.consistency_lost.fetch_add(1, Ordering::Relaxed);
    }

    pub fn response_truncated(&self) {
        self.response_truncations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn artifact_written(&self, bytes: usize) {
        self.artifact_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn inferior_output_dropped(&self, bytes: u64) {
        self.inferior_output_dropped_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn render(&self) -> String {
        let value = |metric: &AtomicU64| metric.load(Ordering::Relaxed);
        format!(
            concat!(
                "gdbai_sessions_total {}\n",
                "gdbai_sessions_active {}\n",
                "gdbai_session_failures_total {}\n",
                "gdbai_gdb_start_failures_total {}\n",
                "gdbai_mi_records_total {}\n",
                "gdbai_mi_parse_errors_total {}\n",
                "gdbai_mi_unknown_classes_total {}\n",
                "gdbai_commands_total {}\n",
                "gdbai_command_latency_seconds {}\n",
                "gdbai_command_timeouts_total {}\n",
                "gdbai_target_stops_total {}\n",
                "gdbai_snapshot_total {}\n",
                "gdbai_snapshot_partial_total {}\n",
                "gdbai_raw_commands_total {}\n",
                "gdbai_reconciliations_total {}\n",
                "gdbai_consistency_lost_total {}\n",
                "gdbai_response_truncations_total {}\n",
                "gdbai_artifact_bytes_total {}\n",
                "gdbai_inferior_output_dropped_bytes_total {}\n"
            ),
            value(&self.sessions_total),
            value(&self.sessions_active),
            value(&self.session_failures),
            value(&self.gdb_start_failures),
            value(&self.mi_records),
            value(&self.mi_parse_errors),
            value(&self.mi_unknown_classes),
            value(&self.commands),
            value(&self.command_latency_micros) as f64 / 1_000_000.0,
            value(&self.command_timeouts),
            value(&self.target_stops),
            value(&self.snapshots),
            value(&self.snapshot_partial),
            value(&self.raw_commands),
            value(&self.reconciliations),
            value(&self.consistency_lost),
            value(&self.response_truncations),
            value(&self.artifact_bytes),
            value(&self.inferior_output_dropped_bytes)
        )
    }
}
