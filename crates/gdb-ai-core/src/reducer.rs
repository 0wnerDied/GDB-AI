use crate::{
    Error, ErrorCode, Result,
    domain::{
        BackendHealth, BreakpointId, BreakpointLocationState, BreakpointState, Consistency,
        DomainEvent, InferiorId, InferiorState, InferiorStatus, JournaledEvent, ModuleState,
        SessionLifecycle, SessionState, SnapshotRef, SnapshotStatus, StopId, StopReason,
        TargetOrigin, ThreadId, ThreadState,
    },
};

const MAX_LIMITATIONS: usize = 64;
const LIMITATIONS_OMITTED: &str = "additional limitations omitted";

fn push_limitation(limitations: &mut Vec<String>, limitation: String) {
    if limitations.contains(&limitation)
        || limitations
            .iter()
            .any(|current| current == LIMITATIONS_OMITTED)
    {
        return;
    }
    // 2026-08-30: Repeated backend anomalies grew every persisted state and
    // amplified the journal quadratically. Keep a fixed unique prefix and an
    // explicit truncation marker instead of retaining unbounded free text.
    if limitations.len() < MAX_LIMITATIONS - 1 {
        limitations.push(limitation);
    } else {
        limitations.push(LIMITATIONS_OMITTED.to_owned());
    }
}

/// The sole transition point for session state. Events arrive in journal
/// order so replay applies the same revisions as a live session.
#[derive(Debug)]
pub struct StateReducer {
    state: SessionState,
}

impl StateReducer {
    pub fn new(state: SessionState) -> Self {
        Self { state }
    }

    pub fn state(&self) -> &SessionState {
        &self.state
    }

    pub fn into_state(self) -> SessionState {
        self.state
    }

    pub fn fail_closed(&mut self) -> bool {
        let changed = self.fail_backend();
        if changed {
            self.state.revision += 1;
        }
        changed
    }

    pub fn apply(&mut self, journaled: &JournaledEvent) -> Result<bool> {
        if journaled.seq() <= self.state.event_seq {
            return Err(Error::new(
                ErrorCode::InvalidState,
                format!(
                    "event sequence {} is not greater than {}",
                    journaled.seq(),
                    self.state.event_seq
                ),
            ));
        }
        self.state.event_seq = journaled.seq();
        let changed = self.reduce(journaled.event());
        if changed {
            self.state.revision += 1;
        }
        Ok(changed)
    }

    fn reduce(&mut self, event: &DomainEvent) -> bool {
        match event {
            DomainEvent::SessionClosing => {
                self.state.lifecycle = SessionLifecycle::Closing;
                true
            }
            DomainEvent::SessionClosed => {
                self.state.lifecycle = SessionLifecycle::Closed;
                self.state.backend = BackendHealth::Dead;
                true
            }
            DomainEvent::BackendStarted => {
                self.state.lifecycle = SessionLifecycle::Ready;
                self.state.backend = BackendHealth::Healthy;
                true
            }
            DomainEvent::BackendExited { .. } => self.fail_backend(),
            DomainEvent::InferiorAdded { backend_id, pid } => {
                let seq = self.state.event_seq;
                let session_id = self.state.session_id.clone();
                let inferior = self.ensure_inferior(backend_id, seq);
                // 2026-09-04: GDB reuses a thread-group after exit, which
                // carried its terminal code and handles into the next launch.
                // A PID-bearing add for a new process starts a clean generation.
                if pid.is_some()
                    && (inferior.pid != *pid
                        || matches!(
                            inferior.status,
                            InferiorStatus::Exited
                                | InferiorStatus::Detached
                                | InferiorStatus::Disconnected
                        ))
                {
                    *inferior = InferiorState {
                        id: InferiorId::from_backend(&session_id, seq, backend_id),
                        backend_id: backend_id.clone(),
                        pid: None,
                        generation: seq,
                        status: InferiorStatus::Empty,
                        exit_code: None,
                        threads: Default::default(),
                    };
                }
                inferior.pid = *pid;
                if pid.is_some() && inferior.status == InferiorStatus::Empty {
                    inferior.status = InferiorStatus::Connecting;
                }
                if pid.is_some() {
                    self.state.lifecycle = SessionLifecycle::Active;
                }
                true
            }
            DomainEvent::InferiorRemoved { backend_id } => {
                let Some(removed) = self.state.inferiors.remove(backend_id) else {
                    return false;
                };
                if self.state.stopped_inferior_id.as_ref() == Some(&removed.id) {
                    self.clear_stop_context();
                }
                true
            }
            DomainEvent::InferiorExited {
                backend_id,
                exit_code,
                from_stop_record,
            } => {
                // 2026-08-29: A lost RSP connection is reported as a remote
                // thread-group exit without an exit code. Treat it as a
                // disconnect unless an earlier stopped record already proved
                // the inferior exited normally.
                let disconnected = self.state.target_origin == TargetOrigin::Remote
                    && !from_stop_record
                    && exit_code.is_none()
                    && self
                        .state
                        .inferiors
                        .get(backend_id)
                        .is_none_or(|inferior| inferior.status != InferiorStatus::Exited);
                // 2026-08-30: An unrelated inferior exit used to invalidate
                // the current stopped inferior, while direct removal left a
                // dangling stop. Scope stop invalidation to its owning group.
                let invalidates_stop =
                    self.state
                        .inferiors
                        .get(backend_id)
                        .is_some_and(|inferior| {
                            self.state.stopped_inferior_id.as_ref() == Some(&inferior.id)
                        });
                let seq = self.state.event_seq;
                let inferior = self.ensure_inferior(backend_id, seq);
                inferior.status = if disconnected {
                    InferiorStatus::Disconnected
                } else {
                    InferiorStatus::Exited
                };
                inferior.exit_code.clone_from(exit_code);
                if invalidates_stop {
                    self.clear_stop_context();
                }
                true
            }
            DomainEvent::TargetRunning { backend_inferiors } => {
                let was_running = self
                    .state
                    .inferiors
                    .values()
                    .any(|inferior| inferior.status == InferiorStatus::Running);
                let previous_lifecycle = self.state.lifecycle;
                let had_stop = self.state.stop_id.is_some();
                let mut status_changed = false;
                let seq = self.state.event_seq;
                if self.state.inferiors.is_empty() {
                    self.ensure_inferior(
                        backend_inferiors.first().map_or("i1", String::as_str),
                        seq,
                    );
                }
                for (backend_id, inferior) in &mut self.state.inferiors {
                    if backend_inferiors.is_empty() || backend_inferiors.contains(backend_id) {
                        status_changed |= inferior.status != InferiorStatus::Running;
                        inferior.status = InferiorStatus::Running;
                        for thread in inferior.threads.values_mut() {
                            thread.running = true;
                            thread.frame = None;
                        }
                    }
                }
                self.state.lifecycle = SessionLifecycle::Active;
                let is_running = self
                    .state
                    .inferiors
                    .values()
                    .any(|inferior| inferior.status == InferiorStatus::Running);
                // 2026-08-28: Repeated or per-inferior *running records for one
                // resume incremented the global epoch more than once. Advance
                // only on the aggregate not-running to running edge.
                let running_edge = !was_running && is_running;
                if running_edge {
                    self.state.execution_epoch += 1;
                }
                self.clear_stop_context();
                running_edge
                    || status_changed
                    || had_stop
                    || previous_lifecycle != SessionLifecycle::Active
            }
            DomainEvent::TargetStopped {
                backend_inferior,
                backend_thread,
                reason,
                reason_detail,
                frame,
            } => {
                let backend_id = backend_inferior
                    .as_deref()
                    .or_else(|| self.state.inferiors.keys().next().map(String::as_str))
                    .unwrap_or("i1")
                    .to_owned();
                let seq = self.state.event_seq;
                self.ensure_inferior(&backend_id, seq);
                for inferior in self.state.inferiors.values_mut() {
                    if !matches!(
                        inferior.status,
                        InferiorStatus::Exited
                            | InferiorStatus::Detached
                            | InferiorStatus::Disconnected
                    ) {
                        inferior.status = InferiorStatus::Stopped;
                        for thread in inferior.threads.values_mut() {
                            thread.running = false;
                        }
                    }
                }
                let stopped_inferior_id = self
                    .state
                    .inferiors
                    .get(&backend_id)
                    .map(|inferior| inferior.id.clone());
                let mut stopped_thread_id = None;
                if let Some(backend_thread) = backend_thread {
                    let inferior = self.state.inferiors.get_mut(&backend_id).unwrap();
                    let id = inferior
                        .threads
                        .get(backend_thread)
                        .map(|thread| thread.id.clone())
                        .unwrap_or_else(|| {
                            ThreadId::from_backend(&inferior.id, seq, backend_thread)
                        });
                    stopped_thread_id = Some(id.clone());
                    inferior.threads.insert(
                        backend_thread.clone(),
                        ThreadState {
                            id,
                            backend_id: backend_thread.clone(),
                            running: false,
                            frame: frame.clone(),
                        },
                    );
                }
                let stop_id = StopId::from_event(&self.state.session_id, self.state.event_seq);
                self.state.stop_id = Some(stop_id.clone());
                self.state.stop_reason = Some(reason.clone());
                self.state.stop_reason_detail = reason_detail.clone().or_else(|| {
                    Some(StopReason::Unknown {
                        raw_reason: reason.clone(),
                    })
                });
                self.state.stopped_inferior_id = stopped_inferior_id;
                self.state.stopped_thread_id = stopped_thread_id;
                self.state.snapshot = Some(SnapshotRef {
                    snapshot_id: format!("snap_{stop_id}"),
                    stop_id,
                    status: SnapshotStatus::Building,
                    partial: false,
                });
                self.state.lifecycle = SessionLifecycle::Active;
                self.state.backend = BackendHealth::Healthy;
                true
            }
            DomainEvent::ThreadCreated {
                backend_inferior,
                backend_thread,
            } => {
                let seq = self.state.event_seq;
                let inferior = self.ensure_inferior(backend_inferior, seq);
                if let Some(thread) = inferior.threads.get_mut(backend_thread) {
                    let running = inferior.status == InferiorStatus::Running;
                    let changed = thread.running != running;
                    thread.running = running;
                    changed
                } else {
                    let id = ThreadId::from_backend(&inferior.id, seq, backend_thread);
                    inferior.threads.insert(
                        backend_thread.clone(),
                        ThreadState {
                            id,
                            backend_id: backend_thread.clone(),
                            running: inferior.status == InferiorStatus::Running,
                            frame: None,
                        },
                    );
                    true
                }
            }
            DomainEvent::ThreadExited {
                backend_inferior,
                backend_thread,
            } => {
                if let Some(backend_inferior) = backend_inferior {
                    self.state
                        .inferiors
                        .get_mut(backend_inferior)
                        .is_some_and(|inferior| inferior.threads.remove(backend_thread).is_some())
                } else {
                    self.state
                        .inferiors
                        .values_mut()
                        .any(|inferior| inferior.threads.remove(backend_thread).is_some())
                }
            }
            DomainEvent::BreakpointCreated {
                backend_number,
                enabled,
                pending,
            }
            | DomainEvent::BreakpointModified {
                backend_number,
                enabled,
                pending,
            } => {
                let id = self
                    .state
                    .breakpoints
                    .get(backend_number)
                    .map(|breakpoint| breakpoint.id.clone())
                    .unwrap_or_else(|| {
                        // 2026-08-31: GDB reuses deleted breakpoint numbers.
                        // The session event sequence prevents aliases without
                        // repeating the already-scoped session ID.
                        if self.state.session_id.uses_compact_handles() {
                            BreakpointId(format!(
                                "b{}_{}",
                                self.state.event_seq,
                                backend_number.replace('.', "_")
                            ))
                        } else {
                            BreakpointId(format!(
                                "bp_{}_{}_{}",
                                self.state.session_id.0,
                                self.state.event_seq,
                                backend_number.replace('.', "_")
                            ))
                        }
                    });
                let locations = self
                    .state
                    .breakpoints
                    .get(backend_number)
                    .map(|breakpoint| breakpoint.locations.clone())
                    .unwrap_or_default();
                self.state.breakpoints.insert(
                    backend_number.clone(),
                    BreakpointState {
                        id,
                        backend_number: backend_number.clone(),
                        enabled: *enabled,
                        pending: *pending,
                        locations,
                    },
                );
                true
            }
            DomainEvent::BreakpointDeleted { backend_number } => {
                self.state.breakpoints.remove(backend_number).is_some()
            }
            DomainEvent::BreakpointLocations {
                backend_number,
                locations,
            } => {
                if let Some(breakpoint) = self.state.breakpoints.get_mut(backend_number) {
                    breakpoint.locations.clone_from(locations);
                    true
                } else {
                    false
                }
            }
            DomainEvent::BreakpointRebound {
                id,
                old_backend_number,
                new_backend_number,
                enabled,
                address,
            } => {
                self.state.breakpoints.remove(old_backend_number);
                self.state.breakpoints.remove(new_backend_number);
                self.state.breakpoints.insert(
                    new_backend_number.clone(),
                    BreakpointState {
                        id: id.clone(),
                        backend_number: new_backend_number.clone(),
                        enabled: *enabled,
                        pending: address.is_none(),
                        locations: address
                            .as_ref()
                            .map(|address| {
                                vec![BreakpointLocationState {
                                    id: format!("bpl_{}_{}_1", id.0, self.state.event_seq),
                                    backend_number: new_backend_number.clone(),
                                    address: Some(address.clone()),
                                    function: None,
                                }]
                            })
                            .unwrap_or_default(),
                    },
                );
                true
            }
            DomainEvent::LibraryLoaded {
                id,
                target_name,
                host_name,
                symbols_loaded,
            } => {
                self.state.modules.insert(
                    id.clone(),
                    ModuleState {
                        id: id.clone(),
                        target_name: target_name.clone(),
                        host_name: host_name.clone(),
                        symbols_loaded: *symbols_loaded,
                    },
                );
                true
            }
            DomainEvent::LibraryUnloaded { id } => self.state.modules.remove(id).is_some(),
            // 2026-08-28: Target mutations previously advanced revision but
            // left a stale snapshot advertised as current.
            DomainEvent::MemoryChanged | DomainEvent::RegisterChanged { .. } => {
                self.state.snapshot = None;
                true
            }
            // 2026-08-28: Controller registries and inferior I/O previously
            // changed without advancing optimistic-concurrency revision.
            DomainEvent::ControllerChanged { .. } => true,
            DomainEvent::SignalPolicyChanged { signal, policy } => {
                self.state
                    .signal_policies
                    .insert(signal.clone(), policy.clone());
                true
            }
            DomainEvent::SnapshotStarted { stop_id }
                if self.state.stop_id.as_ref() == Some(stop_id) =>
            {
                // 2026-08-30: A synchronous enrichment attempt replaced the
                // committed minimal snapshot before the new value existed.
                // Keep the last readable snapshot until commit succeeds.
                if self
                    .state
                    .snapshot
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.status == SnapshotStatus::Ready)
                {
                    return false;
                }
                self.state.snapshot = Some(SnapshotRef {
                    snapshot_id: format!("snap_{stop_id}"),
                    stop_id: stop_id.clone(),
                    status: SnapshotStatus::Building,
                    partial: false,
                });
                true
            }
            DomainEvent::SnapshotReady { stop_id, partial }
                if self.state.stop_id.as_ref() == Some(stop_id) =>
            {
                if let Some(snapshot) = &mut self.state.snapshot {
                    snapshot.status = SnapshotStatus::Ready;
                    snapshot.partial = *partial;
                }
                true
            }
            DomainEvent::SnapshotFailed { stop_id }
                if self.state.stop_id.as_ref() == Some(stop_id) =>
            {
                if let Some(snapshot) = &mut self.state.snapshot {
                    if snapshot.status == SnapshotStatus::Ready {
                        return false;
                    }
                    snapshot.status = SnapshotStatus::Failed;
                    snapshot.partial = true;
                }
                true
            }
            DomainEvent::SnapshotStarted { .. }
            | DomainEvent::SnapshotReady { .. }
            | DomainEvent::SnapshotFailed { .. } => false,
            DomainEvent::CommandOutcomeUnknown { token } => {
                self.state.outcome_unknown_tokens.insert(*token);
                self.state.backend = BackendHealth::Unresponsive;
                if self.state.consistency != Consistency::Tainted {
                    self.state.consistency = Consistency::ManagedDirty;
                }
                true
            }
            DomainEvent::CommandOutcomeResolved { token } => {
                let removed = self.state.outcome_unknown_tokens.remove(token);
                if self.state.outcome_unknown_tokens.is_empty() {
                    self.state.backend = BackendHealth::Healthy;
                    self.state.reconciliation_required = true;
                }
                removed
            }
            DomainEvent::ConsistencyDirty { reason } => {
                // 2026-08-28: A later managed raw command must not erase an
                // earlier unknown raw effect; TAINTED lasts for the session.
                if self.state.consistency != Consistency::Tainted {
                    self.state.consistency = Consistency::ManagedDirty;
                }
                self.state.reconciliation_required = true;
                push_limitation(&mut self.state.limitations, reason.clone());
                true
            }
            DomainEvent::ConsistencyReconciling => {
                if self.state.consistency == Consistency::Tainted {
                    false
                } else {
                    self.state.consistency = Consistency::Reconciling;
                    true
                }
            }
            DomainEvent::ConsistencyTainted { reason } => {
                self.state.consistency = Consistency::Tainted;
                self.state.reconciliation_required = true;
                push_limitation(&mut self.state.limitations, reason.clone());
                true
            }
            DomainEvent::ConsistencyRestored { warnings } => {
                self.state.reconciliation_required = false;
                if self.state.consistency == Consistency::Tainted {
                    for warning in warnings {
                        push_limitation(&mut self.state.limitations, warning.clone());
                    }
                    !warnings.is_empty()
                } else {
                    self.state.consistency = Consistency::Clean;
                    self.state.limitations.clear();
                    for warning in warnings {
                        push_limitation(&mut self.state.limitations, warning.clone());
                    }
                    true
                }
            }
            DomainEvent::ConsistencyLost { reason } => {
                self.state.consistency = Consistency::Lost;
                self.state.reconciliation_required = false;
                push_limitation(&mut self.state.limitations, reason.clone());
                true
            }
            DomainEvent::TargetDisconnected => {
                for inferior in self.state.inferiors.values_mut() {
                    inferior.status = InferiorStatus::Disconnected;
                }
                // 2026-08-28: A disconnected target retained a current stop
                // and snapshot even though no stop-scoped handle was usable.
                self.clear_stop_context();
                true
            }
            DomainEvent::TargetDetached => {
                for inferior in self.state.inferiors.values_mut() {
                    inferior.status = InferiorStatus::Detached;
                }
                self.clear_stop_context();
                true
            }
            DomainEvent::CoreOpened { backend_id } => {
                let seq = self.state.event_seq;
                let inferior = self.ensure_inferior(backend_id, seq);
                inferior.status = InferiorStatus::Core;
                self.state.target_origin = TargetOrigin::Core;
                self.state.lifecycle = SessionLifecycle::Active;
                true
            }
            DomainEvent::TargetConfigured { origin } => {
                self.state.target_origin = *origin;
                true
            }
            DomainEvent::UnknownBackendEvent { class } => {
                self.state.consistency = Consistency::Tainted;
                self.state.reconciliation_required = true;
                let limitation = format!("unknown backend event: {class}");
                push_limitation(&mut self.state.limitations, limitation);
                true
            }
            DomainEvent::UnknownBackendNotification { class } => {
                if self.state.consistency != Consistency::Tainted {
                    self.state.consistency = Consistency::ManagedDirty;
                }
                self.state.reconciliation_required = true;
                let limitation = format!("unknown backend notification: {class}");
                push_limitation(&mut self.state.limitations, limitation);
                true
            }
            DomainEvent::Output { .. } | DomainEvent::OutputAdvanced { .. } => false,
        }
    }

    // 2026-09-01: GDB can exit before publishing its final RSP group-exit
    // notification, which left a dead backend with a RUNNING inferior. Mark
    // every still-live target disconnected while preserving proven exits.
    fn fail_backend(&mut self) -> bool {
        let mut changed = self.state.lifecycle != SessionLifecycle::Failed
            || self.state.backend != BackendHealth::Dead
            || self.state.stop_id.is_some();
        self.state.lifecycle = SessionLifecycle::Failed;
        self.state.backend = BackendHealth::Dead;
        for inferior in self.state.inferiors.values_mut() {
            if !matches!(
                inferior.status,
                InferiorStatus::Empty
                    | InferiorStatus::Exited
                    | InferiorStatus::Detached
                    | InferiorStatus::Disconnected
            ) {
                inferior.status = InferiorStatus::Disconnected;
                changed = true;
            }
        }
        self.clear_stop_context();
        changed
    }

    fn clear_stop_context(&mut self) {
        self.state.stop_id = None;
        self.state.stop_reason = None;
        self.state.stop_reason_detail = None;
        self.state.stopped_inferior_id = None;
        self.state.stopped_thread_id = None;
        self.state.snapshot = None;
    }

    fn ensure_inferior(&mut self, backend_id: &str, generation: u64) -> &mut InferiorState {
        let session_id = self.state.session_id.clone();
        self.state
            .inferiors
            .entry(backend_id.to_owned())
            .or_insert_with(|| InferiorState {
                id: InferiorId::from_backend(&session_id, generation, backend_id),
                backend_id: backend_id.to_owned(),
                pid: None,
                generation,
                status: InferiorStatus::Empty,
                exit_code: None,
                threads: Default::default(),
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::{
        DomainEvent, FrameSummary, JournaledEvent, SessionId, SessionState, StopReason,
    };

    use super::*;

    fn apply(reducer: &mut StateReducer, seq: u64, event: DomainEvent) {
        reducer
            .apply(&JournaledEvent::for_replay(seq, event))
            .unwrap();
    }

    #[test]
    fn fail_closed_publishes_one_terminal_revision() {
        let mut reducer =
            StateReducer::new(SessionState::creating(SessionId("sess_failed".into())));
        assert!(reducer.fail_closed());
        assert_eq!(reducer.state().lifecycle, SessionLifecycle::Failed);
        assert_eq!(reducer.state().backend, BackendHealth::Dead);
        assert_eq!(reducer.state().revision, 1);
        assert!(!reducer.fail_closed());
        assert_eq!(reducer.state().revision, 1);
    }

    #[test]
    fn limitations_remain_bounded_under_repeated_anomalies() {
        let mut reducer =
            StateReducer::new(SessionState::creating(SessionId("sess_bounded".into())));
        for seq in 1..=100 {
            apply(
                &mut reducer,
                seq,
                DomainEvent::ConsistencyDirty {
                    reason: format!("anomaly {seq}"),
                },
            );
        }

        assert_eq!(reducer.state().limitations.len(), MAX_LIMITATIONS);
        assert_eq!(
            reducer.state().limitations.last().map(String::as_str),
            Some(LIMITATIONS_OMITTED)
        );
    }

    #[test]
    fn running_invalidates_stop_scoped_context() {
        let session = SessionId("sess_replay".into());
        let mut reducer = StateReducer::new(SessionState::creating(session));
        apply(&mut reducer, 1, DomainEvent::BackendStarted);
        apply(
            &mut reducer,
            2,
            DomainEvent::InferiorAdded {
                backend_id: "i1".into(),
                pid: Some(42),
            },
        );
        apply(
            &mut reducer,
            3,
            DomainEvent::TargetStopped {
                backend_inferior: Some("i1".into()),
                backend_thread: Some("1".into()),
                reason: "breakpoint-hit".into(),
                reason_detail: Some(StopReason::Breakpoint {
                    backend_number: Some("1".into()),
                    disposition: Some("keep".into()),
                }),
                frame: Some(FrameSummary {
                    level: 0,
                    address: Some("0x1".into()),
                    function: Some("main".into()),
                    source: None,
                    line: None,
                }),
            },
        );
        let old_stop = reducer.state().stop_id.clone().unwrap();
        assert!(reducer.state().require_stop(&old_stop).is_ok());

        apply(
            &mut reducer,
            4,
            DomainEvent::TargetRunning {
                backend_inferiors: vec!["i1".into()],
            },
        );
        assert_eq!(reducer.state().execution_epoch, 1);
        assert!(matches!(
            reducer.state().require_stop(&old_stop),
            Err(Error {
                code: ErrorCode::StaleContext,
                ..
            })
        ));
        apply(
            &mut reducer,
            5,
            DomainEvent::TargetStopped {
                backend_inferior: Some("i1".into()),
                backend_thread: Some("1".into()),
                reason: "signal-received".into(),
                reason_detail: Some(StopReason::Signal {
                    name: Some("SIGTRAP".into()),
                    meaning: Some("Trace/breakpoint trap".into()),
                }),
                frame: None,
            },
        );
        let mut failed = StateReducer::new(reducer.state().clone());
        apply(
            &mut failed,
            6,
            DomainEvent::BackendExited { status: Some(134) },
        );
        assert_eq!(
            failed.state().inferiors["i1"].status,
            InferiorStatus::Disconnected
        );
        assert!(failed.state().stop_id.is_none());
        assert!(failed.state().snapshot.is_none());

        apply(&mut reducer, 6, DomainEvent::TargetDisconnected);
        assert!(reducer.state().stop_id.is_none());
        assert!(reducer.state().snapshot.is_none());
    }

    #[test]
    fn failed_enrichment_preserves_the_committed_snapshot() {
        let mut reducer =
            StateReducer::new(SessionState::creating(SessionId("sess_snapshot".into())));
        apply(&mut reducer, 1, DomainEvent::BackendStarted);
        apply(
            &mut reducer,
            2,
            DomainEvent::TargetStopped {
                backend_inferior: Some("i1".into()),
                backend_thread: None,
                reason: "breakpoint-hit".into(),
                reason_detail: None,
                frame: None,
            },
        );
        let stop_id = reducer.state().stop_id.clone().unwrap();
        apply(
            &mut reducer,
            3,
            DomainEvent::SnapshotReady {
                stop_id: stop_id.clone(),
                partial: true,
            },
        );
        let committed = reducer.state().snapshot.clone();

        apply(
            &mut reducer,
            4,
            DomainEvent::SnapshotStarted {
                stop_id: stop_id.clone(),
            },
        );
        apply(&mut reducer, 5, DomainEvent::SnapshotFailed { stop_id });

        assert_eq!(reducer.state().snapshot, committed);
    }

    #[test]
    fn stopped_frame_belongs_to_the_current_stop() {
        let mut reducer =
            StateReducer::new(SessionState::creating(SessionId("sess_frames".into())));
        apply(&mut reducer, 1, DomainEvent::BackendStarted);
        for (seq, backend_id) in [(2, "i1"), (3, "i2")] {
            apply(
                &mut reducer,
                seq,
                DomainEvent::InferiorAdded {
                    backend_id: backend_id.into(),
                    pid: Some(seq),
                },
            );
        }
        for (seq, backend_id, backend_thread, function) in [
            (4, "i1", "1", "older_frame"),
            (5, "i2", "2", "current_frame"),
        ] {
            apply(
                &mut reducer,
                seq,
                DomainEvent::TargetStopped {
                    backend_inferior: Some(backend_id.into()),
                    backend_thread: Some(backend_thread.into()),
                    reason: "breakpoint-hit".into(),
                    reason_detail: None,
                    frame: Some(FrameSummary {
                        level: 0,
                        address: None,
                        function: Some(function.into()),
                        source: None,
                        line: None,
                    }),
                },
            );
        }

        assert_eq!(
            reducer.state().stopped_frame().unwrap().function.as_deref(),
            Some("current_frame")
        );
    }

    #[test]
    fn distinguishes_remote_exit_from_connection_loss() {
        let reduce = |from_stop_record| {
            let mut reducer =
                StateReducer::new(SessionState::creating(SessionId("sess_remote_exit".into())));
            apply(&mut reducer, 1, DomainEvent::BackendStarted);
            apply(
                &mut reducer,
                2,
                DomainEvent::TargetConfigured {
                    origin: TargetOrigin::Remote,
                },
            );
            apply(
                &mut reducer,
                3,
                DomainEvent::InferiorAdded {
                    backend_id: "i1".into(),
                    pid: Some(42),
                },
            );
            apply(
                &mut reducer,
                4,
                DomainEvent::InferiorExited {
                    backend_id: "i1".into(),
                    exit_code: None,
                    from_stop_record,
                },
            );
            apply(
                &mut reducer,
                5,
                DomainEvent::BackendExited { status: Some(134) },
            );
            reducer.state().inferiors["i1"].status
        };

        assert_eq!(reduce(true), InferiorStatus::Exited);
        assert_eq!(reduce(false), InferiorStatus::Disconnected);
    }

    #[test]
    fn inferior_lifecycle_only_invalidates_its_own_stop() {
        let mut reducer = StateReducer::new(SessionState::creating(SessionId(
            "sess_multi_inferior".into(),
        )));
        apply(&mut reducer, 1, DomainEvent::BackendStarted);
        for (seq, backend_id) in [(2, "i1"), (3, "i2")] {
            apply(
                &mut reducer,
                seq,
                DomainEvent::InferiorAdded {
                    backend_id: backend_id.into(),
                    pid: Some(40 + seq),
                },
            );
        }
        apply(
            &mut reducer,
            4,
            DomainEvent::TargetStopped {
                backend_inferior: Some("i1".into()),
                backend_thread: Some("1".into()),
                reason: "breakpoint-hit".into(),
                reason_detail: None,
                frame: None,
            },
        );
        let stop = reducer.state().stop_id.clone();

        apply(
            &mut reducer,
            5,
            DomainEvent::InferiorExited {
                backend_id: "i2".into(),
                exit_code: Some("0".into()),
                from_stop_record: false,
            },
        );
        assert_eq!(reducer.state().stop_id, stop);
        assert!(reducer.state().snapshot.is_some());

        apply(
            &mut reducer,
            6,
            DomainEvent::InferiorRemoved {
                backend_id: "i1".into(),
            },
        );
        assert!(reducer.state().stop_id.is_none());
        assert!(reducer.state().snapshot.is_none());
        assert!(reducer.state().stopped_inferior_id.is_none());
    }

    #[test]
    fn same_events_produce_same_state() {
        let events = [
            DomainEvent::BackendStarted,
            DomainEvent::InferiorAdded {
                backend_id: "i1".into(),
                pid: Some(7),
            },
            DomainEvent::ThreadCreated {
                backend_inferior: "i1".into(),
                backend_thread: "1".into(),
            },
        ];
        let run = || {
            let mut reducer = StateReducer::new(SessionState::creating(SessionId("sess_x".into())));
            for (index, event) in events.iter().cloned().enumerate() {
                apply(&mut reducer, index as u64 + 1, event);
            }
            reducer.into_state()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn duplicate_running_records_share_one_execution_epoch() {
        let mut reducer = StateReducer::new(SessionState::creating(SessionId("sess_run".into())));
        apply(&mut reducer, 1, DomainEvent::BackendStarted);
        apply(
            &mut reducer,
            2,
            DomainEvent::InferiorAdded {
                backend_id: "i1".into(),
                pid: Some(42),
            },
        );
        apply(
            &mut reducer,
            3,
            DomainEvent::TargetRunning {
                backend_inferiors: vec!["i1".into()],
            },
        );
        let revision = reducer.state().revision;
        apply(
            &mut reducer,
            4,
            DomainEvent::TargetRunning {
                backend_inferiors: vec!["i1".into()],
            },
        );
        assert_eq!(reducer.state().execution_epoch, 1);
        assert_eq!(reducer.state().revision, revision);
    }

    #[test]
    fn reused_backend_inferior_starts_a_clean_generation() {
        let mut reducer =
            StateReducer::new(SessionState::creating(SessionId("sess_restart".into())));
        apply(&mut reducer, 1, DomainEvent::BackendStarted);
        apply(
            &mut reducer,
            2,
            DomainEvent::InferiorAdded {
                backend_id: "i1".into(),
                pid: Some(42),
            },
        );
        apply(
            &mut reducer,
            3,
            DomainEvent::ThreadCreated {
                backend_inferior: "i1".into(),
                backend_thread: "1".into(),
            },
        );
        let first_id = reducer.state().inferiors["i1"].id.clone();
        apply(
            &mut reducer,
            4,
            DomainEvent::InferiorExited {
                backend_id: "i1".into(),
                exit_code: Some("0270".into()),
                from_stop_record: true,
            },
        );
        apply(
            &mut reducer,
            5,
            DomainEvent::InferiorAdded {
                backend_id: "i1".into(),
                pid: Some(43),
            },
        );

        let restarted = &reducer.state().inferiors["i1"];
        assert_ne!(restarted.id, first_id);
        assert_eq!(restarted.generation, 5);
        assert_eq!(restarted.pid, Some(43));
        assert_eq!(restarted.status, InferiorStatus::Connecting);
        assert_eq!(restarted.exit_code, None);
        assert!(restarted.threads.is_empty());
    }

    #[test]
    fn reused_backend_thread_id_gets_a_new_public_id() {
        let mut reducer =
            StateReducer::new(SessionState::creating(SessionId("sess_thread".into())));
        apply(&mut reducer, 1, DomainEvent::BackendStarted);
        apply(
            &mut reducer,
            2,
            DomainEvent::InferiorAdded {
                backend_id: "i1".into(),
                pid: Some(42),
            },
        );
        apply(
            &mut reducer,
            3,
            DomainEvent::ThreadCreated {
                backend_inferior: "i1".into(),
                backend_thread: "1".into(),
            },
        );
        let first = reducer.state().inferiors["i1"].threads["1"].id.clone();
        apply(
            &mut reducer,
            4,
            DomainEvent::ThreadExited {
                backend_inferior: Some("i1".into()),
                backend_thread: "1".into(),
            },
        );
        apply(
            &mut reducer,
            5,
            DomainEvent::ThreadCreated {
                backend_inferior: "i1".into(),
                backend_thread: "1".into(),
            },
        );
        let second = reducer.state().inferiors["i1"].threads["1"].id.clone();
        assert_ne!(first, second);
    }

    #[test]
    fn unknown_notification_can_reconcile_without_permanent_taint() {
        let mut reducer =
            StateReducer::new(SessionState::creating(SessionId("sess_notify".into())));
        apply(&mut reducer, 1, DomainEvent::BackendStarted);
        apply(
            &mut reducer,
            2,
            DomainEvent::UnknownBackendNotification {
                class: "notify:future-event".into(),
            },
        );
        assert_eq!(reducer.state().consistency, Consistency::ManagedDirty);
        assert!(reducer.state().reconciliation_required);
        apply(
            &mut reducer,
            3,
            DomainEvent::ConsistencyRestored { warnings: vec![] },
        );
        assert_eq!(reducer.state().consistency, Consistency::Clean);
        assert!(!reducer.state().reconciliation_required);
    }

    #[test]
    fn unknown_command_outcome_fences_state_until_late_result() {
        let mut reducer = StateReducer::new(SessionState::creating(SessionId("sess_wait".into())));
        apply(&mut reducer, 1, DomainEvent::BackendStarted);
        apply(
            &mut reducer,
            2,
            DomainEvent::CommandOutcomeUnknown { token: 7 },
        );
        assert_eq!(reducer.state().backend, BackendHealth::Unresponsive);
        assert!(reducer.state().outcome_unknown_tokens.contains(&7));
        assert!(!reducer.state().reconciliation_required);

        apply(
            &mut reducer,
            3,
            DomainEvent::CommandOutcomeResolved { token: 7 },
        );
        assert_eq!(reducer.state().backend, BackendHealth::Healthy);
        assert!(reducer.state().outcome_unknown_tokens.is_empty());
        assert!(reducer.state().reconciliation_required);
    }

    #[test]
    fn taint_survives_managed_reconciliation_without_repeating_it() {
        let mut reducer = StateReducer::new(SessionState::creating(SessionId("sess_x".into())));
        apply(
            &mut reducer,
            1,
            DomainEvent::ConsistencyTainted {
                reason: "unknown raw command".into(),
            },
        );
        assert!(reducer.state().reconciliation_required);
        apply(
            &mut reducer,
            2,
            DomainEvent::ConsistencyRestored { warnings: vec![] },
        );
        assert_eq!(reducer.state().consistency, Consistency::Tainted);
        assert!(!reducer.state().reconciliation_required);
    }
}
