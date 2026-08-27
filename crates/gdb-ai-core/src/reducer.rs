use crate::{
    Error, ErrorCode, Result,
    domain::{
        BackendHealth, BreakpointId, BreakpointState, Consistency, DomainEvent, InferiorId,
        InferiorState, InferiorStatus, JournaledEvent, ModuleState, SessionLifecycle, SessionState,
        SnapshotRef, SnapshotStatus, StopId, ThreadId, ThreadState,
    },
};

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
            DomainEvent::BackendExited { .. } => {
                self.state.lifecycle = SessionLifecycle::Failed;
                self.state.backend = BackendHealth::Dead;
                true
            }
            DomainEvent::InferiorAdded { backend_id, pid } => {
                let seq = self.state.event_seq;
                let inferior = self.ensure_inferior(backend_id, seq);
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
                self.state.inferiors.remove(backend_id).is_some()
            }
            DomainEvent::InferiorExited {
                backend_id,
                exit_code,
            } => {
                let seq = self.state.event_seq;
                let inferior = self.ensure_inferior(backend_id, seq);
                inferior.status = InferiorStatus::Exited;
                inferior.exit_code.clone_from(exit_code);
                true
            }
            DomainEvent::TargetRunning { backend_inferiors } => {
                let seq = self.state.event_seq;
                if self.state.inferiors.is_empty() {
                    self.ensure_inferior(
                        backend_inferiors.first().map_or("i1", String::as_str),
                        seq,
                    );
                }
                for (backend_id, inferior) in &mut self.state.inferiors {
                    if backend_inferiors.is_empty() || backend_inferiors.contains(backend_id) {
                        inferior.status = InferiorStatus::Running;
                        for thread in inferior.threads.values_mut() {
                            thread.running = true;
                            thread.frame = None;
                        }
                    }
                }
                self.state.lifecycle = SessionLifecycle::Active;
                self.state.execution_epoch += 1;
                self.state.stop_id = None;
                self.state.stop_reason = None;
                self.state.snapshot = None;
                true
            }
            DomainEvent::TargetStopped {
                backend_inferior,
                backend_thread,
                reason,
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
                if let Some(backend_thread) = backend_thread {
                    let inferior = self.state.inferiors.get_mut(&backend_id).unwrap();
                    let id =
                        ThreadId::from_backend(&inferior.id, inferior.generation, backend_thread);
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
                let id = ThreadId::from_backend(&inferior.id, inferior.generation, backend_thread);
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
                        BreakpointId(format!(
                            "bp_{}_{}",
                            self.state.session_id.0,
                            backend_number.replace('.', "_")
                        ))
                    });
                self.state.breakpoints.insert(
                    backend_number.clone(),
                    BreakpointState {
                        id,
                        backend_number: backend_number.clone(),
                        enabled: *enabled,
                        pending: *pending,
                    },
                );
                true
            }
            DomainEvent::BreakpointDeleted { backend_number } => {
                self.state.breakpoints.remove(backend_number).is_some()
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
            DomainEvent::MemoryChanged => true,
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
                    snapshot.status = SnapshotStatus::Failed;
                    snapshot.partial = true;
                }
                true
            }
            DomainEvent::SnapshotReady { .. } | DomainEvent::SnapshotFailed { .. } => false,
            DomainEvent::ConsistencyDirty { reason } => {
                self.state.consistency = Consistency::ManagedDirty;
                self.state.limitations.push(reason.clone());
                true
            }
            DomainEvent::ConsistencyTainted { reason } => {
                self.state.consistency = Consistency::Tainted;
                self.state.limitations.push(reason.clone());
                true
            }
            DomainEvent::ConsistencyRestored { warnings } => {
                self.state.consistency = Consistency::Clean;
                self.state.limitations.clone_from(warnings);
                true
            }
            DomainEvent::ConsistencyLost { reason } => {
                self.state.consistency = Consistency::Lost;
                self.state.limitations.push(reason.clone());
                true
            }
            DomainEvent::TargetDisconnected => {
                for inferior in self.state.inferiors.values_mut() {
                    inferior.status = InferiorStatus::Disconnected;
                }
                true
            }
            DomainEvent::UnknownBackendEvent { class } => {
                self.state.consistency = Consistency::Tainted;
                self.state
                    .limitations
                    .push(format!("unknown backend event: {class}"));
                true
            }
            DomainEvent::Output { .. } => false,
        }
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
    use crate::domain::{DomainEvent, FrameSummary, JournaledEvent, SessionId, SessionState};

    use super::*;

    fn apply(reducer: &mut StateReducer, seq: u64, event: DomainEvent) {
        reducer
            .apply(&JournaledEvent::for_replay(seq, event))
            .unwrap();
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
}
