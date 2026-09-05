use std::ops::Deref;

use tokio::sync::watch;

use crate::{
    Result,
    domain::{DomainEvent, SessionState},
    reducer::StateReducer,
};

/// Owns the actor's reducer state and its watch publication boundary.
/// Performance mode mutates the watched value under its write guard and runs
/// related actor updates before notifying readers. Durable mode stages each
/// transition privately until its checkpoint succeeds.
pub(super) struct LiveState {
    sender: watch::Sender<SessionState>,
    staged: Option<StateReducer>,
}

impl LiveState {
    pub(super) fn new(sender: watch::Sender<SessionState>, durable: bool) -> Self {
        let staged = durable.then(|| StateReducer::new(sender.borrow().clone()));
        Self { sender, staged }
    }

    pub(super) fn borrow(&self) -> LiveStateRef<'_> {
        match &self.staged {
            Some(reducer) => LiveStateRef::Staged(reducer.state()),
            None => LiveStateRef::Published(self.sender.borrow()),
        }
    }

    pub(super) fn apply_event(&mut self, sequence: u64, event: &DomainEvent) -> Result<bool> {
        self.apply_event_with(sequence, event, |_| {})
    }

    pub(super) fn apply_event_with(
        &mut self,
        sequence: u64,
        event: &DomainEvent,
        after: impl FnOnce(&SessionState),
    ) -> Result<bool> {
        if let Some(reducer) = &mut self.staged {
            let changed = reducer.apply_event(sequence, event)?;
            after(reducer.state());
            return Ok(changed);
        }
        let mut outcome = None;
        let mut after = Some(after);
        self.sender.send_if_modified(|state| {
            let result = StateReducer::apply_event_to(state, sequence, event);
            let publish = result.is_ok();
            if publish {
                after.take().expect("state callback runs once")(state);
            }
            outcome = Some(result);
            // Every accepted event advances event_seq, including events that
            // leave the optimistic-concurrency revision unchanged. The
            // callback completes related actor state before readers wake.
            publish
        });
        outcome.expect("watch mutation closure always runs")
    }

    pub(super) fn publish(&self) {
        if let Some(reducer) = &self.staged {
            self.sender.send_replace(reducer.state().clone());
        }
    }

    pub(super) fn fail_closed(&mut self) -> bool {
        if let Some(reducer) = &mut self.staged {
            let changed = reducer.fail_closed();
            if changed {
                self.sender.send_replace(reducer.state().clone());
            }
            return changed;
        }
        let mut changed = false;
        self.sender.send_if_modified(|state| {
            changed = StateReducer::fail_closed_state(state);
            changed
        });
        changed
    }
}

pub(super) enum LiveStateRef<'a> {
    Published(watch::Ref<'a, SessionState>),
    Staged(&'a SessionState),
}

impl Deref for LiveStateRef<'_> {
    type Target = SessionState;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Published(state) => state,
            Self::Staged(state) => state,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::{DomainEvent, ModuleState, OutputSource, SessionId, SessionState};

    use super::LiveState;

    #[test]
    fn publishes_after_actor_callback_without_copying_retained_registries() {
        let mut state = SessionState::creating(SessionId("sess_state".into()));
        state.modules.insert(
            "module".into(),
            ModuleState {
                id: "module".into(),
                target_name: None,
                host_name: Some("/a/retained/module".into()),
                symbols_loaded: Some(true),
            },
        );
        let retained = state.modules["module"].host_name.as_ref().unwrap().as_ptr();
        let (sender, receiver) = tokio::sync::watch::channel(state);
        let mut live = LiveState::new(sender, false);

        let mut callback_ran = false;
        assert!(
            !live
                .apply_event_with(
                    1,
                    &DomainEvent::Output {
                        source: OutputSource::GdbConsoleStream,
                        bytes: b"output".to_vec(),
                    },
                    |state| {
                        assert_eq!(state.event_seq, 1);
                        assert!(!receiver.has_changed().unwrap());
                        callback_ran = true;
                    },
                )
                .unwrap()
        );
        assert!(callback_ran);
        assert!(receiver.has_changed().unwrap());

        let published = receiver.borrow();
        assert_eq!(published.event_seq, 1);
        assert_eq!(published.revision, 0);
        assert_eq!(
            published.modules["module"]
                .host_name
                .as_ref()
                .unwrap()
                .as_ptr(),
            retained
        );
    }

    #[test]
    fn durable_state_stays_staged_until_publication() {
        let state = SessionState::creating(SessionId("sess_durable".into()));
        let (sender, receiver) = tokio::sync::watch::channel(state);
        let mut live = LiveState::new(sender, true);

        assert!(live.apply_event(1, &DomainEvent::BackendStarted).unwrap());
        assert_eq!(live.borrow().event_seq, 1);
        assert_eq!(receiver.borrow().event_seq, 0);

        live.publish();
        assert_eq!(receiver.borrow().event_seq, 1);
    }
}
