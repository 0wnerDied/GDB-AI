#![no_main]

use gdb_ai_core::{
    domain::{DomainEvent, JournaledEvent, SessionId, SessionState},
    reducer::StateReducer,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(events) = serde_json::from_slice::<Vec<DomainEvent>>(data) else {
        return;
    };
    let mut reducer = StateReducer::new(SessionState::creating(SessionId("sess_fuzz".into())));
    for (index, event) in events.into_iter().take(1_024).enumerate() {
        let previous_revision = reducer.state().revision;
        let previous_epoch = reducer.state().execution_epoch;
        let changed = reducer
            .apply(&JournaledEvent::for_replay(index as u64 + 1, event))
            .expect("sequential replay events must apply");
        let state = reducer.state();

        assert_eq!(state.event_seq, index as u64 + 1);
        assert_eq!(
            state.revision,
            previous_revision + u64::from(changed),
            "revision must advance exactly once for a visible transition"
        );
        assert!(state.execution_epoch >= previous_epoch);
        if state
            .inferiors
            .values()
            .any(|inferior| inferior.status == gdb_ai_core::domain::InferiorStatus::Running)
        {
            assert!(state.stop_id.is_none(), "running invalidates stop context");
        }
        if let Some(snapshot) = &state.snapshot {
            assert_eq!(Some(&snapshot.stop_id), state.stop_id.as_ref());
        }
    }
});
