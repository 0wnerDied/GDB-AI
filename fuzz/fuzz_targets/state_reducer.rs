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
        let _ = reducer.apply(&JournaledEvent::for_replay(index as u64 + 1, event));
    }
});
