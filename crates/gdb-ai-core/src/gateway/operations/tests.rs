use super::*;
use crate::{
    domain::{FrameId, JournaledEvent, SessionState},
    reducer::StateReducer,
};

#[test]
fn parses_and_revalidates_attach_identity() {
    let stat = "123 (worker name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242";
    assert_eq!(parse_process_start_time(stat).unwrap(), 4242);

    let pid = u64::from(std::process::id());
    let identity = validate_attach_target(pid).unwrap();
    identity.revalidate(pid).unwrap();
    let changed = AttachIdentity {
        start_time_ticks: identity.start_time_ticks.saturating_add(1),
    };
    assert_eq!(
        changed.revalidate(pid).unwrap_err().code,
        ErrorCode::Conflict
    );
}

#[test]
fn start_policies_map_to_explicit_gdb_stops() {
    let first: StartPolicy = serde_json::from_value(json!("entry")).unwrap();
    assert_eq!(first.as_str(), "first_instruction");
    assert_eq!(
        first.command().unwrap().encoded(1),
        b"1-interpreter-exec console \"starti\"\n"
    );
    assert_eq!(
        StartPolicy::Main.command().unwrap().encoded(2),
        b"2-exec-run --start\n"
    );
    assert_eq!(
        StartPolicy::None.command().unwrap().encoded(3),
        b"3-exec-run\n"
    );
}

#[test]
fn inherits_only_allowlisted_environment_variables() {
    let path = std::env::var("PATH").unwrap();
    let environment = inherited_environment(&[
        "PATH".into(),
        "GDB_AI_TEST_VARIABLE_THAT_DOES_NOT_EXIST".into(),
    ])
    .unwrap();

    assert_eq!(environment.len(), 1);
    assert_eq!(environment.get("PATH"), Some(&path));
}

#[test]
fn frame_context_encodes_its_thread_before_positional_arguments() {
    let mut reducer = StateReducer::new(SessionState::creating(SessionId("sess_ctx".into())));
    for (seq, event) in [
        (
            1,
            DomainEvent::InferiorAdded {
                backend_id: "i1".into(),
                pid: Some(7),
            },
        ),
        (
            2,
            DomainEvent::ThreadCreated {
                backend_inferior: "i1".into(),
                backend_thread: "1".into(),
            },
        ),
        (
            3,
            DomainEvent::ThreadCreated {
                backend_inferior: "i1".into(),
                backend_thread: "2".into(),
            },
        ),
        (
            4,
            DomainEvent::TargetStopped {
                backend_inferior: Some("i1".into()),
                backend_thread: Some("2".into()),
                reason: "breakpoint-hit".into(),
                reason_detail: Some(StopReason::Breakpoint {
                    backend_number: Some("1".into()),
                    disposition: Some("keep".into()),
                }),
                frame: None,
            },
        ),
    ] {
        reducer
            .apply(&JournaledEvent::for_replay(seq, event))
            .unwrap();
    }
    let state = reducer.state();
    let stop = state.stop_id.as_ref().unwrap();
    let stopped_thread = state.stopped_thread_id.as_ref().unwrap();
    let frame = FrameId::new(stopped_thread, stop, 3);
    let command = context_options(
        MiCommand::new("-data-evaluate-expression")
            .unwrap()
            .string("$pc"),
        &json!({"stop_id": stop, "frame_id": frame}),
        state,
    )
    .unwrap();
    assert_eq!(
        command.encoded(1),
        b"1-data-evaluate-expression --thread 2 --frame 3 \"$pc\"\n"
    );

    let other_thread = &state.inferiors["i1"].threads["1"].id;
    let error = context_options(
        MiCommand::new("-stack-info-frame").unwrap(),
        &json!({
            "stop_id": stop,
            "thread_id": other_thread,
            "frame_id": frame
        }),
        state,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::StaleContext);

    let focused = context_options(
        MiCommand::new("-data-evaluate-expression")
            .unwrap()
            .string("$pc"),
        &json!({"stop_id": stop}),
        state,
    )
    .unwrap();
    assert_eq!(
        focused.encoded(2),
        b"2-data-evaluate-expression --thread 2 --frame 0 \"$pc\"\n"
    );
}

#[test]
fn strict_operation_parameters_ignore_gateway_controls() {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StrictParameters {
        stop: StartPolicy,
    }

    let request = ApiRequest {
        api_version: crate::protocol::API_VERSION.into(),
        request_id: "strict-parameters".into(),
        session_id: Some("sess_test".into()),
        method: CanonicalMethod::TargetRestart,
        expected_revision: Some(1),
        idempotency_key: None,
        parameters: json!({
            "stop": "main",
            "lease_id": "lease_test",
            "accept_latest_revision": true
        }),
    };
    let decoded: StrictParameters = parameters(&request).unwrap();
    assert_eq!(decoded.stop.as_str(), "main");
}
