use gdb_ai_mi::{MiFramer, MiLimits, MiRecord, MiResult, MiValue, parse_record};

fn field(name: &str, value: MiValue) -> MiResult {
    MiResult {
        name: name.into(),
        value,
    }
}

fn text(value: &str) -> MiValue {
    MiValue::Const(value.as_bytes().to_vec())
}

fn basic_records() -> Vec<MiRecord> {
    vec![
        MiRecord::Result {
            token: Some(1),
            class: "done".into(),
            results: vec![field(
                "features",
                MiValue::ValueList(vec![text("frozen-varobjs"), text("pending-breakpoints")]),
            )],
        },
        MiRecord::NotifyAsync {
            token: None,
            class: "thread-group-added".into(),
            results: vec![field("id", text("i1"))],
        },
        MiRecord::NotifyAsync {
            token: None,
            class: "thread-created".into(),
            results: vec![field("id", text("1")), field("group-id", text("i1"))],
        },
        MiRecord::Result {
            token: Some(2),
            class: "running".into(),
            results: vec![],
        },
        MiRecord::ExecAsync {
            token: None,
            class: "running".into(),
            results: vec![field("thread-id", text("all"))],
        },
        MiRecord::ExecAsync {
            token: None,
            class: "stopped".into(),
            results: vec![
                field("reason", text("breakpoint-hit")),
                field("thread-id", text("1")),
                field("thread-group", text("i1")),
                field(
                    "frame",
                    MiValue::Tuple(vec![
                        field("addr", text("0x0000000000401000")),
                        field("func", text("main")),
                        field("file", text("main.c")),
                        field("fullname", text("/workspace/main.c")),
                        field("line", text("7")),
                    ]),
                ),
            ],
        },
        MiRecord::Prompt,
    ]
}

fn future_records() -> Vec<MiRecord> {
    vec![
        MiRecord::Result {
            token: Some(7),
            class: "future".into(),
            results: vec![
                field("known", text("value")),
                field(
                    "future",
                    MiValue::Tuple(vec![
                        field("duplicate", text("1")),
                        field("duplicate", text("2")),
                    ]),
                ),
            ],
        },
        MiRecord::NotifyAsync {
            token: None,
            class: "future-notification".into(),
            results: vec![field(
                "new-field",
                MiValue::ResultList(vec![field(
                    "item",
                    MiValue::Tuple(vec![field("value", text("x"))]),
                )]),
            )],
        },
        MiRecord::ConsoleStream(b"console\n".to_vec()),
        MiRecord::TargetStream(b"\xffbinary".to_vec()),
        MiRecord::Result {
            token: Some(8),
            class: "done".into(),
            results: vec![field(
                "bkpt",
                MiValue::Tuple(vec![
                    field("number", text("1")),
                    field(
                        "script",
                        MiValue::ValueList(vec![text("silent"), text("echo \"ready\"\n")]),
                    ),
                ]),
            )],
        },
        MiRecord::Prompt,
    ]
}

#[test]
fn parses_saved_transcripts_at_every_chunk_boundary() {
    // 2026-09-08: Parsing the expected side with the same parser hid shared
    // semantic errors. Fixed ASTs check bytes, field order and duplicate keys
    // independently of both parsing and transport chunk boundaries.
    for (fixture, expected) in [
        (
            include_bytes!("../../../tests/mi-fixtures/basic.mi").as_slice(),
            basic_records(),
        ),
        (
            include_bytes!("../../../tests/mi-fixtures/future-fields.mi").as_slice(),
            future_records(),
        ),
    ] {
        for chunk_size in 1..=fixture.len() {
            let mut framer = MiFramer::new(MiLimits::default());
            let mut actual = Vec::new();
            for chunk in fixture.chunks(chunk_size) {
                actual.extend(
                    framer
                        .push(chunk)
                        .unwrap()
                        .into_iter()
                        .map(|line| parse_record(&line, MiLimits::default()).unwrap()),
                );
            }
            assert!(framer.finish().unwrap().is_none());
            assert_eq!(actual, expected, "chunk size {chunk_size}");
        }
    }
}
