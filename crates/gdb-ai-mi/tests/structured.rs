use std::{hint::black_box, time::Instant};

use gdb_ai_mi::{MiFramer, MiLimits, MiRecord, MiResult, MiValue, parse_record};

// GDB 17.1 MI4 replies from the vertical C fixture stopped in marker:
// two stack frames, 32 registers and 128 unsigned-char variable children.
// Debug paths are mapped to /workspace; timings need no running debugger.
const TRANSCRIPT: &[u8] = include_bytes!("../../../tests/mi-fixtures/structured.mi");

fn responses() -> impl Iterator<Item = &'static [u8]> {
    TRANSCRIPT
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
}

#[test]
fn preserves_native_structured_read_results() {
    let records = responses()
        .map(|line| parse_record(line, MiLimits::default()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|record| record.class() == Some("done")));
    assert_eq!(
        records.iter().map(MiRecord::token).collect::<Vec<_>>(),
        [Some(5), Some(6), Some(8)]
    );

    let Some(MiValue::ResultList(frames)) = MiResult::find(records[0].results(), "stack") else {
        panic!("expected named stack frames");
    };
    assert_eq!(frames.len(), 2);
    for (frame, function) in frames.iter().zip(["marker", "main"]) {
        assert_eq!(frame.name, "frame");
        let fields = frame.value.results().unwrap();
        assert_eq!(MiResult::find_str(fields, "func"), Some(function));
        assert_eq!(
            MiResult::find_str(fields, "fullname"),
            Some("/workspace/vertical.c")
        );
    }

    let Some(MiValue::ValueList(registers)) =
        MiResult::find(records[1].results(), "register-values")
    else {
        panic!("expected register tuples");
    };
    assert_eq!(registers.len(), 32);
    for (number, register) in registers.iter().enumerate() {
        let fields = register.results().unwrap();
        assert_eq!(
            MiResult::find_str(fields, "number"),
            Some(number.to_string().as_str())
        );
    }
    assert_eq!(
        MiResult::find_str(registers[16].results().unwrap(), "value"),
        Some("0x5555555551d1")
    );

    assert_eq!(
        MiResult::find_str(records[2].results(), "numchild"),
        Some("128")
    );
    assert_eq!(
        MiResult::find_str(records[2].results(), "has_more"),
        Some("0")
    );
    let Some(MiValue::ResultList(children)) = MiResult::find(records[2].results(), "children")
    else {
        panic!("expected named variable children");
    };
    assert_eq!(children.len(), 128);
    for (number, child) in children.iter().enumerate() {
        assert_eq!(child.name, "child");
        let fields = child.value.results().unwrap();
        assert_eq!(
            MiResult::find_str(fields, "exp"),
            Some(number.to_string().as_str())
        );
        assert_eq!(MiResult::find_str(fields, "type"), Some("unsigned char"));
        assert_eq!(
            MiResult::find_str(fields, "value"),
            Some(if number == 0 { "90 'Z'" } else { "0 '\\000'" })
        );
    }
}

fn measure(case: &str, phase: &str, bytes: usize, records: usize, mut operation: impl FnMut()) {
    let started = Instant::now();
    for _ in 0..records {
        operation();
    }
    eprintln!(
        "{}",
        serde_json::json!({
            "benchmark": "structured_mi",
            "case": case,
            "phase": phase,
            "record_bytes": bytes,
            "records": records,
            "elapsed_ns": started.elapsed().as_nanos(),
        })
    );
}

#[test]
#[ignore = "microbenchmark: run explicitly with an optimized build"]
fn benchmark_structured_records() {
    for (case, raw) in ["stack", "registers", "children"]
        .into_iter()
        .zip(responses())
    {
        let records = (64 * 1024 * 1024 / raw.len()).min(100_000);
        let limits = MiLimits::default();
        measure(case, "raw_copy", raw.len(), records, || {
            black_box(black_box(raw).to_vec());
        });
        measure(case, "parse", raw.len(), records, || {
            black_box(parse_record(black_box(raw), limits).unwrap());
        });
        let mut wire = raw.to_vec();
        wire.push(b'\n');
        let mut framer = MiFramer::new(limits);
        measure(case, "frame", raw.len(), records, || {
            let frames = framer.push(black_box(&wire));
            assert_eq!(frames.error, None);
            black_box(frames.records);
        });
        measure(case, "frame_parse", raw.len(), records, || {
            let frames = framer.push(black_box(&wire));
            assert_eq!(frames.error, None);
            for line in frames.records {
                black_box(parse_record(&line, limits).unwrap());
            }
        });
        assert!(framer.finish().unwrap().is_none());
    }
}
