#![no_main]

use gdb_ai_mi::{MiFramer, MiLimits};
use libfuzzer_sys::fuzz_target;

fn frame(data: &[u8], chunk_size: usize, limits: MiLimits) -> (Vec<Vec<u8>>, bool) {
    let mut framer = MiFramer::new(limits);
    let mut records = Vec::new();
    for chunk in data.chunks(chunk_size) {
        let frames = framer.push(chunk);
        records.extend(frames.records);
        if frames.error.is_some() {
            return (records, true);
        }
    }
    match framer.finish() {
        Ok(last) => {
            records.extend(last);
            (records, false)
        }
        Err(_) => (records, true),
    }
}

fuzz_target!(|data: &[u8]| {
    let limits = MiLimits {
        max_record_bytes: 4 * 1024,
        max_depth: 32,
        max_decoded_string_bytes: 64 * 1024,
    };
    let expected = frame(data, data.len().max(1), limits);
    for chunk_size in 1..=data.len().clamp(1, 32) {
        assert_eq!(frame(data, chunk_size, limits), expected);
    }
});
