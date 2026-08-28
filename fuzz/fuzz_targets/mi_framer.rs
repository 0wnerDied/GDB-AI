#![no_main]

use gdb_ai_mi::{MiFramer, MiLimits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = MiLimits {
        max_record_bytes: 64 * 1024,
        max_depth: 32,
        max_decoded_string_bytes: 64 * 1024,
    };
    for chunk_size in 1..=data.len().clamp(1, 32) {
        let mut framer = MiFramer::new(limits);
        for chunk in data.chunks(chunk_size) {
            if framer.push(chunk).is_err() {
                break;
            }
        }
        let _ = framer.finish();
    }
});
