#![no_main]

use gdb_ai_mi::{MiLimits, parse_record};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_record(
        data,
        MiLimits {
            max_record_bytes: 64 * 1024,
            max_depth: 32,
            max_decoded_string_bytes: 64 * 1024,
        },
    );
});
