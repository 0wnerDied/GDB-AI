#![no_main]

use gdb_ai_mi::{MiLimits, MiRecord, parse_record, quote_c_string};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = MiLimits {
        max_record_bytes: 64 * 1024,
        max_depth: 32,
        max_decoded_string_bytes: 64 * 1024,
    };
    let _ = parse_record(data, limits);
    if data.len() <= limits.max_decoded_string_bytes {
        let encoded = format!("~{}", quote_c_string(data));
        let limits = MiLimits {
            max_record_bytes: encoded.len(),
            ..limits
        };
        assert_eq!(
            parse_record(encoded.as_bytes(), limits).unwrap(),
            MiRecord::ConsoleStream(data.to_vec())
        );
    }
});
