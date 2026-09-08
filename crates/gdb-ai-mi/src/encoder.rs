pub fn quote_c_string(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len() + 2);
    encoded.push('"');
    for byte in value {
        match byte {
            b'\\' => encoded.push_str("\\\\"),
            b'"' => encoded.push_str("\\\""),
            b'\n' => encoded.push_str("\\n"),
            b'\r' => encoded.push_str("\\r"),
            b'\t' => encoded.push_str("\\t"),
            0x20..=0x7e => encoded.push(char::from(*byte)),
            // 2026-08-29: Keep the shared encoder valid under the declared
            // Rust 1.88 Clippy gate by using captured format arguments.
            _ => encoded.push_str(&format!("\\{byte:03o}")),
        }
    }
    encoded.push('"');
    encoded
}

pub fn encode_command(token: u64, command: &str, arguments: &[String]) -> Vec<u8> {
    let mut line = format!("{token}{command}");
    for argument in arguments {
        line.push(' ');
        line.push_str(argument);
    }
    line.push('\n');
    line.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_binary_as_c_string() {
        assert_eq!(quote_c_string(b"a\n\"\\\xff"), "\"a\\n\\\"\\\\\\377\"");
    }

    #[test]
    fn every_byte_round_trips_individually_and_together() {
        let bytes = (0..=u8::MAX).collect::<Vec<_>>();
        for value in std::iter::once(bytes.as_slice()).chain(bytes.chunks(1)) {
            let record = format!("~{}", quote_c_string(value));
            assert_eq!(
                crate::parse_record(record.as_bytes(), crate::MiLimits::default()).unwrap(),
                crate::MiRecord::ConsoleStream(value.to_vec())
            );
        }
    }
}
