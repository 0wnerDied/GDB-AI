use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Map, Value};

use crate::{Error, ErrorCode, Result};

pub(super) fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::new(
            ErrorCode::GdbError,
            "GDB returned malformed hexadecimal bytes",
        ));
    }
    // 2026-08-30: Per-byte UTF-8 and radix parsing dominated large memory
    // reads. Decode both nibbles directly in one bounded pass.
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    // 2026-08-30: Formatting each byte was the dominant cost of large memory
    // writes. The fixed ASCII table produces the same lowercase MI payload.
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::new(
            ErrorCode::GdbError,
            "GDB returned malformed hexadecimal bytes",
        )),
    }
}

pub(super) fn parse_gdb_u64(value: &str) -> Result<u64> {
    if let Some(start) = value.find("0x") {
        let digits: String = value[start + 2..]
            .chars()
            .take_while(|character| character.is_ascii_hexdigit())
            .collect();
        if !digits.is_empty() {
            return u64::from_str_radix(&digits, 16)
                .map_err(|_| Error::new(ErrorCode::GdbError, "invalid GDB hexadecimal value"));
        }
    }
    value
        .split_whitespace()
        .find_map(|word| {
            word.trim_matches(|character: char| !character.is_ascii_digit())
                .parse()
                .ok()
        })
        .ok_or_else(|| {
            Error::new(
                ErrorCode::GdbError,
                format!("GDB value is not an unsigned integer: {value}"),
            )
        })
}

pub(super) fn gdb_c_string(value: &str) -> String {
    // 2026-08-28: GDB prefixes pointer-to-char values with an address and
    // symbol, while fixed arrays begin at the quote. Normalize both forms.
    let value = value
        .find('"')
        .map_or(value, |quote| &value[quote.saturating_add(1)..]);
    let end = [value.find("\\000"), value.find('"')]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(value.len());
    value[..end].trim_end_matches('"').to_owned()
}

pub(super) fn parse_address(value: &str) -> Result<u64> {
    let value = value
        .split_whitespace()
        .next()
        .unwrap_or(value)
        .trim_matches(|character: char| matches!(character, '(' | ')' | ','));
    let value = value.strip_prefix("0x").ok_or_else(|| {
        Error::new(
            ErrorCode::GdbError,
            format!("GDB value is not a hexadecimal address: {value}"),
        )
    })?;
    u64::from_str_radix(value, 16)
        .map_err(|_| Error::new(ErrorCode::GdbError, "invalid hexadecimal address"))
}

pub(super) fn input_bytes(parameters: &Value) -> Result<Vec<u8>> {
    if let Some(encoded) = parameters.get("data_base64").and_then(Value::as_str) {
        return BASE64.decode(encoded).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid data_base64: {error}"),
            )
        });
    }
    if let Some(text) = parameters.get("text").and_then(Value::as_str) {
        return Ok(text.as_bytes().to_vec());
    }
    Err(Error::new(
        ErrorCode::InvalidArgument,
        "text or data_base64 is required",
    ))
}

pub(super) fn byte_content(bytes: Vec<u8>) -> Map<String, Value> {
    // 2026-08-30: Returning UTF-8 as both text and base64 duplicated target
    // evidence and inflated Agent context. Emit exactly one lossless form.
    let mut content = Map::new();
    match String::from_utf8(bytes) {
        Ok(text) => {
            content.insert("encoding".into(), Value::String("utf-8".into()));
            content.insert("text".into(), Value::String(text));
        }
        Err(error) => {
            content.insert("encoding".into(), Value::String("binary".into()));
            content.insert(
                "data_base64".into(),
                Value::String(BASE64.encode(error.into_bytes())),
            );
        }
    }
    content
}

pub(super) fn first_word(command: &str) -> &str {
    command.split_whitespace().next().unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hexadecimal_codec_preserves_bytes_and_rejects_malformed_input() {
        let bytes = [0x00, 0xab, 0xcd, 0xff];
        assert_eq!(hex_encode(&bytes), "00abcdff");
        assert_eq!(hex_decode("00aBcDfF").unwrap(), bytes);
        assert!(hex_decode("0").is_err());
        assert!(hex_decode("0z").is_err());
    }

    #[test]
    fn byte_content_uses_one_lossless_representation() {
        let text = byte_content(b"hello".to_vec());
        assert_eq!(text["text"], "hello");
        assert!(!text.contains_key("data_base64"));

        let binary = byte_content(vec![0xff]);
        assert_eq!(binary["data_base64"], "/w==");
        assert!(!binary.contains_key("text"));
    }
}
