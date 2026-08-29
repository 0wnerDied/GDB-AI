use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;

use crate::{Error, ErrorCode, Result};

pub(super) fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::new(
            ErrorCode::GdbError,
            "GDB returned malformed hexadecimal bytes",
        ));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16)
                .map_err(|_| Error::new(ErrorCode::GdbError, "invalid hexadecimal byte"))
        })
        .collect()
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
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

pub(super) fn first_word(command: &str) -> &str {
    command.split_whitespace().next().unwrap_or("unknown")
}
