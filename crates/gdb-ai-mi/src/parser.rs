use std::fmt;

use thiserror::Error;

use crate::{MiRecord, MiResult, MiValue};

#[derive(Clone, Copy, Debug)]
pub struct MiLimits {
    pub max_record_bytes: usize,
    pub max_depth: usize,
    pub max_decoded_string_bytes: usize,
}

impl Default for MiLimits {
    fn default() -> Self {
        Self {
            max_record_bytes: 8 * 1024 * 1024,
            max_depth: 128,
            max_decoded_string_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MiError {
    #[error("empty MI record")]
    Empty,
    #[error("unexpected byte at offset {offset}: expected {expected}, found {found}")]
    Unexpected {
        offset: usize,
        expected: &'static str,
        found: DisplayByte,
    },
    #[error("invalid numeric token at offset {offset}")]
    InvalidToken { offset: usize },
    #[error("MI {kind} exceeds limit {limit}")]
    Limit { kind: &'static str, limit: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayByte(Option<u8>);

impl fmt::Display for DisplayByte {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(byte) if byte.is_ascii_graphic() || byte == b' ' => {
                write!(formatter, "{:?}", char::from(byte))
            }
            Some(byte) => write!(formatter, "0x{byte:02x}"),
            None => formatter.write_str("end of record"),
        }
    }
}

pub fn parse_record(input: &[u8], limits: MiLimits) -> Result<MiRecord, MiError> {
    if input.is_empty() {
        return Err(MiError::Empty);
    }
    if input.len() > limits.max_record_bytes {
        return Err(MiError::Limit {
            kind: "record bytes",
            limit: limits.max_record_bytes,
        });
    }

    let prompt = trim_ascii_whitespace(input);
    if prompt == b"(gdb)" {
        return Ok(MiRecord::Prompt);
    }

    Parser {
        input,
        offset: 0,
        limits,
    }
    .record()
}

fn trim_ascii_whitespace(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(u8::is_ascii_whitespace) {
        input = &input[1..];
    }
    while input.last().is_some_and(u8::is_ascii_whitespace) {
        input = &input[..input.len() - 1];
    }
    input
}

struct Parser<'a> {
    input: &'a [u8],
    offset: usize,
    limits: MiLimits,
}

impl Parser<'_> {
    fn record(mut self) -> Result<MiRecord, MiError> {
        let token = self.token()?;
        let prefix = self.take("MI record prefix")?;
        let record = match prefix {
            b'^' => {
                let (class, results) = self.class_and_results()?;
                MiRecord::Result {
                    token,
                    class,
                    results,
                }
            }
            b'*' => {
                let (class, results) = self.class_and_results()?;
                MiRecord::ExecAsync {
                    token,
                    class,
                    results,
                }
            }
            b'+' => {
                let (class, results) = self.class_and_results()?;
                MiRecord::StatusAsync {
                    token,
                    class,
                    results,
                }
            }
            b'=' => {
                let (class, results) = self.class_and_results()?;
                MiRecord::NotifyAsync {
                    token,
                    class,
                    results,
                }
            }
            b'~' | b'@' | b'&' if token.is_none() => {
                let bytes = self.c_string()?;
                match prefix {
                    b'~' => MiRecord::ConsoleStream(bytes),
                    b'@' => MiRecord::TargetStream(bytes),
                    b'&' => MiRecord::LogStream(bytes),
                    _ => unreachable!(),
                }
            }
            _ => return self.unexpected("^, *, +, =, ~, @, or &"),
        };
        if self.offset != self.input.len() {
            return self.unexpected("end of record");
        }
        Ok(record)
    }

    fn token(&mut self) -> Result<Option<u64>, MiError> {
        let start = self.offset;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.offset += 1;
        }
        if self.offset == start {
            return Ok(None);
        }
        let token = std::str::from_utf8(&self.input[start..self.offset])
            .ok()
            .and_then(|value| value.parse().ok())
            .ok_or(MiError::InvalidToken { offset: start })?;
        Ok(Some(token))
    }

    fn class_and_results(&mut self) -> Result<(String, Vec<MiResult>), MiError> {
        let start = self.offset;
        while self.peek().is_some_and(|byte| byte != b',') {
            let byte = self.peek().unwrap();
            if byte.is_ascii_whitespace() || matches!(byte, b'{' | b'}' | b'[' | b']' | b'=' | b'"')
            {
                return self.unexpected("result or async class");
            }
            self.offset += 1;
        }
        if self.offset == start {
            return self.unexpected("non-empty result or async class");
        }
        let class = String::from_utf8_lossy(&self.input[start..self.offset]).into_owned();
        let mut results = Vec::new();
        while self.peek() == Some(b',') {
            self.offset += 1;
            results.push(self.result(0)?);
        }
        Ok((class, results))
    }

    fn result(&mut self, depth: usize) -> Result<MiResult, MiError> {
        let start = self.offset;
        while let Some(byte) = self.peek() {
            if byte == b'=' {
                break;
            }
            if matches!(byte, b',' | b'{' | b'}' | b'[' | b']' | b'"') || byte.is_ascii_whitespace()
            {
                return self.unexpected("result name followed by =");
            }
            self.offset += 1;
        }
        if self.offset == start || self.peek() != Some(b'=') {
            return self.unexpected("result name followed by =");
        }
        let name = String::from_utf8_lossy(&self.input[start..self.offset]).into_owned();
        self.offset += 1;
        let value = self.value(depth)?;
        Ok(MiResult { name, value })
    }

    fn value(&mut self, depth: usize) -> Result<MiValue, MiError> {
        match self.peek() {
            Some(b'"') => Ok(MiValue::Const(self.c_string()?)),
            Some(b'{') => self.tuple(depth),
            Some(b'[') => self.list(depth),
            _ => self.unexpected("MI value"),
        }
    }

    fn tuple(&mut self, depth: usize) -> Result<MiValue, MiError> {
        self.check_depth(depth)?;
        self.expect(b'{', "{")?;
        let mut results = Vec::new();
        if self.peek() != Some(b'}') {
            loop {
                results.push(self.result(depth + 1)?);
                if self.peek() != Some(b',') {
                    break;
                }
                self.offset += 1;
            }
        }
        self.expect(b'}', "}")?;
        Ok(MiValue::Tuple(results))
    }

    fn list(&mut self, depth: usize) -> Result<MiValue, MiError> {
        self.check_depth(depth)?;
        self.expect(b'[', "[")?;
        if self.peek() == Some(b']') {
            self.offset += 1;
            return Ok(MiValue::ValueList(Vec::new()));
        }

        if self.looks_like_result() {
            let mut results = Vec::new();
            loop {
                results.push(self.result(depth + 1)?);
                if self.peek() != Some(b',') {
                    break;
                }
                self.offset += 1;
            }
            self.expect(b']', "]")?;
            Ok(MiValue::ResultList(results))
        } else {
            let mut values = Vec::new();
            loop {
                values.push(self.value(depth + 1)?);
                if self.peek() != Some(b',') {
                    break;
                }
                self.offset += 1;
            }
            self.expect(b']', "]")?;
            Ok(MiValue::ValueList(values))
        }
    }

    fn looks_like_result(&self) -> bool {
        let mut offset = self.offset;
        while let Some(byte) = self.input.get(offset) {
            match byte {
                b'=' => return offset > self.offset,
                b',' | b']' | b'{' | b'}' | b'[' | b'"' => return false,
                byte if byte.is_ascii_whitespace() => return false,
                _ => offset += 1,
            }
        }
        false
    }

    fn c_string(&mut self) -> Result<Vec<u8>, MiError> {
        self.expect(b'"', "opening quote")?;
        let mut decoded = Vec::new();
        loop {
            let byte = self.take("closing quote")?;
            match byte {
                b'"' => break,
                b'\\' => self.escape(&mut decoded)?,
                b'\n' | b'\r' => return self.unexpected("escaped newline or closing quote"),
                byte => decoded.push(byte),
            }
            if decoded.len() > self.limits.max_decoded_string_bytes {
                return Err(MiError::Limit {
                    kind: "decoded C-string bytes",
                    limit: self.limits.max_decoded_string_bytes,
                });
            }
        }
        Ok(decoded)
    }

    fn escape(&mut self, decoded: &mut Vec<u8>) -> Result<(), MiError> {
        let escaped = self.take("C-string escape")?;
        let byte = match escaped {
            b'a' => 0x07,
            b'b' => 0x08,
            b'e' => 0x1b,
            b'f' => 0x0c,
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'v' => 0x0b,
            b'\\' => b'\\',
            b'"' => b'"',
            b'\'' => b'\'',
            b'?' => b'?',
            b'x' => {
                let start = self.offset;
                let mut value = 0u8;
                let mut digits = 0;
                while let Some(digit) = self.peek().and_then(hex_digit) {
                    value = value.wrapping_mul(16).wrapping_add(digit);
                    self.offset += 1;
                    digits += 1;
                }
                if digits == 0 {
                    return Err(MiError::Unexpected {
                        offset: start,
                        expected: "hexadecimal escape digit",
                        found: DisplayByte(self.peek()),
                    });
                }
                value
            }
            b'0'..=b'7' => {
                let mut value = escaped - b'0';
                for _ in 0..2 {
                    let Some(next @ b'0'..=b'7') = self.peek() else {
                        break;
                    };
                    value = value.wrapping_mul(8).wrapping_add(next - b'0');
                    self.offset += 1;
                }
                value
            }
            // GDB occasionally forwards target-specific escapes. C treats an
            // unknown escaped character as that character, so retain it.
            other => other,
        };
        decoded.push(byte);
        Ok(())
    }

    fn check_depth(&self, depth: usize) -> Result<(), MiError> {
        if depth >= self.limits.max_depth {
            Err(MiError::Limit {
                kind: "nesting depth",
                limit: self.limits.max_depth,
            })
        } else {
            Ok(())
        }
    }

    fn expect(&mut self, expected: u8, description: &'static str) -> Result<(), MiError> {
        if self.peek() != Some(expected) {
            return self.unexpected(description);
        }
        self.offset += 1;
        Ok(())
    }

    fn take(&mut self, expected: &'static str) -> Result<u8, MiError> {
        let Some(byte) = self.peek() else {
            return self.unexpected(expected);
        };
        self.offset += 1;
        Ok(byte)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.offset).copied()
    }

    fn unexpected<T>(&self, expected: &'static str) -> Result<T, MiError> {
        Err(MiError::Unexpected {
            offset: self.offset,
            expected,
            found: DisplayByte(self.peek()),
        })
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &[u8]) -> MiRecord {
        parse_record(input, MiLimits::default()).unwrap()
    }

    #[test]
    fn parses_every_record_kind() {
        assert!(
            matches!(parse(b"9^future,x=\"y\""), MiRecord::Result { token: Some(9), class, .. } if class == "future")
        );
        assert!(matches!(parse(b"*stopped"), MiRecord::ExecAsync { .. }));
        assert!(matches!(parse(b"+download"), MiRecord::StatusAsync { .. }));
        assert!(matches!(
            parse(b"=thread-created,id=\"1\""),
            MiRecord::NotifyAsync { .. }
        ));
        assert_eq!(
            parse(b"~\"console\\n\""),
            MiRecord::ConsoleStream(b"console\n".to_vec())
        );
        assert_eq!(
            parse(b"@\"\\377target\""),
            MiRecord::TargetStream(b"\xfftarget".to_vec())
        );
        assert_eq!(parse(b"&\"log\""), MiRecord::LogStream(b"log".to_vec()));
        assert_eq!(parse(b" (gdb) "), MiRecord::Prompt);
    }

    #[test]
    fn preserves_duplicate_and_unknown_fields() {
        let MiRecord::Result { results, .. } = parse(
            b"1^done,a=\"1\",a=\"2\",future={x=\"y\"},values=[\"a\",\"b\"],results=[x=\"1\",x=\"2\"]",
        ) else {
            panic!("wrong record");
        };
        assert_eq!(
            results.iter().filter(|result| result.name == "a").count(),
            2
        );
        assert!(matches!(
            MiResult::find(&results, "future"),
            Some(MiValue::Tuple(_))
        ));
        assert!(matches!(
            MiResult::find(&results, "values"),
            Some(MiValue::ValueList(_))
        ));
        assert!(matches!(
            MiResult::find(&results, "results"),
            Some(MiValue::ResultList(_))
        ));
    }

    #[test]
    fn enforces_depth_and_decoded_size() {
        let limits = MiLimits {
            max_depth: 2,
            max_decoded_string_bytes: 3,
            ..MiLimits::default()
        };
        assert!(matches!(
            parse_record(b"^done,x={a={b={c=\"d\"}}}", limits),
            Err(MiError::Limit {
                kind: "nesting depth",
                ..
            })
        ));
        assert!(matches!(
            parse_record(b"~\"1234\"", limits),
            Err(MiError::Limit {
                kind: "decoded C-string bytes",
                ..
            })
        ));
    }

    #[test]
    fn rejects_trailing_or_partial_input() {
        assert!(parse_record(b"^done garbage", MiLimits::default()).is_err());
        assert!(parse_record(b"^done,x=\"unterminated", MiLimits::default()).is_err());
        assert!(parse_record(b"^done,x=[a=\"1\",\"mixed\"]", MiLimits::default()).is_err());
    }
}
