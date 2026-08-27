use bytes::{Buf, BytesMut};

use crate::{MiError, MiLimits};

#[derive(Debug)]
pub struct MiFramer {
    buffer: BytesMut,
    max_record_bytes: usize,
}

impl MiFramer {
    pub fn new(limits: MiLimits) -> Self {
        Self {
            buffer: BytesMut::new(),
            max_record_bytes: limits.max_record_bytes,
        }
    }

    pub fn push(&mut self, input: &[u8]) -> Result<Vec<Vec<u8>>, MiError> {
        if self.buffer.len().saturating_add(input.len()) > self.max_record_bytes
            && !input.contains(&b'\n')
        {
            return Err(MiError::Limit {
                kind: "unterminated record",
                limit: self.max_record_bytes,
            });
        }

        self.buffer.extend_from_slice(input);
        let mut records = Vec::new();
        while let Some(newline) = self.buffer.iter().position(|byte| *byte == b'\n') {
            if newline > self.max_record_bytes {
                return Err(MiError::Limit {
                    kind: "record bytes",
                    limit: self.max_record_bytes,
                });
            }
            let mut record = self.buffer.split_to(newline + 1).to_vec();
            record.pop();
            if record.last() == Some(&b'\r') {
                record.pop();
            }
            if !record.is_empty() {
                records.push(record);
            }
        }

        if self.buffer.len() > self.max_record_bytes {
            return Err(MiError::Limit {
                kind: "unterminated record",
                limit: self.max_record_bytes,
            });
        }
        Ok(records)
    }

    pub fn finish(&mut self) -> Result<Option<Vec<u8>>, MiError> {
        if self.buffer.is_empty() {
            return Ok(None);
        }
        if self.buffer.len() > self.max_record_bytes {
            return Err(MiError::Limit {
                kind: "record bytes",
                limit: self.max_record_bytes,
            });
        }
        let record = self.buffer.to_vec();
        self.buffer.advance(self.buffer.len());
        Ok(Some(record))
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_is_independent_of_chunks_and_newlines() {
        let input = b"1^done,value=\"x\"\r\n*stopped,reason=\"breakpoint-hit\"\n(gdb) \n";
        let expected = vec![
            b"1^done,value=\"x\"".to_vec(),
            b"*stopped,reason=\"breakpoint-hit\"".to_vec(),
            b"(gdb) ".to_vec(),
        ];

        for chunk_size in 1..=input.len() {
            let mut framer = MiFramer::new(MiLimits::default());
            let mut actual = Vec::new();
            for chunk in input.chunks(chunk_size) {
                actual.extend(framer.push(chunk).unwrap());
            }
            assert_eq!(actual, expected, "chunk size {chunk_size}");
        }
    }

    #[test]
    fn rejects_unterminated_oversize_record() {
        let mut framer = MiFramer::new(MiLimits {
            max_record_bytes: 4,
            ..MiLimits::default()
        });
        assert!(matches!(framer.push(b"12345"), Err(MiError::Limit { .. })));
    }
}
