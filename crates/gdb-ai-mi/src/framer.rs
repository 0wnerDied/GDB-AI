use bytes::{Buf, BytesMut};

use crate::{MiError, MiLimits};

/// Frames arbitrary byte chunks before parsing and enforces the untrusted
/// record-size boundary even when GDB never emits a newline.
#[derive(Debug)]
pub struct MiFramer {
    buffer: BytesMut,
    scanned: usize,
    max_record_bytes: usize,
}

impl MiFramer {
    pub fn new(limits: MiLimits) -> Self {
        Self {
            buffer: BytesMut::new(),
            scanned: 0,
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
        // 2026-09-06: Rescanning a fragmented record's entire prefix made
        // framing quadratic. Bytes before scanned are already newline-free.
        while let Some(relative) = self.buffer[self.scanned..]
            .iter()
            .position(|byte| *byte == b'\n')
        {
            let newline = self.scanned + relative;
            if newline > self.max_record_bytes {
                return Err(MiError::Limit {
                    kind: "record bytes",
                    limit: self.max_record_bytes,
                });
            }
            let mut record = self.buffer.split_to(newline + 1).to_vec();
            self.scanned = 0;
            record.pop();
            if record.last() == Some(&b'\r') {
                record.pop();
            }
            if !record.is_empty() {
                records.push(record);
            }
        }
        self.scanned = self.buffer.len();

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
        self.scanned = 0;
        Ok(Some(record))
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    pub fn preview(&self, maximum: usize) -> Vec<u8> {
        self.buffer.iter().take(maximum).copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_is_independent_of_chunks_and_newlines() {
        let input = b"1^done,value=\"x\"\r\n*stopped,reason=\"breakpoint-hit\"\n(gdb) \nlast";
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
            assert_eq!(framer.finish().unwrap(), Some(b"last".to_vec()));
            assert_eq!(framer.push(b"new\n").unwrap(), [b"new".to_vec()]);
        }
    }

    #[test]
    fn preserves_record_limits_and_error_previews_across_chunks() {
        let limits = MiLimits {
            max_record_bytes: 4,
            ..MiLimits::default()
        };
        let mut framer = MiFramer::new(limits);
        assert!(framer.push(b"1234").unwrap().is_empty());
        assert_eq!(
            framer.push(b"5").unwrap_err(),
            MiError::Limit {
                kind: "unterminated record",
                limit: 4,
            }
        );
        assert_eq!(framer.preview(64), b"1234");
        assert_eq!(framer.push(b"\n").unwrap(), [b"1234".to_vec()]);

        assert!(framer.push(b"1234").unwrap().is_empty());
        assert_eq!(
            framer.push(b"\r\n").unwrap_err(),
            MiError::Limit {
                kind: "record bytes",
                limit: 4,
            }
        );
        assert_eq!(framer.preview(64), b"1234\r\n");

        let mut framer = MiFramer::new(limits);
        assert!(framer.push(b"ok\n12345").is_err());
        assert_eq!(framer.preview(64), b"12345");
        assert!(framer.finish().is_err());
    }

    #[test]
    #[ignore = "microbenchmark: run explicitly with an optimized build"]
    fn benchmark_fragmented_records() {
        for (record_bytes, chunk_bytes, records) in [
            (64, 64 * 1024, 500_000),
            (2 * 1024 * 1024, 64 * 1024, 16),
            (2 * 1024 * 1024, 4 * 1024, 16),
        ] {
            let mut record = vec![b'x'; record_bytes];
            record.push(b'\n');
            let batch_records = (chunk_bytes / record.len()).max(1);
            let input = record.repeat(batch_records);
            let batches = records / batch_records;
            let mut framer = MiFramer::new(MiLimits::default());
            let mut framed = 0;
            let started = std::time::Instant::now();
            for _ in 0..batches {
                for chunk in input.chunks(chunk_bytes) {
                    let records = std::hint::black_box(framer.push(chunk).unwrap());
                    framed += records.len();
                }
            }
            let elapsed = started.elapsed();
            assert_eq!(framed, batches * batch_records);
            assert!(framer.finish().unwrap().is_none());
            eprintln!(
                "{}",
                serde_json::json!({
                    "benchmark": "mi_framing",
                    "record_bytes": record_bytes,
                    "chunk_bytes": chunk_bytes,
                    "records": framed,
                    "elapsed_ns": elapsed.as_nanos()
                })
            );
        }
    }
}
