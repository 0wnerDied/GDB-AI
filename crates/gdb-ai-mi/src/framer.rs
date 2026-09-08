use bytes::{Buf, BytesMut};

use crate::{MiError, MiLimits};

/// Complete records preceding an optional terminal framing error.
/// Consume the records in order before handling the error.
#[derive(Debug)]
#[must_use]
pub struct MiFrames {
    pub records: Vec<Vec<u8>>,
    pub error: Option<MiError>,
}

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

    /// Frames a chunk, preserving complete records even if a later record
    /// exceeds the limit. Discard the framer after a framing error.
    pub fn push(&mut self, input: &[u8]) -> MiFrames {
        // 2026-09-08: Returning only Err discarded complete prefix records
        // from the same chunk. Keep their delivery independent of chunking.
        let mut records = Vec::new();
        let error = self.push_into(input, &mut records).err();
        MiFrames { records, error }
    }

    fn push_into(&mut self, input: &[u8], records: &mut Vec<Vec<u8>>) -> Result<(), MiError> {
        if self.buffer.len().saturating_add(input.len()) > self.max_record_bytes
            && !input.contains(&b'\n')
        {
            return Err(MiError::Limit {
                kind: "unterminated record",
                limit: self.max_record_bytes,
            });
        }

        self.buffer.extend_from_slice(input);
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
        Ok(())
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
                let frames = framer.push(chunk);
                assert_eq!(frames.error, None);
                actual.extend(frames.records);
            }
            assert_eq!(actual, expected, "chunk size {chunk_size}");
            assert_eq!(framer.finish().unwrap(), Some(b"last".to_vec()));
            let frames = framer.push(b"new\n");
            assert_eq!(frames.error, None);
            assert_eq!(frames.records, [b"new".to_vec()]);
        }
    }

    #[test]
    fn preserves_record_limits_and_error_previews_across_chunks() {
        let limits = MiLimits {
            max_record_bytes: 4,
            ..MiLimits::default()
        };
        let mut framer = MiFramer::new(limits);
        assert!(framer.push(b"1234").error.is_none());
        assert_eq!(
            framer.push(b"5").error.unwrap(),
            MiError::Limit {
                kind: "unterminated record",
                limit: 4,
            }
        );
        assert_eq!(framer.preview(64), b"1234");

        let mut framer = MiFramer::new(limits);
        assert!(framer.push(b"1234").error.is_none());
        assert_eq!(
            framer.push(b"\r\n").error.unwrap(),
            MiError::Limit {
                kind: "record bytes",
                limit: 4,
            }
        );
        assert_eq!(framer.preview(64), b"1234\r\n");

        let mut framer = MiFramer::new(limits);
        let frames = framer.push(b"ok\n12345");
        assert_eq!(frames.records, [b"ok".to_vec()]);
        assert!(frames.error.is_some());
        assert_eq!(framer.preview(64), b"12345");
        assert!(framer.finish().is_err());
    }

    #[test]
    fn preserves_complete_records_before_a_later_limit_error() {
        let limits = MiLimits {
            max_record_bytes: 16,
            ..MiLimits::default()
        };
        let input = b"1^done\n2^done\n~\"a normal but longer console line\"\n";
        for end in [input.len() - 1, input.len()] {
            let input = &input[..end];
            for chunk_size in 1..=input.len() {
                let mut framer = MiFramer::new(limits);
                let mut records = Vec::new();
                let mut failed = false;
                for chunk in input.chunks(chunk_size) {
                    let frames = framer.push(chunk);
                    records.extend(frames.records);
                    if let Some(error) = frames.error {
                        assert!(matches!(error, MiError::Limit { limit: 16, .. }));
                        failed = true;
                        break;
                    }
                }
                assert!(failed);
                assert_eq!(
                    records,
                    [b"1^done".to_vec(), b"2^done".to_vec()],
                    "chunk size {chunk_size}"
                );
            }
        }
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
                    let frames = std::hint::black_box(framer.push(chunk));
                    assert_eq!(frames.error, None);
                    framed += frames.records.len();
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
