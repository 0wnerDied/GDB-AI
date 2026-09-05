use std::collections::VecDeque;

use serde::Serialize;

#[derive(Debug)]
pub struct ByteRing {
    capacity: usize,
    start_offset: u64,
    end_offset: u64,
    bytes: VecDeque<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RingRead {
    pub requested_offset: u64,
    pub available_from: u64,
    pub next_offset: u64,
    pub gap: bool,
    pub bytes: Vec<u8>,
}

impl ByteRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            start_offset: 0,
            end_offset: 0,
            bytes: VecDeque::with_capacity(capacity.min(64 * 1024)),
        }
    }

    pub fn append(&mut self, input: &[u8]) -> u64 {
        let offset = self.end_offset;
        self.end_offset = self.end_offset.saturating_add(input.len() as u64);
        if input.len() >= self.capacity {
            self.bytes.clear();
            self.bytes.extend(&input[input.len() - self.capacity..]);
            self.start_offset = self.end_offset - self.capacity as u64;
            return offset;
        }
        // 2026-08-30: Extending a full ring before eviction grew its backing
        // allocation beyond the configured bound. Make room before appending.
        let evicted = self
            .bytes
            .len()
            .saturating_add(input.len())
            .saturating_sub(self.capacity);
        self.bytes.drain(..evicted);
        self.start_offset = self.start_offset.saturating_add(evicted as u64);
        self.bytes.extend(input);
        offset
    }

    pub fn read(&self, after_offset: u64, max_bytes: usize) -> RingRead {
        let actual_start = after_offset.clamp(self.start_offset, self.end_offset);
        let skip = (actual_start - self.start_offset) as usize;
        // 2026-09-06: Per-byte collection held output readers in a copy loop.
        // Copy at most two contiguous slices while preserving the cursor bounds.
        let length = max_bytes.min(self.bytes.len() - skip);
        let (first, second) = self.bytes.as_slices();
        let mut bytes = Vec::with_capacity(length);
        if skip < first.len() {
            let end = (skip + length).min(first.len());
            bytes.extend_from_slice(&first[skip..end]);
            bytes.extend_from_slice(&second[..length - bytes.len()]);
        } else {
            let start = skip - first.len();
            bytes.extend_from_slice(&second[start..start + length]);
        }
        RingRead {
            requested_offset: after_offset,
            available_from: self.start_offset,
            next_offset: actual_start + bytes.len() as u64,
            gap: after_offset < self.start_offset,
            bytes,
        }
    }

    pub fn end_offset(&self) -> u64 {
        self.end_offset
    }

    pub fn dropped_bytes(&self) -> u64 {
        self.start_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_gap_after_old_bytes_roll_off() {
        let mut ring = ByteRing::new(4);
        assert_eq!(ring.append(b"abc"), 0);
        assert_eq!(ring.append(b"def"), 3);
        for (offset, limit, expected, next_offset) in [
            (0, 10, b"cdef".as_slice(), 6),
            (3, 2, b"de", 5),
            (4, 10, b"ef", 6),
            (5, 1, b"f", 6),
            (6, 10, b"", 6),
            (100, 10, b"", 6),
            (0, 0, b"", 2),
        ] {
            let read = ring.read(offset, limit);
            assert_eq!(read.requested_offset, offset);
            assert_eq!(read.gap, offset < 2);
            assert_eq!(read.available_from, 2);
            assert_eq!(read.bytes, expected);
            assert_eq!(read.next_offset, next_offset);
        }
    }

    #[test]
    fn appending_to_a_full_ring_reuses_its_allocation() {
        let mut ring = ByteRing::new(1024);
        ring.append(&vec![b'a'; 1024]);
        let capacity = ring.bytes.capacity();

        ring.append(&vec![b'b'; 512]);

        assert_eq!(ring.bytes.capacity(), capacity);
        assert_eq!(
            ring.read(512, usize::MAX).bytes,
            [vec![b'a'; 512], vec![b'b'; 512]].concat()
        );
    }

    #[test]
    #[ignore = "microbenchmark: run explicitly with an optimized build"]
    fn benchmark_output_reads() {
        for (read_bytes, wrapped, reads) in [
            (64, false, 200_000),
            (64 * 1024, false, 4096),
            (64 * 1024, true, 4096),
            (256 * 1024, true, 1024),
        ] {
            let mut ring = ByteRing::new(read_bytes * 2);
            ring.append(&vec![b'x'; read_bytes * 2]);
            if wrapped {
                ring.append(&vec![b'x'; read_bytes / 2]);
            }
            let offset = ring.end_offset() - read_bytes as u64;
            assert_eq!(ring.read(offset, read_bytes).bytes, vec![b'x'; read_bytes]);
            for encode in [false, true] {
                let started = std::time::Instant::now();
                for _ in 0..reads {
                    let read = ring.read(std::hint::black_box(offset), read_bytes);
                    if encode {
                        std::hint::black_box(crate::normalize::byte_content(read.bytes));
                    } else {
                        std::hint::black_box(read);
                    }
                }
                let elapsed = started.elapsed();
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "benchmark": "output_reads",
                        "read_bytes": read_bytes,
                        "wrapped": wrapped,
                        "encode": encode,
                        "reads": reads,
                        "elapsed_ns": elapsed.as_nanos()
                    })
                );
            }
        }
    }
}
