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
        let bytes: Vec<u8> = self
            .bytes
            .iter()
            .skip(skip)
            .take(max_bytes)
            .copied()
            .collect();
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
        let read = ring.read(0, 10);
        assert!(read.gap);
        assert_eq!(read.available_from, 2);
        assert_eq!(read.bytes, b"cdef");
        assert_eq!(read.next_offset, 6);
    }

    #[test]
    fn appending_to_a_full_ring_reuses_its_allocation() {
        let mut ring = ByteRing::new(1024);
        ring.append(&vec![b'a'; 1024]);
        let capacity = ring.bytes.capacity();

        ring.append(&vec![b'b'; 512]);

        assert_eq!(ring.bytes.capacity(), capacity);
        assert_eq!(
            ring.read(512, 1024).bytes,
            [vec![b'a'; 512], vec![b'b'; 512]].concat()
        );
    }
}
