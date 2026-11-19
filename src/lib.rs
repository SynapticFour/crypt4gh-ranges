// SPDX-License-Identifier: Apache-2.0
//! Byte-range planning for [Crypt4GH](https://samtools.github.io/hts-specs/crypt4gh.pdf) files.
//!
//! A Crypt4GH body is the plaintext cut into 65 536-byte segments, each stored as
//! nonce (12) + ciphertext + MAC (16). To serve part of a file you need to know
//! which segments to read, where they sit in the ciphertext, and — when the
//! client decrypts itself — a *data edit list* so that its decryptor outputs
//! exactly the requested bytes.
//!
//! This crate does only that arithmetic. It does no I/O and no cryptography, so
//! servers (Ferrum, Synaptic-Core) can use it with their own storage and their
//! own Crypt4GH implementation.
//!
//! ```
//! use crypt4gh_ranges::{plan, PlainRange};
//! // Two regions of a 1 MiB file whose Crypt4GH header is 124 bytes long.
//! let p = plan(&[PlainRange::new(70_000, 70_099).unwrap(),
//!                PlainRange::new(900_000, 900_009).unwrap()], 1 << 20).unwrap();
//! assert_eq!(p.segments.len(), 2);                 // segment 1 and segment 13
//! let bytes = p.cipher_ranges(124, 1 << 20);       // what to read from storage
//! assert_eq!(bytes[0].0, 124 + 65_564);
//! // Skip to 70 000 inside segment 1, keep 100; skip to 900 000 inside segment 13, keep 10.
//! assert_eq!(p.edit_list, vec![4_464, 100, 109_004, 10]);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Plaintext bytes per segment.
pub const SEGMENT_SIZE: u64 = 65_536;
/// Nonce bytes before each encrypted segment (ChaCha20-IETF-Poly1305).
pub const NONCE_SIZE: u64 = 12;
/// MAC bytes after each encrypted segment.
pub const MAC_SIZE: u64 = 16;
/// Stored bytes per full segment.
pub const CIPHER_SEGMENT_SIZE: u64 = SEGMENT_SIZE + NONCE_SIZE + MAC_SIZE;

/// Errors for invalid input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeError {
    /// `start > end`.
    Inverted {
        /// Requested start.
        start: u64,
        /// Requested end (inclusive).
        end: u64,
    },
    /// The range reaches past the end of the plaintext.
    PastEnd {
        /// Requested end (inclusive).
        end: u64,
        /// Plaintext length.
        len: u64,
    },
    /// No ranges were given.
    Empty,
}

impl std::fmt::Display for RangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inverted { start, end } => write!(f, "range start {start} > end {end}"),
            Self::PastEnd { end, len } => {
                write!(f, "range end {end} is past plaintext length {len}")
            }
            Self::Empty => write!(f, "no ranges"),
        }
    }
}

impl std::error::Error for RangeError {}

/// A plaintext byte range, both ends inclusive (like HTTP `Range`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlainRange {
    /// First byte.
    pub start: u64,
    /// Last byte (inclusive).
    pub end: u64,
}

impl PlainRange {
    /// Builds a range; `start <= end`.
    pub fn new(start: u64, end: u64) -> Result<Self, RangeError> {
        if start > end {
            return Err(RangeError::Inverted { start, end });
        }
        Ok(Self { start, end })
    }

    /// Number of bytes.
    pub fn len(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Never true for a valid range.
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// Consecutive segments `first..=last` (0-based segment numbers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentRange {
    /// First segment number.
    pub first: u64,
    /// Last segment number (inclusive).
    pub last: u64,
}

impl SegmentRange {
    /// Plaintext offset where `first` begins.
    pub fn plain_start(&self) -> u64 {
        self.first * SEGMENT_SIZE
    }

    /// Plaintext bytes these segments hold in a file of `plain_len` bytes.
    pub fn plain_len(&self, plain_len: u64) -> u64 {
        let end = ((self.last + 1) * SEGMENT_SIZE).min(plain_len);
        end - self.plain_start()
    }

    /// Ciphertext byte range (inclusive) of these segments, given the header length
    /// and the plaintext length (the last segment of a file may be short).
    pub fn cipher_range(&self, header_len: u64, plain_len: u64) -> (u64, u64) {
        let start = header_len + self.first * CIPHER_SEGMENT_SIZE;
        let segs = self.last - self.first; // full segments before the last one
        let last_plain = self.last_segment_plain_len(plain_len);
        let end = start + segs * CIPHER_SEGMENT_SIZE + NONCE_SIZE + last_plain + MAC_SIZE - 1;
        (start, end)
    }

    fn last_segment_plain_len(&self, plain_len: u64) -> u64 {
        let seg_start = self.last * SEGMENT_SIZE;
        (plain_len - seg_start).min(SEGMENT_SIZE)
    }
}

/// Segment that holds plaintext byte `offset`.
pub fn segment_of(offset: u64) -> u64 {
    offset / SEGMENT_SIZE
}

/// Ciphertext length of a Crypt4GH body for `plain_len` plaintext bytes.
pub fn cipher_body_len(plain_len: u64) -> u64 {
    let segments = plain_len.div_ceil(SEGMENT_SIZE);
    plain_len + segments * (NONCE_SIZE + MAC_SIZE)
}

/// What to read and how to cut it, for a set of plaintext ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Requested ranges, sorted and merged (overlapping or adjacent ranges joined).
    pub ranges: Vec<PlainRange>,
    /// Segment runs to send, sorted, non-overlapping, non-adjacent.
    pub segments: Vec<SegmentRange>,
    /// Crypt4GH data edit list over the plaintext of `segments` concatenated:
    /// alternating skip, keep, skip, keep … (starts with a skip, ends with a keep).
    pub edit_list: Vec<u64>,
}

impl Plan {
    /// Ciphertext byte ranges (inclusive) to read from storage, in order.
    pub fn cipher_ranges(&self, header_len: u64, plain_len: u64) -> Vec<(u64, u64)> {
        self.segments
            .iter()
            .map(|s| s.cipher_range(header_len, plain_len))
            .collect()
    }

    /// Total bytes the client ends up with after applying the edit list.
    pub fn output_len(&self) -> u64 {
        self.ranges.iter().map(PlainRange::len).sum()
    }
}

/// Plans segment reads and the edit list for `ranges` in a file of `plain_len` bytes.
pub fn plan(ranges: &[PlainRange], plain_len: u64) -> Result<Plan, RangeError> {
    if ranges.is_empty() {
        return Err(RangeError::Empty);
    }
    for r in ranges {
        if r.end >= plain_len {
            return Err(RangeError::PastEnd {
                end: r.end,
                len: plain_len,
            });
        }
    }
    let merged = merge(ranges);

    // Segment runs: each range's segments, joined when they touch.
    let mut segments: Vec<SegmentRange> = Vec::new();
    for r in &merged {
        let s = SegmentRange {
            first: segment_of(r.start),
            last: segment_of(r.end),
        };
        match segments.last_mut() {
            Some(prev) if s.first <= prev.last + 1 => prev.last = prev.last.max(s.last),
            _ => segments.push(s),
        }
    }

    // Edit list over the concatenated plaintext of the segment runs.
    // Map a file offset to its position in that concatenation.
    let mut edit_list = Vec::with_capacity(merged.len() * 2);
    let mut cursor = 0u64; // position in the concatenation already accounted for
    for r in &merged {
        let pos = concat_offset(&segments, r.start, plain_len);
        edit_list.push(pos - cursor);
        edit_list.push(r.len());
        cursor = pos + r.len();
    }
    Ok(Plan {
        ranges: merged,
        segments,
        edit_list,
    })
}

fn concat_offset(segments: &[SegmentRange], offset: u64, plain_len: u64) -> u64 {
    let mut before = 0u64;
    for s in segments {
        let start = s.plain_start();
        let len = s.plain_len(plain_len);
        if offset >= start && offset < start + len {
            return before + (offset - start);
        }
        before += len;
    }
    unreachable!("offset {offset} is not inside the planned segments")
}

/// Sorts and merges overlapping or adjacent ranges.
pub fn merge(ranges: &[PlainRange]) -> Vec<PlainRange> {
    let mut v = ranges.to_vec();
    v.sort();
    let mut out: Vec<PlainRange> = Vec::with_capacity(v.len());
    for r in v {
        match out.last_mut() {
            Some(prev) if r.start <= prev.end.saturating_add(1) => prev.end = prev.end.max(r.end),
            _ => out.push(r),
        }
    }
    out
}

/// Plaintext content of a Crypt4GH *data edit list* header packet, before it is
/// encrypted for the recipient: packet type 1 (u32 LE), number of lengths
/// (u32 LE), then each length (u64 LE).
pub fn edit_list_packet(edit_list: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + edit_list.len() * 8);
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(edit_list.len() as u32).to_le_bytes());
    for n in edit_list {
        out.extend_from_slice(&n.to_le_bytes());
    }
    out
}

/// Applies an edit list to plaintext (reference behaviour of a Crypt4GH decryptor):
/// skip, keep, skip, keep …; anything after the last keep is dropped.
pub fn apply_edit_list(data: &[u8], edit_list: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    for (i, n) in edit_list.iter().enumerate() {
        let n = *n as usize;
        let end = (pos + n).min(data.len());
        if i % 2 == 1 {
            out.extend_from_slice(&data[pos..end]);
        }
        pos = end;
    }
    out
}

/// Cuts decrypted plaintext of whole segments down to one range (server-side
/// decryption mode): `data` holds `segments` starting at `segments.plain_start()`.
pub fn trim_to_range(data: &[u8], segments: SegmentRange, range: PlainRange) -> &[u8] {
    let from = (range.start - segments.plain_start()) as usize;
    let to = (range.end - segments.plain_start()) as usize + 1;
    &data[from..to.min(data.len())]
}
