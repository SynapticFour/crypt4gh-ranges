use crypt4gh_ranges::*;
use proptest::prelude::*;

fn file(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

/// Simulates a server: picks the planned segments' plaintext out of the file.
fn selected_plaintext(data: &[u8], plan: &Plan) -> Vec<u8> {
    let len = data.len() as u64;
    let mut out = Vec::new();
    for s in &plan.segments {
        let a = s.plain_start() as usize;
        out.extend_from_slice(&data[a..a + s.plain_len(len) as usize]);
    }
    out
}

fn expected(data: &[u8], plan: &Plan) -> Vec<u8> {
    plan.ranges
        .iter()
        .flat_map(|r| data[r.start as usize..=r.end as usize].to_vec())
        .collect()
}

proptest! {
    #[test]
    fn edit_list_yields_exactly_the_ranges(
        len in 1usize..600_000,
        raw in prop::collection::vec((0u64..600_000, 0u64..200_000), 1..6),
    ) {
        let data = file(len);
        let n = len as u64;
        let ranges: Vec<PlainRange> = raw.iter()
            .map(|(s, l)| { let s = s % n; PlainRange::new(s, (s + l).min(n - 1)).unwrap() })
            .collect();
        let p = plan(&ranges, n).unwrap();
        let got = apply_edit_list(&selected_plaintext(&data, &p), &p.edit_list);
        prop_assert_eq!(got.len() as u64, p.output_len());
        prop_assert_eq!(got, expected(&data, &p));
    }

    #[test]
    fn segments_are_minimal_and_disjoint(
        len in 1u64..2_000_000,
        raw in prop::collection::vec((0u64..2_000_000, 0u64..300_000), 1..6),
    ) {
        let ranges: Vec<PlainRange> = raw.iter()
            .map(|(s, l)| { let s = s % len; PlainRange::new(s, (s + l).min(len - 1)).unwrap() })
            .collect();
        let p = plan(&ranges, len).unwrap();
        for w in p.segments.windows(2) {
            prop_assert!(w[0].last + 1 < w[1].first, "runs must not touch: {:?}", w);
        }
        // Every planned segment holds at least one requested byte.
        for s in &p.segments {
            for seg in s.first..=s.last {
                let (a, b) = (seg * SEGMENT_SIZE, ((seg + 1) * SEGMENT_SIZE).min(len) - 1);
                prop_assert!(p.ranges.iter().any(|r| r.start <= b && r.end >= a), "segment {} unused", seg);
            }
        }
    }

    #[test]
    fn cipher_ranges_stay_inside_the_body(
        len in 1u64..5_000_000, header in 16u64..4096, s in 0u64..5_000_000, l in 0u64..1_000_000,
    ) {
        let s = s % len;
        let p = plan(&[PlainRange::new(s, (s + l).min(len - 1)).unwrap()], len).unwrap();
        for (a, b) in p.cipher_ranges(header, len) {
            prop_assert!(a >= header && a <= b);
            prop_assert!(b < header + cipher_body_len(len));
            prop_assert_eq!((a - header) % CIPHER_SEGMENT_SIZE, 0);
        }
    }
}

#[test]
fn last_segment_of_file_is_short() {
    let len = 2 * SEGMENT_SIZE + 10;
    let p = plan(&[PlainRange::new(len - 1, len - 1).unwrap()], len).unwrap();
    let (a, b) = p.cipher_ranges(100, len)[0];
    assert_eq!(a, 100 + 2 * CIPHER_SEGMENT_SIZE);
    assert_eq!(b - a + 1, NONCE_SIZE + 10 + MAC_SIZE);
    assert_eq!(b + 1, 100 + cipher_body_len(len));
}

#[test]
fn header_and_eof_with_a_region() {
    // htsget-style: BAM header, one region, the 28-byte BGZF EOF.
    let len = 10 * SEGMENT_SIZE;
    let ranges = [
        PlainRange::new(0, 999).unwrap(),
        PlainRange::new(4 * SEGMENT_SIZE + 5, 4 * SEGMENT_SIZE + 5000).unwrap(),
        PlainRange::new(len - 28, len - 1).unwrap(),
    ];
    let p = plan(&ranges, len).unwrap();
    assert_eq!(
        p.segments,
        vec![
            SegmentRange { first: 0, last: 0 },
            SegmentRange { first: 4, last: 4 },
            SegmentRange { first: 9, last: 9 },
        ]
    );
    assert_eq!(p.edit_list.len(), 6);
    assert_eq!(p.edit_list[0], 0);
}

#[test]
fn packet_layout() {
    let pk = edit_list_packet(&[5, 10]);
    assert_eq!(&pk[0..4], &1u32.to_le_bytes());
    assert_eq!(&pk[4..8], &2u32.to_le_bytes());
    assert_eq!(&pk[8..16], &5u64.to_le_bytes());
    assert_eq!(&pk[16..24], &10u64.to_le_bytes());
}

#[test]
fn errors() {
    assert!(PlainRange::new(5, 4).is_err());
    assert_eq!(plan(&[], 10), Err(RangeError::Empty));
    assert!(matches!(
        plan(&[PlainRange::new(0, 10).unwrap()], 10),
        Err(RangeError::PastEnd { .. })
    ));
}

#[test]
fn trim_cuts_server_side_output() {
    let data = file(3 * SEGMENT_SIZE as usize);
    let r = PlainRange::new(SEGMENT_SIZE + 7, 2 * SEGMENT_SIZE + 3).unwrap();
    let segs = SegmentRange { first: 1, last: 2 };
    let dec = &data[SEGMENT_SIZE as usize..];
    assert_eq!(
        trim_to_range(dec, segs, r),
        &data[r.start as usize..=r.end as usize]
    );
}
