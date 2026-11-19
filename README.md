# crypt4gh-ranges

Byte-range planning for [Crypt4GH](https://samtools.github.io/hts-specs/crypt4gh.pdf) files. Given plaintext byte ranges, it tells a server:

- which 64 KiB segments to read, and where they sit in the ciphertext;
- the **data edit list** that makes a client's Crypt4GH decryptor output exactly those bytes (Crypt4GH on the wire);
- how to cut decrypted segments down to a range (server-side decryption).

No I/O, no cryptography, no dependencies. Bring your own storage and your own Crypt4GH implementation; this crate does the arithmetic and is property-tested.

Used by [Ferrum](https://github.com/SynapticFour/Ferrum) for htsget region tickets and HTTP `Range` on encrypted DRS objects, and by Synaptic Core for Crypt4GH streaming. Design: [Ferrum `docs/HTSGET-REGIONS-DESIGN.md`](https://github.com/SynapticFour/Ferrum/blob/main/docs/HTSGET-REGIONS-DESIGN.md).

```rust
use crypt4gh_ranges::{plan, PlainRange};

let plain_len = 1 << 20;            // plaintext length from the object's metadata
let header_len = 124;               // length of the stored Crypt4GH header
let p = plan(&[PlainRange::new(70_000, 70_099)?], plain_len)?;

for (start, end) in p.cipher_ranges(header_len, plain_len) {
    // read bytes start..=end from storage and send them unchanged
}
// re-wrap the header for the requester and add an edit list packet:
let packet = crypt4gh_ranges::edit_list_packet(&p.edit_list);
# Ok::<(), crypt4gh_ranges::RangeError>(())
```

## Guarantees (tested with proptest)

- Applying the edit list to the plaintext of the planned segments yields exactly the requested ranges, merged and in order.
- Planned segment runs never overlap or touch, and every planned segment holds at least one requested byte.
- Ciphertext ranges start on segment boundaries and stay inside the body, including a short last segment.

## Licence

Apache-2.0.
