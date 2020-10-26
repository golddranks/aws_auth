use std::cmp::Ordering;
use std::ops::Not;

use super::hex;

type AsciiChart = [u32; 4];
const BITS_PER_ROW: usize = 32;

pub const URL_SAFE: AsciiChart = [
    0b_00000000000000000000000000000000, // Control characters
    0b_00000000000001101111111111000000, // Symbols and numbers (contains . and -)
    0b_01111111111111111111111111100001, // Uppercase alphabet (contains _)
    0b_01111111111111111111111111100010, // Lowercase alphabet (contains ~)
];

pub const URL_SAFE_PATH: AsciiChart = [
    0b_00000000000000000000000000000000, // Control characters
    0b_00000000000001111111111111000000, // Symbols and numbers (contains . - and /)
    0b_01111111111111111111111111100001, // Uppercase alphabet (contains _)
    0b_01111111111111111111111111100010, // Lowercase alphabet (contains ~)
];

const LEFTMOST_BIT: u32 = 0b_10000000000000000000000000000000;

const fn not_safe(chart: &AsciiChart, byte: u8) -> bool {
    let row = chart[byte as usize / BITS_PER_ROW];
    let mask = LEFTMOST_BIT >> (byte as usize % BITS_PER_ROW);
    (row & mask) == 0
}

fn should_encode(chart: &AsciiChart, byte: u8) -> bool {
    byte.is_ascii().not() || not_safe(chart, byte)
}

pub fn encode(buffer: &mut Vec<u8>, input: &[u8], chart: &AsciiChart) {
    let mut streak_start = 0;
    for (i, &byte) in input.iter().enumerate() {
        if should_encode(chart, byte) {
            buffer.extend_from_slice(&input[streak_start..i]);
            buffer.push(b'%');
            buffer.push(hex::nibble_to_uppercase_hex(byte >> 4));
            buffer.push(hex::nibble_to_uppercase_hex(byte & 0x0f));
            streak_start = i + 1;
        }
    }
    buffer.extend_from_slice(&input[streak_start..]);
}

pub fn ordering(left: &&[u8], right: &&[u8]) -> Ordering {
    let chart = &URL_SAFE;

    // Compare byte by byte
    for (&lbyte, &rbyte) in left.iter().zip(right.iter()) {
        let ord = match (should_encode(chart, lbyte), should_encode(chart, rbyte)) {
            (false, false) => lbyte.cmp(&rbyte),
            (false, true) => lbyte.cmp(&b'%'), // Note: any non-encoded is greater than %
            (true, false) => b'%'.cmp(&rbyte), // Note: % is less than any non-encoded
            (true, true) => lbyte.cmp(&rbyte),
        };

        // Early return if difference is found
        if ord != Ordering::Equal {
            return ord;
        }
    }

    // The byte-by-byte comparable parts were equal; the shorter becomes first
    left.len().cmp(&right.len())
}

#[test]
fn test_encode_path() {
    let mut buffer = Vec::new();
    encode(
        &mut buffer,
        b"/uploads/uploaded_file/sheet/478/Jisseki.zip",
        &URL_SAFE_PATH,
    );
}

#[test]
fn test_safe_or_not() {
    assert!(not_safe(&URL_SAFE, b'!'));
    assert!(not_safe(&URL_SAFE, b'/'));
    assert!(not_safe(&URL_SAFE, b'\0'));
    assert!(not_safe(&URL_SAFE, b':'));
    assert!(not_safe(&URL_SAFE, b' '));
    assert!(not_safe(&URL_SAFE, b'@'));
    assert!(not_safe(&URL_SAFE, b'['));
    assert!(not_safe(&URL_SAFE, b'`'));
    assert!(not_safe(&URL_SAFE, b'{'));
    assert!(!not_safe(&URL_SAFE, b'a'));
    assert!(!not_safe(&URL_SAFE, b'A'));
    assert!(!not_safe(&URL_SAFE, b'0'));
    assert!(!not_safe(&URL_SAFE, b'1'));
    assert!(!not_safe(&URL_SAFE, b'9'));
    assert!(!not_safe(&URL_SAFE, b'z'));
    assert!(!not_safe(&URL_SAFE, b'Z'));
    assert!(!not_safe(&URL_SAFE, b'_'));
    assert!(!not_safe(&URL_SAFE, b'.'));
    assert!(!not_safe(&URL_SAFE, b'-'));
    assert!(!not_safe(&URL_SAFE, b'~'));
}
