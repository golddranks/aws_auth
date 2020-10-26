fn chunk_sha256(input_buf: &[u8; 32]) -> &[u32; 8] {
    let reinterpret_ptr = input_buf as *const [u8; 32] as *const [u32; 8];
    unsafe { &*reinterpret_ptr }
}

fn chunk_mut_hex_sha256(input_buf: &mut [u8; 64]) -> &mut [u64; 8] {
    let reinterpret_ptr = input_buf as *mut [u8; 64] as *mut [u64; 8];
    unsafe { &mut *reinterpret_ptr }
}

// TODO: try multiplication method: http://0x80.pl/articles/convert-to-hex.html (Split nibbles: x86 - plain)
// TODO: shift nibble mask instead of input, to save from shifting back
fn expand_nibbles(input: u32) -> u64 {
    let input = input as u64;

    const NIBBLE_MASK: u64 = 0x000000000000000f;
    let n0 = input & NIBBLE_MASK;
    let n1 = (input >> 4) & NIBBLE_MASK;
    let n2 = (input >> 8) & NIBBLE_MASK;
    let n3 = (input >> 12) & NIBBLE_MASK;
    let n4 = (input >> 16) & NIBBLE_MASK;
    let n5 = (input >> 20) & NIBBLE_MASK;
    let n6 = (input >> 24) & NIBBLE_MASK;
    let n7 = (input >> 28) & NIBBLE_MASK;

    // Note: when displayed as hexadecimal, the nibbles are displayed as big-endian
    // For example, 16 is 0x10 ('1' is the most significant nibble here, signifying 1 x 16)
    // Modern platforms are little-endian, so we need to swap the positions.
    // This is why the order of the nibble pairs here is swapped:
    n1 | (n0 << 8) | (n3 << 16) | (n2 << 24) | (n5 << 32) | (n4 << 40) | (n7 << 48) | (n6 << 56)
}
const fn packed(byte: u8) -> u64 {
    byte as u64 * 0x0101010101010101
}

fn nibbles_to_lowercase_hex(nibbles: u64) -> u64 {
    debug_assert_eq!(nibbles & 0xf0f0f0f0f0f0f0f0, 0);

    let ascii09 = nibbles + packed(b'0');
    const CORRECTION: u64 = packed(b'a' - b'0' - 10);

    let tmp = nibbles + packed(128 - 10);
    let msb = tmp & packed(0x80);
    let mask = msb - (msb >> 7);

    return ascii09 + (mask & CORRECTION);
}

pub fn nibble_to_uppercase_hex(low: u8) -> u8 {
    debug_assert_eq!(low & 0xf0, 0);

    let ascii09 = low + b'0';
    const CORRECTION: u8 = b'A' - b'0' - 10;

    let tmp = low + 128 - 10;
    let msb = tmp & 0x80;
    let mask = msb - (msb >> 7);

    return ascii09 + (mask & CORRECTION);
}

fn write_u32_lowercase_hex(input: u32) -> u64 {
    let nibbles = expand_nibbles(input);
    nibbles_to_lowercase_hex(nibbles)
}

pub fn write_sha256_hex(input_buf: &[u8; 32], output_buf: &mut [u8; 64]) {
    let io = chunk_sha256(input_buf)
        .iter()
        .zip(chunk_mut_hex_sha256(output_buf));
    for (input, output) in io {
        *output = write_u32_lowercase_hex(*input);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_nibbles() {
        assert_eq!(
            expand_nibbles(u32::from_ne_bytes([0, 1, 2, 3])).to_ne_bytes(),
            [0, 0, 0, 1, 0, 2, 0, 3]
        );
        assert_eq!(
            expand_nibbles(u32::from_ne_bytes([12, 13, 14, 15])).to_ne_bytes(),
            [0, 12, 0, 13, 0, 14, 0, 15]
        );
        assert_eq!(
            expand_nibbles(u32::from_ne_bytes([16, 17, 18, 19])).to_ne_bytes(),
            [1, 0, 1, 1, 1, 2, 1, 3]
        );
        assert_eq!(
            expand_nibbles(u32::from_ne_bytes([252, 253, 254, 255])).to_ne_bytes(),
            [15, 12, 15, 13, 15, 14, 15, 15]
        );
    }

    #[test]
    fn test_nibbles_to_hex() {
        assert_eq!(
            nibbles_to_lowercase_hex(u64::from_ne_bytes([0, 0, 1, 0, 2, 0, 3, 0])),
            u64::from_ne_bytes(*b"00102030")
        );
        assert_eq!(
            nibbles_to_lowercase_hex(u64::from_ne_bytes([12, 15, 13, 15, 14, 15, 15, 15])),
            u64::from_ne_bytes(*b"cfdfefff")
        );
        assert_eq!(nibble_to_uppercase_hex(0x01), b'1');
        assert_eq!(nibble_to_uppercase_hex(0x0f), b'F');
    }

    #[test]
    fn test_write_u32_lowercase_hex() {
        let hex = write_u32_lowercase_hex(u32::from_ne_bytes([255, 0, 0, 0]));
        assert_eq!(&hex.to_ne_bytes()[..], &b"ff000000"[..]);

        let hex = write_u32_lowercase_hex(u32::from_ne_bytes([0, 0, 0, 255]));
        assert_eq!(&hex.to_ne_bytes()[..], &b"000000ff"[..]);

        let hex = write_u32_lowercase_hex(u32::from_ne_bytes([0, 0, 0, 16]));
        assert_eq!(&hex.to_ne_bytes()[..], &b"00000010"[..]);

        let hex = write_u32_lowercase_hex(u32::from_ne_bytes(*b"\xf5\x36\x97\x5d"));
        assert_eq!(hex.to_ne_bytes(), *b"f536975d");
    }

    #[test]
    fn test_write_sha256_hex_1() {
        let mut buffer = [0u8; 64];
        write_sha256_hex(
            &[
                1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4,
                4, 4, 4, 4,
            ],
            &mut buffer,
        );
        assert_eq!(
            &buffer[..],
            &b"0101010101010101020202020202020203030303030303030404040404040404"[..]
        );
    }

    #[test]
    fn test_write_sha256_hex_2() {
        let mut buffer = [0u8; 64];
        write_sha256_hex(
            &[
                240, 240, 240, 240, 240, 240, 240, 240, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255,
                255, 255, 255, 255, 15, 15, 15, 15, 15, 15, 15, 15,
            ],
            &mut buffer,
        );
        assert_eq!(
            &buffer[..],
            &b"f0f0f0f0f0f0f0f00000000000000000ffffffffffffffff0f0f0f0f0f0f0f0f"[..]
        );
    }

    #[test]
    fn test_write_sha256_hex_3() {
        let hash = [
            255, 0, 240, 15, 6, 192, 48, 146, 20, 248, 5, 187, 144, 204, 255, 8, 146, 25, 236, 214,
            139, 37, 119, 239, 239, 35, 237, 212, 59, 126, 26, 89,
        ];
        let mut buffer = [0; 64];
        write_sha256_hex(&hash, &mut buffer);

        assert_eq!(
            &buffer[..],
            &b"ff00f00f06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"[..]
        );
    }
}
