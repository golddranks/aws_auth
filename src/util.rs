use std::cmp::Ordering;
use std::convert::TryInto;
use std::ops::Not;

pub mod hex;
pub mod iso8601;
pub mod url_encode;

pub use iso8601::FormatTime;

/// Checks if a slice is sorted according to a comparison function.
/// Intended only for debugging.
pub fn is_sorted_by<T>(input: &[T], cmp: impl Fn(&T, &T) -> Ordering) -> bool {
    input
        .windows(2)
        .all(|w| cmp(&w[0], &w[1]) != Ordering::Greater)
}

pub use hex::write_sha256_hex;

pub use url_encode::ordering as ord_url_encoded;

pub fn ord_ignore_case(left: &[u8], right: &[u8]) -> Ordering {
    // Compare byte by byte
    for (&lbyte, &rbyte) in left.iter().zip(right.iter()) {
        let ord = lbyte.to_ascii_lowercase().cmp(&rbyte.to_ascii_lowercase());
        if ord != Ordering::Equal {
            return ord;
        }
    }

    // The byte-by-byte comparable parts were equal; the shorter becomes first
    left.len().cmp(&right.len())
}

pub fn whitespace(c: u8) -> bool {
    c == b'\t' || c == b' ' || c == b'\n' || c == b'\r'
}

pub trait SliceExt {
    fn trim(&self) -> &Self;
    fn no_consequent_spaces(&self) -> bool;
    fn into_mut_array_40(&mut self) -> &mut [u8; 40];
    fn into_array_40(&self) -> &[u8; 40];
    fn into_mut_array_64(&mut self) -> &mut [u8; 64];
}

impl SliceExt for [u8] {
    fn trim(&self) -> &[u8] {
        if let Some(first) = self.iter().position(|b| !whitespace(*b)) {
            if let Some(last) = self.iter().rposition(|b| !whitespace(*b)) {
                &self[first..last + 1]
            } else {
                unreachable!();
            }
        } else {
            &[]
        }
    }

    fn no_consequent_spaces(&self) -> bool {
        self.windows(2)
            .any(|w| whitespace(w[0]) && whitespace(w[1]))
            .not()
    }

    // TODO: remove this once try_into supports arrays of length 40
    fn into_mut_array_40(&mut self) -> &mut [u8; 40] {
        assert!(self.len() == 40);
        let reinterpret_ptr = self as *mut [u8] as *mut [u8; 40];
        unsafe { &mut *reinterpret_ptr }
    }

    // TODO: remove this once try_into supports arrays of length 40
    fn into_array_40(&self) -> &[u8; 40] {
        assert!(self.len() == 40);
        let reinterpret_ptr = self as *const [u8] as *const [u8; 40];
        unsafe { &*reinterpret_ptr }
    }

    // TODO: remove this once try_into supports arrays of length 64
    fn into_mut_array_64(&mut self) -> &mut [u8; 64] {
        assert!(self.len() == 64);
        let reinterpret_ptr = self as *mut [u8] as *mut [u8; 64];
        unsafe { &mut *reinterpret_ptr }
    }
}

pub trait VecExt {
    fn space_for_yyyymmdd(&mut self) -> &mut [u8; 8];
    fn space_for_iso8602_basic_seconds_utc(&mut self) -> &mut [u8; 16];
    fn space_for_sha256(&mut self) -> &mut [u8; 64];
    fn push_url_encoded(&mut self, input: &[u8]) -> &mut [u8];
    fn push_url_encoded_preserve_paths(&mut self, input: &[u8]) -> &mut [u8];
    fn push_lowercase(&mut self, input: &[u8]) -> &mut [u8];
}

impl VecExt for Vec<u8> {
    fn space_for_yyyymmdd(&mut self) -> &mut [u8; 8] {
        let offset = self.len();
        self.extend_from_slice(&iso8601::YYYYMMDD);
        (&mut self[offset..]).try_into().expect("always succeeds")
    }

    fn space_for_iso8602_basic_seconds_utc(&mut self) -> &mut [u8; 16] {
        let offset = self.len();
        self.extend_from_slice(&iso8601::BASIC_FORMAT_SEC_UTC);
        (&mut self[offset..]).try_into().expect("always succeeds")
    }

    fn space_for_sha256(&mut self) -> &mut [u8; 64] {
        let offset = self.len();
        self.extend_from_slice(super::vocab::EMPTY_STR_SHA256);
        self[offset..].into_mut_array_64()
    }

    fn push_url_encoded(&mut self, input: &[u8]) -> &mut [u8] {
        let offset = self.len();
        url_encode::encode(self, input, &url_encode::URL_SAFE);
        &mut self[offset..]
    }

    fn push_url_encoded_preserve_paths(&mut self, input: &[u8]) -> &mut [u8] {
        let offset = self.len();
        url_encode::encode(self, input, &url_encode::URL_SAFE_PATH);
        &mut self[offset..]
    }

    fn push_lowercase(&mut self, input: &[u8]) -> &mut [u8] {
        let offset = self.len();
        self.extend_from_slice(input);
        for byte in &mut self[offset..] {
            u8::make_ascii_lowercase(byte);
        }
        &mut self[offset..]
    }
}

#[test]
fn test_push_lowercase() {
    let mut test_vec = "abCD123".to_owned().into_bytes();
    test_vec.push_lowercase(&b"abyz1234567890ABCXYZ\0\x01\x02\xff.-!@%^&*("[..]);
    assert_eq!(
        test_vec.as_slice(),
        &b"abCD123abyz1234567890abcxyz\0\x01\x02\xff.-!@%^&*("[..]
    );
}
