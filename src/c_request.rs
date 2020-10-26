use std::cmp::Ordering;

use super::util::{is_sorted_by, ord_ignore_case, ord_url_encoded, whitespace, SliceExt, VecExt};
use super::vocab::{Hash, HttpMethod};

pub struct QueryIter<'a>(&'a [u8]);

impl<'a> Iterator for QueryIter<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<(&'a [u8], &'a [u8])> {
        if self.0.len() == 0 {
            return None;
        }
        let mut split = self.0.splitn(2, |&b| b == b'&');
        let param = split.next().expect("succeeds at least once");
        let remainder = split.next().unwrap_or(&[]);
        self.0 = remainder;
        let mut split = param.splitn(2, |&b| b == b'=');

        let key = split.next().expect("succeeds at least once");
        if let Some(val) = split.next() {
            Some((key, val))
        } else {
            Some((key, &[]))
        }
    }
}

// TODO: error handling
pub fn split_url(mut url: &[u8]) -> (&[u8], &[u8], QueryIter<'_>) {
    if url.starts_with(b"https://") {
        url = &url[b"https://".len()..];
    } else {
        panic!()
    }
    let split_idx = url
        .iter()
        .position(|&b| b == b'/')
        .expect("no domain/path separator");
    let domain = &url[..split_idx];
    let path = &url[split_idx..];
    let mut split = path.splitn(2, |&b| b == b'?');
    let abspath = split.next().unwrap();
    let query = split.next().unwrap_or(b"");

    (domain, abspath, QueryIter(query))
}

#[test]
fn test_split_url() {
    let (domain, abspath, query) = split_url(&b"https://data.dev.m-haihon.r-crois.jp.s3.amazonaws.com/uploads/uploaded_file/sheet/478/Jisseki.zip"[..]);
    assert_eq!(
        domain,
        &b"data.dev.m-haihon.r-crois.jp.s3.amazonaws.com"[..]
    );
    assert_eq!(
        abspath,
        &b"/uploads/uploaded_file/sheet/478/Jisseki.zip"[..]
    );
    assert_eq!(query.collect::<Vec<_>>().len(), 0);
}

pub fn ensure_query_order(slice: &mut [(&[u8], &[u8])]) {
    slice.sort_by(|(key_a, _), (key_b, _)| ord_url_encoded(key_a, key_b))
}

pub fn ensure_header_order(slice: &mut [(&[u8], &[u8])]) {
    slice.sort_by(|(key_a, _), (key_b, _)| ord_ignore_case(key_a, key_b))
}

pub fn write_signed_headers(buffer: &mut Vec<u8>, headers: &[(&[u8], &[u8])]) {
    // Check that the required headers are set
    debug_assert!(headers
        .iter()
        .any(|(key, _)| ord_ignore_case(key, b"host") == Ordering::Equal));
    /*    debug_assert!(headers
    .iter()
    .any(|(key, _)| ord_ignore_case(key, b"x-amz-content-sha256") == Ordering::Equal));*/
    debug_assert!(headers
        .iter()
        .any(|(key, _)| ord_ignore_case(key, b"x-amz-date") == Ordering::Equal));
    // Check that the headers are in correct order
    debug_assert!(is_sorted_by(headers, |(lkey, _), (rkey, _)| {
        ord_ignore_case(lkey, rkey)
    }));
    // Check that the headers don't contain consequent spaces and are trimmed
    debug_assert!(headers.iter().all(|(h, _)| h.no_consequent_spaces()));
    debug_assert!(headers
        .iter()
        .all(|(h, _)| !whitespace(h[0]) && !whitespace(h[h.len() - 1])));

    for (key, _) in headers {
        buffer.push_lowercase(key);
        buffer.push(b';');
    }
    if headers.len() > 0 {
        let _ = buffer.pop(); // Popping off the last '&'
    }
}

// TODO: try to input to hash function directly and compare performance
pub fn generate(
    buffer: &mut Vec<u8>,
    http_method: HttpMethod,
    abspath: &[u8],
    query: &[(&[u8], &[u8])],
    headers: &[(&[u8], &[u8])],
    payload_hash: &Hash,
) {
    // HTTP Verb
    buffer.extend_from_slice(http_method.to_bytes());
    buffer.push(b'\n');

    // Canonical URI
    buffer.push_url_encoded_preserve_paths(abspath);
    buffer.push(b'\n');

    // Canonical Query String
    debug_assert!(is_sorted_by(query, |(lkey, _), (rkey, _)| ord_url_encoded(
        lkey, rkey
    )));

    for (key, val) in query {
        buffer.push_url_encoded(key);
        buffer.push(b'=');
        buffer.push_url_encoded(val);
        buffer.push(b'&');
    }
    if query.len() > 0 {
        let _ = buffer.pop(); // Popping off the last '&'
    }
    buffer.push(b'\n');

    // Canonical Headers
    for (key, val) in headers {
        buffer.push_lowercase(key);
        buffer.push(b':');
        buffer.extend_from_slice(val);
        buffer.push(b'\n');
    }
    buffer.push(b'\n');

    // Signed Headers
    write_signed_headers(buffer, headers);
    buffer.push(b'\n');

    // Hashed Payload
    buffer.extend_from_slice(payload_hash.as_hex());
}

#[test]
fn test_generate_c_request() {
    let mut buffer = Vec::new();
    let hash = Hash::new(&b""[..]);

    assert_eq!(
        &hash.as_hex()[..],
        &b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"[..]
    );

    let signed_headers = vec![
        (
            &b"host"[..],
            &b"data.dev.m-haihon.r-crois.jp.s3.amazonaws.com"[..],
        ),
        (&b"x-amz-content-sha256"[..], hash.as_hex()),
        (&b"x-amz-date"[..], &b"20191010T210709Z"[..]),
    ];

    generate(
        &mut buffer,
        HttpMethod::Get,
        b"/uploads/uploaded_file/sheet/478/Jisseki.zip",
        &[],
        &signed_headers,
        &hash,
    );

    println!("Canonical Request:\n{}", String::from_utf8_lossy(&buffer));
    println!(
        "Canonical Request Hash:\n{}",
        String::from_utf8_lossy(&hash.as_hex()[..])
    );

    assert_eq!(
        &buffer[..],
        &b"GET
/uploads/uploaded_file/sheet/478/Jisseki.zip

host:data.dev.m-haihon.r-crois.jp.s3.amazonaws.com
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date:20191010T210709Z

host;x-amz-content-sha256;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"[..]
    );

    let hash = Hash::new(&buffer);
    assert_eq!(
        &hash.as_hex()[..],
        &b"b70cd69b7192f41461272f430e6fabadf527080c92ba3fd93edfd7df5c0ae121"[..]
    );
}

#[test]
fn test_hashing_c_request() {
    let c_request = &b"GET
/
Action=ListUsers&Version=2010-05-08
content-type:application/x-www-form-urlencoded; charset=utf-8
host:iam.amazonaws.com
x-amz-date:20150830T123600Z

content-type;host;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"[..];
    let hash = Hash::new(c_request);

    assert_eq!(
        &hash.as_hex()[..],
        &b"f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"[..]
    );
}
