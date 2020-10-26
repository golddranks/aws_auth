use std::time::SystemTime;

use crate::c_request::write_signed_headers;
use crate::string_to_sign::write_scope;
use crate::util::VecExt;
use crate::vocab::{AwsRegion, AwsService, Signature};

pub fn generate(
    buffer: &mut Vec<u8>,
    headers: &[(&[u8], &[u8])],
    key_date: SystemTime,
    region: AwsRegion,
    service: AwsService,
    access_key_id: &[u8; 20],
    signature: &Signature,
) {
    buffer.extend_from_slice(b"AWS4-HMAC-SHA256 Credential=");
    buffer.extend_from_slice(access_key_id);
    buffer.push(b'/');
    write_scope(buffer, key_date, region, service);
    buffer.extend_from_slice(b", SignedHeaders=");
    write_signed_headers(buffer, headers);
    buffer.extend_from_slice(b", Signature=");
    let sig_buffer = buffer.space_for_sha256();
    signature.write_hex(sig_buffer);
}

#[test]
fn test_auth_header() {
    use std::time::{Duration, UNIX_EPOCH};

    let mut buffer = Vec::new();
    let headers = vec![
        (&b"content-type"[..], &[][..]),
        (&b"host"[..], &[][..]),
        (&b"x-amz-date"[..], &[][..]),
    ];
    let key_date = UNIX_EPOCH + Duration::from_secs(1440938160);
    let key_id = b"AKIDEXAMPLE000000000";
    let signature = Signature(*b"\x5d\x67\x2d\x79\xc1\x5b\x13\x16\x2d\x92\x79\xb0\x85\x5c\xfb\xa6\x78\x9a\x8e\xdb\x4c\x82\xc4\x00\xe0\x6b\x59\x24\xa6\xf2\xb5\xd7");
    generate(
        &mut buffer,
        headers.as_slice(),
        key_date,
        AwsRegion::UsEast1,
        AwsService::Iam,
        &key_id,
        &signature,
    );

    println!(
        "Generated Authorization Header:\n{}",
        String::from_utf8_lossy(&buffer)
    );

    assert_eq!(&buffer[..], &b"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE000000000/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"[..]);
}
