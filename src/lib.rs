use std::time::SystemTime;

mod auth_header;
mod c_request;
mod keys;
mod string_to_sign;
mod util;
mod vocab;

pub use c_request::{ensure_header_order, ensure_query_order, split_url};
pub use keys::{signing_key, validate_key_id, validate_secret_key, Key};
pub use util::FormatTime;
pub use vocab::{AwsRegion, AwsService, Hash, HttpMethod, Signature};

pub fn gen_auth_header<'a>(
    buffer: &'a mut Vec<u8>,
    http_method: HttpMethod,
    abspath: &[u8],
    query: &[(&[u8], &[u8])],
    signed_headers: &[(&[u8], &[u8])],
    signing_key: &Key,
    key_id: &[u8; 20],
    region: AwsRegion,
    service: AwsService,
    request_time: SystemTime,
    key_date: SystemTime,
    payload_hash: &Hash,
) -> &'a [u8] {
    let offset = buffer.len();
    c_request::generate(
        buffer,
        http_method,
        abspath,
        query,
        signed_headers,
        payload_hash,
    );
    let c_request_hash = Hash::new(&buffer[offset..]);
    buffer.truncate(offset);
    string_to_sign::generate(
        buffer,
        request_time,
        key_date,
        region,
        service,
        &c_request_hash,
    );
    let signature = signing_key.sign(&buffer[offset..]);
    buffer.truncate(offset);
    auth_header::generate(
        buffer,
        signed_headers,
        key_date,
        region,
        service,
        key_id,
        &signature,
    );
    &buffer[offset..]
}
