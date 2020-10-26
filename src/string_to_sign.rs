use std::time::SystemTime;

use super::util::{FormatTime, VecExt};
use super::vocab::{AwsRegion, AwsService, Hash};

pub fn write_scope(
    buffer: &mut Vec<u8>,
    key_date: SystemTime,
    region: AwsRegion,
    service: AwsService,
) {
    // Date
    key_date.write_yyyymmdd(buffer.space_for_yyyymmdd());
    buffer.push(b'/');
    // Region
    buffer.extend_from_slice(region.to_bytes());
    buffer.push(b'/');
    // Service
    buffer.extend_from_slice(service.to_bytes());
    // Footer
    buffer.extend_from_slice(b"/aws4_request");
}

pub fn generate(
    buffer: &mut Vec<u8>,
    request_time: SystemTime,
    key_date: SystemTime,
    region: AwsRegion,
    service: AwsService,
    c_request_hash: &Hash,
) {
    // Algorithm Header
    buffer.extend_from_slice(b"AWS4-HMAC-SHA256\n");

    // ISO 8602 'Basic format' UTC Timestamp
    request_time.write_iso8602_basic_seconds_utc(buffer.space_for_iso8602_basic_seconds_utc());
    buffer.push(b'\n');

    // Scope
    // Date
    write_scope(buffer, key_date, region, service);
    buffer.push(b'\n');

    // Canonical Request Digest
    buffer.extend_from_slice(c_request_hash.as_hex());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_string_to_sign_1() {
        // An actual string to sign returned by s3 as a response to invalid request

        let mut buffer = Vec::new();
        // Timestamp: 20191010T210709Z
        let request_time = UNIX_EPOCH + Duration::from_secs(1570741629);
        let hash = Hash(*b"b70cd69b7192f41461272f430e6fabadf527080c92ba3fd93edfd7df5c0ae121");
        generate(
            &mut buffer,
            request_time,
            request_time,
            AwsRegion::ApNortheast1,
            AwsService::S3,
            &hash,
        );

        println!(
            "Generated String to Sign:\n{}",
            String::from_utf8_lossy(&buffer)
        );

        assert_eq!(
            &buffer[..],
            &b"AWS4-HMAC-SHA256
20191010T210709Z
20191010/ap-northeast-1/s3/aws4_request
b70cd69b7192f41461272f430e6fabadf527080c92ba3fd93edfd7df5c0ae121"[..]
        );
    }

    #[test]
    fn test_string_to_sign_2() {
        // Example from here
        // https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html

        let mut buffer = Vec::new();
        // Timestamp: 20150830
        let request_time = UNIX_EPOCH + Duration::from_secs(1440938160);
        let hash = Hash(*b"f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59");
        generate(
            &mut buffer,
            request_time,
            request_time,
            AwsRegion::UsEast1,
            AwsService::Iam,
            &hash,
        );

        println!(
            "Generated String to Sign:\n{}",
            String::from_utf8_lossy(&buffer)
        );

        assert_eq!(
            &buffer[..],
            &b"AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/iam/aws4_request
f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"[..]
        );
    }
}
