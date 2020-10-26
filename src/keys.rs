use std::convert::TryInto;
use std::time::SystemTime;

use crate::util::{FormatTime, SliceExt};
use crate::vocab::{AwsRegion, AwsService, Signature};

#[derive(Clone, Debug)]
pub struct Key(pub(crate) ring::hmac::Key);

impl Key {
    pub fn new(secret: &[u8]) -> Key {
        Key(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret))
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut signature = Signature([0; 32]);
        let hmac = ring::hmac::sign(&self.0, message);
        signature.0.copy_from_slice(hmac.as_ref());
        signature
    }
}

fn signing_key_secret(
    secret_access_key: &[u8; 40],
    key_date: SystemTime,
    key_region: AwsRegion,
    service: AwsService,
) -> Signature {
    let mut key_buf = *b"AWS40000000000000000000000000000000000000000";
    let key_secret = &mut key_buf[4..];
    key_secret.copy_from_slice(secret_access_key);
    let mut date_buf = *b"00000000";
    key_date.write_yyyymmdd(&mut date_buf);
    let key = Key::new(&key_buf[..]);
    let date_key = Key::new(key.sign(&mut date_buf).as_bytes());
    let date_region_key = Key::new(date_key.sign(key_region.to_bytes()).as_bytes());
    let date_region_service_key = Key::new(date_region_key.sign(service.to_bytes()).as_bytes());
    date_region_service_key.sign(b"aws4_request")
}

pub fn signing_key(
    secret_access_key: &[u8; 40],
    key_date: SystemTime,
    key_region: AwsRegion,
    service: AwsService,
) -> Key {
    let key_secret = signing_key_secret(secret_access_key, key_date, key_region, service);
    Key::new(key_secret.as_bytes())
}

pub fn validate_secret_key<S>(key: &S) -> Result<&[u8; 40], ()>
where
    S: AsRef<[u8]>,
{
    let key = key.as_ref();
    if key.len() == 40 {
        Ok(key.into_array_40())
    } else {
        Err(())
    }
}

pub fn validate_key_id<S>(key: &S) -> Result<&[u8; 20], ()>
where
    S: AsRef<[u8]>,
{
    key.as_ref().try_into().map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_generation() {
        // Example from: https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
        let secret = b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        // Date: 20150830
        let key_date = UNIX_EPOCH + Duration::from_secs(1440938160);
        let key_secret = signing_key_secret(secret, key_date, AwsRegion::UsEast1, AwsService::Iam);
        let mut key_secret_buf = [0; 64];
        key_secret.write_hex(&mut key_secret_buf);
        assert_eq!(
            &key_secret_buf[..],
            &b"c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"[..]
        );
    }

    #[test]
    fn test_signing() {
        // Example from: https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
        let test_key = Key::new(b"\xc4\xaf\xb1\xcc\x57\x71\xd8\x71\x76\x3a\x39\x3e\x44\xb7\x03\x57\x1b\x55\xcc\x28\x42\x4d\x1a\x5e\x86\xda\x6e\xd3\xc1\x54\xa4\xb9");
        let signature = test_key.sign(
            &b"AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/iam/aws4_request
f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"[..],
        );
        let mut signature_buf = [0; 64];
        signature.write_hex(&mut signature_buf);
        assert_eq!(
            &signature_buf[..],
            &b"5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"[..]
        );
    }
}
