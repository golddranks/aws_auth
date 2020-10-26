use std::convert::TryInto;
use std::ops::Not;

use super::util::write_sha256_hex;

pub(super) const EMPTY_STR_SHA256: &[u8; 64] =
    b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Clone)]
pub struct Hash(pub(super) [u8; 64]); // As hex

#[derive(Copy, Clone, Debug)]
pub struct Signature(pub(super) [u8; 32]); // As bytes

impl Hash {
    pub fn new(input: &[u8]) -> Hash {
        let mut hash = Hash(*EMPTY_STR_SHA256);
        if input.is_empty().not() {
            let digest = ring::digest::digest(&ring::digest::SHA256, input);
            let digest = digest.as_ref().try_into().expect("always succeeds");
            write_sha256_hex(digest, &mut hash.0);
        }
        hash
    }

    pub fn as_hex(&self) -> &[u8; 64] {
        &self.0
    }
}

#[test]
fn test_hash_empty() {
    assert_eq!(&Hash::new(b"").as_hex()[..], &EMPTY_STR_SHA256[..]);
}

impl Signature {
    pub fn as_array(&self) -> &[u8; 32] {
        self.0.as_ref().try_into().expect("always succeeds")
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn write_hex(&self, output_buf: &mut [u8; 64]) {
        super::util::write_sha256_hex(self.as_array(), output_buf);
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

impl HttpMethod {
    pub fn to_bytes(self) -> &'static [u8] {
        use HttpMethod::*;
        match self {
            Get => b"GET",
            Post => b"POST",
            Put => b"PUT",
            Delete => b"DELETE",
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum AwsRegion {
    UsEast1,
    UsEast2,
    UsWest1,
    UsWest2,
    CaCentral1,
    EuCentral1,
    EuWest1,
    EuWest2,
    EuWest3,
    EuNorth1,
    ApEast1,
    ApNortheast1,
    ApNortheast2,
    ApNortheast3,
    ApSoutheast1,
    ApSoutheast2,
    ApSouth1,
    MeSouth1,
    SaEast1,
}
impl AwsRegion {
    pub fn to_str(self) -> &'static str {
        use AwsRegion::*;
        match self {
            UsEast1 => "us-east-1",
            UsEast2 => "us-east-2",
            UsWest1 => "us-west-1",
            UsWest2 => "us-west-2",
            CaCentral1 => "ca-central-1",
            EuCentral1 => "eu-central-1",
            EuWest1 => "eu-west-1",
            EuWest2 => "eu-west-2",
            EuWest3 => "eu-west-3",
            EuNorth1 => "eu-north-1",
            ApEast1 => "ap-east-1",
            ApNortheast1 => "ap-northeast-1",
            ApNortheast2 => "ap-northeast-2",
            ApNortheast3 => "ap-northeast-3",
            ApSoutheast1 => "ap-southeast-1",
            ApSoutheast2 => "ap-southeast-2",
            ApSouth1 => "ap-south-1",
            MeSouth1 => "me-south-1",
            SaEast1 => "sa-east-1",
        }
    }

    pub fn to_bytes(self) -> &'static [u8] {
        self.to_str().as_bytes()
    }

    pub fn try_from<S>(bytes: &S) -> Result<AwsRegion, ()>
    where
        S: AsRef<[u8]>,
    {
        use AwsRegion::*;
        Ok(match bytes.as_ref() {
            b"us-east-1" => UsEast1,
            b"us-east-2" => UsEast2,
            b"us-west-1" => UsWest1,
            b"us-west-2" => UsWest2,
            b"ca-central-1" => CaCentral1,
            b"eu-central-1" => EuCentral1,
            b"eu-west-1" => EuWest1,
            b"eu-west-2" => EuWest2,
            b"eu-west-3" => EuWest3,
            b"eu-north-1" => EuNorth1,
            b"ap-east-1" => ApEast1,
            b"ap-northeast-1" => ApNortheast1,
            b"ap-northeast-2" => ApNortheast2,
            b"ap-northeast-3" => ApNortheast3,
            b"ap-southeast-1" => ApSoutheast1,
            b"ap-southeast-2" => ApSoutheast2,
            b"ap-south-1" => ApSouth1,
            b"me-south-1" => MeSouth1,
            b"sa-east-1" => SaEast1,
            _ => return Err(()),
        })
    }
}

impl From<AwsRegion> for &'static [u8] {
    fn from(from: AwsRegion) -> &'static [u8] {
        from.to_bytes()
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum AwsService {
    S3,
    Iam,
}

impl AwsService {
    pub fn to_str(self) -> &'static str {
        use AwsService::*;
        match self {
            S3 => "s3",
            Iam => "iam",
        }
    }

    pub fn to_bytes(self) -> &'static [u8] {
        self.to_str().as_bytes()
    }
}
