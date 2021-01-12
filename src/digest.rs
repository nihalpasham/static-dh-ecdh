// #![allow(warnings)]

use sha2::{Sha256, Sha384, Digest};

use core::convert::TryInto;


/// A struct representing a SHA256 Digest instance
pub struct SHA256Digest;

impl SHA256Digest {
    /// Computes the SHA256 digest of a slice of bytes. 
    pub fn digest(&self, data: &[u8]) -> [u8; 32] {
        let sha256: [u8; 32] = Sha256::digest(data).as_slice().try_into().unwrap();
        sha256
    }

    /// Returns the length of SHA256 Digest
    pub fn get_length() -> u8 {
        0x20
    }

    /// Returns the Hash algorithm id. This is used to identify the hashing algorithm in HIPv2
    pub fn get_alg_id() -> u8 {
        0x1
    }
}

/// A struct representing a SHA384 Digest instance
pub struct SHA384Digest;

impl SHA384Digest {
    /// Computes the SHA384 digest of a slice of bytes. 
    pub fn digest(&self, data: &[u8]) -> [u8; 48] {
        let sha384: [u8; 48] = Sha384::digest(data).as_slice().try_into().unwrap();
        sha384
    }

    /// Returns the length of SHA384 Digest
    pub fn get_length(&self) -> u8 {
        0x30
    }

    /// Returns the Hash algorithm id. This is used to identify the hashing algorithm in HIPv2
    pub fn get_alg_id() -> u8 {
        0x2
    }
}
