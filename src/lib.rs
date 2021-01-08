//! Pure Rust implementations of static Diffie-Hellman key-exchange. 
//! It includes impls for both plain vanilla DH and elliptic-curve DH.

#![no_std]
#![deny(unsafe_code)]
#![deny(missing_docs)]

/// ECDH implementation 
pub mod ecdh;
/// DH implementation
pub mod dh;
pub mod constants;


use core::fmt;

/// The CryptoError type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {

    /// Error while performing an EC Crypto operation
    ECCError,
    /// Invalid encoding
    InvalidEncoding,

    #[doc(hidden)]
    __Nonexhaustive,
}

/// The result type for Crypto.
pub type Result<T> = core::result::Result<T, CryptoError>;

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &CryptoError::ECCError              => write!(f, "EC Crypto operation failed"),
            &CryptoError::InvalidEncoding       => write!(f, "Invalid encoding"),
            &CryptoError::__Nonexhaustive       => unreachable!(),
        }
    }   
}

impl From<p256::elliptic_curve::Error> for CryptoError {
    fn from(_error: p256::elliptic_curve::Error) -> Self {
        CryptoError::ECCError
    }
}

