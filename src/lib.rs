//! Pure Rust implementations of static Diffie-Hellman key-exchange. 
//! It includes impls for both plain vanilla DH and elliptic-curve DH.

#![no_std]
#![deny(unsafe_code)]
#![deny(missing_docs)]

/// ECDH implementation 
pub mod ecdh;
/// DH implementation
pub mod dh;
/// A module to import Hash Types from RustCrypto
pub mod digest;
/// ECDSA implementation
pub mod signatures;
pub mod constants;


use core::fmt;

/// The CryptoError type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {

    /// Error while performing an EC Crypto operation
    ECCError,
    /// Invalid encoding
    InvalidEncoding,
    /// Signature Error
    SignatureError,

    #[doc(hidden)]
    __Nonexhaustive,
}

/// The result type for Crypto operations
pub type Result<T> = core::result::Result<T, CryptoError>;

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &CryptoError::ECCError              => write!(f, "EC Crypto operation failed"),
            &CryptoError::InvalidEncoding       => write!(f, "Invalid encoding"),
            &CryptoError::SignatureError        => write!(f, "Signature Error"),
            &CryptoError::__Nonexhaustive       => unreachable!(),
        }
    }   
}

impl From<p256::elliptic_curve::Error> for CryptoError {
    fn from(_error: p256::elliptic_curve::Error) -> Self {
        CryptoError::ECCError
    }
}

