#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
//! RSA Implementation in pure Rust.
//!
//!
//! # Usage
//!
//! ```
//! extern crate rsa;
//! extern crate rand;
//!
//! use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme};
//! use rand::rngs::OsRng;
//!
//! let mut rng = OsRng;
//! let bits = 2048;
//! let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
//! let public_key = RSAPublicKey::from(&private_key);
//!
//! // Encrypt
//! let data = b"hello world";
//! let enc_data = public_key.encrypt(&mut rng, PaddingScheme::PKCS1v15, &data[..]).expect("failed to encrypt");
//! assert_ne!(&data[..], &enc_data[..]);
//!
//! // Decrypt
//! let dec_data = private_key.decrypt(PaddingScheme::PKCS1v15, &enc_data).expect("failed to decrypt");
//! assert_eq!(&data[..], &dec_data[..]);
//! ```
//!

#[macro_use]
extern crate lazy_static;

extern crate num_iter;
extern crate rand;
extern crate subtle;
extern crate zeroize;

#[cfg(feature = "serde")]
extern crate serde_crate;

#[cfg(test)]
extern crate base64;
#[cfg(test)]
extern crate hex;
#[cfg(all(test, feature = "serde"))]
extern crate serde_test;

pub use num_bigint::BigUint;

/// Useful algorithms.
pub mod algorithms;

/// Error types.
pub mod errors;

/// Supported hash functions.
pub mod hash;

/// Supported padding schemes.
pub mod padding;

#[cfg(feature = "pem")]
pub use pem;

mod encode;
mod key;
mod parse;
mod pkcs1v15;
mod raw;

pub use self::encode::{
    PrivateKeyEncoding, PrivateKeyPemEncoding, PublicKeyEncoding, PublicKeyPemEncoding,
};
pub use self::key::{PublicKey, RSAPrivateKey, RSAPublicKey};
pub use self::padding::PaddingScheme;

// Optionally expose internals if requested via feature-flag.

#[cfg(not(feature = "expose-internals"))]
mod internals;

/// Internal raw RSA functions.
#[cfg(feature = "expose-internals")]
pub mod internals;
