#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
//! RSA Implementation in pure Rust.
//!
//!
//! # Usage
//!
//! Using PKCS1v15.
//! ```
//! use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme};
//! # /*
//! use rand::rngs::OsRng;
//! let mut rng = OsRng;
//! # */
//! # use rand::{SeedableRng, rngs::StdRng};
//! # let mut rng = rand::rngs::StdRng::seed_from_u64(0);
//! let bits = 2048;
//! let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
//! let public_key = RSAPublicKey::from(&private_key);
//!
//! // Encrypt
//! let data = b"hello world";
//! let padding = PaddingScheme::new_pkcs1v15_encrypt();
//! let enc_data = public_key.encrypt(&mut rng, padding, &data[..]).expect("failed to encrypt");
//! assert_ne!(&data[..], &enc_data[..]);
//!
//! // Decrypt
//! let padding = PaddingScheme::new_pkcs1v15_encrypt();
//! let dec_data = private_key.decrypt(padding, &enc_data).expect("failed to decrypt");
//! assert_eq!(&data[..], &dec_data[..]);
//! ```
//!
//! Using OAEP.
//! ```
//! use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme};
//! # /*
//! use rand::rngs::OsRng;
//! let mut rng = OsRng;
//! # */
//! # use rand::{SeedableRng, rngs::StdRng};
//! # let mut rng = rand::rngs::StdRng::seed_from_u64(0);
//!
//! let bits = 2048;
//! let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
//! let public_key = RSAPublicKey::from(&private_key);
//!
//! // Encrypt
//! let data = b"hello world";
//! let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
//! let enc_data = public_key.encrypt(&mut rng, padding, &data[..]).expect("failed to encrypt");
//! assert_ne!(&data[..], &enc_data[..]);
//!
//! // Decrypt
//! let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
//! let dec_data = private_key.decrypt(padding, &enc_data).expect("failed to decrypt");
//! assert_eq!(&data[..], &dec_data[..]);
//! ```
#![cfg_attr(not(test), no_std)]

#[cfg(not(feature = "alloc"))]
compile_error!("This crate does not yet support environments without liballoc. See https://github.com/RustCrypto/RSA/issues/51.");

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[macro_use]
extern crate lazy_static;

#[cfg(feature = "serde")]
extern crate serde_crate;

#[cfg(test)]
extern crate base64;
#[cfg(test)]
extern crate hex;
#[cfg(all(test, feature = "serde"))]
extern crate serde_test;

#[cfg(feature = "alloc")]
pub use num_bigint::BigUint;

/// Useful algorithms.
#[cfg(feature = "alloc")]
pub mod algorithms;

/// Error types.
#[cfg(feature = "alloc")]
pub mod errors;

/// Supported hash functions.
#[cfg(feature = "alloc")]
pub mod hash;

/// Supported padding schemes.
#[cfg(feature = "alloc")]
pub mod padding;

#[cfg(feature = "pem")]
pub use pem;

#[cfg(feature = "std")]
mod encode;

#[cfg(feature = "alloc")]
mod key;
#[cfg(feature = "alloc")]
mod oaep;
#[cfg(feature = "std")]
mod parse;
#[cfg(feature = "alloc")]
mod pkcs1v15;
#[cfg(feature = "alloc")]
mod pss;
#[cfg(feature = "alloc")]
mod raw;

#[cfg(feature = "std")]
pub use self::encode::{
    PrivateKeyEncoding, PrivateKeyPemEncoding, PublicKeyEncoding, PublicKeyPemEncoding,
};
#[cfg(feature = "alloc")]
pub use self::hash::Hash;
#[cfg(feature = "alloc")]
pub use self::key::{PublicKey, PublicKeyParts, RSAPrivateKey, RSAPublicKey};
#[cfg(feature = "alloc")]
pub use self::padding::PaddingScheme;

// Optionally expose internals if requested via feature-flag.

#[cfg(not(feature = "expose-internals"))]
#[cfg(feature = "alloc")]
mod internals;

/// Internal raw RSA functions.
#[cfg(feature = "expose-internals")]
#[cfg(feature = "alloc")]
pub mod internals;
