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
//! use rsa::{PublicKey, RSAPrivateKey, PaddingScheme};
//! use rand::rngs::OsRng;
//!
//! let mut rng = OsRng::new().expect("no secure randomness available");
//! let bits = 2048;
//! let key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
//!
//! // Encrypt
//! let data = b"hello world";
//! let enc_data = key.encrypt(&mut rng, PaddingScheme::PKCS1v15, &data[..]).expect("failed to encrypt");
//! assert_ne!(&data[..], &enc_data[..]);
//!
//! // Decrypt
//! let dec_data = key.decrypt(PaddingScheme::PKCS1v15, &enc_data).expect("failed to decrypt");
//! assert_eq!(&data[..], &dec_data[..]);
//! ```
//!

extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;
#[macro_use]
extern crate lazy_static;
extern crate byteorder;
#[macro_use]
extern crate failure;
extern crate clear_on_drop;
extern crate num_iter;
extern crate rand;
extern crate subtle;

#[cfg(feature = "serde1")]
extern crate serde;

#[cfg(test)]
extern crate base64;
#[cfg(test)]
extern crate hex;
#[cfg(all(test, feature = "serde1"))]
extern crate serde_test;
#[cfg(test)]
extern crate sha1;

pub mod algorithms;
pub mod danger;
pub mod errors;
pub mod hash;
pub mod padding;

mod key;
mod pkcs1v15;

pub use self::key::{PublicKey, RSAPrivateKey, RSAPublicKey};
pub use self::padding::PaddingScheme;
