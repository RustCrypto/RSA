#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "getrandom", doc = include_str!("../README.md"))] // example needs `getrandom`
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]

//! # Supported algorithms
//!
//! This crate supports several schemes described in [RFC8017]:
//!
//! - [OAEP encryption scheme](#oaep-encryption)
//! - [PKCS#1 v1.5 encryption scheme](#pkcs1-v15-encryption)
//! - [PKCS#1 v1.5 signature scheme](#pkcs1-v15-signatures)
//! - [PSS signature scheme](#pss-signatures)
//!
//! These schemes are described below.
//!
//! # Usage
//!
//! [`PublicKey`] and [`PrivateKey`] provide algorithm-specific methods for
//! encryption, decryption, signing, and verification. Signing and verification
//! methods hash the message; their `_prehash` counterparts accept a digest instead.
//!
//! Methods ending in `_with_rng` accept a caller-provided [`rand_core::TryCryptoRng`].
//! With the default `getrandom` feature, encryption, decryption, and signing methods
//! without an RNG argument use the operating system RNG. Without that feature,
//! encryption and PSS signing require `_with_rng`; decryption and PKCS#1 v1.5
//! signing remain available without blinding.
//!
//! The algorithm-specific key types in [`oaep`], `pkcs1v15`, and [`pss`] also
//! implement encryption and signature traits. Use these types for configurable
//! OAEP labels and MGF1 digests, PSS salt lengths, or unprefixed PKCS#1 v1.5 signatures.
//! PKCS#1 v1.5 methods and key types require the `pkcs1v15` feature.
//!
//! ## Key generation
//!
//! [`Generate`] creates 3072-bit RSA keys with public exponent 65537. This targets an estimated
//! 128-bit security strength; see [`PrivateKey::DEFAULT_BITS`] for the rationale. Use
//! [`PrivateKey::new`] to select a different key size.
//!
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! use rsa::{Generate, PrivateKey};
//!
//! let private_key = PrivateKey::generate();
//! ```
//!
//! With the `getrandom` feature (enabled by default), `Generate::generate` and
//! `Generate::try_generate` use the operating system RNG. Use `Generate::generate_from_rng`
//! or `Generate::try_generate_from_rng` to supply an RNG explicitly.
//!
//! ## OAEP encryption
//!
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! # fn main() -> Result<(), rsa::Error> {
//! use rsa::{Generate, PrivateKey, sha2::Sha256};
//!
//! let private_key = PrivateKey::generate();
//! let public_key = private_key.to_public_key();
//!
//! // Encrypt
//! let data = b"hello world";
//! let enc_data = public_key.oaep_encrypt::<Sha256>(data)?;
//! assert_ne!(&data[..], &enc_data[..]);
//!
//! // Decrypt
//! let dec_data = private_key.oaep_decrypt::<Sha256>(&enc_data)?;
//! assert_eq!(&data[..], &dec_data[..]);
//! # Ok(())
//! # }
//! ```
//!
//! ## PKCS#1 v1.5 encryption
//!
//! <div class="warning">
//! <b>Warning:</b>
//! PKCS#1 v1.5 encryption is deprecated due to security concerns. See security notes in the
//! <code><a href="./pkcs1v15/index.html">pkcs1v15</a></code> module.
//! </div>
//!
#![cfg_attr(all(feature = "getrandom", feature = "pkcs1v15"), doc = "```")]
#![cfg_attr(
    not(all(feature = "getrandom", feature = "pkcs1v15")),
    doc = "```ignore"
)]
//! # fn main() -> Result<(), rsa::Error> {
//! use rsa::{Generate, PrivateKey};
//!
//! let private_key = PrivateKey::generate();
//! let public_key = private_key.to_public_key();
//!
//! // Encrypt
//! let data = b"hello world";
//! let enc_data = public_key.pkcs1v15_encrypt(data)?;
//! assert_ne!(&data[..], &enc_data[..]);
//!
//! // Decrypt
//! let dec_data = private_key.pkcs1v15_decrypt(&enc_data)?;
//! assert_eq!(&data[..], &dec_data[..]);
//! # Ok(())
//! # }
//! ```
//!
//! ## PKCS#1 v1.5 signatures
//!
//! <div class="warning">
//! <b>Warning:</b>
//! See security notes in the <code><a href="./pkcs1v15/index.html">pkcs1v15</a></code> module.
//! </div>
//!
#![cfg_attr(all(feature = "getrandom", feature = "pkcs1v15"), doc = "```")]
#![cfg_attr(
    not(all(feature = "getrandom", feature = "pkcs1v15")),
    doc = "```ignore"
)]
//! # fn main() -> Result<(), rsa::Error> {
//! use rsa::{Generate, PrivateKey, sha2::Sha256};
//!
//! let private_key = PrivateKey::generate();
//! let public_key = private_key.to_public_key();
//!
//! // Sign
//! let data = b"hello world";
//! let signature = private_key.pkcs1v15_sign::<Sha256>(data)?;
//!
//! // Verify
//! public_key.pkcs1v15_verify::<Sha256>(data, &signature)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## PSS signatures
//!
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! # fn main() -> Result<(), rsa::Error> {
//! use rsa::{Generate, PrivateKey, sha2::Sha256};
//!
//! let private_key = PrivateKey::generate();
//! let public_key = private_key.to_public_key();
//!
//! // Sign
//! let data = b"hello world";
//! let signature = private_key.pss_sign::<Sha256>(data)?;
//!
//! // Verify
//! public_key.pss_verify::<Sha256>(data, &signature)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## PKCS#1 RSA Key Encoding
//!
//! PKCS#1 supports a legacy format for encoding RSA keys as binary (DER) or
//! text (PEM) data.
//!
//! You can recognize PEM encoded PKCS#1 keys because they have "RSA * KEY" in
//! the type label, e.g.:
//!
//! ```text
//! -----BEGIN RSA PRIVATE KEY-----
//! ```
//!
//! Most modern applications use the newer PKCS#8 format instead (see below).
//!
//! The following traits can be used to decode/encode [`PrivateKey`] and
//! [`PublicKey`] as PKCS#1. Note that [`pkcs1`] is re-exported from the
//! toplevel of the `rsa` crate:
//!
//! - [`pkcs1::DecodeRsaPrivateKey`]: decode RSA private keys from PKCS#1
//! - [`pkcs1::EncodeRsaPrivateKey`]: encode RSA private keys to PKCS#1
//! - [`pkcs1::DecodeRsaPublicKey`]: decode RSA public keys from PKCS#1
//! - [`pkcs1::EncodeRsaPublicKey`]: encode RSA public keys to PKCS#1
//!
//! ### Example
//!
#![cfg_attr(feature = "encoding", doc = "```")]
#![cfg_attr(not(feature = "encoding"), doc = "```ignore")]
//! # fn main() -> Result<(), rsa::Error> {
//! use rsa::{PublicKey, pkcs1::DecodeRsaPublicKey};
//!
//! let pem = "-----BEGIN RSA PUBLIC KEY-----
//! MIIBCgKCAQEAtsQsUV8QpqrygsY+2+JCQ6Fw8/omM71IM2N/R8pPbzbgOl0p78MZ
//! GsgPOQ2HSznjD0FPzsH8oO2B5Uftws04LHb2HJAYlz25+lN5cqfHAfa3fgmC38Ff
//! wBkn7l582UtPWZ/wcBOnyCgb3yLcvJrXyrt8QxHJgvWO23ITrUVYszImbXQ67YGS
//! 0YhMrbixRzmo2tpm3JcIBtnHrEUMsT0NfFdfsZhTT8YbxBvA8FdODgEwx7u/vf3J
//! 9qbi4+Kv8cvqyJuleIRSjVXPsIMnoejIn04APPKIjpMyQdnWlby7rNyQtE4+CV+j
//! cFjqJbE/Xilcvqxt6DirjFCvYeKYl1uHLwIDAQAB
//! -----END RSA PUBLIC KEY-----";
//!
//! let public_key = PublicKey::from_pkcs1_pem(pem)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## PKCS#8 RSA Key Encoding
//!
//! PKCS#8 is a private key format with support for multiple algorithms.
//! Like PKCS#1, it can be encoded as binary (DER) or text (PEM).
//!
//! You can recognize PEM encoded PKCS#8 keys because they *don't* have
//! an algorithm name in the type label, e.g.:
//!
//! ```text
//! -----BEGIN PRIVATE KEY-----
//! ```
//!
//! The following traits can be used to decode/encode [`PrivateKey`] and
//! [`PublicKey`] as PKCS#8. Note that [`pkcs8`] is re-exported from the
//! toplevel of the `rsa` crate:
//!
//! - [`pkcs8::DecodePrivateKey`]: decode private keys from PKCS#8
//! - [`pkcs8::EncodePrivateKey`]: encode private keys to PKCS#8
//! - [`pkcs8::DecodePublicKey`]: decode public keys from PKCS#8
//! - [`pkcs8::EncodePublicKey`]: encode public keys to PKCS#8
//!
//! ### Example
//!
#![cfg_attr(feature = "encoding", doc = "```")]
#![cfg_attr(not(feature = "encoding"), doc = "```ignore")]
//! # fn main() -> Result<(), rsa::pkcs8::Error> {
//! use rsa::{PublicKey, pkcs8::DecodePublicKey};
//!
//! let pem = "-----BEGIN PUBLIC KEY-----
//! MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtsQsUV8QpqrygsY+2+JC
//! Q6Fw8/omM71IM2N/R8pPbzbgOl0p78MZGsgPOQ2HSznjD0FPzsH8oO2B5Uftws04
//! LHb2HJAYlz25+lN5cqfHAfa3fgmC38FfwBkn7l582UtPWZ/wcBOnyCgb3yLcvJrX
//! yrt8QxHJgvWO23ITrUVYszImbXQ67YGS0YhMrbixRzmo2tpm3JcIBtnHrEUMsT0N
//! fFdfsZhTT8YbxBvA8FdODgEwx7u/vf3J9qbi4+Kv8cvqyJuleIRSjVXPsIMnoejI
//! n04APPKIjpMyQdnWlby7rNyQtE4+CV+jcFjqJbE/Xilcvqxt6DirjFCvYeKYl1uH
//! LwIDAQAB
//! -----END PUBLIC KEY-----";
//!
//! let public_key = PublicKey::from_public_key_pem(pem)?;
//! # Ok(())
//! # }
//! ```
//!
//! [RFC8017]: https://www.rfc-editor.org/rfc/rfc8017.html
//!
// TODO(tarcieri): figure out why rustdoc isn't rendering these links correctly
//! [`pkcs8::DecodePublicKey`]: https://docs.rs/pkcs8/latest/pkcs8/trait.DecodePublicKey.html
//! [`pkcs8::EncodePublicKey`]: https://docs.rs/pkcs8/latest/pkcs8/trait.EncodePublicKey.html

#[cfg(doctest)]
pub struct ReadmeDoctests;

#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub use crypto_bigint::BoxedUint;
pub use crypto_common::Generate;
pub use rand_core;
pub use signature;

mod algorithms;
pub mod errors;
pub mod oaep;
pub mod pss;
pub mod traits;

#[cfg(feature = "pkcs1v15")]
pub mod pkcs1v15;

#[cfg(not(feature = "getrandom"))]
mod dummy_rng;
mod encoding;
mod private_key;
mod public_key;

#[cfg(feature = "encoding")]
pub use pkcs1;
#[cfg(feature = "encoding")]
pub use pkcs8;
pub use sha2;

pub use crate::{
    errors::{Error, Result},
    oaep::Oaep,
    private_key::PrivateKey,
    pss::Pss,
    public_key::PublicKey,
    traits::keys::CrtValue,
};

#[cfg(feature = "pkcs1v15")]
pub use crate::pkcs1v15::{Pkcs1v15Encrypt, Pkcs1v15Sign};

#[cfg(feature = "hazmat")]
pub mod hazmat;

/// Deprecated alias for [`PrivateKey`].
#[deprecated(since = "0.10.0", note = "use `rsa::PrivateKey` instead")]
pub type RsaPrivateKey = PrivateKey;

/// Deprecated alias for [`PublicKey`].
#[deprecated(since = "0.10.0", note = "use `rsa::PublicKey` instead")]
pub type RsaPublicKey = PublicKey;
