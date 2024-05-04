#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

//! ## Usage
//!
//! ### Implementing `Deserialize` and `Serialize` for arrays.
//!
#![cfg_attr(feature = "alloc", doc = " ```")]
#![cfg_attr(not(feature = "alloc"), doc = " ```ignore")]
//! # use serde::{Deserialize, Deserializer, Serialize, Serializer};
//! #
//! # #[derive(Debug, PartialEq)]
//! struct SecretData([u8; 32]);
//!
//! impl<'de> Deserialize<'de> for SecretData {
//!     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//!     where
//!         D: Deserializer<'de>,
//!     {
//!         let mut buffer = [0; 32];
//!         serdect::array::deserialize_hex_or_bin(&mut buffer, deserializer)?;
//!         Ok(Self(buffer))
//!     }
//! }
//!
//! impl Serialize for SecretData {
//!     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//!     where
//!         S: Serializer,
//!     {
//!         serdect::array::serialize_hex_lower_or_bin(&self.0, serializer)
//!     }
//! }
//!
//! let data = SecretData([42; 32]);
//!
//! let serialized = bincode::serialize(&data).unwrap();
//! // bincode, a binary serialization format, is serialized into bytes.
//! assert_eq!(serialized.as_slice(), [42; 32]);
//! # let deserialized: SecretData = bincode::deserialize(&serialized).unwrap();
//! # assert_eq!(deserialized, data);
//!
//! let serialized = serde_json::to_string(&data).unwrap();
//! // JSON, a human-readable serialization format, is serialized into lower-case HEX.
//! assert_eq!(
//!     serialized,
//!     "\"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a\""
//! );
//! # let deserialized: SecretData = serde_json::from_str(&serialized).unwrap();
//! # assert_eq!(deserialized, data);
//! ```
//!
//! ### Implementing `Deserialize` and `Serialize` for slices.
//!
#![cfg_attr(feature = "alloc", doc = " ```")]
#![cfg_attr(not(feature = "alloc"), doc = " ```ignore")]
//! # use serde::{Deserialize, Deserializer, Serialize, Serializer};
//! #
//! # #[derive(Debug, PartialEq)]
//! struct SecretData(Vec<u8>);
//!
//! impl<'de> Deserialize<'de> for SecretData {
//!     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//!     where
//!         D: Deserializer<'de>,
//!     {
//!         serdect::slice::deserialize_hex_or_bin_vec(deserializer).map(Self)
//!     }
//! }
//!
//! impl Serialize for SecretData {
//!     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//!     where
//!         S: Serializer,
//!     {
//!         serdect::slice::serialize_hex_lower_or_bin(&self.0, serializer)
//!     }
//! }
//!
//! let data = SecretData(vec![42; 32]);
//!
//! let serialized = bincode::serialize(&data).unwrap();
//! // bincode, a binary serialization format is serialized into bytes.
//! assert_eq!(
//!     serialized.as_slice(),
//!     [
//!         // Not fixed-size, so a size will be encoded.
//!         32, 0, 0, 0, 0, 0, 0, 0,
//!         // Actual data.
//!         42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
//!         42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
//!     ]
//! );
//! # let deserialized: SecretData = bincode::deserialize(&serialized).unwrap();
//! # assert_eq!(deserialized, data);
//!
//! let serialized = serde_json::to_string(&data).unwrap();
//! // JSON, a human-readable serialization format is serialized into lower-case HEX.
//! assert_eq!(
//!     serialized,
//!     "\"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a\""
//! );
//! # let deserialized: SecretData = serde_json::from_str(&serialized).unwrap();
//! # assert_eq!(deserialized, data);
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod array;
pub mod slice;

pub use serde;

use serde::Serializer;

#[cfg(not(feature = "alloc"))]
use serde::ser::Error;

#[cfg(feature = "alloc")]
use serde::Serialize;

fn serialize_hex<S, T, const UPPERCASE: bool>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    #[cfg(feature = "alloc")]
    if UPPERCASE {
        return base16ct::upper::encode_string(value.as_ref()).serialize(serializer);
    } else {
        return base16ct::lower::encode_string(value.as_ref()).serialize(serializer);
    }
    #[cfg(not(feature = "alloc"))]
    {
        let _ = value;
        let _ = serializer;
        return Err(S::Error::custom(
            "serializer is human readable, which requires the `alloc` crate feature",
        ));
    }
}
