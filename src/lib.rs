#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
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

pub mod errors;
pub mod padding;
pub use key::{PublicKey, RSAPrivateKey, RSAPublicKey};
pub mod algorithms;
pub mod hash;

mod key;
mod pkcs1v15;
