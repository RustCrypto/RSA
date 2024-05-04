#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

//! # `p7b` support
//!
//! This crate can be used to convert an X.509 certificate into a certs-only
//! [`signed_data::SignedData`] message, a.k.a `.p7b` file.
//!
//! Use a [`TryFrom`] conversion between [`cert::x509::Certificate`] and
//! [`content_info::ContentInfo`] to generate the data structures, then use
//! `to_der` to serialize it.

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod attr;
pub mod authenticated_data;
pub mod builder;
pub mod cert;
pub mod compressed_data;
pub mod content_info;
pub mod digested_data;
pub mod encrypted_data;
pub mod enveloped_data;
pub mod revocation;
pub mod signed_data;
