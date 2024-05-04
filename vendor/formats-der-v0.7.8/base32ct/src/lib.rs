//! Pure Rust implementation of Base32 ([RFC 4648]).
//!
//! Implements Base32 variants without data-dependent branches
//! or lookup  tables, thereby providing portable "best effort" constant-time
//! operation. Not constant-time with respect to message length (only data).
//!
//! Supports `no_std` environments and avoids heap allocations in the core API
//! (but also provides optional `alloc` support for convenience).
//!
//! Adapted from: <https://github.com/paragonie/constant_time_encoding/blob/master/src/Base32.php>
//!
//! [RFC 4648]: https://tools.ietf.org/html/rfc4648

// Copyright (c) 2016 - 2018 Paragon Initiative Enterprises.
// Copyright (c) 2014 Steve "Sc00bz" Thomas (steve at tobtu dot com).
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod alphabet;
mod encoding;
mod error;

pub use crate::{
    alphabet::rfc4648::{Base32, Base32Unpadded, Base32Upper},
    encoding::Encoding,
    error::{Error, Result},
};
