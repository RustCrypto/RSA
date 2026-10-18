//! Building blocks for the schemes in [RFC8017]:
//!
//! - OAEP and PKCS#1 v1.5 encryption encoding/decoding operate on encoded-message octet strings.
//! - EMSA-PSS and EMSA-PKCS1-v1_5 operate on encoded-message octet strings for signatures.
//! - OS2IP and I2OSP convert between octet strings and integer representatives.
//! - RSAEP/RSAVP1 use public-key arithmetic; RSADP/RSASP1 use private-key arithmetic.
//!
//! Scheme boundaries enforce encoded lengths and representative ranges. The internal infallible
//! I2OSP helpers require callers to establish that the integer fits in the requested width.
//! For secret representatives, storage precision and conversion widths must be independent of
//! the representative's value; see [`pad::i2osp_zeroizing`].
//!
//! [RFC8017]: https://www.rfc-editor.org/rfc/rfc8017.html

mod mgf;

pub(crate) mod generate;
pub(crate) mod oaep;
pub(crate) mod pad;
pub(crate) mod pkcs1v15;
pub(crate) mod pss;
pub(crate) mod rsa;
