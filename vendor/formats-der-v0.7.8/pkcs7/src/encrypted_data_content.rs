//! `encrypted-data` content type [RFC 5652 § 8](https://datatracker.ietf.org/doc/html/rfc5652#section-8)

use crate::enveloped_data_content::EncryptedContentInfo;
use der::{Enumerated, Sequence};

/// Syntax version of the `encrypted-data` content type.
///
/// ```text
/// Version ::= Integer
/// ```
///
/// The only version supported by this library is `0`.
/// See [RFC 5652 § 8](https://datatracker.ietf.org/doc/html/rfc5652#section-8).
#[derive(Clone, Copy, Debug, Enumerated, Eq, PartialEq)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum Version {
    /// syntax version 0 for [EncryptedDataContent].
    V0 = 0,
}

impl From<Version> for u8 {
    fn from(version: Version) -> Self {
        version as u8
    }
}

/// Encrypted-data content type [RFC 5652 § 8](https://datatracker.ietf.org/doc/html/rfc5652#section-8)
///
/// ```text
/// EncryptedData ::= SEQUENCE {
///   version Version,
///   encryptedContentInfo EncryptedContentInfo }
/// ```
///
/// The encrypted-data content type consists of encrypted content of any
/// type. Unlike the enveloped-data content type, the encrypted-data
/// content type has neither recipients nor encrypted content-encryption
/// keys. Keys are assumed to be managed by other means.
///
/// The fields of type EncryptedData have the following meanings:
///   - [`version`](EncryptedDataContent::version) is the syntax version number.
///   - [`encrypted_content_info`](EncryptedDataContent::encrypted_content_info) is the encrypted content
///     information, as in [EncryptedContentInfo].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EncryptedDataContent<'a> {
    /// the syntax version number.
    pub version: Version,

    /// the encrypted content information.
    pub encrypted_content_info: EncryptedContentInfo<'a>,
}
