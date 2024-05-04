//! Registration Info-related types

use der::asn1::Utf8StringRef;

use crate::request::CertRequest;

/// The `PrivateKeyInfo` type is defined in [RFC 4211 Section 7.1].
///
/// ```text
///   UTF8Pairs ::= UTF8String
/// ```
///
/// [RFC 4211 Section 7.1]: https://www.rfc-editor.org/rfc/rfc4211#section-7.1
pub type Utf8Pairs<'a> = Utf8StringRef<'a>;

/// The `PrivateKeyInfo` type is defined in [RFC 4211 Section 7.2].
///
/// ```text
///   CertReq ::= CertRequest
/// ```
///
/// [RFC 4211 Section 7.2]: https://www.rfc-editor.org/rfc/rfc4211#section-7.2
pub type CertReq = CertRequest;
