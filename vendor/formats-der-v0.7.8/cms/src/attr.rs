//! Attribute-related types
use der::asn1::OctetString;

use x509_cert::time::Time;

use crate::signed_data::SignerInfo;

/// The `MessageDigest` attribute is defined in [RFC 5652 Section 11.2].
///
/// ```text
///   MessageDigest ::= OCTET STRING
/// ```
///
/// [RFC 5652 Section 11.2]: https://www.rfc-editor.org/rfc/rfc5652#section-11.2
pub type MessageDigest = OctetString;

/// The `SigningTime` attribute is defined in [RFC 5652 Section 11.3].
///
/// ```text
///   SigningTime  ::= Time
/// ```
///
/// [RFC 5652 Section 11.3]: https://www.rfc-editor.org/rfc/rfc5652#section-11.3
pub type SigningTime = Time;

/// The `Countersignature` attribute is defined in [RFC 5652 Section 11.4].
///
/// ```text
///   Countersignature ::= SignerInfo
/// ```
///
/// [RFC 5652 Section 11.4]: https://www.rfc-editor.org/rfc/rfc5652#section-11.4
pub type Countersignature = SignerInfo;
