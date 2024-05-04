//! DigestedData-related types
use der::{asn1::OctetString, Sequence};

use spki::AlgorithmIdentifierOwned;

use crate::content_info::CmsVersion;
use crate::signed_data::EncapsulatedContentInfo;

/// The `DigestedData` type is defined in [RFC 5652 Section 7].
///
/// ```text
///   DigestedData ::= SEQUENCE {
///       version CMSVersion,
///       digestAlgorithm DigestAlgorithmIdentifier,
///       encapContentInfo EncapsulatedContentInfo,
///       digest Digest
///   }
/// ```
///
/// [RFC 5652 Section 7]: https://www.rfc-editor.org/rfc/rfc5652#section-7
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct DigestedData {
    pub version: CmsVersion,
    pub digest_alg: AlgorithmIdentifierOwned,
    pub encap_content_info: EncapsulatedContentInfo,
    pub digest: Digest,
}

/// The `Digest` type is defined in [RFC 5652 Section 7].
///
/// ```text
///   Digest ::= OCTET STRING
/// ```
///
/// [RFC 5652 Section 7]: https://www.rfc-editor.org/rfc/rfc5652#section-7
pub type Digest = OctetString;
