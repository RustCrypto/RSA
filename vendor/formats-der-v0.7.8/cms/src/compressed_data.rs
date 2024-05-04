//! CompressedData-related types
use der::Sequence;
use spki::AlgorithmIdentifierOwned;

use crate::content_info::CmsVersion;
use crate::signed_data::EncapsulatedContentInfo;

/// The `CompressedData` type is defined in [RFC 3274 Section 1.1].
///
/// ```text
/// CompressedData ::= SEQUENCE {
///     version CMSVersion,
///     compressionAlgorithm CompressionAlgorithmIdentifier,
///     encapContentInfo EncapsulatedContentInfo
/// }
/// ```
///
/// [RFC 3274 Section 1.1]: https://www.rfc-editor.org/rfc/rfc3274#section-1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CompressedData {
    pub version: CmsVersion,
    pub compression_alg: AlgorithmIdentifierOwned,
    pub encap_content_info: EncapsulatedContentInfo,
}
