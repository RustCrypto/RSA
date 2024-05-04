//! Parameter types

use der::asn1::OctetString;
use der::Sequence;

use spki::AlgorithmIdentifierOwned;

/// The `PBMParameter` type is defined in [RFC 4210 Section 5.1.3.1].
///
/// ```text
/// PBMParameter ::= SEQUENCE {
///     salt                OCTET STRING,
///     owf                 AlgorithmIdentifier{DIGEST-ALGORITHM, {...}},
///     iterationCount      INTEGER,
///     mac                 AlgorithmIdentifier{MAC-ALGORITHM, {...}}
/// }
/// ```
///
/// [RFC 4210 Section 5.1.3.1]: https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct PbmParameter {
    pub salt: OctetString,
    pub owf: AlgorithmIdentifierOwned,
    pub iteration_count: u64,
    pub mac: AlgorithmIdentifierOwned,
}

/// The `PBMParameter` type is defined in [RFC 4210 Section 5.1.3.2].
///
/// ```text
/// DHBMParameter ::= SEQUENCE {
///     owf                 AlgorithmIdentifier{DIGEST-ALGORITHM, {...}},
///     mac                 AlgorithmIdentifier{MAC-ALGORITHM, {...}}
/// }
/// ```
///
/// [RFC 4210 Section 5.1.3.2]: https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct DhbmParameter {
    pub owf: AlgorithmIdentifierOwned,
    pub mac: AlgorithmIdentifierOwned,
}
