//! OOB-related types

use der::asn1::BitString;
use der::Sequence;

use crmf::controls::CertId;
use spki::AlgorithmIdentifierOwned;

use crate::header::CmpCertificate;

/// The `OOBCert` type is defined in [RFC 4210 Section 5.2.5].
///
/// ```text
///  OOBCert ::= CMPCertificate
/// ```
///
/// [RFC 4210 Section 5.2.5]: https://www.rfc-editor.org/rfc/rfc4210#section-5.2.5
pub type OobCert = CmpCertificate;

/// The `OOBCertHash` type is defined in [RFC 4210 Section 5.2.5].
///
/// ```text
///  OOBCertHash ::= SEQUENCE {
///      hashAlg     [0] AlgorithmIdentifier{DIGEST-ALGORITHM, {...}}
///                          OPTIONAL,
///      certId      [1] CertId                  OPTIONAL,
///      hashVal         BIT STRING
///  }
/// ```
///
/// [RFC 4210 Section 5.2.5]: https://www.rfc-editor.org/rfc/rfc4210#section-5.2.5
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct OobCertHash {
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub hash_alg: Option<AlgorithmIdentifierOwned>,
    #[asn1(
        context_specific = "1",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub cert_id: Option<CertId>,
    pub hash_val: BitString,
}
