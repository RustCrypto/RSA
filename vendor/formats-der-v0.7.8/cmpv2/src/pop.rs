//! POP-related types

use alloc::vec::Vec;

use der::asn1::{OctetString, UintRef};
use der::Sequence;

use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::pkix::name::GeneralName;

/// The `POPODecKeyChallContent` type is defined in [RFC 4210 Section 5.2.8.3].
///
/// ```text
///  POPODecKeyChallContent ::= SEQUENCE OF Challenge
/// ```
///
/// [RFC 4210 Section 5.2.8.3]: https://www.rfc-editor.org/rfc/rfc4210#section-5.2.8.3
pub type PopoDecKeyChallContent = Vec<Challenge>;

/// The `Challenge` type is defined in [RFC 4210 Section 5.2.8.3].
///
/// ```text
///  Challenge ::= SEQUENCE {
///      owf                 AlgorithmIdentifier{DIGEST-ALGORITHM, {...}}
///                              OPTIONAL,
///      witness             OCTET STRING,
///      challenge           OCTET STRING
///      -- the encryption (under the public key for which the cert.
///      -- request is being made) of Rand, where Rand is specified as
///      --   Rand ::= SEQUENCE {
///      --      int      INTEGER,
///      --       - the randomly-generated INTEGER A (above)
///      --      sender   GeneralName
///      --       - the sender's name (as included in PKIHeader)
///      --   }
///  }
/// ```
///
/// [RFC 4210 Section 5.2.8.3]: https://www.rfc-editor.org/rfc/rfc4210#section-5.2.8.3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct Challenge {
    pub owf: Option<AlgorithmIdentifierOwned>,
    pub witness: OctetString,
    pub challenge: OctetString,
}

/// The `Rand` type is defined as a comment in the `Challenge` definition in
/// [RFC 4210 Section 5.2.8.3].
///
/// ```text
///    Rand ::= SEQUENCE {
///        int      INTEGER,
///        sender   GeneralName
///   }
/// ```
///
/// [RFC 4210 Section 5.2.8.3]: https://www.rfc-editor.org/rfc/rfc4210#section-5.2.8.3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct Rand<'a> {
    pub integer: UintRef<'a>,
    pub sender: GeneralName,
}

/// The `POPODecKeyRespContent` type is defined in [RFC 4210 Section 5.2.8.3].
///
/// ```text
///  POPODecKeyRespContent ::= SEQUENCE OF INTEGER
///  -- One INTEGER per encryption key certification request (in the
///  -- same order as these requests appear in CertReqMessages).  The
///  -- retrieved INTEGER A (above) is returned to the sender of the
///  -- corresponding Challenge.
/// ```
///
/// [RFC 4210 Section 5.2.8.3]: https://www.rfc-editor.org/rfc/rfc4210#section-5.2.8.3
pub type PopoDecKeyRespContent<'a> = Vec<UintRef<'a>>;
