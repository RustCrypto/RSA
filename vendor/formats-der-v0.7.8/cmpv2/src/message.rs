//! PKIMessage type

use alloc::vec::Vec;
use der::asn1::BitString;
use der::Sequence;

use crate::body::PkiBody;
use crate::header::{CmpCertificate, PkiHeader};

/// The `PKIMessage` type is defined in [RFC 4210 Section 5.1].
///
/// ```text
/// PKIMessage ::= SEQUENCE {
///     header           PKIHeader,
///     body             PKIBody,
///     protection   [0] PKIProtection OPTIONAL,
///     extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
///     OPTIONAL }
///
/// ```
///
/// [RFC 4210 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc4210#section-5.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct PkiMessage<'a> {
    pub header: PkiHeader<'a>,
    pub body: PkiBody<'a>,
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    pub protection: Option<PkiProtection>,
    #[asn1(
        context_specific = "1",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub extra_certs: Option<Vec<CmpCertificate>>,
}

/// The `PkiMessages` type is defined in [RFC 4210 Section 5.1].
///
/// ```text
/// PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage
/// ```
///
/// [RFC 4210 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc4210#section-5.1
pub type PkiMessages<'a> = Vec<PkiMessage<'a>>;

/// The `PKIProtection` type is defined in [RFC 4210 Section 5.1.3].
///
/// ```text
///  PKIProtection ::= BIT STRING
/// ```
///
/// [RFC 4210 Section 5.1.3]: https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3
pub type PkiProtection = BitString;

/// The `ProtectedPart` type is defined in [RFC 4210 Section 5.1.3].
///
/// ```text
/// ProtectedPart ::= SEQUENCE {
///     header    PKIHeader,
///     body      PKIBody }
/// ```
///
/// [RFC 4210 Section 5.1.3]: https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ProtectedPart<'a> {
    pub header: PkiHeader<'a>,
    pub body: PkiBody<'a>,
}
