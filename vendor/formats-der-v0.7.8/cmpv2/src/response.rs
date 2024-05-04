//! Response-related types

use alloc::vec::Vec;

use der::asn1::{Int, OctetString};
use der::Sequence;

use crate::{certified_key_pair::CertifiedKeyPair, header::CmpCertificate, status::PkiStatusInfo};

/// The `CertRepMessage` type is defined in [RFC 4210 Section 5.3.4].
///
/// ```text
///  CertRepMessage ::= SEQUENCE {
///      caPubs       [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
///                    OPTIONAL,
///      response         SEQUENCE OF CertResponse }
/// ```
///
/// [RFC 4210 Section 5.3.4]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CertRepMessage<'a> {
    #[asn1(
        context_specific = "1",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub ca_pubs: Option<Vec<CmpCertificate>>,
    pub response: Vec<CertResponse<'a>>,
}

/// CertResponses corresponds to the type that is inlined in the CertRepMessage definition for the response
/// field, as shown below:
/// ```text
///   response         SEQUENCE OF CertResponse
/// ```
pub type CertResponses<'a> = Vec<CertResponse<'a>>;

/// The `CertResponse` type is defined in [RFC 4210 Section 5.3.4].
///
/// ```text
///  CertResponse ::= SEQUENCE {
///      certReqId           INTEGER,
///      -- to match this response with the corresponding request (a value
///      -- of -1 is to be used if certReqId is not specified in the
///      -- corresponding request)
///      status              PKIStatusInfo,
///      certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
///      rspInfo             OCTET STRING        OPTIONAL
///      -- analogous to the id-regInfo-utf8Pairs string defined
///      -- for regInfo in CertReqMsg [RFC4211]
///  }
/// ```
///
/// [RFC 4210 Section 5.3.4]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CertResponse<'a> {
    pub cert_req_id: Int,
    pub status: PkiStatusInfo<'a>,
    pub certified_key_pair: Option<CertifiedKeyPair>,
    pub rsp_info: Option<OctetString>,
}
