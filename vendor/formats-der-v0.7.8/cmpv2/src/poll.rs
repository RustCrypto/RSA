//! Polling-related types

use alloc::vec::Vec;
use der::asn1::Int;

use der::Sequence;

use crate::header::PkiFreeText;

/// The `PollReqContent` type is defined in [RFC 4210 Section 5.3.22].
///
/// ```text
///  PollReqContent ::= SEQUENCE OF SEQUENCE {
///      certReqId              INTEGER }
/// ```
///
/// [RFC 4210 Section 5.3.22]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.22
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct PollReqContent {
    pub cert_req_ids: Vec<PollReqContentId>,
}

/// The `PollReqContent` and `PollRepContent` types defined in [RFC 4210 Section 5.3.22] use an
/// INTEGER value for certificate IDs. The PollReqContentId type allows for this INTEGER type to
/// be changed.
///
/// [RFC 4210 Section 5.3.22]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.22
pub type PollReqContentId = Int;

/// The `PollRepContent` type is defined in [RFC 4210 Section 5.3.22].
///
/// ```text
///  PollRepContent ::= SEQUENCE OF SEQUENCE {
///      certReqId              INTEGER,
///      checkAfter             INTEGER,  -- time in seconds
///      reason                 PKIFreeText OPTIONAL }
/// ```
///
/// [RFC 4210 Section 5.3.22]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.22
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct PollRepContent<'a> {
    pub cert_req_id: PollReqContentId,
    pub check_after: u64,
    pub reason: Option<PkiFreeText<'a>>,
}
