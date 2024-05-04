//! PKIBody type

use der::asn1::Null;
use der::Choice;

use crmf::request::CertReqMessages;
use x509_cert::request::CertReq;

use crate::ann::{CaKeyUpdAnnContent, CertAnnContent, CrlAnnContent, RevAnnContent};
use crate::certified_key_pair::KeyRecRepContent;
use crate::gen::{GenMsgContent, GenRepContent};
use crate::message::PkiMessages;
use crate::poll::PollRepContent;
use crate::pop::{PopoDecKeyChallContent, PopoDecKeyRespContent};
use crate::response::CertRepMessage;
use crate::rev::{RevRepContent, RevReqContent};
use crate::status::{CertConfirmContent, ErrorMsgContent};

/// The `PKIBody` type is defined in [RFC 4210 Section 5.1.2]
///
/// ```text
/// PKIBody ::= CHOICE {       -- message-specific body elements
///     ir       [0]  CertReqMessages,        --Initialization Request
///     ip       [1]  CertRepMessage,         --Initialization Response
///     cr       [2]  CertReqMessages,        --Certification Request
///     cp       [3]  CertRepMessage,         --Certification Response
///     p10cr    [4]  CertificationRequest,   --imported from [PKCS10]
///     popdecc  [5]  POPODecKeyChallContent, --pop Challenge
///     popdecr  [6]  POPODecKeyRespContent,  --pop Response
///     kur      [7]  CertReqMessages,        --Key Update Request
///     kup      [8]  CertRepMessage,         --Key Update Response
///     krr      [9]  CertReqMessages,        --Key Recovery Request
///     krp      [10] KeyRecRepContent,       --Key Recovery Response
///     rr       [11] RevReqContent,          --Revocation Request
///     rp       [12] RevRepContent,          --Revocation Response
///     ccr      [13] CertReqMessages,        --Cross-Cert. Request
///     ccp      [14] CertRepMessage,         --Cross-Cert. Response
///     ckuann   [15] CAKeyUpdAnnContent,     --CA Key Update Ann.
///     cann     [16] CertAnnContent,         --Certificate Ann.
///     rann     [17] RevAnnContent,          --Revocation Ann.
///     crlann   [18] CRLAnnContent,          --CRL Announcement
///     pkiconf  [19] PKIConfirmContent,      --Confirmation
///     nested   [20] NestedMessageContent,   --Nested Message
///     genm     [21] GenMsgContent,          --General Message
///     genp     [22] GenRepContent,          --General Response
///     error    [23] ErrorMsgContent,        --Error Message
///     certConf [24] CertConfirmContent,     --Certificate confirm
///     pollReq  [25] PollReqContent,         --Polling request
///     pollRep  [26] PollRepContent          --Polling response
/// }
/// ```
///
/// [RFC 4210 Section 5.1.2]: https://datatracker.ietf.org/doc/html/rfc4210#section-5.1.2
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
pub enum PkiBody<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", constructed = "true")]
    Ir(CertReqMessages),
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    Ip(CertRepMessage<'a>),
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
    Cr(CertReqMessages),
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", constructed = "true")]
    Cp(CertRepMessage<'a>),
    #[asn1(context_specific = "4", tag_mode = "EXPLICIT", constructed = "true")]
    P10cr(CertReq),
    #[asn1(context_specific = "5", tag_mode = "EXPLICIT", constructed = "true")]
    Popdecc(PopoDecKeyChallContent),
    #[asn1(context_specific = "6", tag_mode = "EXPLICIT", constructed = "true")]
    Popdecr(PopoDecKeyRespContent<'a>),
    #[asn1(context_specific = "7", tag_mode = "EXPLICIT", constructed = "true")]
    KUr(CertReqMessages),
    #[asn1(context_specific = "8", tag_mode = "EXPLICIT", constructed = "true")]
    Kup(CertRepMessage<'a>),
    #[asn1(context_specific = "9", tag_mode = "EXPLICIT", constructed = "true")]
    Krr(CertReqMessages),
    #[asn1(context_specific = "10", tag_mode = "EXPLICIT", constructed = "true")]
    Krp(KeyRecRepContent<'a>),
    #[asn1(context_specific = "11", tag_mode = "EXPLICIT", constructed = "true")]
    Rr(RevReqContent),
    #[asn1(context_specific = "12", tag_mode = "EXPLICIT", constructed = "true")]
    Rp(RevRepContent<'a>),
    #[asn1(context_specific = "13", tag_mode = "EXPLICIT", constructed = "true")]
    Ccr(CertReqMessages),
    #[asn1(context_specific = "14", tag_mode = "EXPLICIT", constructed = "true")]
    Ccp(CertRepMessage<'a>),
    #[asn1(context_specific = "15", tag_mode = "EXPLICIT", constructed = "true")]
    Ckuann(CaKeyUpdAnnContent),
    #[asn1(context_specific = "16", tag_mode = "EXPLICIT", constructed = "true")]
    Cann(CertAnnContent),
    #[asn1(context_specific = "17", tag_mode = "EXPLICIT", constructed = "true")]
    Rann(RevAnnContent),
    #[asn1(context_specific = "18", tag_mode = "EXPLICIT", constructed = "true")]
    CrlAnn(CrlAnnContent),
    #[asn1(context_specific = "19", tag_mode = "EXPLICIT", constructed = "true")]
    PkiConf(PkiConfirmContent),

    // TODO address recursion error
    // #[asn1(context_specific = "20", tag_mode = "EXPLICIT", constructed = "true")]
    // Nested(NestedMessageContent<'a>),
    #[asn1(context_specific = "21", tag_mode = "EXPLICIT", constructed = "true")]
    GenM(GenMsgContent),
    #[asn1(context_specific = "22", tag_mode = "EXPLICIT", constructed = "true")]
    GenP(GenRepContent),
    #[asn1(context_specific = "23", tag_mode = "EXPLICIT", constructed = "true")]
    Error(ErrorMsgContent<'a>),
    #[asn1(context_specific = "24", tag_mode = "EXPLICIT", constructed = "true")]
    CertConf(CertConfirmContent<'a>),
    #[asn1(context_specific = "25", tag_mode = "EXPLICIT", constructed = "true")]
    PollReq(PollRepContent<'a>),
    #[asn1(context_specific = "26", tag_mode = "EXPLICIT", constructed = "true")]
    PollRep(PollRepContent<'a>),
}

/// The `PKIConfirmContent` type is defined in [RFC 4210 Section 5.3.17]
///
/// ```text
///  PKIConfirmContent ::= NULL
/// ```
///
/// [RFC 4210 Section 5.3.17]: https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3.4
pub type PkiConfirmContent = Null;

/// The `PKIConfirmContent` type is defined in [RFC 4210 Section 5.3.17]
///
/// ```text
///  NestedMessageContent ::= PKIMessages
/// ```
///
/// [RFC 4210 Section 5.1.3.4]: https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3.4
pub type NestedMessageContent<'a> = PkiMessages<'a>;
