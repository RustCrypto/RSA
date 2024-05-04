//! PKIHeader type

use alloc::vec::Vec;
use der::asn1::{GeneralizedTime, OctetString, Utf8StringRef};
use der::{Enumerated, Sequence};

use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::Certificate;

use crate::gen::InfoTypeAndValue;

/// The `PKIHeader` type is defined in [RFC 4210 Section 5.1.1].
///
/// ```text
///     PKIHeader ::= SEQUENCE {
///     pvno                INTEGER     { cmp1999(1), cmp2000(2) },
///     sender              GeneralName,
///     -- identifies the sender
///     recipient           GeneralName,
///     -- identifies the intended recipient
///     messageTime     [0] GeneralizedTime         OPTIONAL,
///     -- time of production of this message (used when sender
///     -- believes that the transport will be "suitable"; i.e.,
///     -- that the time will still be meaningful upon receipt)
///     protectionAlg   [1] AlgorithmIdentifier{ALGORITHM, {...}}
///     OPTIONAL,
///     -- algorithm used for calculation of protection bits
///     senderKID       [2] KeyIdentifier           OPTIONAL,
///     recipKID        [3] KeyIdentifier           OPTIONAL,
///     -- to identify specific keys used for protection
///     transactionID   [4] OCTET STRING            OPTIONAL,
///     -- identifies the transaction; i.e., this will be the same in
///     -- corresponding request, response, certConf, and PKIConf
///     -- messages
///     senderNonce     [5] OCTET STRING            OPTIONAL,
///     recipNonce      [6] OCTET STRING            OPTIONAL,
///     -- nonces used to provide replay protection, senderNonce
///     -- is inserted by the creator of this message; recipNonce
///     -- is a nonce previously inserted in a related message by
///     -- the intended recipient of this message
///     freeText        [7] PKIFreeText             OPTIONAL,
///     -- this may be used to indicate context-specific instructions
///     -- (this field is intended for human consumption)
///     generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
///     InfoTypeAndValue     OPTIONAL
///     -- this may be used to convey context-specific information
///     -- (this field not primarily intended for human consumption)
///     }
/// ```
///
/// [RFC 4210 Section 5.1.1]: https://datatracker.ietf.org/doc/html/rfc4210#section-5.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct PkiHeader<'a> {
    pub pvno: Pvno,
    pub sender: GeneralName,
    pub recipient: GeneralName,
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    pub message_time: Option<GeneralizedTime>,
    #[asn1(
        context_specific = "1",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub protection_alg: Option<AlgorithmIdentifierOwned>,
    #[asn1(
        context_specific = "2",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    pub sender_kid: Option<OctetString>,
    #[asn1(
        context_specific = "3",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    pub recip_kid: Option<OctetString>,
    #[asn1(
        context_specific = "4",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    pub trans_id: Option<OctetString>,
    #[asn1(
        context_specific = "5",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    pub sender_nonce: Option<OctetString>,
    #[asn1(
        context_specific = "6",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    pub recip_nonce: Option<OctetString>,
    #[asn1(
        context_specific = "7",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub free_text: Option<PkiFreeText<'a>>,
    #[asn1(
        context_specific = "8",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub general_info: Option<Vec<InfoTypeAndValue>>,
}

/// The `PKIHeader` type defined in [RFC 4210 Section 5.1.1] features an inline INTEGER definition
/// that is implemented as the Pvno enum.
///
/// ```text
///     pvno                INTEGER     { cmp1999(1), cmp2000(2) },
/// ```
///
/// [RFC 4210 Section 5.1.1]: https://datatracker.ietf.org/doc/html/rfc4210#section-5.1.1
#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated, Ord, PartialOrd)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum Pvno {
    Cmp1999 = 1,
    Cmp2000 = 2,
}

/// The `PKIFreeText` type is defined in [RFC 4210 Section 5.1.1]
///
/// ```text
///  PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
/// ```
///
/// [RFC 4210 Section 5.1.1]: https://www.rfc-editor.org/rfc/rfc4210#section-5.1.1
pub type PkiFreeText<'a> = Vec<Utf8StringRef<'a>>;

/// The `CMPCertificate` type is defined in [RFC 4210 Appendix F]
///
/// ```text
///  CMPCertificate ::= CHOICE { x509v3PKCert Certificate, ... }
/// ```
///
/// [RFC 4210 Appendix F]: https://www.rfc-editor.org/rfc/rfc4210#appendix-F
pub type CmpCertificate = Certificate;
