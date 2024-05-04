//! Status-related types

use crate::header::PkiFreeText;
use alloc::vec::Vec;
use der::asn1::{Int, OctetString};
use der::flagset::{flags, FlagSet};
use der::{Enumerated, Sequence};

/// The `PKIStatus` type is defined in [RFC 4210 Section 5.2.3].
///
/// ```text
///  PKIStatus ::= INTEGER {
///      accepted               (0),
///      -- you got exactly what you asked for
///      grantedWithMods        (1),
///      -- you got something like what you asked for; the
///      -- requester is responsible for ascertaining the differences
///      rejection              (2),
///      -- you don't get it, more information elsewhere in the message
///      waiting                (3),
///      -- the request body part has not yet been processed; expect to
///      -- hear more later (note: proper handling of this status
///      -- response MAY use the polling req/rep PKIMessages specified
///      -- in Section 5.3.22; alternatively, polling in the underlying
///      -- transport layer MAY have some utility in this regard)
///      revocationWarning      (4),
///      -- this message contains a warning that a revocation is
///      -- imminent
///      revocationNotification (5),
///      -- notification that a revocation has occurred
///      keyUpdateWarning       (6)
///      -- update already done for the oldCertId specified in
///      -- CertReqMsg
///  }
/// ```
///
/// [RFC 4210 Section 5.2.3]: https://www.rfc-editor.org/rfc/rfc4210#section-5.2.3
#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum PkiStatus {
    Accepted = 0,
    GrantedWithMods = 1,
    Rejection = 2,
    Waiting = 3,
    RevocationWarning = 4,
    RevocationNotification = 5,
    KeyUpdateWarning = 6,
}

flags! {
    /// The `PKIFailureInfo` type is defined in [RFC 4210 Section 5.2.3].
    ///
    /// ```text
    ///  PKIFailureInfo ::= BIT STRING {
    ///  -- since we can fail in more than one way!
    ///  -- More codes may be added in the future if/when required.
    ///      badAlg              (0),
    ///      -- unrecognized or unsupported Algorithm Identifier
    ///      badMessageCheck     (1),
    ///      -- integrity check failed (e.g., signature did not verify)
    ///      badRequest          (2),
    ///      -- transaction not permitted or supported
    ///      badTime             (3),
    ///      -- messageTime was not sufficiently close to the system time,
    ///      -- as defined by local policy
    ///      badCertId           (4),
    ///      -- no certificate could be found matching the provided criteria
    ///      badDataFormat       (5),
    ///      -- the data submitted has the wrong format
    ///      wrongAuthority      (6),
    ///      -- the authority indicated in the request is different from the
    ///      -- one creating the response token
    ///      incorrectData       (7),
    ///      -- the requester's data is incorrect (for notary services)
    ///      missingTimeStamp    (8),
    ///      -- when the timestamp is missing but should be there
    ///      -- (by policy)
    ///      badPOP              (9),
    ///      -- the proof-of-possession failed
    ///      certRevoked         (10),
    ///      -- the certificate has already been revoked
    ///      certConfirmed       (11),
    ///      -- the certificate has already been confirmed
    ///      wrongIntegrity      (12),
    ///      -- invalid integrity, password based instead of signature or
    ///      -- vice versa
    ///      badRecipientNonce   (13),
    ///      -- invalid recipient nonce, either missing or wrong value
    ///      timeNotAvailable    (14),
    ///      -- the TSA's time source is not available
    ///      unacceptedPolicy    (15),
    ///      -- the requested TSA policy is not supported by the TSA
    ///      unacceptedExtension (16),
    ///      -- the requested extension is not supported by the TSA
    ///      addInfoNotAvailable (17),
    ///      -- the additional information requested could not be
    ///      -- understood or is not available
    ///      badSenderNonce      (18),
    ///      -- invalid sender nonce, either missing or wrong size
    ///      badCertTemplate     (19),
    ///      -- invalid cert. template or missing mandatory information
    ///      signerNotTrusted    (20),
    ///      -- signer of the message unknown or not trusted
    ///      transactionIdInUse  (21),
    ///      -- the transaction identifier is already in use
    ///      unsupportedVersion  (22),
    ///      -- the version of the message is not supported
    ///      notAuthorized       (23),
    ///      -- the sender was not authorized to make the preceding
    ///      -- request or perform the preceding action
    ///      systemUnavail       (24),
    ///      -- the request cannot be handled due to system unavailability
    ///      systemFailure       (25),
    ///      -- the request cannot be handled due to system failure
    ///      duplicateCertReq    (26)
    ///      -- certificate cannot be issued because a duplicate
    ///      -- certificate already exists
    ///  }
    /// ```
    ///
    /// [RFC 4210 Section 5.2.3]: https://www.rfc-editor.org/rfc/rfc4210#section-5.2.3
    #[allow(missing_docs)]
    pub enum PkiFailureInfoValues: u16 {
        BadAlg = 0,
        BadMessageCheck = 1,
        BadRequest      = 2,
        BadTime         = 2,
        BadCertId       = 4,
        BadDataFormat   = 5,
        WrongAuthority  = 6,
        IncorrectData   = 7,
        MissingTimeStamp = 8,
        BadPOP           = 9,
        CertRevoked      = 10,
        CertConfirmed    = 11,
        WrongIntegrity   = 12,
        BadRecipientNonce = 13,
        TimeNotAvailable  = 14,
        UnacceptedPolicy  = 15,
        UnacceptedExtension = 16,
        AddInfoNotAvailable = 17,
        BadSenderNonce      = 18,
        BadCertTemplate     = 19,
        SignerNotTrusted    = 20,
        TransactionIdInUse  = 21,
        UnsupportedVersion  = 22,
        NotAuthorized       = 23,
        SystemUnavail       = 24,
        SystemFailure       = 25,
        DuplicateCertReq    = 26,
    }
}

///  PKIFailureInfo provides a FlagSet for `PkiFailureInfoValues` as defined in
/// [RFC 4210 Section 5.2.3].
///
/// [RFC 4210 Section 5.2.3]: https://www.rfc-editor.org/rfc/rfc4210#section-5.2.3
pub type PkiFailureInfo = FlagSet<PkiFailureInfoValues>;

/// The `PKIStatusInfo` type is defined in [RFC 4210 Section 5.2.3].
///
/// ```text
///  PKIStatusInfo ::= SEQUENCE {
///      status        PKIStatus,
///      statusString  PKIFreeText     OPTIONAL,
///      failInfo      PKIFailureInfo  OPTIONAL }
/// ```
///
/// [RFC 4210 Section 5.2.3]: https://www.rfc-editor.org/rfc/rfc4210#section-5.2.3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct PkiStatusInfo<'a> {
    pub status: PkiStatus,
    pub status_string: Option<PkiFreeText<'a>>,
    pub fail_info: Option<PkiFailureInfo>,
}

/// The `ErrorMsgContent` type is defined in [RFC 4210 Section 5.2.21].
///
/// ```text
///  ErrorMsgContent ::= SEQUENCE {
///      pKIStatusInfo          PKIStatusInfo,
///      errorCode              INTEGER           OPTIONAL,
///      -- implementation-specific error codes
///      errorDetails           PKIFreeText       OPTIONAL
///      -- implementation-specific error details
///  }
/// ```
///
/// [RFC 4210 Section 5.2.21]: https://www.rfc-editor.org/rfc/rfc4210#section-5.2.21
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ErrorMsgContent<'a> {
    pki_status_info: PkiStatusInfo<'a>,
    error_code: Option<u64>,
    error_details: Option<PkiFreeText<'a>>,
}

/// The `CertConfirmContent` type is defined in [RFC 4210 Section 5.2.18].
///
/// ```text
///  CertConfirmContent ::= SEQUENCE OF CertStatus
/// ```
///
/// [RFC 4210 Section 5.2.18]: https://www.rfc-editor.org/rfc/rfc4210#section-5.2.18
pub type CertConfirmContent<'a> = Vec<CertStatus<'a>>;

/// The `CertStatus` type is defined in [RFC 4210 Section 5.2.18].
///
/// ```text
///  CertStatus ::= SEQUENCE {
///      certHash    OCTET STRING,
///      -- the hash of the certificate, using the same hash algorithm
///      -- as is used to create and verify the certificate signature
///      certReqId   INTEGER,
///      -- to match this confirmation with the corresponding req/rep
///      statusInfo  PKIStatusInfo OPTIONAL }
/// ```
///
/// [RFC 4210 Section 5.2.18]: https://www.rfc-editor.org/rfc/rfc4210#section-5.2.18
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CertStatus<'a> {
    pub cert_hash: OctetString,
    pub cert_req_id: Int,
    pub status_info: Option<PkiStatusInfo<'a>>,
}
