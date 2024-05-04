//! Negotiation-related types
use der::{
    asn1::{BitString, OctetStringRef},
    AnyRef, Choice, Enumerated, Sequence,
};

use crate::MechType;

/// The `MechTypeList` type is defined in [RFC 4178 Section 4.1].
///
/// ```text
///   MechTypeList ::= SEQUENCE OF MechType
/// ```
///
/// [RFC 4178 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc4178#section-4.1
pub type MechTypeList = alloc::vec::Vec<MechType>;

/// `NegotiationToken` as defined in [RFC 4178 Section 4.2].
///
/// ```text
/// NegotiationToken ::= CHOICE {
///     negTokenInit    [0] NegTokenInit,
///     negTokenResp    [1] NegTokenResp
/// }
/// ```
///
/// [RFC 4178 Section 4.2]: https://datatracker.ietf.org/doc/html/rfc4178#section-4.2
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
pub enum NegotiationToken<'a> {
    /// This is the inner token of the initial negotiation message.
    #[cfg(feature = "rfc2478")]
    #[asn1(context_specific = "0", constructed = "true", tag_mode = "EXPLICIT")]
    NegTokenInit(NegTokenInit<'a>),
    /// The NegTokenInit2 message extends NegTokenInit with a negotiation hints (negHints) field.
    #[cfg(not(feature = "rfc2478"))]
    #[asn1(context_specific = "0", constructed = "true", tag_mode = "EXPLICIT")]
    NegTokenInit2(NegTokenInit2<'a>),
    /// Negotiation token returned by the target to the initiator which
    /// contains, for the first token returned, a global negotiation result
    /// and the security mechanism selected (if any).
    #[cfg(feature = "rfc2478")]
    #[asn1(context_specific = "1", constructed = "true", tag_mode = "EXPLICIT")]
    NegTokenTarg(NegTokenTarg<'a>),
    /// This is the token for all subsequent negotiation messages.
    #[cfg(not(feature = "rfc2478"))]
    #[asn1(context_specific = "1", constructed = "true", tag_mode = "EXPLICIT")]
    NegTokenResp(NegTokenResp<'a>),
}

/// `NegTokenInit` as defined in [RFC 4178 Section 4.2.1].
///
/// ```text
/// NegTokenInit ::= SEQUENCE {
///     mechTypes       [0] MechTypeList,
///     reqFlags        [1] ContextFlags  OPTIONAL,
///     -- inherited from RFC 2478 for backward compatibility,
///     -- RECOMMENDED to be left out
///     mechToken       [2] OCTET STRING  OPTIONAL,
///     mechListMIC     [3] OCTET STRING  OPTIONAL,
///     ...
/// }
/// ```
///
/// [RFC 4178 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc4178#section-4.2.1
#[cfg(feature = "rfc2478")]
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct NegTokenInit<'a> {
    /// This field contains one or more security mechanisms available for
    /// the initiator, in decreasing preference order (favorite choice
    /// first).
    #[asn1(context_specific = "0", optional = "true", tag_mode = "IMPLICIT")]
    pub mech_types: Option<MechTypeList>,

    /// This field, if present, contains the service options that are
    /// requested to establish the context (the req_flags parameter of
    /// GSS_Init_sec_context()).  This field is inherited from RFC 2478
    /// and is not integrity protected.  For implementations of this
    /// specification, the initiator SHOULD omit this reqFlags field and
    /// the acceptor MUST ignore this reqFlags field.
    ///
    /// The size constraint on the ContextFlags ASN.1 type only applies to
    /// the abstract type.  The ASN.1 DER requires that all trailing zero
    /// bits be truncated from the encoding of a bit string type whose
    /// abstract definition includes named bits.  Implementations should
    /// not expect to receive exactly 32 bits in an encoding of
    /// ContextFlags.
    #[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    pub req_flags: Option<ContextFlags>,

    /// This field, if present, contains the optimistic mechanism token.
    #[asn1(context_specific = "2", optional = "true", tag_mode = "IMPLICIT")]
    pub mech_token: Option<OctetStringRef<'a>>,

    /// This field, if present, contains an MIC token for the mechanism
    /// list in the initial negotiation message.  This MIC token is
    /// computed according to Section 5.
    #[asn1(context_specific = "3", optional = "true", tag_mode = "IMPLICIT")]
    pub mech_list_mic: Option<OctetStringRef<'a>>,
}

/// `ContextFlags` as defined in [RFC 4178 Section 4.2.1].
///
/// ```text
/// ContextFlags ::= BIT STRING {
///     delegFlag       (0),
///     mutualFlag      (1),
///     replayFlag      (2),
///     sequenceFlag    (3),
///     anonFlag        (4),
///     confFlag        (5),
///     integFlag       (6)
/// } (SIZE (32))
/// ```
///
/// [RFC 4178 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc4178#section-4.2.1
pub type ContextFlags = BitString;

/// `NegTokenTarg` as defined in [RFC 2479 Section 3.2.1].
///
/// ```text
/// NegTokenTarg ::= SEQUENCE {
///     negResult      [0] ENUMERATED {
///                             accept_completed    (0),
///                             accept_incomplete   (1),
///                             reject              (2) }          OPTIONAL,
///     supportedMech  [1] MechType                                OPTIONAL,
///     responseToken  [2] OCTET STRING                            OPTIONAL,
///     mechListMIC    [3] OCTET STRING                            OPTIONAL
/// }
/// ```
///
/// [RFC 2479 Section 3.2.1]: https://datatracker.ietf.org/doc/html/rfc2478#section-3.2.1
#[cfg(feature = "rfc2478")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Sequence)]
pub struct NegTokenTarg<'a> {
    /// The result accept_completed indicates that a context has been
    /// successfully established, while the result accept_incomplete
    /// indicates that additional token exchanges are needed.
    ///
    ///  Note:: For the case where (a) a single-token context setup is
    ///  used and (b) the preferred mechanism does not support the
    ///  integrity facility which would cause a mechListMIC to be
    ///  generated and enclosed, this feature allows to make a
    ///  difference between a mechToken sent by the initiator but not
    ///  processed by the target (accept_incomplete) and a mechToken
    ///  sent by the initiator and processed by the target
    ///  (accept_completed).
    ///
    //  For those targets that support piggybacking the initial mechToken,
    //  an optimistic negotiation response is possible and includes in that
    //  case a responseToken which may continue the authentication exchange
    //  (e.g. when mutual authentication has been requested or when
    //  unilateral authentication requires several round trips). Otherwise
    //  the responseToken is used to carry the tokens specific to the
    //  mechanism selected. For subsequent tokens (if any) returned by the
    //  target, negResult, and supportedMech are not present.

    //  For the last token returned by the target, the mechListMIC, when
    //  present, is a MIC computed over the MechTypes using the selected
    //  mechanism.
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub neg_result: Option<NegResult>,

    /// This field has to be present when negResult is "accept_completed"
    /// or "accept_incomplete". It is a choice from the mechanisms offered
    /// by the initiator.
    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub supported_mech: Option<MechType>,

    /// This field may be used either to transmit the response to the
    /// mechToken when sent by the initiator and when the first mechanism
    /// from the list has been selected by the target or to carry the
    /// tokens specific to the selected security mechanism.
    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    pub response_token: Option<OctetStringRef<'a>>,

    /// If the selected mechanism is capable of integrity protection, this
    ///  field must be present in the last message of the negotiation,
    ///  (i.e., when the underlying mechanism returns a non-empty token and
    ///  a major status of GSS_S_COMPLETE); it contains the result of a
    ///  GetMIC of the MechTypes field in the initial NegTokenInit.  It
    ///  allows to verify that the list initially sent by the initiator has
    ///  been received unmodified by the target.
    #[asn1(context_specific = "3", optional = "true", tag_mode = "EXPLICIT")]
    pub mech_list_mic: Option<OctetStringRef<'a>>,
}

/// `NegResult` as defined in [RFC 2479 Section 3.2.1].
///
/// ```text
/// NegTokenTarg ::= SEQUENCE {
///     negResult      [0] ENUMERATED {
///                             accept_completed    (0),
///                             accept_incomplete   (1),
///                             reject              (2) }          OPTIONAL,
///     supportedMech  [1] MechType                                OPTIONAL,
///     responseToken  [2] OCTET STRING                            OPTIONAL,
///     mechListMIC    [3] OCTET STRING                            OPTIONAL
/// }
/// ```
///
/// [RFC 2479 Section 3.2.1]: https://datatracker.ietf.org/doc/html/rfc2478#section-3.2.1
#[cfg(feature = "rfc2478")]
#[derive(Clone, Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Enumerated)]
#[asn1(type = "ENUMERATED")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum NegResult {
    /// The target accepts the preferred security mechanism, and the context is established for the target.
    AcceptCompleted = 0,
    /// The target accepts one of the proposed security mechanisms and further exchanges are necessary.
    AcceptIncomplete = 1,
    /// The target rejects all the proposed security mechanisms.
    Reject = 2,
}

/// `NegTokenResp` as defined in [RFC 4178 Section 4.2.2].
///
/// ```text
/// NegTokenResp ::= SEQUENCE {
/// negState       [0] ENUMERATED {
///     accept-completed    (0),
///     accept-incomplete   (1),
///     reject              (2),
///     request-mic         (3)
/// }                                 OPTIONAL,
///   -- REQUIRED in the first reply from the target
/// supportedMech   [1] MechType      OPTIONAL,
///   -- present only in the first reply from the target
/// responseToken   [2] OCTET STRING  OPTIONAL,
/// mechListMIC     [3] OCTET STRING  OPTIONAL,
/// ...
/// }
/// ```
///
/// [RFC 4178 Section 4.2.2]: https://datatracker.ietf.org/doc/html/rfc4178#section-4.2.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct NegTokenResp<'a> {
    /// This field is REQUIRED in the first reply from the target, and is
    /// OPTIONAL thereafter.  When negState is absent, the actual state
    /// should be inferred from the state of the negotiated mechanism
    /// context.
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub neg_state: Option<NegState>,

    /// This field SHALL only be present in the first reply from the
    /// target. It MUST be one of the mechanism(s) offered by the
    /// initiator.
    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub supported_mech: Option<MechType>,

    /// This field, if present, contains tokens specific to the mechanism
    /// selected.
    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    pub response_token: Option<OctetStringRef<'a>>,

    /// This field, if present, contains an MIC token for the mechanism
    /// list in the initial negotiation message.  This MIC token is
    /// computed according to Section 5.
    #[asn1(context_specific = "3", optional = "true", tag_mode = "EXPLICIT")]
    pub mech_list_mic: Option<OctetStringRef<'a>>,
}

#[derive(Clone, Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Enumerated)]
#[asn1(type = "ENUMERATED")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum NegState {
    /// No further negotiation message from the peer is expected, and
    /// the security context is established for the sender.
    AcceptCompleted = 0,
    /// At least one additional negotiation message from the peer is
    /// needed to establish the security context.
    AcceptIncomplete = 1,
    /// The sender terminates the negotiation.
    Reject = 2,
    /// The sender indicates that the exchange of MIC tokens, as
    /// described in Section 5, will be REQUIRED if per-message
    /// integrity services are available on the mechanism context to be
    /// established.  This value SHALL only be present in the first
    /// reply from the target.
    RequestMic = 3,
}

/// `NegHints` as defined in [MS-SPNG Section 2.2.1].
///
/// ```text
/// NegHints ::= SEQUENCE {
///     hintName[0] GeneralString OPTIONAL,
///     hintAddress[1] OCTET STRING OPTIONAL
/// }
/// ```
///
/// [MS-SPNG Section 2.2.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/8e71cf53-e867-4b79-b5b5-38c92be3d472
#[derive(Clone, Copy, Debug, Eq, PartialEq, Sequence)]
pub struct NegHints<'a> {
    /// SHOULD<5> contain the string "not_defined_in_RFC4178@please_ignore".
    /// This is currently `AnyRef` as `GeneralString` is not part of the `der` crate
    #[asn1(
        context_specific = "0",
        optional = "true",
        tag_mode = "IMPLICIT",
        constructed = "true"
    )]
    pub hint_name: Option<AnyRef<'a>>, // TODO: GeneralString

    /// Never present. MUST be omitted by the sender. Note that the encoding rules, as specified in [X690], require that this structure not be present at all, not just be zero.
    ///
    /// [X690]: https://www.itu.int/rec/T-REC-X.690/
    #[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    pub hint_address: Option<OctetStringRef<'a>>,
}

/// `NegTokenInit2` as defined in [MS-SPNG Section 2.2.1].
///
/// ```text
/// NegTokenInit2 ::= SEQUENCE {
///     mechTypes[0] MechTypeList OPTIONAL,
///     reqFlags [1] ContextFlags OPTIONAL,
///     mechToken [2] OCTET STRING OPTIONAL,
///     negHints [3] NegHints OPTIONAL,
///     mechListMIC [4] OCTET STRING OPTIONAL,
///     ...
/// }
/// ```
///
/// [MS-SPNG Section 2.2.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/8e71cf53-e867-4b79-b5b5-38c92be3d472
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct NegTokenInit2<'a> {
    /// The list of authentication mechanisms that are available, by OID, as specified in [RFC4178] section 4.1.
    ///
    /// [RFC4178]: https://datatracker.ietf.org/doc/html/rfc4178
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub mech_types: Option<MechTypeList>,

    /// As specified in [RFC4178] section 4.2.1 This field SHOULD be omitted by the sender.
    ///
    /// [RFC4178]: https://datatracker.ietf.org/doc/html/rfc4178
    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub req_flags: Option<ContextFlags>,

    /// The optimistic mechanism token ([RFC4178] section 4.2.1).
    ///
    /// [RFC4178]: https://datatracker.ietf.org/doc/html/rfc4178
    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    pub mech_token: Option<OctetStringRef<'a>>,

    /// The server supplies the negotiation hints using a NegHints structure.
    #[asn1(context_specific = "3", optional = "true", tag_mode = "EXPLICIT")]
    pub neg_hints: Option<NegHints<'a>>,

    /// The message integrity code (MIC) token ([RFC4178] section 4.2.1).
    ///
    /// [RFC4178]: https://datatracker.ietf.org/doc/html/rfc4178
    #[asn1(context_specific = "4", optional = "true", tag_mode = "EXPLICIT")]
    pub mech_list_mic: Option<OctetStringRef<'a>>,
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use spki::ObjectIdentifier;

    use super::*;

    use der::Decode;

    #[test]
    fn mech_type() {
        let mech_type_bytes = hex!("060a2b06010401823702020a");
        let mech_type1 = MechType::from_der(&mech_type_bytes).unwrap();
        assert_eq!(
            ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.2.10"),
            mech_type1
        );
    }

    #[test]
    fn token_init() {
        let neg_token_init_bytes = hex!("303ca00e300c060a2b06010401823702020aa32a3028a0261b246e6f745f646566696e65645f696e5f5246433431373840706c656173655f69676e6f7265");
        let neg_token = NegTokenInit2::from_der(&neg_token_init_bytes).unwrap();
        assert_eq!(
            1,
            neg_token.mech_types.unwrap().len(),
            "NegTokenInit2 mech_types len correct"
        );
        assert_eq!(
            b"not_defined_in_RFC4178@please_ignore",
            &neg_token.neg_hints.unwrap().hint_name.unwrap().value()[2..]
        );
    }

    #[test]
    fn token_response() {
        let neg_token_resp_bytes = hex!("308199a0030a0101a10c060a2b06010401823702020aa281830481804e544c4d53535000020000000a000a003800000005028a6234805409a0e0e1f900000000000000003e003e0042000000060100000000000f530041004d004200410002000a00530041004d004200410001000a00530041004d00420041000400000003000a00730061006d00620061000700080036739dbd327fd90100000000");
        let neg_token_resp = NegTokenResp::from_der(&neg_token_resp_bytes).unwrap();
        assert_eq!(
            ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.2.10"),
            neg_token_resp.supported_mech.unwrap()
        );
    }

    #[cfg(feature = "rfc2478")]
    #[test]
    fn decode_rfc2478() {
        let neg_token_targ_bytes = hex!("308199a0030a0101a10c060a2b06010401823702020aa281830481804e544c4d53535000020000000a000a003800000005028a6234805409a0e0e1f900000000000000003e003e0042000000060100000000000f530041004d004200410002000a00530041004d004200410001000a00530041004d00420041000400000003000a00730061006d00620061000700080036739dbd327fd90100000000");
        let neg_token_targ = NegTokenTarg::from_der(&neg_token_targ_bytes).unwrap();
        assert_eq!(
            NegResult::AcceptIncomplete,
            neg_token_targ.neg_result.unwrap()
        );
        assert_eq!(
            ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.2.10"),
            neg_token_targ.supported_mech.unwrap()
        );
    }
}
