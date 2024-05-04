//! Proof of possession (POP)-related types

use alloc::boxed::Box;
use der::asn1::{BitString, Null, OctetString, Utf8StringRef};
use der::{Choice, Enumerated, Sequence};

use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::attr::Attributes;
use x509_cert::ext::pkix::name::GeneralName;

use cms::enveloped_data::EnvelopedData;

/// The `ProofOfPossession` type is defined in [RFC 4211 Section 4].
///
/// ```text
///   ProofOfPossession ::= CHOICE {
///       raVerified        [0] NULL,
///       -- used if the RA has already verified that the requester is in
///       -- possession of the private key
///       signature         [1] POPOSigningKey,
///       keyEncipherment   [2] POPOPrivKey,
///       keyAgreement      [3] POPOPrivKey }
/// ```
///
/// [RFC 4211 Section 4]: https://www.rfc-editor.org/rfc/rfc4211#section-4
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
#[allow(missing_docs)]
pub enum ProofOfPossession {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "false")]
    RaVerified(Null),
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Signature(Box<PopoSigningKey>),
    //todo review EXPLICIT tag here (does not compile as IMPLICIT)
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
    KeyEncipherment(POPOPrivKey),
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", constructed = "true")]
    KeyAgreement(POPOPrivKey),
}

/// The `POPOSigningKey` type is defined in [RFC 4211 Section 4.1].
///
/// ```text
///   POPOSigningKey ::= SEQUENCE {
///       poposkInput           [0] POPOSigningKeyInput OPTIONAL,
///       algorithmIdentifier   AlgorithmIdentifier{SIGNATURE-ALGORITHM,
///                                 {SignatureAlgorithms}},
///       signature             BIT STRING }
/// ```
///
/// [RFC 4211 Section 4.1]: https://www.rfc-editor.org/rfc/rfc4211#section-4.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct PopoSigningKey {
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub poposk_input: Option<PopoSigningKeyInput>,
    pub alg_id: AlgorithmIdentifierOwned,
    pub signature: BitString,
}

/// The `POPOSigningKeyInput` type is defined in [RFC 4211 Section 4.1].
///
/// ```text
///   POPOSigningKeyInput ::= SEQUENCE {
///       authInfo            CHOICE {
///        sender              [0] GeneralName,
///        publicKeyMAC        PKMACValue },
///       publicKey           SubjectPublicKeyInfo }  -- from CertTemplate
/// ```
///
/// [RFC 4211 Section 4.1]: https://www.rfc-editor.org/rfc/rfc4211#section-4.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct PopoSigningKeyInput {
    pub auth_info: PopoSigningKeyInputChoice,
    pub public_key: SubjectPublicKeyInfoOwned,
}

/// The `POPOSigningKeyInput` type defined in [RFC 4211 Section 4.1] features an inline CHOICE
/// definition that is implemented as the POPOSigningKeyInputChoice enum.
///
/// ```text
///       authInfo            CHOICE {
///        sender              [0] GeneralName,
///        publicKeyMAC        PKMACValue },
/// ```
///
/// [RFC 4211 Section 4.1]: https://www.rfc-editor.org/rfc/rfc4211#section-4.1
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
pub enum PopoSigningKeyInputChoice {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", constructed = "true")]
    Sender(GeneralName),

    PublicKeyMAC(PkMacValue),
}

/// The `PKMACValue` type is defined in [RFC 4211 Section 4.1].
///
/// ```text
///   PKMACValue ::= SEQUENCE {
///       algId  AlgorithmIdentifier{MAC-ALGORITHM,
///                  {Password-MACAlgorithms}},
///       value  BIT STRING }
/// ```
///
/// [RFC 4211 Section 4.1]: https://www.rfc-editor.org/rfc/rfc4211#section-4.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct PkMacValue {
    pub alg_id: AlgorithmIdentifierOwned,
    pub value: BitString,
}

/// The `PBMParameter` type is defined in [RFC 4211 Section 4.4].
///
/// ```text
///   PBMParameter ::= SEQUENCE {
///      salt                OCTET STRING,
///      owf                 AlgorithmIdentifier{DIGEST-ALGORITHM,
///                              {DigestAlgorithms}},
///      iterationCount      INTEGER,
///      mac                 AlgorithmIdentifier{MAC-ALGORITHM,
///                              {MACAlgorithms}}
///   }
/// ```
///
/// [RFC 4211 Section 4.4]: https://www.rfc-editor.org/rfc/rfc4211#section-4.4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct PbmParameter {
    pub salt: OctetString,
    pub owf: AlgorithmIdentifierOwned,
    pub iteration_count: u64,
    pub mac: AlgorithmIdentifierOwned,
}

/// The `POPOPrivKey` type is defined in [RFC 4211 Section 4.2].
///
/// ```text
///   POPOPrivKey ::= CHOICE {
///       thisMessage       [0] BIT STRING,         -- Deprecated
///       subsequentMessage [1] SubsequentMessage,
///       dhMAC             [2] BIT STRING,         -- Deprecated
///       agreeMAC          [3] PKMACValue,
///       encryptedKey      [4] EnvelopedData }
/// ```
///
/// [RFC 4211 Section 4.2]: https://www.rfc-editor.org/rfc/rfc4211#section-4.2
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
#[allow(missing_docs)]
pub enum POPOPrivKey {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", constructed = "false")]
    ThisMessage(BitString),
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    SubsequentMessage(SubsequentMessage),
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "false")]
    DhMac(BitString),
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", constructed = "true")]
    AgreeMac(PkMacValue),
    #[asn1(context_specific = "4", tag_mode = "EXPLICIT", constructed = "true")]
    EncryptedKey(EnvelopedData),
}

/// The `SubsequentMessage` type is defined in [RFC 4211 Section 4.2].
///
/// ```text
///   SubsequentMessage ::= INTEGER {
///       encrCert (0),
///       challengeResp (1) }
/// ```
///
/// [RFC 4211 Section 4.2]: https://www.rfc-editor.org/rfc/rfc4211#section-4.2
#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum SubsequentMessage {
    EncrCert = 0,
    ChallengeResp = 1,
}

/// The `SubsequentMessage` type is defined in [RFC 4211 Section 4.2.1].
///
/// ```text
///   EncKeyWithID ::= SEQUENCE {
///       privateKey           PrivateKeyInfo,
///       identifier CHOICE {
///           string             UTF8String,
///           generalName        GeneralName
///       } OPTIONAL
///   }
/// ```
///
/// [RFC 4211 Section 4.2.1]: https://www.rfc-editor.org/rfc/rfc4211#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct EncKeyWithID<'a> {
    pub priv_key: PrivateKeyInfo,
    pub identifier: Option<EncKeyWithIdChoice<'a>>,
}

// TODO address requirement for fixed tag for CHOICE
// This nested CHOICE does not currently work via the Choice procedural macro, so it is avoided here
// in favor of manually implemented traits that avoid a FixedTag requirement. Generated code is below.
/// The `SubsequentMessage` type defined in [RFC 4211 Section 4.2.1] features an inline CHOICE
/// definition that is implemented as EncKeyWithIdChoice.
///
/// ```text
///       identifier CHOICE {
///           string             UTF8String,
///           generalName        GeneralName
///       } OPTIONAL
/// ```
///
/// [RFC 4211 Section 4.2.1]: https://www.rfc-editor.org/rfc/rfc4211#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum EncKeyWithIdChoice<'a> {
    String(Utf8StringRef<'a>),
    GeneralName(GeneralName),
}

impl<'a> ::der::Choice<'a> for EncKeyWithIdChoice<'a> {
    fn can_decode(tag: ::der::Tag) -> bool {
        <Utf8StringRef<'a> as ::der::FixedTag>::TAG == tag || tag.is_context_specific()
    }
}
impl<'a> ::der::Decode<'a> for EncKeyWithIdChoice<'a> {
    fn decode<R: ::der::Reader<'a>>(reader: &mut R) -> ::der::Result<Self> {
        let t = reader.peek_tag()?;
        if t == <Utf8StringRef<'a> as ::der::FixedTag>::TAG {
            Ok(Self::String(reader.decode()?))
        } else if t.is_context_specific() {
            Ok(Self::GeneralName(reader.decode()?))
        } else {
            Err(der::ErrorKind::TagUnexpected {
                expected: None,
                actual: t,
            }
            .into())
        }
    }
}
impl<'a> ::der::EncodeValue for EncKeyWithIdChoice<'a> {
    fn encode_value(&self, encoder: &mut impl ::der::Writer) -> ::der::Result<()> {
        match self {
            Self::String(variant) => variant.encode_value(encoder),
            Self::GeneralName(variant) => variant.encode_value(encoder),
        }
    }
    fn value_len(&self) -> ::der::Result<::der::Length> {
        match self {
            Self::String(variant) => variant.value_len(),
            Self::GeneralName(variant) => variant.value_len(),
        }
    }
}
impl<'a> ::der::Tagged for EncKeyWithIdChoice<'a> {
    fn tag(&self) -> ::der::Tag {
        match self {
            Self::String(_) => <Utf8StringRef<'a> as ::der::FixedTag>::TAG,
            Self::GeneralName(_) => self.tag(),
        }
    }
}

/// The `PrivateKeyInfo` type is defined in [RFC 4211 Section 4.2.1].
///
/// ```text
///   PrivateKeyInfo ::= SEQUENCE {
///      version                   INTEGER,
///      privateKeyAlgorithm       AlgorithmIdentifier{PUBLIC-KEY, {...}},
///      privateKey                OCTET STRING,
///                --  Structure of public key is in PUBLIC-KEY.&PrivateKey
///      attributes                [0] IMPLICIT Attributes OPTIONAL
///   }
/// ```
///
/// [RFC 4211 Section 4.2.1]: https://www.rfc-editor.org/rfc/rfc4211#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct PrivateKeyInfo {
    pub version: u64,
    pub priv_key_alg: AlgorithmIdentifierOwned,
    pub priv_key: OctetString,
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub attrs: Option<Attributes>,
}
