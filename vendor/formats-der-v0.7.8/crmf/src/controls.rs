//! Controls-related types

use alloc::boxed::Box;
use alloc::vec::Vec;
use der::asn1::{BitString, OctetString, Utf8StringRef};
use der::{Choice, Enumerated, Sequence};

use cms::enveloped_data::EnvelopedData;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::serial_number::SerialNumber;

/// The `Controls` type is defined in [RFC 4211 Section 6].
///
/// ```text
///   Controls  ::= SEQUENCE SIZE(1..MAX) OF SingleAttribute
///                     {{RegControlSet}}
/// ```
///
/// [RFC 4211 Section 6]: https://www.rfc-editor.org/rfc/rfc4211#section-6
pub type Controls = Vec<AttributeTypeAndValue>;

/// The `RegToken` control is defined in [RFC 4211 Section 6.1].
///
/// ```text
///   RegToken ::= UTF8String
/// ```
///
/// [RFC 4211 Section 6.1]: https://www.rfc-editor.org/rfc/rfc4211#section-6.1
pub type RegToken<'a> = Utf8StringRef<'a>;

/// The `Authenticator` control is defined in [RFC 4211 Section 6.2].
///
/// ```text
///   Authenticator ::= UTF8String
/// ```
///
/// [RFC 4211 Section 6.2]: https://www.rfc-editor.org/rfc/rfc4211#section-6.2
pub type Authenticator<'a> = Utf8StringRef<'a>;

/// The `PKIPublicationInfo` control is defined in [RFC 4211 Section 6.3].
///
/// ```text
///   PKIPublicationInfo ::= SEQUENCE {
///       action     INTEGER {
///                      dontPublish (0),
///                      pleasePublish (1) },
///       pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
///       -- pubInfos MUST NOT be present if action is "dontPublish"
///       -- (if action is "pleasePublish" and pubInfos is omitted,
///       -- "dontCare" is assumed)
/// ```
///
/// [RFC 4211 Section 6.3]: https://www.rfc-editor.org/rfc/rfc4211#section-6.3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct PkiPublicationInfo {
    pub action: PkiPublicationInfoAction,
    pub pub_infos: Option<Vec<SinglePubInfo>>,
}

/// The `PKIPublicationInfo` control is defined [RFC 4211 Section 6.3] features
/// an inline INTEGER definition that is implemented as the PkiPublicationInfoAction enum.
///
/// [RFC 4211 Section 6.3]: https://www.rfc-editor.org/rfc/rfc4211#section-6.3
#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated, Ord, PartialOrd)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum PkiPublicationInfoAction {
    DontPublish = 0,
    PleasePublish = 1,
}

/// The `SinglePubInfo` control is defined in [RFC 4211 Section 6.3].
///
/// ```text
///   SinglePubInfo ::= SEQUENCE {
///       pubMethod    INTEGER {
///           dontCare    (0),
///           x500        (1),
///           web         (2),
///           ldap        (3) },
///       pubLocation  GeneralName OPTIONAL }
/// ```
///
/// [RFC 4211 Section 6.3]: https://www.rfc-editor.org/rfc/rfc4211#section-6.3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct SinglePubInfo {
    pub pub_method: SinglePubInfoMethod,
    pub pub_location: Option<GeneralName>,
}

/// The `SinglePubInfo` control is defined [RFC 4211 Section 6.3] features
/// an inline INTEGER definition that is implemented as the SinglePubInfoMethod enum.
///
/// [RFC 4211 Section 6.3]: https://www.rfc-editor.org/rfc/rfc4211#section-6.3
#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated, Ord, PartialOrd)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum SinglePubInfoMethod {
    DontCare = 0,
    X500 = 1,
    Web = 2,
    Ldap = 3,
}

/// The `PKIArchiveOptions` control is defined in [RFC 4211 Section 6.4].
///
/// ```text
///   PKIArchiveOptions ::= CHOICE {
///       encryptedPrivKey     [0] EncryptedKey,
///       -- the actual value of the private key
///       keyGenParameters     [1] KeyGenParameters,
///       -- parameters that allow the private key to be re-generated
///       archiveRemGenPrivKey [2] BOOLEAN }
///       -- set to TRUE if sender wishes receiver to archive the private
///       -- key of a key pair that the receiver generates in response to
///       -- this request; set to FALSE if no archive is desired.
/// ```
///
/// [RFC 4211 Section 6.4]: https://www.rfc-editor.org/rfc/rfc4211#section-6.4
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
#[allow(missing_docs)]
pub enum PkiArchiveOptions {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", constructed = "true")]
    EncryptedPrivKey(EncryptedKey),
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    KeyGenParameters(KeyGenParameters),
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "false")]
    ArchiveRemGenPrivKey(bool),
}

/// The `EncryptedKey` type is defined in [RFC 4211 Section 6.4].
///
/// ```text
///   EncryptedKey ::= CHOICE {
///       encryptedValue        EncryptedValue,   -- Deprecated
///       envelopedData     [0] EnvelopedData }
///       -- The encrypted private key MUST be placed in the envelopedData
///       -- encryptedContentInfo encryptedContent OCTET STRING.
/// ```
///
/// [RFC 4211 Section 6.4]: https://www.rfc-editor.org/rfc/rfc4211#section-6.4
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
#[allow(missing_docs)]
pub enum EncryptedKey {
    EncryptedValue(Box<EncryptedValue>),
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", constructed = "true")]
    EnvelopedData(Box<EnvelopedData>),
}

/// The `EncryptedValue` type is defined in [RFC 4211 Section 6.4].
///
/// ```text
///   EncryptedValue ::= SEQUENCE {
///       intendedAlg   [0] AlgorithmIdentifier{ALGORITHM, {...}}  OPTIONAL,
///       -- the intended algorithm for which the value will be used
///       symmAlg       [1] AlgorithmIdentifier{ALGORITHM, {...}}  OPTIONAL,
///       -- the symmetric algorithm used to encrypt the value
///       encSymmKey    [2] BIT STRING           OPTIONAL,
///       -- the (encrypted) symmetric key used to encrypt the value
///       keyAlg        [3] AlgorithmIdentifier{ALGORITHM, {...}}  OPTIONAL,
///       -- algorithm used to encrypt the symmetric key
///       valueHint     [4] OCTET STRING         OPTIONAL,
///       -- a brief description or identifier of the encValue content
///       -- (may be meaningful only to the sending entity, and used only
///       -- if EncryptedValue might be re-examined by the sending entity
///       -- in the future)
///       encValue       BIT STRING }
/// ```
///
/// [RFC 4211 Section 6.4]: https://www.rfc-editor.org/rfc/rfc4211#section-6.4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct EncryptedValue {
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub intended_alg: Option<AlgorithmIdentifierOwned>,
    #[asn1(
        context_specific = "1",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub sym_alg: Option<AlgorithmIdentifierOwned>,
    #[asn1(
        context_specific = "2",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    pub enc_sym_key: Option<BitString>,
    #[asn1(
        context_specific = "3",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub key_alg: Option<AlgorithmIdentifierOwned>,
    #[asn1(
        context_specific = "4",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    pub value_hint: Option<OctetString>,
    pub enc_value: BitString,
}

/// The `KeyGenParameters` control is defined in [RFC 4211 Section 6.4].
///
/// ```text
///   KeyGenParameters ::= OCTET STRING
/// ```
///
/// [RFC 4211 Section 6.4]: https://www.rfc-editor.org/rfc/rfc4211#section-6.4
pub type KeyGenParameters = OctetString;

/// The `OldCertId` control is defined in [RFC 4211 Section 6.5].
///
/// ```text
///   OldCertId ::= CertId
/// ```
///
/// [RFC 4211 Section 6.5]: https://www.rfc-editor.org/rfc/rfc4211#section-6.5
pub type OldCertId = CertId;

/// The `CertId` control is defined in [RFC 4211 Section 6.5].
///
/// ```text
///   CertId ::= SEQUENCE {
///       issuer           GeneralName,
///       serialNumber     INTEGER }
/// ```
///
/// [RFC 4211 Section 6.5]: https://www.rfc-editor.org/rfc/rfc4211#section-6.5
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CertId {
    pub issuer: GeneralName,
    pub serial_number: SerialNumber,
}

/// The `ProtocolEncrKey` control is defined in [RFC 4211 Section 6.6].
///
/// ```text
///   ProtocolEncrKey ::= SubjectPublicKeyInfo
/// ```
///
/// [RFC 4211 Section 6.6]: https://www.rfc-editor.org/rfc/rfc4211#section-6.6
pub type ProtocolEncrKey = SubjectPublicKeyInfoOwned;
