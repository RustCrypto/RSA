#![cfg(feature = "builder")]

use cms::builder::{create_signing_time_attribute, SignedDataBuilder, SignerInfoBuilder};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
use der::asn1::{OctetString, SetOfVec, Utf8StringRef};
use der::{Any, DecodePem, Encode, Tag, Tagged};
use p256::{pkcs8::DecodePrivateKey, NistP256};
use pem_rfc7468::LineEnding;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use sha2::Sha256;
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::{Attribute, AttributeTypeAndValue};
use x509_cert::name::{RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;

const RSA_2048_PRIV_DER_EXAMPLE: &[u8] = include_bytes!("examples/rsa2048-priv.der");
const PKCS8_PRIVATE_KEY_DER: &[u8] = include_bytes!("examples/p256-priv.der");

fn rsa_signer() -> SigningKey<Sha256> {
    let private_key = rsa::RsaPrivateKey::from_pkcs1_der(RSA_2048_PRIV_DER_EXAMPLE).unwrap();
    let signing_key = SigningKey::<Sha256>::new(private_key);
    signing_key
}

fn ecdsa_signer() -> ecdsa::SigningKey<NistP256> {
    let secret_key = p256::SecretKey::from_pkcs8_der(PKCS8_PRIVATE_KEY_DER).unwrap();
    ecdsa::SigningKey::from(secret_key)
}

fn signer_identifier(id: i32) -> SignerIdentifier {
    let mut rdn_sequence = RdnSequence::default();
    let rdn = &[AttributeTypeAndValue {
        oid: const_oid::db::rfc4519::CN,
        value: Any::from(Utf8StringRef::new(&format!("test client {id}")).unwrap()),
    }];
    let set_of_vector = SetOfVec::try_from(rdn.to_vec()).unwrap();
    rdn_sequence
        .0
        .push(RelativeDistinguishedName::from(set_of_vector));
    SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: rdn_sequence,
        serial_number: SerialNumber::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
            .expect("failed to create a serial number"),
    })
}

#[test]
fn test_build_signed_data() {
    // Make some content
    let content = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: Some(
            Any::new(
                Tag::OctetString,
                OctetString::new(vec![48]).unwrap().to_der().unwrap(),
            )
            .unwrap(),
        ),
    };
    // Create multiple signer infos
    let signer = rsa_signer();
    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };
    let external_message_digest = None;
    let signer_info_builder_1 = SignerInfoBuilder::new(
        &signer,
        signer_identifier(1),
        digest_algorithm.clone(),
        &content,
        external_message_digest,
    )
    .expect("Could not create RSA SignerInfoBuilder");

    let signer_2 = ecdsa_signer();
    let digest_algorithm_2 = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_512,
        parameters: None,
    };
    let external_message_digest_2 = None;
    let signer_info_builder_2 = SignerInfoBuilder::new(
        &signer_2,
        signer_identifier(1),
        digest_algorithm_2.clone(),
        &content,
        external_message_digest_2,
    )
    .expect("Could not create ECDSA SignerInfoBuilder");

    let certificate_buf = include_bytes!("examples/ValidCertificatePathTest1EE.pem");
    let certificate = x509_cert::Certificate::from_pem(certificate_buf).unwrap();

    let mut builder = SignedDataBuilder::new(&content);

    let signed_data_pkcs7 = builder
        .add_digest_algorithm(digest_algorithm)
        .expect("could not add a digest algorithm")
        .add_certificate(CertificateChoices::Certificate(certificate))
        .expect("error adding certificate")
        .add_signer_info::<SigningKey<Sha256>, rsa::pkcs1v15::Signature>(signer_info_builder_1)
        .expect("error adding RSA signer info")
        .add_signer_info::<ecdsa::SigningKey<NistP256>, p256::ecdsa::DerSignature>(
            signer_info_builder_2,
        )
        .expect("error adding RSA signer info")
        .build()
        .expect("building signed data failed");
    let signed_data_pkcs7_der = signed_data_pkcs7
        .to_der()
        .expect("conversion of signed data to DER failed.");
    println!(
        "{}",
        pem_rfc7468::encode_string("PKCS7", LineEnding::LF, &signed_data_pkcs7_der)
            .expect("PEM encoding of signed data DER failed")
    );
}

// TODO more tests:
// - external message
// - PKCS #7 message:
//   - different encapsulated content ASN.1 encoding
//   - enveloped data content
//   - additional signed attributes

#[test]
fn test_create_signing_attribute() {
    let attribute: Attribute =
        create_signing_time_attribute().expect("Creation of signing time attribute failed.");
    let mut arcs = attribute.oid.arcs();
    assert_eq!(
        arcs.next(),
        Some(1),
        "Invalid arc value in signing time attribute value"
    );
    assert_eq!(
        arcs.next(),
        Some(2),
        "Invalid arc value in signing time attribute value"
    );
    assert_eq!(
        arcs.next(),
        Some(840),
        "Invalid arc value in signing time attribute value"
    );
    assert_eq!(
        arcs.next(),
        Some(113549),
        "Invalid arc value in signing time attribute value"
    );
    assert_eq!(
        arcs.next(),
        Some(1),
        "Invalid arc value in signing time attribute value"
    );
    assert_eq!(
        arcs.next(),
        Some(9),
        "Invalid arc value in signing time attribute value"
    );
    assert_eq!(
        arcs.next(),
        Some(5),
        "Invalid arc value in signing time attribute value"
    );
    assert_eq!(
        arcs.next(),
        None,
        "Invalid arc value in signing time attribute value"
    );
    assert_eq!(
        attribute.values.len(),
        1,
        "Too many attribute values in signing time attribute"
    );
    let signing_time = attribute
        .values
        .iter()
        .next()
        .expect("No time in signing time attribute");
    let tag = signing_time.tag();
    assert!(
        tag == Tag::GeneralizedTime || tag == Tag::UtcTime,
        "Invalid tag number in signing time attribute value"
    );
}
