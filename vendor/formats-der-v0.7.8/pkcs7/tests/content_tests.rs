//! PKCS#7 example tests

use der::{
    asn1::{ObjectIdentifier, OctetStringRef, SequenceRef},
    Decode, DecodePem, SliceWriter,
};
use hex_literal::hex;
use pkcs7::algorithm_identifier_types::{DigestAlgorithmIdentifier, DigestAlgorithmIdentifiers};
use pkcs7::certificate_choices::CertificateChoices;
use pkcs7::signed_data_content::CertificateSet;
use pkcs7::signer_info::SignerInfos;
use pkcs7::{
    cms_version::CmsVersion, encapsulated_content_info::EncapsulatedContentInfo,
    encrypted_data_content::EncryptedDataContent, enveloped_data_content::EncryptedContentInfo,
    signed_data_content::SignedDataContent, ContentInfo, ContentType,
};
use spki::AlgorithmIdentifierRef;
use std::fs;

fn encode_content_info<'a>(content_info: &ContentInfo<'a>, buf: &'a mut [u8]) -> &'a [u8] {
    let mut encoder = SliceWriter::new(buf);
    encoder.encode(content_info).expect("encoded content info");
    encoder.finish().expect("encoding success")
}

#[test]
fn decode_cert_example() {
    let path = "./tests/examples/certData.bin";
    let bytes = fs::read(path).unwrap_or_else(|_| panic!("Failed to read from {}", &path));

    let content = ContentInfo::from_der(&bytes).expect("expected valid data");

    match content {
        ContentInfo::Data(data) => assert_eq!(data.content.len(), 781),
        _ => panic!("expected ContentInfo::Data(Some(_))"),
    }

    let mut buf = vec![0u8; bytes.len()];
    let encoded_content = encode_content_info(&content, &mut buf);

    assert_eq!(encoded_content, bytes);
}

#[test]
fn decode_encrypted_key_example() {
    let path = "./tests/examples/keyEncryptedData.bin";
    let bytes = fs::read(path).unwrap_or_else(|_| panic!("Failed to read from {}", &path));

    let content = ContentInfo::from_der(&bytes).expect("expected valid data");

    let expected_oid = ObjectIdentifier::new("1.2.840.113549.1.12.1.6").unwrap();
    let expected_salt = &hex!("ad2d4b4e87b34d67");
    match content {
        ContentInfo::EncryptedData(EncryptedDataContent {
            version: _,
            encrypted_content_info:
                EncryptedContentInfo {
                    content_type: ContentType::Data,
                    content_encryption_algorithm:
                        AlgorithmIdentifierRef {
                            oid,
                            parameters: Some(any),
                        },
                    encrypted_content: Some(bytes),
                },
        }) => {
            assert_eq!(oid, expected_oid);

            let (salt, iter) = any
                .sequence(|decoder| {
                    let salt = OctetStringRef::decode(decoder)?;
                    let iter = u16::decode(decoder)?;
                    Ok((salt, iter))
                })
                .expect("salt and iters parameters");
            assert_eq!(salt.as_bytes(), expected_salt);
            assert_eq!(iter, 2048);

            assert_eq!(552u32, bytes.len().into())
        }
        _ => panic!("expected ContentInfo::Data(Some(_))"),
    }

    let mut buf = vec![0u8; bytes.len()];
    let encoded_content = encode_content_info(&content, &mut buf);

    assert_eq!(encoded_content, bytes)
}

#[test]
fn decode_signed_mdm_example() {
    let path = "./tests/examples/apple_mdm_signature_der.bin";
    let bytes = fs::read(path).unwrap_or_else(|_| panic!("Failed to read from {}", &path));

    let content = ContentInfo::from_der(&bytes).expect("expected valid data");

    match content {
        ContentInfo::SignedData(SignedDataContent {
            version: _,
            digest_algorithms: _,
            encap_content_info:
                EncapsulatedContentInfo {
                    e_content_type: _,
                    e_content: Some(content),
                },
            certificates: _,
            crls: _,
            signer_infos: _,
        }) => {
            let _content = content
                .decode_as::<SequenceRef>()
                .expect("Content should be in the correct format: SequenceRef");
        }
        _ => panic!("expected ContentInfo::SignedData(Some(_))"),
    }
}

#[test]
fn decode_signed_scep_example() {
    let path = "./tests/examples/scep_der.bin";
    let bytes = fs::read(path).unwrap_or_else(|_| panic!("Failed to read from {}", &path));

    let content = ContentInfo::from_der(&bytes).expect("expected valid data");

    match content {
        ContentInfo::SignedData(SignedDataContent {
            version: ver,
            digest_algorithms: _,
            encap_content_info:
                EncapsulatedContentInfo {
                    e_content_type: _,
                    e_content: Some(content),
                },
            certificates: _,
            crls: _,
            signer_infos: _,
        }) => {
            let _content = content
                .decode_as::<OctetStringRef>()
                .expect("Content should be in the correct format: OctetStringRef");

            assert_eq!(ver, CmsVersion::V1)
        }
        _ => panic!("expected ContentInfo::SignedData(Some(_))"),
    }

    let mut buf = vec![0u8; bytes.len()];
    encode_content_info(&content, &mut buf);
}

// TODO(tarcieri): BER support
#[test]
#[ignore]
fn decode_signed_ber() {
    let bytes = include_bytes!("examples/cms_ber.bin");

    let content = match ContentInfo::from_der(bytes) {
        Ok(ContentInfo::SignedData(data)) => data,
        other => panic!("unexpected result: {:?}", other),
    };

    assert_eq!(
        content
            .encap_content_info
            .e_content
            .unwrap()
            .decode_as::<OctetStringRef>()
            .unwrap()
            .as_bytes()
            .len(),
        10034
    );
}

#[test]
fn decode_signed_der() {
    let bytes = include_bytes!("examples/cms_der.bin");

    let content = match ContentInfo::from_der(bytes) {
        Ok(ContentInfo::SignedData(data)) => data,
        other => panic!("unexpected result: {:?}", other),
    };

    assert_eq!(
        content
            .encap_content_info
            .e_content
            .unwrap()
            .decode_as::<OctetStringRef>()
            .unwrap()
            .as_bytes()
            .len(),
        10034
    );
}

#[test]
fn create_pkcs7_signed_data() {
    // {iso(1) identified-organization(3) thawte(101) id-Ed25519(112)}
    const OID_ED25519: &str = "1.3.101.112";
    // {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-7(7) signedData(2)}
    const OID_PKCS7_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

    let digest_algorithms = {
        let digest_algorithm = DigestAlgorithmIdentifier {
            oid: der::asn1::ObjectIdentifier::new(OID_ED25519).unwrap(),
            parameters: None,
        };
        let mut digest_algorithms = DigestAlgorithmIdentifiers::new();
        digest_algorithms.insert(digest_algorithm).unwrap();
        digest_algorithms
    };

    let encap_content_info = {
        EncapsulatedContentInfo {
            e_content_type: der::asn1::ObjectIdentifier::new(OID_PKCS7_SIGNED_DATA).unwrap(),
            e_content: None,
        }
    };

    let certificates = {
        let cert_pem = include_bytes!("../tests/examples/cert.pem");
        let cert: x509_cert::Certificate = x509_cert::Certificate::from_pem(cert_pem).unwrap();
        let cert_choice = CertificateChoices::Certificate(cert);
        let mut certs = CertificateSet::new();
        certs.insert(cert_choice).unwrap();
        Some(certs)
    };

    fn get_signer_infos<'a>() -> SignerInfos<'a> {
        let signer_infos = SignerInfos::new();
        signer_infos
    }

    let content_info = ContentInfo::SignedData(SignedDataContent {
        version: pkcs7::cms_version::CmsVersion::V1,
        digest_algorithms,
        encap_content_info,
        certificates,
        crls: None,
        signer_infos: get_signer_infos(),
    });

    let mut buf = vec![0u8; 10000]; // buffer length must be guessed in advance :|
    encode_content_info(&content_info, &mut buf);
}
