use cms::content_info::{CmsVersion, ContentInfo};
use cms::encrypted_data::EncryptedData;
use cms::signed_data::SignedData;
use const_oid::ObjectIdentifier;
use der::asn1::OctetStringRef;
use der::{AnyRef, Decode, Encode};
use hex_literal::hex;
use pkcs5::pbes2::Pbkdf2Params;

#[test]
fn cms_decode_cert_example() {
    let enc_ci = include_bytes!("../../pkcs7/tests/examples/certData.bin");
    let ci = ContentInfo::from_der(enc_ci).unwrap();
    assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_DATA);
    assert_eq!(ci.content.value().len(), 781);
    let reencoded_ci = ci.to_der().unwrap();
    assert_eq!(reencoded_ci, enc_ci)
}

#[test]
fn cms_decode_encrypted_key_example() {
    let enc_ci = include_bytes!("../../pkcs7/tests/examples/keyEncryptedData.bin");
    let ci = ContentInfo::from_der(enc_ci).unwrap();
    assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_ENCRYPTED_DATA);
    let data = EncryptedData::from_der(ci.content.to_der().unwrap().as_slice()).unwrap();
    assert_eq!(
        data.enc_content_info.content_type,
        const_oid::db::rfc5911::ID_DATA
    );
    assert_eq!(
        data.enc_content_info.content_enc_alg.oid,
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.6")
    );
    let enc_pbkdf2 = data
        .enc_content_info
        .content_enc_alg
        .parameters
        .as_ref()
        .unwrap()
        .to_der()
        .unwrap();
    let pbkdf2 = Pbkdf2Params::from_der(enc_pbkdf2.as_slice()).unwrap();
    assert_eq!(hex!("ad2d4b4e87b34d67"), pbkdf2.salt);
    assert_eq!(2048, pbkdf2.iteration_count);
    assert_eq!(
        552u32,
        data.enc_content_info
            .encrypted_content
            .unwrap()
            .len()
            .into()
    );
}

#[test]
fn cms_decode_signed_mdm_example() {
    let der_signed_data_in_ci =
        include_bytes!("../../pkcs7/tests/examples/apple_mdm_signature_der.bin");
    let ci = ContentInfo::from_der(der_signed_data_in_ci).unwrap();
    assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_SIGNED_DATA);

    // re-encode the AnyRef to get the SignedData bytes
    let bytes = ci.content.to_der().unwrap();

    // parse as SignedData then re-encode
    let sd = SignedData::from_der(bytes.as_slice()).unwrap();
    let reencoded_signed_data = sd.to_der().unwrap();

    // assemble a new ContentInfo and encode it
    let ci2 = ContentInfo {
        content_type: ci.content_type,
        content: AnyRef::try_from(reencoded_signed_data.as_slice())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let reencoded_der_signed_data_in_ci = ci2.to_der().unwrap();

    // should match the original
    assert_eq!(reencoded_der_signed_data_in_ci, der_signed_data_in_ci)
}

#[test]
fn cms_decode_signed_scep_example() {
    let der_signed_data_in_ci = include_bytes!("../../pkcs7/tests/examples/scep_der.bin");
    let ci = ContentInfo::from_der(der_signed_data_in_ci).unwrap();
    assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_SIGNED_DATA);

    // re-encode the AnyRef to get the SignedData bytes
    let bytes = ci.content.to_der().unwrap();

    // parse as SignedData then re-encode
    let sd = SignedData::from_der(bytes.as_slice()).unwrap();
    assert_eq!(sd.version, CmsVersion::V1);
    let reencoded_signed_data = sd.to_der().unwrap();

    // assemble a new ContentInfo and encode it
    let ci2 = ContentInfo {
        content_type: ci.content_type,
        content: AnyRef::try_from(reencoded_signed_data.as_slice())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let reencoded_der_signed_data_in_ci = ci2.to_der().unwrap();

    // should match the original
    assert_eq!(reencoded_der_signed_data_in_ci, der_signed_data_in_ci)
}

#[test]
fn cms_decode_signed_der() {
    let der_signed_data_in_ci = include_bytes!("../../pkcs7/tests/examples/cms_der.bin");
    let ci = ContentInfo::from_der(der_signed_data_in_ci).unwrap();
    assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_SIGNED_DATA);

    // re-encode the AnyRef to get the SignedData bytes
    let bytes = ci.content.to_der().unwrap();

    // parse as SignedData then re-encode
    let sd = SignedData::from_der(bytes.as_slice()).unwrap();

    let reencoded_signed_data = sd.to_der().unwrap();
    assert_eq!(
        sd.encap_content_info
            .econtent
            .unwrap()
            .decode_as::<OctetStringRef>()
            .unwrap()
            .as_bytes()
            .len(),
        10034
    );

    // assemble a new ContentInfo and encode it
    let ci2 = ContentInfo {
        content_type: ci.content_type,
        content: AnyRef::try_from(reencoded_signed_data.as_slice())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let reencoded_der_signed_data_in_ci = ci2.to_der().unwrap();

    // should match the original
    assert_eq!(reencoded_der_signed_data_in_ci, der_signed_data_in_ci)
}
