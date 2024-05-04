extern crate core;

use cms::content_info::{CmsVersion, ContentInfo};
use cms::encrypted_data::EncryptedData;
use const_oid::ObjectIdentifier;
use der::{AnyRef, Decode, Encode};
use hex_literal::hex;

#[test]
fn reencode_encrypted_data_test() {
    // read DigestedData object created via:
    //  openssl cms --digest_create -in data.txt -binary -outform DER -out digested_data.bin
    let der_ci = include_bytes!("examples/encrypted_data.bin");
    let ci = ContentInfo::from_der(der_ci).unwrap();
    assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_ENCRYPTED_DATA);

    // re-encode the AnyRef to get the SignedData bytes
    let bytes = ci.content.to_der().unwrap();

    // parse as EncryptedData then re-encode
    let data = EncryptedData::from_der(bytes.as_slice()).unwrap();
    assert_eq!(CmsVersion::V0, data.version);

    assert_eq!(
        data.enc_content_info.content_type,
        const_oid::db::rfc5911::ID_DATA
    );

    let iv = hex!("898082D894EA58BBFBB46D4626EDC2BC");
    assert_eq!(
        data.enc_content_info.content_enc_alg.oid,
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.2")
    );
    assert_eq!(
        data.enc_content_info
            .content_enc_alg
            .parameters
            .as_ref()
            .unwrap()
            .value(),
        iv
    );

    let reencoded_data = data.to_der().unwrap();

    // assemble a new ContentInfo and encode it
    let ci2 = ContentInfo {
        content_type: ci.content_type,
        content: AnyRef::try_from(reencoded_data.as_slice())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let reencoded_data_inci = ci2.to_der().unwrap();

    // should match the original
    assert_eq!(reencoded_data_inci, der_ci)
}
