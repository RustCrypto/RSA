use cms::content_info::ContentInfo;
use cms::enveloped_data::EnvelopedData;
use crmf::controls::{EncryptedKey, PkiArchiveOptions};
use der::{Decode, Encode};

#[test]
fn pki_archive_options_test() {
    let der_ci = include_bytes!("../../cms/tests/examples/enveloped_data_ktri.bin");
    let ci = ContentInfo::from_der(der_ci).unwrap();
    assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_ENVELOPED_DATA);

    // re-encode the AnyRef to get the SignedData bytes
    let bytes = ci.content.to_der().unwrap();

    // parse as EnvelopedData then re-encode
    let data = EnvelopedData::from_der(bytes.as_slice()).unwrap();

    let pao = PkiArchiveOptions::EncryptedPrivKey(EncryptedKey::EnvelopedData(Box::new(data)));
    let encoded_data = pao.to_der().unwrap();
    let pao2 = PkiArchiveOptions::from_der(encoded_data.as_slice()).unwrap();
    let encoded_data2 = pao2.to_der().unwrap();
    assert_eq!(encoded_data, encoded_data2);
    println!("Encoded : {:02X?}", encoded_data);
    match pao2 {
        PkiArchiveOptions::EncryptedPrivKey(EncryptedKey::EnvelopedData(ed2)) => {
            let reencoded_ed = ed2.to_der().unwrap();
            assert_eq!(bytes, reencoded_ed);
        }
        _ => panic!(),
    }
}
