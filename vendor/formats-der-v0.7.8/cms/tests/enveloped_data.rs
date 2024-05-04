extern crate core;

use cms::content_info::{CmsVersion, ContentInfo};
use cms::enveloped_data::{
    EnvelopedData, KeyAgreeRecipientIdentifier, OriginatorIdentifierOrKey, RecipientIdentifier,
    RecipientInfo,
};
use const_oid::ObjectIdentifier;
use der::{AnyRef, Decode, Encode, Tag, Tagged};
use hex_literal::hex;
use pkcs5::pbes2::Pbkdf2Params;
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

#[test]
fn reencode_enveloped_data_ktri_test() {
    // read EnvelopedData object created via:
    //  openssl cms -encrypt -in data.txt -recip cert.der -originator cert.der -out enveloped_data.bin -aes256 -outform DER
    let der_ci = include_bytes!("examples/enveloped_data_ktri.bin");
    let ci = ContentInfo::from_der(der_ci).unwrap();
    assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_ENVELOPED_DATA);

    // re-encode the AnyRef to get the SignedData bytes
    let bytes = ci.content.to_der().unwrap();

    // parse as EnvelopedData then re-encode
    let data = EnvelopedData::from_der(bytes.as_slice()).unwrap();
    assert_eq!(CmsVersion::V0, data.version);

    assert_eq!(
        data.encrypted_content.content_type,
        const_oid::db::rfc5911::ID_DATA
    );

    let rsa_cert = include_bytes!("examples/rsa_cert.der");
    let cert = Certificate::from_der(rsa_cert).unwrap();
    assert_eq!(1, data.recip_infos.0.len());
    for ri in data.recip_infos.0.iter() {
        match ri {
            RecipientInfo::Ktri(ktri) => {
                assert_eq!(CmsVersion::V0, ktri.version);
                assert_eq!(
                    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
                    ktri.key_enc_alg.oid
                );
                assert_eq!(
                    Tag::Null,
                    ktri.key_enc_alg.parameters.as_ref().unwrap().tag()
                );
                match &ktri.rid {
                    RecipientIdentifier::IssuerAndSerialNumber(iasn) => {
                        assert_eq!(cert.tbs_certificate.issuer, iasn.issuer);
                        assert_eq!(cert.tbs_certificate.serial_number, iasn.serial_number);
                    }
                    _ => panic!(),
                }
            }
            _ => panic!(),
        }
    }

    let iv = hex!("FA5ABFA1AECE35AB8A6485BEFBB7D8E0");
    assert_eq!(
        data.encrypted_content.content_enc_alg.oid,
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42")
    );
    assert_eq!(
        data.encrypted_content
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
    let reencoded_data_in_ci = ci2.to_der().unwrap();

    // should match the original
    assert_eq!(reencoded_data_in_ci, der_ci)
}

#[test]
fn reencode_enveloped_data_kari_test() {
    // read EnvelopedData object created via:
    //  openssl cms -encrypt -in data.txt -out enveloped_data_kari.bin -aes256 -outform DER -binary eci384-ee-key.der
    let der_ci = include_bytes!("examples/enveloped_data_kari.bin");
    let ci = ContentInfo::from_der(der_ci).unwrap();
    assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_ENVELOPED_DATA);

    // re-encode the AnyRef to get the SignedData bytes
    let bytes = ci.content.to_der().unwrap();

    // parse as EnvelopedData then re-encode
    let data = EnvelopedData::from_der(bytes.as_slice()).unwrap();
    assert_eq!(CmsVersion::V2, data.version);

    assert_eq!(
        data.encrypted_content.content_type,
        const_oid::db::rfc5911::ID_DATA
    );

    let ec_cert = include_bytes!("examples/ec384-ee-key.der");
    let cert = Certificate::from_der(ec_cert).unwrap();
    assert_eq!(1, data.recip_infos.0.len());
    for ri in data.recip_infos.0.iter() {
        match ri {
            RecipientInfo::Kari(kari) => {
                assert_eq!(CmsVersion::V3, kari.version);
                match &kari.originator {
                    OriginatorIdentifierOrKey::OriginatorKey(ok) => {
                        assert_eq!(
                            ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
                            ok.algorithm.oid
                        );
                        assert_eq!(None, ok.algorithm.parameters);
                    }
                    _ => panic!(),
                }
                assert_eq!(
                    ObjectIdentifier::new_unwrap("1.3.133.16.840.63.0.2"),
                    kari.key_enc_alg.oid
                );
                let params_alg = AlgorithmIdentifierOwned::from_der(
                    kari.key_enc_alg
                        .parameters
                        .as_ref()
                        .unwrap()
                        .to_der()
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
                assert_eq!(
                    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45"),
                    params_alg.oid
                );

                for rk in &kari.recipient_enc_keys {
                    match &rk.rid {
                        KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(iasn) => {
                            assert_eq!(cert.tbs_certificate.issuer, iasn.issuer);
                            assert_eq!(cert.tbs_certificate.serial_number, iasn.serial_number);
                        }
                        _ => panic!(),
                    }
                }
            }
            _ => panic!(),
        }
    }

    let iv = hex!("62E7BA310340FE8CEB32765240778AFD");
    assert_eq!(
        data.encrypted_content.content_enc_alg.oid,
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42")
    );
    assert_eq!(
        data.encrypted_content
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
    let reencoded_data_in_ci = ci2.to_der().unwrap();

    // should match the original
    assert_eq!(reencoded_data_in_ci, der_ci)
}

#[test]
fn reencode_enveloped_data_pwri_test() {
    // read EnvelopedData object created via:
    //  openssl cms -encrypt -in data.txt  -out enveloped_data_pwri.bin -outform DER -pwri_password password -aes128 -binary
    let der_ci = include_bytes!("examples/enveloped_data_pwri.bin");
    let ci = ContentInfo::from_der(der_ci).unwrap();
    assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_ENVELOPED_DATA);

    // re-encode the AnyRef to get the SignedData bytes
    let bytes = ci.content.to_der().unwrap();

    // parse as EnvelopedData then re-encode
    let data = EnvelopedData::from_der(bytes.as_slice()).unwrap();
    assert_eq!(CmsVersion::V3, data.version);

    assert_eq!(
        data.encrypted_content.content_type,
        const_oid::db::rfc5911::ID_DATA
    );

    assert_eq!(1, data.recip_infos.0.len());
    for ri in data.recip_infos.0.iter() {
        match ri {
            RecipientInfo::Pwri(pwri) => {
                assert_eq!(CmsVersion::V0, pwri.version);
                let kdf_alg = pwri.key_derivation_alg.as_ref().unwrap();
                assert_eq!(
                    ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.12"),
                    kdf_alg.oid
                );
                let enc_pbkdf2 = kdf_alg.parameters.as_ref().unwrap().to_der().unwrap();
                let pbkdf2 = Pbkdf2Params::from_der(enc_pbkdf2.as_slice()).unwrap();
                assert_eq!(hex!("7F EE A8 FD 56 8E 8F 07"), pbkdf2.salt);
                assert_eq!(2048, pbkdf2.iteration_count);
                assert_eq!(
                    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.9"),
                    pwri.key_enc_alg.oid
                );
                let params_alg = AlgorithmIdentifierOwned::from_der(
                    pwri.key_enc_alg
                        .parameters
                        .as_ref()
                        .unwrap()
                        .to_der()
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
                assert_eq!(
                    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.2"),
                    params_alg.oid
                );
                let os = params_alg.parameters.as_ref().unwrap().value();
                assert_eq!(hex!("9C B5 40 61 E3 9D 56 D0 40 8B 8D E7 DE AD 77 1C"), os)
            }
            _ => panic!(),
        }
    }

    let iv = hex!("0381DB365D03E89C4194904626EC5713");
    assert_eq!(
        data.encrypted_content.content_enc_alg.oid,
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.2")
    );
    assert_eq!(
        data.encrypted_content
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
    let reencoded_data_in_ci = ci2.to_der().unwrap();

    // should match the original
    assert_eq!(reencoded_data_in_ci, der_ci)
}

#[test]
fn reencode_enveloped_data_kek_test() {
    // read EnvelopedData object created via:
    //  openssl cms -encrypt -in data.txt  -out enveloped_data_kek.bin -outform DER -secretkey 0102030405060708090A0B0C0D0E0F00 -aes128 -binary --secretkeyid DEADBEEF
    let der_ci = include_bytes!("examples/enveloped_data_kekri.bin");
    let ci = ContentInfo::from_der(der_ci).unwrap();
    assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_ENVELOPED_DATA);

    // re-encode the AnyRef to get the SignedData bytes
    let bytes = ci.content.to_der().unwrap();

    // parse as EnvelopedData then re-encode
    let data = EnvelopedData::from_der(bytes.as_slice()).unwrap();
    assert_eq!(CmsVersion::V2, data.version);

    assert_eq!(
        data.encrypted_content.content_type,
        const_oid::db::rfc5911::ID_DATA
    );

    assert_eq!(1, data.recip_infos.0.len());
    for ri in data.recip_infos.0.iter() {
        match ri {
            RecipientInfo::Kekri(kekri) => {
                assert_eq!(CmsVersion::V4, kekri.version);
                assert_eq!(hex!("DEADBEEF"), kekri.kek_id.kek_identifier.as_bytes());
                assert_eq!(
                    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.5"),
                    kekri.key_enc_alg.oid
                );
            }
            _ => panic!(),
        }
    }

    let iv = hex!("F26776E818FFB5BB650F54AF38B7A6C4");
    assert_eq!(
        data.encrypted_content.content_enc_alg.oid,
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.2")
    );
    assert_eq!(
        data.encrypted_content
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
    let reencoded_data_in_ci = ci2.to_der().unwrap();

    // should match the original
    assert_eq!(reencoded_data_in_ci, der_ci)
}

#[test]
fn reencode_enveloped_data_multi_test() {
    // read EnvelopedData object created via:
    //  openssl cms -encrypt -in data.txt -out enveloped_data_multi.bin -aes256 -outform DER -pwri_password password -secretkey 0102030405060708090A0B0C0D0E0F00 --secretkeyid DEADBEEF cert.der ec384-ee-key.der
    let der_ci = include_bytes!("examples/enveloped_data_multi.bin");
    let ci = ContentInfo::from_der(der_ci).unwrap();
    assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_ENVELOPED_DATA);

    // re-encode the AnyRef to get the SignedData bytes
    let bytes = ci.content.to_der().unwrap();

    // parse as EnvelopedData then re-encode
    let data = EnvelopedData::from_der(bytes.as_slice()).unwrap();
    assert_eq!(CmsVersion::V3, data.version);

    assert_eq!(
        data.encrypted_content.content_type,
        const_oid::db::rfc5911::ID_DATA
    );

    let enc_rsa_cert = include_bytes!("examples/rsa_cert.der");
    let rsa_cert = Certificate::from_der(enc_rsa_cert).unwrap();
    let enc_ec_cert = include_bytes!("examples/ec384-ee-key.der");
    let ec_cert = Certificate::from_der(enc_ec_cert).unwrap();

    assert_eq!(4, data.recip_infos.0.len());
    for ri in data.recip_infos.0.iter() {
        match ri {
            RecipientInfo::Ktri(ktri) => {
                assert_eq!(CmsVersion::V0, ktri.version);
                assert_eq!(
                    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
                    ktri.key_enc_alg.oid
                );
                assert_eq!(
                    Tag::Null,
                    ktri.key_enc_alg.parameters.as_ref().unwrap().tag()
                );
                match &ktri.rid {
                    RecipientIdentifier::IssuerAndSerialNumber(iasn) => {
                        assert_eq!(rsa_cert.tbs_certificate.issuer, iasn.issuer);
                        assert_eq!(rsa_cert.tbs_certificate.serial_number, iasn.serial_number);
                    }
                    _ => panic!(),
                }
            }
            RecipientInfo::Kari(kari) => {
                assert_eq!(CmsVersion::V3, kari.version);
                match &kari.originator {
                    OriginatorIdentifierOrKey::OriginatorKey(ok) => {
                        assert_eq!(
                            ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
                            ok.algorithm.oid
                        );
                        assert_eq!(None, ok.algorithm.parameters);
                    }
                    _ => panic!(),
                }
                assert_eq!(
                    ObjectIdentifier::new_unwrap("1.3.133.16.840.63.0.2"),
                    kari.key_enc_alg.oid
                );
                let params_alg = AlgorithmIdentifierOwned::from_der(
                    kari.key_enc_alg
                        .parameters
                        .as_ref()
                        .unwrap()
                        .to_der()
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
                assert_eq!(
                    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45"),
                    params_alg.oid
                );

                for rk in &kari.recipient_enc_keys {
                    match &rk.rid {
                        KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(iasn) => {
                            assert_eq!(ec_cert.tbs_certificate.issuer, iasn.issuer);
                            assert_eq!(ec_cert.tbs_certificate.serial_number, iasn.serial_number);
                        }
                        _ => panic!(),
                    }
                }
            }
            RecipientInfo::Pwri(pwri) => {
                assert_eq!(CmsVersion::V0, pwri.version);
                let kdf_alg = pwri.key_derivation_alg.as_ref().unwrap();
                assert_eq!(
                    ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.12"),
                    kdf_alg.oid
                );
                let enc_pbkdf2 = kdf_alg.parameters.as_ref().unwrap().to_der().unwrap();
                let pbkdf2 = Pbkdf2Params::from_der(enc_pbkdf2.as_slice()).unwrap();
                assert_eq!(hex!("39 04 A7 33 A0 6A 1B 27"), pbkdf2.salt);
                assert_eq!(2048, pbkdf2.iteration_count);
                assert_eq!(
                    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.9"),
                    pwri.key_enc_alg.oid
                );
                let params_alg = AlgorithmIdentifierOwned::from_der(
                    pwri.key_enc_alg
                        .parameters
                        .as_ref()
                        .unwrap()
                        .to_der()
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
                assert_eq!(
                    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42"),
                    params_alg.oid
                );
                let os = params_alg.parameters.as_ref().unwrap().value();
                assert_eq!(hex!("20ABB209D2C71522C578610E61AE8DC3"), os)
            }
            RecipientInfo::Kekri(kekri) => {
                assert_eq!(CmsVersion::V4, kekri.version);
                assert_eq!(hex!("DEADBEEF"), kekri.kek_id.kek_identifier.as_bytes());
                assert_eq!(
                    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.5"),
                    kekri.key_enc_alg.oid
                );
            }
            _ => panic!(),
        }
    }

    let iv = hex!("3FD9F4A34B2DD65EA2CE75D8CCBAA8FE");
    assert_eq!(
        data.encrypted_content.content_enc_alg.oid,
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42")
    );
    assert_eq!(
        data.encrypted_content
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
    let reencoded_data_in_ci = ci2.to_der().unwrap();

    // should match the original
    assert_eq!(reencoded_data_in_ci, der_ci)
}
