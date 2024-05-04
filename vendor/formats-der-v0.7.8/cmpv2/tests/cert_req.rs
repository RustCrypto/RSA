use cmpv2::body::PkiBody;
use cmpv2::message::PkiMessage;
use cmpv2::status::PkiStatus;
use const_oid::ObjectIdentifier;
use crmf::pop::ProofOfPossession;
use der::{Decode, Encode};
use hex_literal::hex;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::Certificate;

#[test]
fn cr_req_message_test() {
    // read request object created and captured via:
    // server:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-server-key.pem
    //   - openssl req -new -key ec384-server-key.pem -out ec384-server-key.csr
    //   - openssl req -text -in ec384-server-key.csr -noout
    //   - openssl x509 -req -days 365 -in ec384-server-key.csr -signkey ec384-server-key.pem -out ec384-server-key.crt
    //   - openssl cmp -port 8888 -srv_ref ABCD --srv_key ec384-server-key.pem -srv_cert ec384-server-key.crt
    // client:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-key-pair.pem
    //   - openssl cmp -cmd cr -server 127.0.0.1:8888 -path pkix/ -ref 1234 -secret pass:1234-5678-1234-5678 -recipient "/CN=CMPserver" -newkey ec384-key-pair.pem -subject "/CN=MyName" -cacertsout capubs.pem -certout cl_cert.pem -srv_cert ec384-server-key.crt -reqout cr_req_01.bin -rspout cr_rsp_01.bin
    let req_01 = include_bytes!("examples/cr_req_01.bin");
    let result = PkiMessage::from_der(req_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let message = result.unwrap();

    let header = &message.header;
    match &header.sender {
        GeneralName::DirectoryName(name) => assert_eq!("CN=MyName", name.to_string()),
        _ => panic!(),
    }
    match &header.recipient {
        GeneralName::DirectoryName(name) => assert_eq!("CN=CMPserver", name.to_string()),
        _ => panic!(),
    }
    let m = header.message_time.unwrap();
    assert_eq!(1674070261000, m.to_unix_duration().as_millis());
    assert_eq!(
        const_oid::db::rfc5912::ID_PASSWORD_BASED_MAC,
        header.protection_alg.as_ref().unwrap().oid
    );
    //inspect params
    assert_eq!(
        "1234".as_bytes(),
        header.sender_kid.as_ref().unwrap().as_bytes()
    );
    assert_eq!(
        hex!("6A 6A 01 B0 84 DF 4D 56 C1 25 DA 54 5F 4C 5E C1"),
        header.trans_id.as_ref().unwrap().as_bytes()
    );
    assert_eq!(
        hex!("29 16 D3 95 71 A4 EF 23 88 43 20 78 E8 90 00 64"),
        header.sender_nonce.as_ref().unwrap().as_bytes()
    );

    match &message.body {
        PkiBody::Cr(crs) => {
            assert_eq!(1, crs.len());
            let cr = &crs[0];
            assert_eq!([0x00], cr.cert_req.cert_req_id.as_bytes());
            assert_eq!(
                "CN=MyName",
                cr.cert_req
                    .cert_template
                    .subject
                    .as_ref()
                    .unwrap()
                    .to_string()
            );
            let spki = cr
                .cert_req
                .cert_template
                .subject_public_key_info
                .as_ref()
                .unwrap();
            assert_eq!(
                ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
                spki.algorithm.oid
            );
            assert_eq!(
                const_oid::db::rfc5912::SECP_384_R_1.as_bytes(),
                spki.algorithm.parameters.as_ref().unwrap().value()
            );
            match cr.popo.as_ref().unwrap() {
                ProofOfPossession::Signature(sig) => {
                    assert_eq!(const_oid::db::rfc5912::ECDSA_WITH_SHA_256, sig.alg_id.oid);
                }
                _ => panic!(),
            }
        }
        _ => panic!(),
    };

    let protection = message.protection.as_ref().unwrap();
    assert_eq!(
        hex!("60 8D 69 86 58 C7 76 DD 16 EC 1E AC 00 A8 74 69 0F 52 2C 59"),
        protection.as_bytes().unwrap()
    );

    let reencoded_req_01 = message.to_der().unwrap();
    println!("Original : {:02X?}", req_01);
    println!("Reencoded: {:02X?}", reencoded_req_01);
    assert_eq!(req_01, reencoded_req_01.as_slice());
}

#[test]
fn cr_rsp_message_test() {
    // read request object created and captured via:
    // server:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-server-key.pem
    //   - openssl req -new -key ec384-server-key.pem -out ec384-server-key.csr
    //   - openssl req -text -in ec384-server-key.csr -noout
    //   - openssl x509 -req -days 365 -in ec384-server-key.csr -signkey ec384-server-key.pem -out ec384-server-key.crt
    //   - openssl cmp -port 8888 -srv_ref ABCD --srv_key ec384-server-key.pem -srv_cert ec384-server-key.crt
    // client:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-key-pair.pem
    //   - openssl cmp -cmd cr -server 127.0.0.1:8888 -path pkix/ -ref 1234 -secret pass:1234-5678-1234-5678 -recipient "/CN=CMPserver" -newkey ec384-key-pair.pem -subject "/CN=MyName" -cacertsout capubs.pem -certout cl_cert.pem -srv_cert ec384-server-key.crt -reqout cr_req_01.bin -rspout cr_rsp_01.bin
    let req_01 = include_bytes!("examples/cr_rsp_01.bin");
    let result = PkiMessage::from_der(req_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let message = result.unwrap();

    let enc_server_cert = include_bytes!("examples/ec384-server-key.der");
    let server_cert = Certificate::from_der(enc_server_cert).unwrap();
    let header = &message.header;
    match &header.sender {
        GeneralName::DirectoryName(name) => assert_eq!(server_cert.tbs_certificate.subject, *name),
        _ => panic!(),
    }
    match &header.recipient {
        GeneralName::DirectoryName(name) => assert_eq!("CN=MyName", name.to_string()),
        _ => panic!(),
    }
    let m = header.message_time.unwrap();
    assert_eq!(1674070261000, m.to_unix_duration().as_millis());
    assert_eq!(
        const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
        header.protection_alg.as_ref().unwrap().oid
    );
    //inspect params
    assert_eq!(
        "ABCD".as_bytes(),
        header.sender_kid.as_ref().unwrap().as_bytes()
    );
    assert_eq!(
        hex!("6A 6A 01 B0 84 DF 4D 56 C1 25 DA 54 5F 4C 5E C1"),
        header.trans_id.as_ref().unwrap().as_bytes()
    );
    assert_eq!(
        hex!("FB 3B 11 E4 7B D9 A6 EF 79 16 E5 66 03 F6 81 F1"),
        header.sender_nonce.as_ref().unwrap().as_bytes()
    );
    assert_eq!(
        hex!("29 16 D3 95 71 A4 EF 23 88 43 20 78 E8 90 00 64"),
        header.recip_nonce.as_ref().unwrap().as_bytes()
    );

    match &message.body {
        PkiBody::Cp(cp) => {
            assert_eq!(1, cp.response.len());
            let cr = &cp.response[0];
            assert_eq!([0x00], cr.cert_req_id.as_bytes());
            let status = &cr.status;
            assert_eq!(PkiStatus::Accepted, status.status);
        }
        _ => panic!(),
    };

    let protection = message.protection.as_ref().unwrap();
    assert_eq!(105u32, protection.encoded_len().unwrap().into());

    let reencoded_req_01 = message.to_der().unwrap();
    println!("Original : {:02X?}", req_01);
    println!("Reencoded: {:02X?}", reencoded_req_01);
    assert_eq!(req_01, reencoded_req_01.as_slice());
}
