//! PKCS#1 v1.5 implicit rejection test vectors (draft-irtf-cfrg-rsa-guidance-08 appendix B: 2048-, 2049-, 4096-bit keys).
//! [draft-irtf-cfrg-rsa-guidance-08]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-guidance-08
//!
//! Vectors are stored in `examples/pkcs1v15_implicit_rfc/appendix_b.json`.

#![cfg(all(feature = "implicit_rejection", feature = "encoding"))]

use pkcs8::DecodePrivateKey;
use rsa::{traits::PublicKeyParts, Pkcs1v15EncryptImplicitRejection, RsaPrivateKey};
use serde::Deserialize;

#[derive(Deserialize)]
struct Appendix {
    #[serde(rename = "B.1")]
    b1: Section,
    #[serde(rename = "B.2")]
    b2: Section,
    #[serde(rename = "B.4")]
    b4: Section,
}

#[derive(Deserialize)]
struct Section {
    key_pem: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    ciphertext_hex: String,
    expect: Expect,
}

#[derive(Deserialize, Debug)]
struct Expect {
    #[serde(default)]
    empty: bool,
    ascii: Option<String>,
    hex: Option<String>,
}

fn static_key_pem(file: &str) -> &'static str {
    match file {
        "k2048.pem" => include_str!("examples/pkcs1v15_cfrg_rsa_guidance/k2048.pem"),
        "k2049.pem" => include_str!("examples/pkcs1v15_cfrg_rsa_guidance/k2049.pem"),
        "k4096.pem" => include_str!("examples/pkcs1v15_cfrg_rsa_guidance/k4096.pem"),
        _ => panic!("unknown key file {file}"),
    }
}

fn expected_bytes(ex: &Expect) -> Vec<u8> {
    if ex.empty {
        return Vec::new();
    }
    if let Some(s) = &ex.ascii {
        return s.as_bytes().to_vec();
    }
    if let Some(h) = &ex.hex {
        return hex::decode(h)
            .unwrap_or_else(|e| panic!("bad expect hex {}: {e}", ex.hex.as_deref().unwrap()));
    }
    panic!("expect exactly one of empty/ascii/hex ({ex:?})");
}

#[test]
fn implicit_rejection_draft_irtf_cfrg_rsa_guidance() {
    let data: Appendix = serde_json::from_str(include_str!(
        "examples/pkcs1v15_cfrg_rsa_guidance/test_cases.json"
    ))
    .unwrap();

    for section in [&data.b1, &data.b2, &data.b4] {
        let pem = static_key_pem(&section.key_pem);
        let key = RsaPrivateKey::from_pkcs8_pem(pem).unwrap_or_else(|e| {
            panic!("parse {}: {e}", section.key_pem);
        });

        for case in &section.cases {
            let ct = hex::decode(&case.ciphertext_hex)
                .unwrap_or_else(|e| panic!("{} bad ciphertext hex: {e}", case.id));
            assert_eq!(ct.len(), key.size(), "{} ciphertext length", case.id);

            let got = key
                .decrypt(Pkcs1v15EncryptImplicitRejection, &ct)
                .unwrap_or_else(|e| panic!("{} decrypt: {e}", case.id));
            let want = expected_bytes(&case.expect);
            assert_eq!(got, want, "{}", case.id);
        }
    }
}
