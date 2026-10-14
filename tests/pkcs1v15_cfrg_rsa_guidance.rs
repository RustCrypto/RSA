//! PKCS#1 v1.5 implicit rejection test vectors from
//! [draft-irtf-cfrg-rsa-guidance-10 appendix B](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-guidance-10#appendix-B).

#![cfg(feature = "encoding")]

use std::collections::HashMap;

use pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use serde::{de::IgnoredAny, Deserialize};

#[derive(Deserialize)]
struct Section {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    #[serde(rename = "ciphertext_hex", with = "hex")]
    ciphertext: Vec<u8>,
    expect: Expect,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Expect {
    Empty(IgnoredAny),
    Ascii(String),
    #[serde(with = "hex")]
    Hex(Vec<u8>),
}

macro_rules! example {
    ($file:literal) => {
        include_str!(concat!("examples/pkcs1v15_cfrg_rsa_guidance/", $file))
    };
}

const KEYS: [(&str, &str); 4] = [
    ("B.1", example!("k2048.pem")),
    ("B.2", example!("k2049.pem")),
    ("B.3", example!("k3072.pem")),
    ("B.4", example!("k4096.pem")),
];

#[test]
fn implicit_rejection_draft_irtf_cfrg_rsa_guidance() {
    let sections: HashMap<String, Section> =
        serde_json::from_str(example!("test_cases.json")).unwrap();

    for (section, pem) in KEYS {
        let key = RsaPrivateKey::from_pkcs8_pem(pem).unwrap();
        for case in &sections[section].cases {
            let expected = match &case.expect {
                Expect::Empty(_) => Vec::new(),
                Expect::Ascii(s) => s.as_bytes().to_vec(),
                Expect::Hex(h) => h.clone(),
            };
            let plaintext = key.decrypt(Pkcs1v15Encrypt, &case.ciphertext).unwrap();
            assert_eq!(plaintext, expected, "{}", case.id);
        }
    }
}
