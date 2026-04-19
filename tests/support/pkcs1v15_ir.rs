#![allow(dead_code)]

use pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use serde::Deserialize;

const CASES_JSON: &str = include_str!("../examples/pkcs1v15_ir/cases.json");
const K2048_PEM: &str = include_str!("../examples/pkcs1v15_ir/k2048.pem");
const K2049_PEM: &str = include_str!("../examples/pkcs1v15_ir/k2049.pem");
const K3072_PEM: &str = include_str!("../examples/pkcs1v15_ir/k3072.pem");
const K4096_PEM: &str = include_str!("../examples/pkcs1v15_ir/k4096.pem");

#[derive(Debug, Deserialize)]
pub(crate) struct Corpus {
    pub(crate) families: Vec<Family>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Family {
    pub(crate) id: String,
    pub(crate) section: String,
    pub(crate) cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Case {
    pub(crate) title: String,
    ciphertext_hex: String,
    expected_hex: String,
}

impl Corpus {
    pub(crate) fn family(&self, id: &str) -> &Family {
        self.families
            .iter()
            .find(|family| family.id == id)
            .unwrap_or_else(|| panic!("missing family fixture: {id}"))
    }
}

impl Family {
    pub(crate) fn case(&self, title: &str) -> &Case {
        self.cases
            .iter()
            .find(|case| case.title == title)
            .unwrap_or_else(|| panic!("missing case fixture: {} / {title}", self.id))
    }

    pub(crate) fn invalid_cases(&self) -> impl Iterator<Item = &Case> {
        self.cases
            .iter()
            .filter(|case| case.title.starts_with("Invalid"))
    }
}

impl Case {
    pub(crate) fn ciphertext(&self) -> Vec<u8> {
        hex::decode(&self.ciphertext_hex)
            .unwrap_or_else(|e| panic!("invalid ciphertext_hex for case '{}': {e}", self.title))
    }

    pub(crate) fn expected(&self) -> Vec<u8> {
        hex::decode(&self.expected_hex)
            .unwrap_or_else(|e| panic!("invalid expected_hex for case '{}': {e}", self.title))
    }
}

pub(crate) fn load_corpus() -> Corpus {
    serde_json::from_str(CASES_JSON).expect("failed to parse tests/examples/pkcs1v15_ir/cases.json")
}

pub(crate) fn load_private_key(id: &str) -> RsaPrivateKey {
    let pem = match id {
        "k2048" => K2048_PEM,
        "k2049" => K2049_PEM,
        "k3072" => K3072_PEM,
        "k4096" => K4096_PEM,
        _ => panic!("missing PEM fixture: {id}"),
    };

    RsaPrivateKey::from_pkcs8_pem(pem)
        .unwrap_or_else(|e| panic!("failed to parse PKCS#8 fixture '{id}': {e}"))
}
