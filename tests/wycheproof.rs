//! Executes tests based on the wycheproof testsuite.

#![cfg(feature = "encoding")]

// This implementation here is based on
// <https://github.com/ctz/graviola/blob/main/graviola/tests/wycheproof.rs>

use std::{fmt::Debug, fs::File};

use pkcs1::DecodeRsaPublicKey;
use pkcs8::DecodePrivateKey;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey, pkcs1v15, pss, signature::Verifier};
use rstest::rstest;
use serde::Deserialize;
use sha1::Sha1;
use sha2::{
    Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
    digest::{Digest, FixedOutputReset},
};

#[derive(Deserialize, Debug)]
struct TestFile {
    #[serde(rename(deserialize = "testGroups"))]
    groups: Vec<TestGroup>,
    header: Vec<String>,
    algorithm: String,
}

#[derive(Deserialize, Debug)]
struct TestGroup {
    #[serde(rename(deserialize = "type"))]
    typ: String,

    #[serde(default, rename(deserialize = "publicKeyAsn"), with = "hex::serde")]
    public_key_asn: Vec<u8>,

    #[serde(default, rename(deserialize = "privateKeyPkcs8"), with = "hex::serde")]
    private_key_pkcs8: Vec<u8>,

    #[serde(default)]
    sha: String,

    #[serde(default, rename(deserialize = "mgfSha"))]
    mgf_sha: String,

    #[serde(default, rename(deserialize = "sLen"))]
    salt_len: usize,

    tests: Vec<Test>,
}

#[derive(Deserialize, Debug)]
struct Test {
    #[serde(rename(deserialize = "tcId"))]
    #[allow(unused)] // for Debug
    id: usize,
    #[allow(unused)] // for Debug
    comment: String,
    #[serde(default, with = "hex::serde")]
    msg: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    sig: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    ct: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    label: Vec<u8>,
    result: ExpectedResult,
}

#[derive(Copy, Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
enum ExpectedResult {
    Valid,
    Invalid,
    Acceptable,
}

#[derive(Debug)]
struct Summary {
    started: usize,
    skipped: usize,
    failed: usize,
    in_test: bool,
}

impl Summary {
    fn new() -> Self {
        Self {
            started: 0,
            skipped: 0,
            failed: 0,
            in_test: false,
        }
    }

    fn fail(&mut self, test: Test, res: impl Debug) {
        if self.in_test {
            eprintln!(
                "    failed: {}: expected {:?}, got {:?}",
                test.id, test.result, res
            );
            self.failed += 1;
            self.in_test = false;
        }
    }

    fn group(&mut self, group: &TestGroup) {
        println!("  group: {:?}", group.typ);
        self.in_test = false;
    }

    fn start(&mut self, test: &Test) {
        println!("    test {}:", test.id);
        self.started += 1;
        self.in_test = true;
    }

    fn skipped(&mut self, why: &str) {
        if self.in_test {
            println!("      skipped: {why}");
            self.skipped += 1;
            self.in_test = false;
        } else {
            println!("    skipped group: {why}");
        }
    }
}

impl Drop for Summary {
    fn drop(&mut self) {
        let passed = self.started - self.skipped - self.failed;
        println!(
            "DONE: started {} passed {} skipped {} failed {}",
            self.started, passed, self.skipped, self.failed
        );
        assert!(passed > 0, "no tests have passed");

        if self.failed > 0 {
            panic!("{} tests failed", self.failed);
        }
    }
}

#[rstest]
#[case("rsa_signature_2048_sha256_test.json")]
#[case("rsa_signature_2048_sha384_test.json")]
#[case("rsa_signature_2048_sha512_test.json")]
#[case("rsa_signature_3072_sha256_test.json")]
#[case("rsa_signature_3072_sha384_test.json")]
#[case("rsa_signature_3072_sha512_test.json")]
#[case("rsa_signature_4096_sha256_test.json")]
#[case("rsa_signature_4096_sha384_test.json")]
#[case("rsa_signature_4096_sha512_test.json")]
// #[case("rsa_signature_8192_sha256_test.json")] TODO: needs disabling of maxsize
// #[case("rsa_signature_8192_sha384_test.json")] TODO: needs disabling of maxsize
// #[case("rsa_signature_8192_sha512_test.json")] TODO: needs disabling of maxsize
fn test_rsa_pkcs1_verify(#[case] file: &str) {
    let path = format!("thirdparty/wycheproof/testvectors_v1/{file}");
    let data_file = File::open(&path)
        .expect("failed to open data file (try running `git submodule update --init`)");

    println!("Loading file: {path}");

    let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

    println!("{}:\n{}\n", tests.algorithm, tests.header.join(""));
    let mut summary = Summary::new();

    for group in tests.groups {
        summary.group(&group);

        let key = RsaPublicKey::from_pkcs1_der(&group.public_key_asn).unwrap();
        println!("key is {:?}", key);

        for test in group.tests {
            summary.start(&test);

            let sig = pkcs1v15::Signature::try_from(&test.sig[..]).expect("invalid signature");
            let result = match group.sha.as_ref() {
                "SHA-256" => {
                    let vk = pkcs1v15::VerifyingKey::<Sha256>::new(key.clone());
                    vk.verify(&test.msg, &sig)
                }
                "SHA-384" => {
                    let vk = pkcs1v15::VerifyingKey::<Sha384>::new(key.clone());
                    vk.verify(&test.msg, &sig)
                }
                "SHA-512" => {
                    let vk = pkcs1v15::VerifyingKey::<Sha512>::new(key.clone());
                    vk.verify(&test.msg, &sig)
                }
                other => panic!("unhandled sha {other:?}"),
            };

            match (test.result, &result) {
                (ExpectedResult::Valid, Ok(())) => {}
                (ExpectedResult::Invalid | ExpectedResult::Acceptable, Err(_err)) => {}
                _ => summary.fail(test, result.err()),
            }
        }
    }
}

#[rstest]
#[case("rsa_pss_2048_sha256_mgf1_0_test.json")]
#[case("rsa_pss_2048_sha256_mgf1_32_test.json")]
#[case("rsa_pss_2048_sha384_mgf1_48_test.json")]
#[case("rsa_pss_3072_sha256_mgf1_32_test.json")]
#[case("rsa_pss_4096_sha256_mgf1_32_test.json")]
#[case("rsa_pss_4096_sha384_mgf1_48_test.json")]
#[case("rsa_pss_4096_sha512_mgf1_64_test.json")]
#[case("rsa_pss_misc_test.json")]
fn test_rsa_pss_verify(#[case] file: &str) {
    let path = format!("thirdparty/wycheproof/testvectors_v1/{file}");
    let data_file = File::open(&path)
        .expect("failed to open data file (try running `git submodule update --init`)");

    println!("Loading file: {path}");

    let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

    println!("{}:\n{}\n", tests.algorithm, tests.header.join(""));
    let mut summary = Summary::new();

    for group in tests.groups {
        summary.group(&group);

        let key = RsaPublicKey::from_pkcs1_der(&group.public_key_asn).unwrap();
        println!("key is {:?}", key);

        for test in group.tests {
            summary.start(&test);

            if group.sha != group.mgf_sha {
                summary.skipped(&format!(
                    "pss with sha={} mgf={} salt_len={} not supported",
                    group.sha, group.mgf_sha, group.salt_len,
                ));
            }
            let sig = pss::Signature::try_from(&test.sig[..]).expect("invalid signature");
            let result = match group.sha.as_ref() {
                "SHA-1" => {
                    let vk =
                        pss::VerifyingKey::<Sha1>::new_with_salt_len(key.clone(), group.salt_len);
                    vk.verify(&test.msg, &sig)
                }
                "SHA-256" => {
                    let vk =
                        pss::VerifyingKey::<Sha256>::new_with_salt_len(key.clone(), group.salt_len);
                    vk.verify(&test.msg, &sig)
                }
                "SHA-224" => {
                    let vk =
                        pss::VerifyingKey::<Sha224>::new_with_salt_len(key.clone(), group.salt_len);
                    vk.verify(&test.msg, &sig)
                }
                "SHA-384" => {
                    let vk =
                        pss::VerifyingKey::<Sha384>::new_with_salt_len(key.clone(), group.salt_len);
                    vk.verify(&test.msg, &sig)
                }
                "SHA-512" => {
                    let vk =
                        pss::VerifyingKey::<Sha512>::new_with_salt_len(key.clone(), group.salt_len);
                    vk.verify(&test.msg, &sig)
                }
                other => panic!("unhandled sha {other:?}"),
            };

            match (test.result, &result) {
                (ExpectedResult::Valid, Ok(())) => {}
                (ExpectedResult::Invalid | ExpectedResult::Acceptable, Err(_err)) => {}
                _ => {
                    summary.fail(test, result.err());
                }
            };
        }
    }
}

fn oaep_decrypt<D, MGD>(key: &RsaPrivateKey, label: &[u8], ct: &[u8]) -> rsa::Result<Vec<u8>>
where
    D: Digest + FixedOutputReset,
    MGD: Digest + FixedOutputReset,
{
    if label.is_empty() {
        key.decrypt(Oaep::<D, MGD>::new_with_mgf_hash(), ct)
    } else {
        key.decrypt(Oaep::<D, MGD>::new_with_mgf_hash_and_label(label), ct)
    }
}

fn oaep_decrypt_with_mgf<D>(
    mgf_sha: &str,
    key: &RsaPrivateKey,
    label: &[u8],
    ct: &[u8],
) -> rsa::Result<Vec<u8>>
where
    D: Digest + FixedOutputReset,
{
    match mgf_sha {
        "SHA-1" => oaep_decrypt::<D, Sha1>(key, label, ct),
        "SHA-224" => oaep_decrypt::<D, Sha224>(key, label, ct),
        "SHA-256" => oaep_decrypt::<D, Sha256>(key, label, ct),
        "SHA-384" => oaep_decrypt::<D, Sha384>(key, label, ct),
        "SHA-512" => oaep_decrypt::<D, Sha512>(key, label, ct),
        "SHA-512/224" => oaep_decrypt::<D, Sha512_224>(key, label, ct),
        "SHA-512/256" => oaep_decrypt::<D, Sha512_256>(key, label, ct),
        other => panic!("unhandled mgf sha {other:?}"),
    }
}

#[rstest]
#[case("rsa_oaep_2048_sha1_mgf1sha1_test.json")]
#[case("rsa_oaep_2048_sha224_mgf1sha1_test.json")]
#[case("rsa_oaep_2048_sha224_mgf1sha224_test.json")]
#[case("rsa_oaep_2048_sha256_mgf1sha1_test.json")]
#[case("rsa_oaep_2048_sha256_mgf1sha256_test.json")]
#[case("rsa_oaep_2048_sha384_mgf1sha1_test.json")]
#[case("rsa_oaep_2048_sha384_mgf1sha384_test.json")]
#[case("rsa_oaep_2048_sha512_224_mgf1sha1_test.json")]
#[case("rsa_oaep_2048_sha512_224_mgf1sha512_224_test.json")]
#[case("rsa_oaep_2048_sha512_mgf1sha1_test.json")]
#[case("rsa_oaep_2048_sha512_mgf1sha512_test.json")]
#[case("rsa_oaep_3072_sha256_mgf1sha1_test.json")]
#[case("rsa_oaep_3072_sha256_mgf1sha256_test.json")]
#[case("rsa_oaep_3072_sha512_256_mgf1sha1_test.json")]
#[case("rsa_oaep_3072_sha512_256_mgf1sha512_256_test.json")]
#[case("rsa_oaep_3072_sha512_mgf1sha1_test.json")]
#[case("rsa_oaep_3072_sha512_mgf1sha512_test.json")]
#[case("rsa_oaep_4096_sha256_mgf1sha1_test.json")]
#[case("rsa_oaep_4096_sha256_mgf1sha256_test.json")]
#[case("rsa_oaep_4096_sha512_mgf1sha1_test.json")]
#[case("rsa_oaep_4096_sha512_mgf1sha512_test.json")]
#[case("rsa_oaep_misc_test.json")]
fn test_rsa_oaep_decrypt(#[case] file: &str) {
    let path = format!("thirdparty/wycheproof/testvectors_v1/{file}");
    let data_file = File::open(&path)
        .expect("failed to open data file (try running `git submodule update --init`)");

    println!("Loading file: {path}");

    let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");

    println!("{}:\n{}\n", tests.algorithm, tests.header.join(""));
    let mut summary = Summary::new();

    for group in tests.groups {
        summary.group(&group);

        let key = RsaPrivateKey::from_pkcs8_der(&group.private_key_pkcs8).unwrap();

        for mut test in group.tests {
            // Skip first byte tests as CFRG's RSA guidance requires ignoring the first OAEP octet:
            // https://www.ietf.org/archive/id/draft-irtf-cfrg-rsa-guidance-10.html#section-7
            if test.comment == "First byte is 1" {
                test.result = ExpectedResult::Valid;
            }

            summary.start(&test);

            let result = match group.sha.as_ref() {
                "SHA-1" => {
                    oaep_decrypt_with_mgf::<Sha1>(&group.mgf_sha, &key, &test.label, &test.ct)
                }
                "SHA-224" => {
                    oaep_decrypt_with_mgf::<Sha224>(&group.mgf_sha, &key, &test.label, &test.ct)
                }
                "SHA-256" => {
                    oaep_decrypt_with_mgf::<Sha256>(&group.mgf_sha, &key, &test.label, &test.ct)
                }
                "SHA-384" => {
                    oaep_decrypt_with_mgf::<Sha384>(&group.mgf_sha, &key, &test.label, &test.ct)
                }
                "SHA-512" => {
                    oaep_decrypt_with_mgf::<Sha512>(&group.mgf_sha, &key, &test.label, &test.ct)
                }
                "SHA-512/224" => {
                    oaep_decrypt_with_mgf::<Sha512_224>(&group.mgf_sha, &key, &test.label, &test.ct)
                }
                "SHA-512/256" => {
                    oaep_decrypt_with_mgf::<Sha512_256>(&group.mgf_sha, &key, &test.label, &test.ct)
                }
                other => panic!("unhandled sha {other:?}"),
            };

            match (test.result, &result) {
                (ExpectedResult::Valid | ExpectedResult::Acceptable, Ok(msg))
                    if *msg == test.msg => {}
                (ExpectedResult::Invalid | ExpectedResult::Acceptable, Err(_err)) => {}
                _ => summary.fail(test, result),
            }
        }
    }
}
