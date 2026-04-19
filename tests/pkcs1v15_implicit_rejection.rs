#![cfg(feature = "encoding")]

#[path = "support/pkcs1v15_ir.rs"]
mod support;

use rand::rngs::ChaCha8Rng;
use rand_core::SeedableRng;
use rsa::{
    pkcs1v15::DecryptingKey,
    traits::{Decryptor, PublicKeyParts, RandomizedDecryptor},
    Error, Pkcs1v15Encrypt,
};

#[test]
fn wrong_length_ciphertexts_still_error() {
    let corpus = support::load_corpus();
    let family = corpus.family("k2048");
    let private_key = support::load_private_key("k2048");
    let mut ciphertext = family.case("Valid").ciphertext();
    ciphertext.pop();

    assert_eq!(
        private_key.decrypt(Pkcs1v15Encrypt, &ciphertext),
        Err(Error::Decryption)
    );
}

#[test]
fn out_of_range_ciphertexts_still_error() {
    let private_key = support::load_private_key("k2048");
    let modulus_bytes = private_key.n_bytes();
    let mut ciphertext = vec![0u8; private_key.size()];
    ciphertext[private_key.size() - modulus_bytes.len()..].copy_from_slice(&modulus_bytes);

    assert_eq!(
        private_key.decrypt(Pkcs1v15Encrypt, &ciphertext),
        Err(Error::Decryption)
    );
}

#[test]
fn implicit_rejection_is_deterministic_with_and_without_blinding() {
    let corpus = support::load_corpus();
    let family = corpus.family("k2048");
    let private_key = support::load_private_key("k2048");

    for case in family.invalid_cases() {
        let expected = private_key
            .decrypt(Pkcs1v15Encrypt, &case.ciphertext())
            .unwrap();
        let mut rng = ChaCha8Rng::from_seed([7; 32]);
        let blinded = private_key
            .decrypt_blinded(&mut rng, Pkcs1v15Encrypt, &case.ciphertext())
            .unwrap();

        assert_eq!(expected, case.expected(), "{}", case.title);
        assert_eq!(blinded, case.expected(), "{}", case.title);
    }
}

#[test]
fn different_invalid_ciphertexts_produce_distinct_rejection_symbols() {
    let corpus = support::load_corpus();
    let family = corpus.family("k2048");
    let private_key = support::load_private_key("k2048");
    let first = family.case("Invalid first byte of padding");
    let second = family.case("Invalid second byte of padding");

    let first_output = private_key
        .decrypt(Pkcs1v15Encrypt, &first.ciphertext())
        .unwrap();
    let second_output = private_key
        .decrypt(Pkcs1v15Encrypt, &second.ciphertext())
        .unwrap();

    assert_ne!(first_output, second_output);
}

#[test]
fn decrypting_key_matches_shared_decrypt_path_for_invalid_padding() {
    let corpus = support::load_corpus();
    let family = corpus.family("k2048");
    let private_key = support::load_private_key("k2048");
    let decrypting_key = DecryptingKey::new(private_key.clone());
    let case = family.case("Invalid with padding separator missing");
    let expected = private_key
        .decrypt(Pkcs1v15Encrypt, &case.ciphertext())
        .unwrap();
    let mut rng = ChaCha8Rng::from_seed([9; 32]);

    assert_eq!(
        decrypting_key.decrypt(&case.ciphertext()).unwrap(),
        expected
    );
    assert_eq!(
        decrypting_key
            .decrypt_with_rng(&mut rng, &case.ciphertext())
            .unwrap(),
        expected
    );
}
