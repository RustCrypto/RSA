#![cfg(feature = "encoding")]

#[path = "support/pkcs1v15_ir.rs"]
mod support;

use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

#[test]
fn appendix_b_vectors_match_draft_08() {
    let corpus = support::load_corpus();
    assert_eq!(corpus.families.len(), 4);

    for family in &corpus.families {
        assert_eq!(family.cases.len(), 12, "{}", family.section);

        let private_key: RsaPrivateKey = support::load_private_key(&family.id);

        for case in &family.cases {
            let decrypted = private_key
                .decrypt(Pkcs1v15Encrypt, &case.ciphertext())
                .unwrap_or_else(|e| {
                    panic!("{} {}: decrypt failed: {e}", family.section, case.title)
                });
            assert_eq!(
                decrypted,
                case.expected(),
                "{} {}",
                family.section,
                case.title
            );
        }
    }
}
