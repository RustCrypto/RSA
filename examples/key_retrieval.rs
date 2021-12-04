use rand::rngs::OsRng;
use rsa::pkcs1::{FromRsaPrivateKey, FromRsaPublicKey, ToRsaPrivateKey, ToRsaPublicKey};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

use std::fs::{read_to_string, File};
use std::io::Write;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let bits = 2048;

    let priv_key_path = Path::new("id_rsa");
    let pub_key_path = Path::new("id_rsa.pub");
    {
        // Create private key and write to .pem file
        let private_key = RsaPrivateKey::new(&mut rng, bits)?;
        let priv_key_pem = private_key.to_pkcs1_pem()?;

        let mut priv_key_file = File::create(priv_key_path)?;
        priv_key_file.write_all(priv_key_pem.as_bytes())?;

        // Derive public key and write to .pen file
        let public_key = RsaPublicKey::from(&private_key);
        let pub_key_pem = public_key.to_pkcs1_pem()?;

        let mut pub_key_file = File::create(pub_key_path)?;
        pub_key_file.write_all(pub_key_pem.as_bytes())?;
    }

    // Retrieve public key from .pem file
    let public_key_pem = read_to_string(pub_key_path)?;
    let public_key = RsaPublicKey::from_pkcs1_pem(&public_key_pem)?;
    // Retrieve private key from .pem file
    let private_key_pem = read_to_string(priv_key_path)?;
    let private_key = RsaPrivateKey::from_pkcs1_pem(&private_key_pem)?;

    // Encrypt data using public key
    let data = b"hello world";
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let enc_data = public_key
        .encrypt(&mut rng, padding, &data[..])
        .expect("failed to encrypt");
    assert_ne!(&data[..], &enc_data[..]);

    // Decrypt data using private key
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let dec_data = private_key
        .decrypt(padding, &enc_data)
        .expect("failed to decrypt");
    assert_eq!(&data[..], &dec_data[..]);
}
