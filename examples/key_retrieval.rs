use rand::rngs::OsRng;
use rsa::pkcs1::{FromRsaPrivateKey, FromRsaPublicKey, ToRsaPrivateKey, ToRsaPublicKey};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let bits = 2048;

    let private_key_path = Path::new("id_rsa");
    let public_key_path = Path::new("id_rsa.pub");
    {
        // Create private key and write to .pem file
        let private_key = RsaPrivateKey::new(&mut rng, bits)?;
        private_key.write_pkcs1_pem_file(private_key_path)?;
    
        // Derive public key and write to .pen file
        let public_key = RsaPublicKey::from(&private_key);
        public_key.write_pkcs1_pem_file(public_key_path)?;
    }

    // Retrieve public key from .pem file
    let public_key = RsaPublicKey::read_pkcs1_pem_file(public_key_path)?;
    // Retrieve private key from .pem file
    let private_key = RsaPrivateKey::read_pkcs1_pem_file(private_key_path)?;

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

    Ok(())
}
