//! Local PKCS#1 v1.5 timing driver for marvin-toolkit.

use anyhow::{Context, Result, ensure};
use clap::{Parser, ValueEnum};
use rsa::{
    Pkcs1v15Encrypt, RsaPrivateKey,
    pkcs8::DecodePrivateKey,
    traits::{PaddingScheme, PublicKeyParts},
};
use std::{
    fs::{self, File},
    hint::black_box,
    io::{BufReader, BufWriter, Read, Write},
    path::PathBuf,
    time::Instant,
};

#[derive(Debug, Parser)]
#[command(about = "Measure local rsa PKCS#1 v1.5 decryption times in nanoseconds")]
struct Args {
    /// Ciphertexts from marvin-toolkit's step2.py, in their generated order.
    #[arg(short, long)]
    infile: PathBuf,
    /// New CSV file to receive one timing per ciphertext.
    #[arg(short, long)]
    outfile: PathBuf,
    /// PKCS#8 PEM private key corresponding to the generated ciphertexts.
    #[arg(short, long)]
    keyfile: PathBuf,
    /// Ciphertext size in bytes; must match the key's modulus size.
    #[arg(short = 'n', long)]
    size: usize,
    /// Default API (OS blinding), explicit RNG blinding, or no blinding.
    #[arg(long, value_enum, default_value_t = Mode::Default)]
    mode: Mode,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Default,
    Blinded,
    Unblinded,
}

fn measure(args: &Args, mut decrypt: impl FnMut(&[u8]) -> rsa::Result<Vec<u8>>) -> Result<()> {
    let input = File::open(&args.infile).context("opening ciphertexts")?;
    let len = input.metadata()?.len();
    ensure!(len > 0, "ciphertext file is empty");
    ensure!(len % args.size as u64 == 0, "truncated ciphertext file");
    let mut input = BufReader::new(input);
    let output = File::create_new(&args.outfile).context("creating timing file")?;
    let mut output = BufWriter::new(output);
    writeln!(output, "raw times")?;
    let mut ciphertext = vec![0; args.size];

    for _ in 0..len / args.size as u64 {
        input.read_exact(&mut ciphertext)?;
        let start = Instant::now();
        let result = black_box(decrypt(black_box(&ciphertext)));
        let elapsed = start.elapsed().as_nanos();
        // Invalid padding uses implicit rejection, so generated probes should all
        // succeed. Check operational errors and dispose of the result after timing.
        drop(result.context("decrypting generated probe")?);
        writeln!(output, "{elapsed}")?;
    }
    output.flush()?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let pem = fs::read_to_string(&args.keyfile).context("reading PKCS#8 key")?;
    let mut key = RsaPrivateKey::from_pkcs8_pem(&pem)?;
    key.validate()?;
    key.precompute()?;
    ensure!(
        args.size == key.size(),
        "ciphertext size must match key size"
    );

    // Select the API outside the measured loop. Initialize the RNG before timing.
    match args.mode {
        Mode::Default => measure(&args, |ciphertext| key.decrypt(Pkcs1v15Encrypt, ciphertext)),
        Mode::Blinded => {
            let mut rng = rand::rng();
            measure(&args, |ciphertext| {
                key.decrypt_blinded(&mut rng, Pkcs1v15Encrypt, ciphertext)
            })
        }
        Mode::Unblinded => measure(&args, |ciphertext| {
            // Bypass the default API's OS blinding without changing Cargo features.
            Pkcs1v15Encrypt.decrypt::<rand::rngs::ThreadRng>(None, &key, ciphertext)
        }),
    }
}
