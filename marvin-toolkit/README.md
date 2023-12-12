# Marvin tool-kit integration
This document describes the procedure for replicating the analysis for the Marvin attack. This analysis is best done on a container for reproducibility.

**TL;DR**:
```bash
# Build the image
docker build -t marvin:latest .

# Create the output directory and allow container to write to it
mkdir -p outputs
chmod a+rw outputs

# Run the analysis
docker run -d --rm \
    --name marvin \
    -v $(pwd)/outputs:/home/rustcrypto/marvin-toolkit/outputs \
    -v $(pwd)/Cargo.toml:/home/rustcrypto/marvin-toolkit/example/rust-crypto/Cargo.toml \
    marvin:latest

# Use "docker logs -f marvin" to read live output

# Read the output
cat outputs/results/report.txt
```

## Adjusting analysis parameters
For more help on the options pass in the `-h` flag in the `docker run` command:

```
docker run ... marvin:latest -h
```

There are two main parameters of the analysis: RSA key size and the number of repetitions during ciphertext generation.

RSA key size is specified through `-s <1024|2048|4096>`. The number of repetition is specified through `-n <num>`. A larger repetition number will increase the confidence of the analysis, but will make the analysis take longer. The default key size is 2048 and the default repetition count is 100,000.

```bash
# Run analysis for RSA 4096 with 1 million repetition
docker run -d --rm \
    --name marvin \
    marvin:latest -s 4096 -n 1000000
```

## Extracting keys, ciphertexts, and analysis results (WIP)
After the analysis is done, the generate keys, ciphertexts, and the analysis outputs are all copied into the directory `/home/rustcrypto/marvin-toolkit/outputs`. To extract and preserve these artifacts, mount a volume into this directory, such as using a bind mount:

```bash
mkdir -p outputs
chmod a+rw outputs

# Mount
docker run -d --rm --name "marvin" \
    -v $(pwd)/outputs:/home/rustcrypto/marvin-toolkit/outputs \
    marvin:latest
```

## Compile test harness with custom `Cargo.toml`
The test harness is compiled at container run-time, so a custom `Cargo.toml` can be passed into the container at runtime to compile the test harness using custom versions of `RustCrypto/RSA` and/or `RustCrypto/crypto-bigint`:

```bash
docker run -d --rm --name "marvin" \
    -v $(pwd)/Cargo.toml:/home/rustcrypto/marvin-toolkit/example/rust-crypto/Cargo.toml \
    marvin:latest
```

If no `Cargo.toml` is specified, the default one will use `rsa = 0.9`