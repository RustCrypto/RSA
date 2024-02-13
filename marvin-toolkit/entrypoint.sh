#!/bin/bash

# Build the test harness
cd example/rust-crypto
cargo update --quiet
cargo build --profile release --quiet
cd ~/marvin-toolkit

# Parse CLI inputs to $size and $repeat
size=2048
repeat=100000

# Function to display help message
display_help() {
  echo "Usage: $0 [-s SIZE] [-n NUMBER] [-h]"
  echo "  -s SIZE    Set the RSA key size (1024, 2048, or 4096; default: 2048)"
  echo "  -n NUMBER  Set the repeat number (integer; default: 100000)"
  echo "  -h         Display this help message"
}

# Parse command-line arguments using getopts
while getopts ":s:n:h" opt; do
  case $opt in
    s)
      size=$OPTARG
      if [[ ! "$size" =~ ^(1024|2048|4096)$ ]]; then
        echo "Error: Invalid size. Please choose 1024, 2048, or 4096."
        exit 1
      fi
      ;;
    n)
      repeat=$OPTARG
      if ! [[ "$repeat" =~ ^[0-9]+$ ]]; then
        echo "Error: Invalid number. Please specify a valid integer."
        exit 1
      fi
      ;;
    h)
      display_help
      exit 0
      ;;
    \?)
      echo "Error: Invalid option -$OPTARG"
      display_help
      exit 1
      ;;
    :)
      echo "Error: Option -$OPTARG requires an argument."
      display_help
      exit 1
      ;;
  esac
done
size_bytes=$(($size / 8))

# Step 1: Generate key pairs
. ./certgen/certgen/lib.sh
name="rsa${size}"
tmp_file="$(mktemp)"
if ! x509KeyGen -s $size $name &> "$tmp_file"; then
    echo "ERROR $size bit key generation failed" >&2
    cat "$tmp_file" >&2
    exit 1
fi
if ! x509SelfSign $name &> "$tmp_file"; then
    echo "ERROR: $size bit key self-signing failed" >&2
    cat "$tmp_file" >&2
    exit 1
fi

echo "RSA $size bit private key in old OpenSSL PEM format is in" $(x509Key $name)
echo "RSA $size bit private key in old OpenSSL DER format is in" $(x509Key --der $name)
echo "RSA $size bit private key in PKCS#8 PEM format is in" $(x509Key --pkcs8 $name)
echo "RSA $size bit private key in PKCS#8 DER format is in" $(x509Key --der --pkcs8 $name)
echo "RSA $size bit private key in PKCS#12 format is in" $(x509Key --with-cert --pkcs12 $name)
echo "RSA $size bit self-signed certificate is in" $(x509Cert $name)
echo

# Generate ciphertexts
case $size in
  1024)
    PYTHONPATH=tlsfuzzer ./marvin-venv/bin/python ./step2.py \
    -c rsa1024/cert.pem -o rsa1024_repeat \
    --repeat ${repeat} --verbose \
    no_structure no_padding=48 signature_padding=8 \
    valid_repeated_byte_payload="118 0xff" \
    valid_repeated_byte_payload="118 0x01" \
    valid=48 header_only \
    no_header_with_payload=48 zero_byte_in_padding="48 4" \
    valid=0 valid=118
    ;;
  2048)
    PYTHONPATH=tlsfuzzer ./marvin-venv/bin/python ./step2.py \
    -c rsa2048/cert.pem -o rsa2048_repeat \
    --repeat ${repeat} --verbose \
    no_structure no_padding=48 signature_padding=8 \
    valid_repeated_byte_payload="246 0xff" \
    valid_repeated_byte_payload="246 0x01" \
    valid=48 header_only \
    no_header_with_payload=48 zero_byte_in_padding="48 4" \
    valid=0 valid=192 valid=246
    ;;
  4096)
    PYTHONPATH=tlsfuzzer ./marvin-venv/bin/python ./step2.py \
    -c rsa4096/cert.pem -o rsa4096_repeat \
    --repeat ${repeat} --verbose \
    no_structure no_padding=48 signature_padding=8 \
    valid_repeated_byte_payload="502 0xff" \
    valid_repeated_byte_payload="502 0x01" \
    valid=48 header_only \
    no_header_with_payload=48 zero_byte_in_padding="48 4" \
    valid=0 valid=192 valid=502
    ;;
esac

# Run decryptions and analyze data
echo "Starting decryption"
./example/rust-crypto/target/release/rust-crypto \
    -i rsa${size}_repeat/ciphers.bin \
    -o rsa${size}_repeat/raw_times.csv -k rsa${size}/pkcs8.pem -n $size_bytes
echo "Decryptions finished"
PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/extract.py \
-l rsa${size}_repeat/log.csv --raw-times rsa${size}_repeat/raw_times.csv \
-o rsa${size}_repeat/ \
--clock-frequency 1000
PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/analysis.py \
-o rsa${size}_repeat/ --verbose

# Copy over the keys and the results, if the results directory exists
if [[ -d ~/marvin-toolkit/outputs ]]; then
  cp -r rsa${size} ~/marvin-toolkit/outputs/keys
  cp -r rsa${size}_repeat ~/marvin-toolkit/outputs/results
fi