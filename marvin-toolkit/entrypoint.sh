#!/bin/bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(dirname -- "$script_dir")
size=2048
repeat=100000
workers=1
mode=default
analysis_args=()
output="${MARVIN_OUTPUT_ROOT:-$script_dir/outputs}/run-$(date -u +%Y%m%dT%H%M%SZ)"

display_help() {
  cat <<HELP
Usage: $0 [-s SIZE] [-n REPEATS] [-o OUTPUT] [-j WORKERS] [-m MODE] [-q] [-h]
  -s SIZE     RSA key size: 1024, 2048, 3072, or 4096 (default: 2048)
  -n REPEATS  Repetitions per probe (default: 100000)
  -o OUTPUT   New output directory (must not already exist)
  -j WORKERS  Analysis workers (default: 1)
  -m MODE     default (OS blinding), blinded (rand::rng), or unblinded
  -q          Minimal analysis without plots (still writes report.txt)
  -h          Show help
Set MARVIN_TOOLKIT to the prepared upstream toolkit checkout (see README.md).
HELP
}

while getopts ':s:n:o:j:m:qh' opt; do
  case "$opt" in
    s) size=$OPTARG ;;
    n) repeat=$OPTARG ;;
    o) output=$OPTARG ;;
    j) workers=$OPTARG ;;
    m) mode=$OPTARG ;;
    q) analysis_args=(--minimal-analysis) ;;
    h) display_help; exit 0 ;;
    *) display_help >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
if [[ $# != 0 || ! $size =~ ^(1024|2048|3072|4096)$ ||
      ! $mode =~ ^(default|blinded|unblinded)$ ||
      ! $repeat =~ ^[1-9][0-9]*$ || ! $workers =~ ^[1-9][0-9]*$ ]]; then
  display_help >&2
  exit 2
fi
: "${MARVIN_TOOLKIT:?Set MARVIN_TOOLKIT to the prepared upstream toolkit checkout}"
toolkit=$(cd -- "$MARVIN_TOOLKIT" && pwd)
python="$toolkit/marvin-venv/bin/python"
[[ -x "$python" && -f "$toolkit/tlsfuzzer/tlsfuzzer/analysis.py" ]]
export PYTHONPATH="$toolkit/tlsfuzzer"
# Keep numerical libraries from multiplying the requested analysis worker count.
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1

cargo build --release --locked --manifest-path "$repo_dir/Cargo.toml" \
  -p rsa-marvin --target-dir "$repo_dir/target"
# Refuse reuse so a previous report can never be mistaken for this run's result.
umask 077
mkdir -p -- "$(dirname -- "$output")"
mkdir -- "$output"
output=$(cd -- "$output" && pwd)
mkdir "$output/keys"
{
  printf 'RSA checkout: '
  git -C "$script_dir" rev-parse HEAD 2>/dev/null || echo 'unavailable (container build context)'
  git -C "$script_dir" diff --stat 2>/dev/null || true
  printf 'Marvin toolkit: '; git -C "$toolkit" rev-parse HEAD
  printf 'tlsfuzzer: '; git -C "$toolkit/tlsfuzzer" rev-parse HEAD
  printf 'key_bits=%s repeats=%s mode=%s\n' "$size" "$repeat" "$mode"
  rustc -Vv
  uname -a
  openssl version
  cargo tree --locked --manifest-path "$script_dir/Cargo.toml"
} > "$output/environment.txt"
cp "$repo_dir/Cargo.lock" "$output/Cargo.lock"
"$python" -m pip freeze > "$output/python-requirements.txt"

openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$size" \
  -out "$output/keys/pkcs8.pem"
openssl req -new -x509 -key "$output/keys/pkcs8.pem" \
  -subj '/CN=marvin-test-only' -days 1 -out "$output/keys/cert.pem"

size_bytes=$((size / 8))
max_payload=$((size_bytes - 11))
short_padding_payload=$((size_bytes - 10))
# Preserve the old seven-byte-PS probes and also test the valid eight-byte boundary.
probes=(no_structure no_padding=48 signature_padding=8
  "valid_repeated_byte_payload=$short_padding_payload 0xff"
  "valid_repeated_byte_payload=$short_padding_payload 0x01"
  valid=48 header_only no_header_with_payload=48 zero_byte_in_padding='48 4'
  valid=0 "valid=$max_payload" "valid=$short_padding_payload"
  "valid_repeated_byte_payload=$max_payload 0xff"
  "valid_repeated_byte_payload=$max_payload 0x01")
if ((size > 1024)); then probes+=(valid=192); fi
"$python" "$toolkit/step2.py" -c "$output/keys/cert.pem" -k "$output/keys/pkcs8.pem" \
  -o "$output/results" --repeat "$repeat" --verbose "${probes[@]}"

"$repo_dir/target/release/rsa-marvin" \
  -i "$output/results/ciphers.bin" -o "$output/results/raw_times.csv" \
  -k "$output/keys/pkcs8.pem" -n "$size_bytes" --mode "$mode"
# Instant::elapsed().as_nanos() uses nanoseconds; this option is in MHz.
"$python" "$toolkit/tlsfuzzer/tlsfuzzer/extract.py" \
  -l "$output/results/log.csv" --raw-times "$output/results/raw_times.csv" \
  -o "$output/results" --clock-frequency 1000

# A detected timing difference is a nonzero analysis result, not a reason to lose data.
status=0
"$python" "$toolkit/tlsfuzzer/tlsfuzzer/analysis.py" \
  -o "$output/results" --verbose --workers "$workers" "${analysis_args[@]}" \
  > "$output/analysis.log" 2>&1 || status=$?
cat "$output/analysis.log"
echo "$status" > "$output/analysis-exit-status.txt"
echo "Results: $output/results/report.txt (analysis exit status: $status)"
exit "$status"
