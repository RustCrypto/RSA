# Marvin toolkit integration

This directory measures PKCS#1 v1.5 decryption in the **local RSA checkout**
using [marvin-toolkit](https://github.com/tomato42/marvin-toolkit) probes and
tlsfuzzer's statistical analysis. It does not download another version of `rsa`.

## Native Linux run

Install Rust, Python with `venv`, Git, and OpenSSL. Prepare the upstream tools:

```bash
git clone https://github.com/tomato42/marvin-toolkit.git /tmp/marvin-toolkit
cd /tmp/marvin-toolkit
git checkout 7d264ab2b6611b25b95d5dd6bd1590a761c47048
git clone https://github.com/tomato42/tlsfuzzer.git
git -C tlsfuzzer checkout 5eebc4464e5197a7f7392fb9acda99cfc32441f7
python3 -m venv marvin-venv
marvin-venv/bin/pip install -r tlsfuzzer/requirements.txt -r tlsfuzzer/requirements-timing.txt
export MARVIN_TOOLKIT=/tmp/marvin-toolkit
```

From the RSA repository root, exercise the full pipeline with a small run:

```bash
./marvin-toolkit/entrypoint.sh -s 2048 -n 1000 -q -o marvin-toolkit/outputs/smoke
cat marvin-toolkit/outputs/smoke/results/report.txt
```

## Docker

Build with the **RSA repository root** as the context; this includes local
source changes in the image:

```bash
docker build -f marvin-toolkit/Dockerfile -t rsa-marvin .
mkdir -p marvin-toolkit/outputs
# Allow the image's non-root user to create run directories in this mount.
chmod a+rwx marvin-toolkit/outputs
docker run --rm \
  -v "$(pwd)/marvin-toolkit/outputs:/outputs" \
  rsa-marvin -s 2048 -n 1000 -q -o /outputs/smoke
```
