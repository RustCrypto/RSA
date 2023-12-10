# Marvin tool-kit integration
This document describes the procedure for replicating the analysis for the Marvin attack. This analysis is best done on a container for reproducibility.

```bash
docker build -t marvin:latest .
docker run --rm \
    --name marvin \
    -v /home/ec2-user/RSA/marvin-toolkit/Cargo.toml:/home/rustcrypto/marvin-toolkit/example/rust-crypto/Cargo.toml \
    marvin:latest
```
