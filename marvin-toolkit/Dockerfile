FROM python:3.12-bookworm

# Create non-root user
RUN adduser rustcrypto --disabled-password --gecos ""

USER rustcrypto

# Install Rust
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/home/rustcrypto/.cargo/bin:${PATH}"

# Clone the marvin-toolkit repository
RUN cd $HOME \
    && git clone https://github.com/tomato42/marvin-toolkit.git \
    && cd marvin-toolkit \
    && chmod +x *.sh \
    && ./step0.sh
WORKDIR "/home/rustcrypto/marvin-toolkit"

# Generating private keys, ciphertexts, building RustCrypto/RSA, should all be done at runtime
COPY --chmod=777 entrypoint.sh ./entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]