# Build from the RSA repository root:
# docker build -f marvin-toolkit/Dockerfile -t rsa-marvin .
FROM python:3.12-bookworm

ARG MARVIN_REV=7d264ab2b6611b25b95d5dd6bd1590a761c47048
ARG TLSFUZZER_REV=5eebc4464e5197a7f7392fb9acda99cfc32441f7
RUN adduser rustcrypto --disabled-password --gecos ""
USER rustcrypto
WORKDIR /home/rustcrypto
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
ENV PATH="/home/rustcrypto/.cargo/bin:${PATH}"
ENV MARVIN_TOOLKIT=/home/rustcrypto/marvin-toolkit
RUN git clone https://github.com/tomato42/marvin-toolkit.git "$MARVIN_TOOLKIT" \
    && cd "$MARVIN_TOOLKIT" && git checkout "$MARVIN_REV" \
    && git clone https://github.com/tomato42/tlsfuzzer.git \
    && git -C tlsfuzzer checkout "$TLSFUZZER_REV" \
    && python -m venv marvin-venv \
    && marvin-venv/bin/pip install -r tlsfuzzer/requirements.txt -r tlsfuzzer/requirements-timing.txt

RUN mkdir /home/rustcrypto/RSA
WORKDIR /home/rustcrypto/RSA
COPY --chown=rustcrypto Cargo.toml Cargo.lock README.md ./
COPY --chown=rustcrypto src ./src
COPY --chown=rustcrypto benches ./benches
COPY --chown=rustcrypto checkct ./checkct
COPY --chown=rustcrypto marvin-toolkit/Cargo.toml ./marvin-toolkit/
COPY --chown=rustcrypto marvin-toolkit/src ./marvin-toolkit/src
COPY --chown=rustcrypto --chmod=755 marvin-toolkit/entrypoint.sh ./marvin-toolkit/entrypoint.sh
RUN cargo build --release --locked -p rsa-marvin
ENV MARVIN_OUTPUT_ROOT=/outputs
ENTRYPOINT ["/home/rustcrypto/RSA/marvin-toolkit/entrypoint.sh"]
