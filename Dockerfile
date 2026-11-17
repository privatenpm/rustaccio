# syntax=docker/dockerfile:1.29.0

# Multi-arch builds use native cross-compilation, not QEMU emulation: the
# builder stage always runs on the build host's platform and compiles for the
# requested target platform. (QEMU-emulated single-core fat-LTO builds took
# hours; cross-compiling runs at native speed.)

FROM --platform=$BUILDPLATFORM rust:1.100.0-trixie AS chef
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu=4:14.2.0-1 g++-aarch64-linux-gnu=4:14.2.0-1 \
 && rm -rf /var/lib/apt/lists/* \
 && rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
 && cargo install cargo-chef --version 0.1.78 --locked

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY webui ./webui
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json

ARG CARGO_BUILD_JOBS=4
ARG CARGO_PROFILE=release
ARG CARGO_FEATURES=s3
ARG TARGETPLATFORM

# Cross linker for arm64 targets (used by rustc and by the cc crate for
# ring's C sources).
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++

RUN case "$TARGETPLATFORM" in \
      linux/amd64) echo x86_64-unknown-linux-gnu > /tmp/rust-target ;; \
      linux/arm64) echo aarch64-unknown-linux-gnu > /tmp/rust-target ;; \
      *) echo "unsupported platform: $TARGETPLATFORM" >&2; exit 1 ;; \
    esac

RUN RUST_TARGET="$(cat /tmp/rust-target)"; \
    if [ "${CARGO_PROFILE}" = "release" ]; then \
      CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS}" cargo chef cook --release --locked --features "${CARGO_FEATURES}" --target "$RUST_TARGET"; \
    else \
      CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS}" cargo chef cook --profile "${CARGO_PROFILE}" --locked --features "${CARGO_FEATURES}" --target "$RUST_TARGET"; \
    fi

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY webui ./webui

RUN RUST_TARGET="$(cat /tmp/rust-target)"; \
    if [ "${CARGO_PROFILE}" = "release" ]; then \
      cargo build --release --locked --features "${CARGO_FEATURES}" --target "$RUST_TARGET" -j "${CARGO_BUILD_JOBS}" && \
      cp "target/${RUST_TARGET}/release/rustaccio" /tmp/rustaccio-bin; \
    else \
      cargo build --profile "${CARGO_PROFILE}" --locked --features "${CARGO_FEATURES}" --target "$RUST_TARGET" -j "${CARGO_BUILD_JOBS}" && \
      cp "target/${RUST_TARGET}/${CARGO_PROFILE}/rustaccio" /tmp/rustaccio-bin; \
    fi

RUN mkdir -p /tmp/rustaccio-root/data

# Includes Debian's zlib1g fixes for CVE-2026-76844 and CVE-2026-85091.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cc66d222f0a7ec996b78a99fe76a969bc80b539a5016ad866c14d1949bc6d0ab AS runtime

WORKDIR /var/lib/rustaccio

COPY --from=builder --chown=65532:65532 /tmp/rustaccio-root/ /var/lib/rustaccio/
COPY --from=builder /tmp/rustaccio-bin /usr/local/bin/rustaccio
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENV RUSTACCIO_BIND=0.0.0.0:4873
ENV RUSTACCIO_DATA_DIR=/var/lib/rustaccio/data

EXPOSE 4873
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/rustaccio"]
