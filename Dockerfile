# Build locally: docker build -t tunnellb:<Cargo.toml version> .
# Use buildx --platform linux/amd64,linux/arm64 with native builders or emulation
# for a multi-platform build. Both remote frps architectures are in every image.
FROM --platform=$BUILDPLATFORM debian:bookworm-20261005-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS frp
ARG TARGETARCH
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl tar coreutils \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /tmp/frp
# Literal upstream checksums from:
# https://github.com/fatedier/frp/releases/download/v0.71.1/frp_sha256_checksums.txt
COPY packaging/frp-checksums.txt ./
RUN set -eux; \
    case "${TARGETARCH}" in amd64|arm64) ;; *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; esac; \
    for arch in amd64 arm64; do \
        curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
            --output "frp_0.71.1_linux_${arch}.tar.gz" \
            "https://github.com/fatedier/frp/releases/download/v0.71.1/frp_0.71.1_linux_${arch}.tar.gz"; \
    done; \
    sha256sum --check --strict frp-checksums.txt; \
    for arch in amd64 arm64; do \
        tar --extract --gzip --file "frp_0.71.1_linux_${arch}.tar.gz" \
            "frp_0.71.1_linux_${arch}/frps" \
            "frp_0.71.1_linux_${arch}/frpc" \
            "frp_0.71.1_linux_${arch}/LICENSE"; \
        install -D -m 0755 "frp_0.71.1_linux_${arch}/frps" "/out/opt/frp/${arch}/frps"; \
    done; \
    install -D -m 0755 "frp_0.71.1_linux_${TARGETARCH}/frpc" /out/usr/local/bin/frpc; \
    install -D -m 0644 frp_0.71.1_linux_amd64/LICENSE /out/usr/share/doc/frp/LICENSE

FROM rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS builder
RUN apt-get update \
    && apt-get install --no-install-recommends -y cmake pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
RUN cargo build --locked --release --bin tunnellb

FROM debian:bookworm-20261005-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS runtime-base
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        ca-certificates openssh-client coreutils tar gzip \
        iptables iproute2 procps findutils \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 tunnellb \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /tmp --shell /usr/sbin/nologin tunnellb

FROM runtime-base AS runtime
COPY --from=frp /out/ /
COPY --from=builder /build/target/release/tunnellb /usr/local/bin/tunnellb
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/tunnellb"]
CMD ["controller"]
