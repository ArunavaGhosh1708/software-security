FROM debian:bookworm-slim
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git libgmp10 && rm -rf /var/lib/apt/lists/*
RUN case "$TARGETARCH" in amd64) asset=opengrep_manylinux_x86;; arm64) asset=opengrep_manylinux_aarch64;; *) exit 1;; esac \
    && curl -fL --retry 3 "https://github.com/opengrep/opengrep/releases/download/v1.16.0/$asset" -o /usr/local/bin/opengrep \
    && chmod 755 /usr/local/bin/opengrep && /usr/local/bin/opengrep --version
ENV HOME=/tmp
ENTRYPOINT ["/usr/local/bin/opengrep"]
