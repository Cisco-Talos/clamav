# syntax=docker/dockerfile:1
# Build and runtime use the same Debian release; do not copy host binaries here.
ARG RUST_IMAGE=rust:1.90-slim-trixie
ARG DEBIAN_IMAGE=debian:trixie-slim
FROM ${RUST_IMAGE} AS builder
ARG BUILD_JOBS=2
ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_BUILD_JOBS=1 \
    CARGO_PROFILE_RELEASE_LTO=false \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake ninja-build pkg-config git ca-certificates \
        gcc g++ make libclang-19-dev \
        libbz2-dev libcurl4-openssl-dev libjson-c-dev libncurses-dev \
        libpcre2-dev libssl-dev libxml2-dev zlib1g-dev \
        check python3 python3-pytest \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo fetch --locked \
    && CARGO_NET_OFFLINE=true cmake -S . -B /build -G Ninja \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_C_FLAGS_RELWITHDEBINFO='-O2 -g -DNDEBUG' \
        -DCMAKE_CXX_FLAGS_RELWITHDEBINFO='-O2 -g -DNDEBUG' \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DAPP_CONFIG_DIRECTORY=/etc/clamav \
        -DDATABASE_DIRECTORY=/var/lib/clamav \
        -DCVD_CERTS_DIRECTORY=/etc/clamav/certs \
        -DBYTECODE_RUNTIME=interpreter \
        -DENABLE_MILTER=OFF -DENABLE_CLAMONACC=OFF \
        -DENABLE_SYSTEMD=OFF -DENABLE_MAN_PAGES=OFF \
        -DENABLE_EXAMPLES=OFF -DENABLE_TESTS=ON \
        -DENABLE_UNRAR=ON -DENABLE_STATIC_LIB=OFF \
        -DENABLE_JSON_SHARED=ON -DMAINTAINER_MODE=OFF \
    && CARGO_NET_OFFLINE=true cmake --build /build --parallel "${BUILD_JOBS}" \
    && CARGO_NET_OFFLINE=true ctest --test-dir /build --output-on-failure \
        -R '^(libclamav|libclamav_rust|clamscan|sigtool)$' \
    && DESTDIR=/install cmake --install /build --strip \
    && nm -D /install/usr/local/lib/libclamav.so | grep -q 'cli_ac_eval_lsig' \
    && rm -rf /install/usr/local/include /install/usr/local/lib/pkgconfig \
        /install/usr/local/lib/cmake /install/usr/local/share/doc

FROM ${DEBIAN_IMAGE} AS runtime
ARG SOURCE_REVISION=unknown
ARG SOURCE_TREE_SHA256=unknown
LABEL org.opencontainers.image.title="Optimized ClamAV" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      local.clamav.source-tree-sha256="${SOURCE_TREE_SHA256}"
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates tini gosu netcat-openbsd \
        libbz2-1.0 libcurl4t64 libjson-c5 libncurses6 libpcre2-8-0 \
        libssl3t64 libstdc++6 libxml2 zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system clamav \
    && useradd --system --uid 100 --gid clamav --home-dir /var/lib/clamav \
        --no-create-home --shell /usr/sbin/nologin clamav \
    && install -d -o clamav -g clamav /var/lib/clamav /var/log/clamav
COPY --from=builder /install/ /
COPY docker/config/clamd.conf docker/config/freshclam.conf /etc/clamav/
COPY --chmod=755 docker/entrypoint.sh docker/healthcheck.sh /usr/local/bin/
RUN ldconfig \
    && chmod 644 /etc/clamav/clamd.conf \
    && chown root:clamav /etc/clamav/freshclam.conf \
    && chmod 640 /etc/clamav/freshclam.conf \
    && clamscan --version && freshclam --version
EXPOSE 3310
VOLUME ["/var/lib/clamav"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5m --retries=3 \
    CMD ["/usr/local/bin/healthcheck.sh"]
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["clamd"]
