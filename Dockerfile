FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl \
    pkg-config \
    libssl-dev \
    cmake \
    perl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain 1.88.0 --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app

# Copy workspace manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY serverwall-core/Cargo.toml       serverwall-core/
COPY serverwall-proxy/Cargo.toml      serverwall-proxy/
COPY serverwall-webui/Cargo.toml      serverwall-webui/
COPY serverwall-cli/Cargo.toml        serverwall-cli/
COPY serverwall-waf/Cargo.toml        serverwall-waf/
COPY serverwall-antispam/Cargo.toml   serverwall-antispam/
COPY serverwall-relay/Cargo.toml      serverwall-relay/

# Create dummy source files for dependency caching
RUN mkdir -p serverwall-core/src      && echo "pub fn _dummy() {}" > serverwall-core/src/lib.rs \
    && mkdir -p serverwall-proxy/src  && echo "fn main() {}" > serverwall-proxy/src/main.rs \
    && mkdir -p serverwall-webui/src  && echo "fn main() {}" > serverwall-webui/src/main.rs \
    && mkdir -p serverwall-cli/src    && echo "fn main() {}" > serverwall-cli/src/main.rs \
    && mkdir -p serverwall-waf/src    && echo "pub fn _dummy() {}" > serverwall-waf/src/lib.rs \
    && mkdir -p serverwall-antispam/src && echo "pub fn _dummy() {}" > serverwall-antispam/src/lib.rs \
    && mkdir -p serverwall-relay/src  && echo "pub fn _dummy() {}" > serverwall-relay/src/lib.rs

# Build dependencies only (cached layer)
RUN cargo build 2>/dev/null || true

# Now copy actual source code
COPY . .

# Touch source files to invalidate the dummy builds
RUN find . -name "*.rs" -exec touch {} +

# Build
RUN cargo build

# Runtime image
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create serverwall user and directory structure
RUN groupadd -r serverwall && useradd -r -g serverwall -s /usr/sbin/nologin serverwall \
    && mkdir -p /opt/serverwall/bin \
    && mkdir -p /opt/serverwall/etc/{certs,dkim,acme} \
    && mkdir -p /opt/serverwall/var/{log,lib,spool} \
    && mkdir -p /opt/serverwall/run \
    && chown -R serverwall:serverwall \
        /opt/serverwall/var \
        /opt/serverwall/run \
    && chown -R root:serverwall /opt/serverwall/etc \
    && chmod 750 /opt/serverwall/etc

COPY --from=builder /app/target/debug/serverwall        /opt/serverwall/bin/serverwall
COPY --from=builder /app/target/debug/serverwall-webui  /opt/serverwall/bin/serverwall-webui
COPY --from=builder /app/target/debug/serverwallctl     /opt/serverwall/bin/serverwallctl

EXPOSE 25 80 443 465 587 993 8443

CMD ["/opt/serverwall/bin/serverwall", "--config", "/opt/serverwall/etc/serverwall.toml"]
