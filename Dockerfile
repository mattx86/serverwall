FROM rust:1.88-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    cmake \
    perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy workspace manifests first for dependency caching
COPY Cargo.toml Cargo.lock* ./
COPY serverwall-core/Cargo.toml serverwall-core/
COPY serverwall-proxy/Cargo.toml serverwall-proxy/
COPY serverwall-api/Cargo.toml serverwall-api/
COPY serverwall-cli/Cargo.toml serverwall-cli/
COPY serverwall-waf/Cargo.toml serverwall-waf/
COPY serverwall-antispam/Cargo.toml serverwall-antispam/
COPY serverwall-relay/Cargo.toml serverwall-relay/

# Create dummy source files for dependency caching
RUN mkdir -p serverwall-core/src && echo "pub fn _dummy() {}" > serverwall-core/src/lib.rs \
    && mkdir -p serverwall-proxy/src && echo "fn main() {}" > serverwall-proxy/src/main.rs \
    && mkdir -p serverwall-api/src && echo "fn main() {}" > serverwall-api/src/main.rs \
    && mkdir -p serverwall-cli/src && echo "fn main() {}" > serverwall-cli/src/main.rs \
    && mkdir -p serverwall-waf/src && echo "pub fn _dummy() {}" > serverwall-waf/src/lib.rs \
    && mkdir -p serverwall-antispam/src && echo "pub fn _dummy() {}" > serverwall-antispam/src/lib.rs \
    && mkdir -p serverwall-relay/src && echo "pub fn _dummy() {}" > serverwall-relay/src/lib.rs

# Build dependencies only (cached layer)
RUN cargo build --release 2>/dev/null || true
RUN cargo build 2>/dev/null || true

# Now copy actual source code
COPY . .

# Touch source files to invalidate the dummy builds
RUN find . -name "*.rs" -exec touch {} +

# Build
RUN cargo build

# Runtime image
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create serverwall user and directories
RUN groupadd -r serverwall && useradd -r -g serverwall -d /etc/serverwall -s /usr/sbin/nologin serverwall \
    && mkdir -p /etc/serverwall/{conf.d,certs,dkim,acme,waf-rules} \
    && mkdir -p /var/log/serverwall/waf \
    && mkdir -p /var/lib/serverwall \
    && mkdir -p /var/spool/serverwall/{queue,bounce,corrupt} \
    && mkdir -p /run/serverwall \
    && chown -R serverwall:serverwall /var/log/serverwall /var/lib/serverwall /var/spool/serverwall /run/serverwall \
    && chown -R root:serverwall /etc/serverwall \
    && chmod 750 /etc/serverwall

COPY --from=builder /app/target/debug/serverwall /usr/bin/serverwall
COPY --from=builder /app/target/debug/serverwall-api /usr/bin/serverwall-api
COPY --from=builder /app/target/debug/serverwallctl /usr/bin/serverwallctl

EXPOSE 25 80 443 465 587 993 8443

CMD ["/usr/bin/serverwall", "--config", "/etc/serverwall/serverwall.toml"]
