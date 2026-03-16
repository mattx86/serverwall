> **⚠️ Alpha Software — Under Active Development**
> ServerWall is not yet production-ready. APIs, configuration formats, and behaviour may change without notice. Use at your own risk.

# ServerWall

A high-performance, multi-protocol load balancer and software firewall written in Rust with integrated OWASP HTTP(S) WAF, SMTP antispam, web/API/CLI management, and more.

ServerWall is built with the intent to surpass other well-established open-source projects and commercial security appliances.

Internet services deserve excellence in security, period.

## Features

### Protocol Support
- **HTTPS** load balancing with full HTTP reverse proxy
- **SMTPS** and **SMTP+STARTTLS** load balancing with integrated antispam
- **IMAPS** load balancing with two-phase LOGIN sniffing and session affinity
- **Generic TCP** load balancing

### Load Balancing
- Round Robin, Least Connections, and IP Hash algorithms
- Health checking (TCP, HTTP, SMTP, IMAP)
- Weighted backends
- Encrypted and unencrypted backend connections

### SSL/TLS Termination
- Combined PEM, separate cert+chain+key, and PKCS#12/PFX import
- OpenSSL-encrypted private key support
- SNI-based certificate selection
- Automated Let's Encrypt (ACME) certificate management
- Configurable TLS versions and cipher suites

### OWASP WAF (HTTPS)
- SQL injection, XSS, path traversal, command injection detection
- Anomaly scoring with configurable thresholds
- Paranoia levels 1-4 (modeled after OWASP CRS)
- Rate limiting (per-IP, per-route, per-header)
- Bot detection with JA3 fingerprinting
- Geo-blocking via MaxMind GeoIP
- Custom rule support

### Antispam Filter (SMTP)
- **Pre-DATA checks**: DNSBL/RBL, SPF, reverse DNS, HELO validation, rate limiting, early talker detection, behavior analysis
- **Post-DATA checks**: DKIM, DMARC, ARC, content scoring, URL/SURBL analysis, attachment analysis, HTML analysis, charset analysis, header analysis, bulk detection, ratio analysis
- **Antivirus**: Pluggable external CLI scanner support (ClamAV, Sophos, ESET, etc.)
- Weighted scoring with configurable thresholds (definite spam = reject, possible spam = flag with headers)
- Per-domain threshold overrides
- `X-Spam-Score`, `X-Spam-Status`, `X-Spam-Report`, `Authentication-Results` headers

### SMTP Outbound Relay
- Trusted host relay model (IP-based authorization, no SMTP AUTH required)
- DKIM signing (RSA-SHA256, Ed25519-SHA256)
- Filesystem message queue with configurable retry schedule
- MX resolution with priority-based delivery
- Opportunistic STARTTLS for outbound connections
- Bounce (DSN) generation
- Outbound policy enforcement (rate limiting, content policy, antivirus)

### Management
- **HTTPS Web UI** on port 8443 with dashboard, mail queue manager, and configuration
- **REST API** with bearer token authentication
- **CLI tool** (`serverwallctl`) for all management operations — no dependency on the web UI being running
- Web-based mail queue management (list, search, retry, hold, delete, flush)
- Default admin account with auto-generated password on first run (`serverwall --init`)

### Logging
- Apache Combined format for HTTP(S)
- Postfix-style format for SMTP
- Protocol-specific format for TCP/IMAP
- Per-vhost/VIP log files
- WAF event logging

### Security
- IP/CIDR allow and block lists
- Domain-based filtering
- Path pattern filtering
- Cookie and header security enforcement
- Security response headers (HSTS, X-Content-Type-Options, X-Frame-Options, etc.)

## Quick Start

### Prerequisites
- Docker (for building)
- Linux (Ubuntu 22.04+ recommended) for deployment

### Build

```bash
# Type check
docker compose --profile check run --rm check

# Debug build
docker compose --profile build run --rm dev

# Release build
docker compose --profile release run --rm release

# Run tests
docker compose --profile test run --rm test

# Lint
docker compose --profile clippy run --rm clippy
```

### Install

```bash
# First-time setup (generates admin password, creates dirs, generates webui TLS cert)
sudo serverwall --init

# Start the service
sudo systemctl start serverwall
sudo systemctl enable serverwall
```

### Configuration

Main configuration file: `/opt/serverwall/etc/serverwall.toml`
Full example: [`config/serverwall.toml`](config/serverwall.toml)

```toml
[global]
log_dir = "/opt/serverwall/var/log"

[[frontend]]
name = "https-main"
protocol = "https"
listen = ["0.0.0.0:443"]
backend_pool = "web-servers"
tls_cert = "/opt/serverwall/etc/certs/example.com.pem"
tls_key = "/opt/serverwall/etc/certs/example.com-key.pem"
balancer = "least_connections"
waf_enabled = true

[[backend_pool]]
name = "web-servers"
health_check_type = "http"
health_check_path = "/healthz"

[[backend_pool.backend]]
name = "web1"
address = "10.0.1.10:8080"

[[backend_pool.backend]]
name = "web2"
address = "10.0.1.11:8080"
```

### CLI Usage

```bash
serverwallctl status                        # Overall status
serverwallctl frontend list                 # List frontends
serverwallctl backend list                  # List backends
serverwallctl queue list                    # List mail queue
serverwallctl cert import --file cert.pem   # Import certificate
serverwallctl reload                        # Reload configuration
```

## Architecture

ServerWall is organized as a Cargo workspace with 7 crates:

| Crate | Binary | Description |
|-------|--------|-------------|
| `serverwall-core` | — | Shared library: config schema/loader, atomic config writer, TLS (SNI/ACME), balancer algorithms, ACL engine, health checking, logging, protocol parsers |
| `serverwall-proxy` | `serverwall` | Main daemon: listener orchestration, HTTP/SMTP/IMAP/TCP proxy handlers, WAF/antispam integration, hot config reload via SIGHUP |
| `serverwall-webui` | `serverwall-webui` | HTTPS management web UI and REST API on port 8443; reads/writes config directly; optional but enabled by default |
| `serverwall-cli` | `serverwallctl` | CLI management tool; reads/writes config directly — no dependency on webui being running |
| `serverwall-waf` | — | WAF engine: anomaly scoring, paranoia levels, SQLi/XSS/path traversal/command injection detection, rate limiting |
| `serverwall-antispam` | — | Antispam engine: pre-DATA and post-DATA pipelines, normalized 0–100% scoring |
| `serverwall-relay` | — | SMTP relay: filesystem spool, MX resolution, retry/backoff, DKIM signing, bounce generation |

```
serverwallctl  ──┐
                 ├─→  /opt/serverwall/etc/serverwall.toml  ──→  serverwall (daemon, SIGHUP)
serverwall-webui─┘
```

Both `serverwallctl` and `serverwall-webui` read/write the config file directly. After any mutation they send SIGHUP to the daemon via `/opt/serverwall/run/serverwall.pid`. The `serverwall-webui` service uses `BindsTo=serverwall.service` so stopping serverwall also stops the webui.

## File System Layout

```
/opt/serverwall/
├── bin/
│   ├── serverwall          # Main proxy daemon
│   ├── serverwall-webui    # Web UI / management API (HTTPS :8443)
│   └── serverwallctl       # CLI management tool
├── etc/
│   ├── serverwall.toml     # Main config
│   ├── certs/              # TLS certificates
│   ├── dkim/               # DKIM signing keys
│   ├── acme/               # Let's Encrypt state
│   ├── api-tokens.toml     # API bearer tokens
│   └── web-users.toml      # Web UI user accounts
├── var/
│   ├── log/                # Log files (per-frontend)
│   ├── lib/                # Persistent data
│   └── spool/              # Outbound mail queue
└── run/
    └── serverwall.pid      # Daemon PID file
```

## License

MIT License — Copyright (c) 2026 Matt Smith. See [LICENSE.md](LICENSE.md).
