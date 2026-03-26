# CLAUDE.md - ServerWall Development Guide

## Project Overview

ServerWall is a multi-protocol load balancer written in Rust. It handles HTTPS, SMTPS, SMTP+STARTTLS, IMAPS, and TCP with integrated OWASP WAF, antispam filtering, SMTP relay, and web management.

## Build Commands

All builds use Docker (no native OpenSSL on Windows dev machine):

```bash
docker compose --profile check run --rm check     # cargo check
docker compose --profile build run --rm dev        # cargo build (debug)
docker compose --profile release run --rm release  # cargo build --release
docker compose --profile test run --rm test        # cargo test
docker compose --profile clippy run --rm clippy    # cargo clippy
```

## Workspace Structure

- `serverwall-core/` - Shared library: config schema/loader, atomic config writer, config editor helpers, SIGHUP signal helper, TLS (SNI, ACME), load balancer algorithms, ACL engine, health checking, logging, protocol parsers (SMTP, IMAP, HTTP), core types
- `serverwall-proxy/` - Main daemon binary (`serverwall`): listener orchestration, protocol-specific proxy handlers (HTTP, SMTP, IMAP, TCP), WAF/antispam pipeline integration, config reload via SIGHUP, metrics; writes PID to `/opt/serverwall/run/serverwall.pid`
- `serverwall-webui/` - Axum management web UI + REST API (`serverwall-webui`): HTTPS on `0.0.0.0:8443` by default, JWT auth, reads/writes config directly via `serverwall-core` editor; optional but enabled by default
- `serverwall-cli/` - CLI management tool (`serverwallctl`): reads/writes config directly (no HTTP client, no dependency on webui running); synchronous binary
- `serverwall-waf/` - OWASP WAF engine: anomaly scoring, paranoia levels, built-in detection modules (SQLi, XSS, path traversal, command injection, protocol attacks), regex rule system, rate limiting
- `serverwall-antispam/` - Antispam filter engine: pre-DATA pipeline (DNSBL, SPF, rDNS, HELO, rate limit, early talker, behavior) and post-DATA pipeline (DKIM, DMARC, ARC, content, URL/SURBL, attachment, HTML, charset, header, bulk, ratio analysis), external AV integration, normalized scoring
- `serverwall-relay/` - SMTP outbound relay: trusted-host receiver, filesystem spool (Pending/Active/Deferred/Held), MX resolution, delivery with retry/backoff, DKIM signing, bounce generation, outbound policy enforcement
- `config/` - Example configuration (`serverwall.toml`) showing all major sections; ships with no frontends or backend pools configured
- `dist/systemd/` - systemd unit files (`serverwall.service`, `serverwall-webui.service`)

## Architecture

```
serverwallctl  ──┐
                 ├─→  /opt/serverwall/etc/serverwall.toml  ──→  serverwall (daemon, SIGHUP)
serverwall-webui─┘
```

Both the CLI and the webui directly read/write `serverwall.toml`. After any mutation, they send SIGHUP to the daemon via the PID file at `/opt/serverwall/run/serverwall.pid`. The CLI and webui are fully independent — neither requires the other to be running.

The `serverwall-webui.service` uses `BindsTo=serverwall.service`, so starting/stopping serverwall also manages the webui.

## Key Technologies

- **Runtime**: Tokio (async, full features) — except `serverwallctl` which is synchronous
- **Web framework**: Axum 0.8 with manual TLS acceptor (`tokio-rustls` + `hyper-util`)
- **TLS**: rustls + openssl (for encrypted PEM/PFX import, DKIM key generation); SNI via custom resolver
- **DNS**: hickory-resolver
- **Mail auth**: mail-auth (SPF/DKIM/DMARC/ARC), mail-parser (MIME)
- **HTML parsing**: lol_html (streaming)
- **Pattern matching**: regex, aho-corasick
- **Concurrency**: DashMap (lock-free maps), arc-swap (atomic pointer swaps for hot config)
- **Storage**: redb available; outbound queue uses filesystem spool
- **Config**: TOML via serde with `#[serde(default)]` throughout; atomic writes via tempfile+rename; `.lock` sentinel for concurrent write protection
- **Security**: argon2 (password hashing), jsonwebtoken (API auth)

## Design Decisions

- No greylisting (user preference)
- Trusted relay model for outbound SMTP (IP-based, no SMTP AUTH)
- External CLI antivirus scanner integration (pluggable: ClamAV, Sophos, ESET, etc.)
- Web admin default user: `admin`, password auto-generated on `serverwall --init`
- TLS supports combined PEM, separate cert+chain+key, and PKCS#12/PFX
- All dependencies are non-copyleft (MIT/Apache-2.0/BSD/ISC); outbound TLS uses `rustls-native-certs` (system CA store) instead of the MPL-2.0 `webpki-roots` bundle
- Antispam uses weighted normalized scoring (0-100%), not raw points
- IMAP proxy uses two-phase model: sniff LOGIN credentials, then proxy transparently
- Backend IDs are deterministic UUID v5 hashes (backend addresses not exposed in API)
- Connection guard pattern (ref-counted) tracks active connections per backend
- ACL evaluation order: block list → allow list → default action
- TOML comment preservation is **not** implemented (uses `toml::to_string_pretty`; comments are lost on write — accepted limitation)
- Config write safety: `.lock` sentinel file with `O_CREAT|O_EXCL`, 5-retry × 100ms, RAII unlock

## Configuration

Main config: `/opt/serverwall/etc/serverwall.toml` (TOML format)
Config schema: `serverwall-core/src/config/schema.rs`
Config editor: `serverwall-core/src/config/editor.rs`
Example config: `config/serverwall.toml`

Key config sections:
- `[global]` - daemon settings (threads, log dir, cert dir, max connections)
- `[webui]` - web UI / management API (listen address, TLS cert/key, tokens file, web users file)
- `[acme]` - Let's Encrypt (directory URL, challenge type, storage, auto-renew)
- `[[frontend]]` - listener definitions (protocol, listen addrs, backend pool, TLS, WAF, logging, headers, ACL)
- `[[backend_pool]]` - backend server pools (backends, health check type/interval/path/expect)
- `[[waf_ruleset]]` - WAF rule sets (mode, anomaly threshold, paranoia level)
- `[security]` - TLS policy (HSTS, OCSP), security response headers
- `[antispam]` - spam filter settings (per-check weights and thresholds, DNSBL lists, AV scanners)
- `[relay]` - outbound SMTP relay (trusted hosts, DKIM signing per domain, spool dir, retry schedule)

## File Layout on Target System

```
/opt/serverwall/
├── bin/
│   ├── serverwall          # Main proxy daemon
│   ├── serverwall-webui    # Web UI / management API
│   └── serverwallctl       # CLI management tool
├── etc/
│   ├── serverwall.toml     # Main config (0640 root:serverwall)
│   ├── certs/              # TLS certificates (webui.pem, webui-key.pem, ...)
│   ├── dkim/               # DKIM signing keys
│   ├── acme/               # Let's Encrypt state
│   ├── api-tokens.toml     # API bearer tokens
│   └── web-users.toml      # Web UI user accounts
├── var/
│   ├── log/                # Log files (per-frontend)
│   ├── lib/                # Persistent data (redb)
│   └── spool/              # Outbound mail queue
└── run/
    └── serverwall.pid      # Daemon PID file
```

## CLI/WebUI Configuration Parity

**Rule:** Every field in every config section of `schema.rs` MUST be configurable via both `serverwallctl` and the WebUI. This is a hard requirement — no field may be write-only from one interface.

**Exception — CLI-only (bootstrapping constraint):** `WebuiConfig` connection fields (`listen`, `tls_cert`, `tls_key`, `tokens_file`, `web_users_file`, `allowed_origins`, `enabled`) can only be set via the CLI. The WebUI cannot safely modify its own TLS/network settings while it is running.

**When adding a schema field:**
1. Add an editor function in `serverwall-core/src/config/editor.rs`
2. Add a CLI flag/subcommand in `serverwall-cli/src/commands/`
3. Add a WebUI form field + route handler update in `serverwall-webui/`
All three in the same PR.

**Command-to-section mapping:**
- `serverwallctl global` → `[global]`
- `serverwallctl acme` → `[acme]`
- `serverwallctl security` → `[security]` (TLS, GeoIP, headers, bot detection, cookies, rate limits, ACL)
- `serverwallctl security-profile` → `[[security_profiles]]`
- `serverwallctl log-profile` → `[[log_profiles]]`
- `serverwallctl relay` → `[relay]` (including bounce, outbound policy, trusted hosts, TLS, retry)
- `serverwallctl dmarc` → `[dmarc_publish]`
- `serverwallctl spf` → `[spf_publish]`
- `serverwallctl frontend` → `[[frontend]]` (full CRUD including `add` and `update`)
- `serverwallctl backend` → `[[backend_pool]]` (full CRUD including `add-pool`, `update-pool`, `add-server`)
- `serverwallctl antispam` → `[antispam]` (full subcommand model — all checks, all lists, DNSBL/SURBL, scanners, domain overrides)
- `serverwallctl webui` → `[webui]` (CLI-only fields)

**`serverwallctl antispam` covers everything `GET/PUT /api/antispam/*` covers** — including SPF severity weights (`--spf-fail-weight`, `--spf-softfail-weight`, etc.) and residential SPF `neutral_triggers`.

## Style Guidelines

- Use `thiserror` for library error types, `anyhow` in binaries
- Use `tracing` for logging (not `log`)
- Config structs use serde derives with `#[serde(default)]`
- Async code uses `tokio` throughout (except `serverwallctl` — synchronous)
- Concurrent data structures: `DashMap`, `arc-swap`
- Tests go in the same file as the code they test (Rust convention)
