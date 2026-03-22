use std::path::PathBuf;

use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use serverwall_core::{send_reload_signal, DEFAULT_PID_FILE};
use serverwall_core::tls::AcmeManager;

use crate::state::AppState;

/// GET /api/certs — list all *.pem files in cert_dir (excluding *-key.pem)
pub async fn list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let cert_dir = &config.global.cert_dir;

    let entries = match std::fs::read_dir(cert_dir) {
        Ok(e) => e,
        Err(_) => return Json(json!({"certificates": []})),
    };

    let frontends = &config.frontend;

    let mut certs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let fname = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        // Only include *.pem cert files, skip key files
        if !fname.ends_with(".pem") || fname.ends_with("-key.pem") {
            continue;
        }
        let name = fname.strip_suffix(".pem").unwrap_or(&fname).to_string();
        let key_file = format!("{}-key.pem", name);
        let key_path = cert_dir.join(&key_file);

        let expiry = parse_cert_expiry(&path);

        // Which frontends reference this cert?
        let in_use_by: Vec<String> = frontends
            .iter()
            .filter(|f| {
                f.tls_cert.as_ref().map_or(false, |p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map_or(false, |n| n == fname)
                })
            })
            .map(|f| f.name.clone())
            .collect();

        // Also check if this is the webui cert
        let webui_cert_name = config
            .webui
            .tls_cert
            .as_ref()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .map(|s| s.to_string());
        let mut all_uses = in_use_by;
        if webui_cert_name.as_deref() == Some(&fname) {
            all_uses.push("(webui)".to_string());
        }

        certs.push(json!({
            "name": name,
            "cert_file": fname,
            "key_file": key_file,
            "key_exists": key_path.exists(),
            "expiry": expiry,
            "in_use_by": all_uses,
        }));
    }

    // Sort by name for stable ordering
    certs.sort_by(|a, b| {
        a["name"].as_str().unwrap_or("").cmp(b["name"].as_str().unwrap_or(""))
    });

    Json(json!({"certificates": certs}))
}

/// GET /api/certs/:name — return full X.509 attributes for a single certificate.
pub async fn get(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> (StatusCode, Json<Value>) {
    let config = state.config.load();
    let cert_dir = &config.global.cert_dir;
    let name = sanitize_cert_name(&name);
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid name"})));
    }
    let cert_path = cert_dir.join(format!("{}.pem", name));
    let key_path = cert_dir.join(format!("{}-key.pem", name));
    drop(config);

    if !cert_path.exists() {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "certificate not found"})));
    }

    let detail = parse_cert_details(&cert_path, &key_path, &name);
    (StatusCode::OK, Json(detail))
}

/// POST /api/certs/import — multipart: name (text), cert (file), key (file)
pub async fn import(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> (StatusCode, Json<Value>) {
    let config = state.config.load();
    let cert_dir = config.global.cert_dir.clone();
    drop(config);

    let mut name: Option<String> = None;
    let mut cert_bytes: Option<Vec<u8>> = None;
    let mut key_bytes: Option<Vec<u8>> = None;
    let mut chain_bytes: Option<Vec<u8>> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name() {
            Some("name") => {
                name = field.text().await.ok();
            }
            Some("cert") => {
                cert_bytes = field.bytes().await.ok().map(|b| b.to_vec());
            }
            Some("key") => {
                key_bytes = field.bytes().await.ok().map(|b| b.to_vec());
            }
            Some("chain") => {
                chain_bytes = field.bytes().await.ok().map(|b| b.to_vec()).filter(|b| !b.is_empty());
            }
            _ => {}
        }
    }

    let name = match name.filter(|n| !n.is_empty()) {
        Some(n) => sanitize_cert_name(&n),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "missing 'name' field"})),
            )
        }
    };
    let cert_bytes = match cert_bytes {
        Some(b) if !b.is_empty() => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "missing 'cert' file"})),
            )
        }
    };
    let key_bytes = match key_bytes {
        Some(b) if !b.is_empty() => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "missing 'key' file"})),
            )
        }
    };

    let cert_path = cert_dir.join(format!("{}.pem", name));
    let key_path = cert_dir.join(format!("{}-key.pem", name));

    // If a CA chain was provided, append it to the cert to form a full-chain PEM.
    let full_cert = if let Some(mut chain) = chain_bytes {
        let mut combined = cert_bytes;
        if !combined.ends_with(b"\n") { combined.push(b'\n'); }
        combined.append(&mut chain);
        combined
    } else {
        cert_bytes
    };

    if let Err(e) = std::fs::write(&cert_path, &full_cert) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to write cert: {}", e)})),
        );
    }
    if let Err(e) = std::fs::write(&key_path, &key_bytes) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to write key: {}", e)})),
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }

    (
        StatusCode::CREATED,
        Json(json!({
            "imported": true,
            "cert": cert_path.display().to_string(),
            "key": key_path.display().to_string(),
        })),
    )
}

#[derive(Deserialize)]
pub struct SelfSignedRequest {
    pub name: String,
    pub cn: String,
    #[serde(default)]
    pub sans: Vec<String>,
}

/// POST /api/certs/self-signed — JSON { name, cn, sans: [] }
pub async fn generate_self_signed(
    State(state): State<AppState>,
    Json(req): Json<SelfSignedRequest>,
) -> (StatusCode, Json<Value>) {
    let config = state.config.load();
    let cert_dir = config.global.cert_dir.clone();
    drop(config);

    let name = sanitize_cert_name(&req.name);
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "name is required"})),
        );
    }

    let cert_path = cert_dir.join(format!("{}.pem", name));
    let key_path = cert_dir.join(format!("{}-key.pem", name));

    // Collect server IPs
    let mut extra_ips: Vec<std::net::IpAddr> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|iface| {
            let ip = iface.addr.ip();
            if ip.is_loopback() { None } else { Some(ip) }
        })
        .collect();

    // Parse any extra SANs that look like IPs
    for san in &req.sans {
        if let Ok(ip) = san.parse::<std::net::IpAddr>() {
            if !extra_ips.contains(&ip) {
                extra_ips.push(ip);
            }
        }
    }

    // For now pass extra_ips (DNS SANs from sans will be added by caller convention;
    // the core function only accepts IPs — DNS cn is always included)
    match serverwall_core::tls::generate_self_signed_cert(&cert_path, &key_path, &req.cn, &extra_ips) {
        Ok(()) => {
            (
                StatusCode::CREATED,
                Json(json!({
                    "generated": true,
                    "cert": cert_path.display().to_string(),
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

#[derive(Deserialize)]
pub struct AcmeRequest {
    pub email: String,
    pub domain: String,
    #[serde(default = "default_challenge_port")]
    pub challenge_port: u16,
}

fn default_challenge_port() -> u16 { 8081 }

/// POST /api/certs/acme — trigger Let's Encrypt certificate issuance
pub async fn acme_request(
    State(state): State<AppState>,
    Json(req): Json<AcmeRequest>,
) -> (StatusCode, Json<Value>) {
    let config = state.config.load();
    let cert_dir = config.global.cert_dir.clone();
    let acme_cfg = config.acme.clone();
    drop(config);

    let manager = AcmeManager::new(&acme_cfg);
    match manager.order_one(&req.domain, &req.email, &cert_dir, req.challenge_port).await {
        Ok(()) => {
            state.reload_config();
            (
                StatusCode::OK,
                Json(json!({"issued": true, "domain": req.domain})),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

/// DELETE /api/certs/:name — remove cert+key files
pub async fn delete(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> (StatusCode, Json<Value>) {
    let config = state.config.load();
    let cert_dir = config.global.cert_dir.clone();

    let cert_file = format!("{}.pem", name);

    // Check if any frontend uses this cert
    let in_use: Vec<String> = config
        .frontend
        .iter()
        .filter(|f| {
            f.tls_cert.as_ref().map_or(false, |p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map_or(false, |n| n == cert_file)
            })
        })
        .map(|f| f.name.clone())
        .collect();

    // Also check webui cert
    let webui_in_use = config
        .webui
        .tls_cert
        .as_ref()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .map_or(false, |n| n == cert_file);

    drop(config);

    if !in_use.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("certificate is in use by: {}", in_use.join(", "))
            })),
        );
    }
    if webui_in_use {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "certificate is in use by the web UI"})),
        );
    }

    let cert_path = cert_dir.join(&cert_file);
    let key_path = cert_dir.join(format!("{}-key.pem", name));

    if !cert_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "certificate not found"})),
        );
    }

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    let _ = send_reload_signal(&PathBuf::from(DEFAULT_PID_FILE));

    (StatusCode::OK, Json(json!({"deleted": true})))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Only allow alphanumeric, hyphen, underscore in cert names (prevent path traversal).
fn sanitize_cert_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

/// Parse the Not After date from a PEM cert file (for list view).
fn parse_cert_expiry(cert_path: &std::path::Path) -> Option<String> {
    use openssl::x509::X509;
    let pem = std::fs::read(cert_path).ok()?;
    let cert = X509::from_pem(&pem).ok()?;
    Some(format_asn1_time(cert.not_after()))
}

/// Parse full X.509 details from a cert+key pair. Returns a JSON object.
fn parse_cert_details(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    name: &str,
) -> Value {
    use openssl::hash::MessageDigest;

    let pem = match std::fs::read(cert_path) {
        Ok(b) => b,
        Err(e) => return json!({"error": format!("failed to read cert: {}", e)}),
    };

    let chain_certs = read_pem_chain(&pem);
    if chain_certs.is_empty() {
        return json!({"error": "failed to parse certificate"});
    }

    let cert = &chain_certs[0];

    let cn          = cert_cn(cert.subject_name());
    let issuer_cn   = cert_cn(cert.issuer_name());
    let self_signed = subject_equals_issuer(cert);
    let not_before  = format_asn1_time(cert.not_before());
    let not_after   = format_asn1_time(cert.not_after());
    let sans        = extract_sans(cert);
    let serial      = cert_serial_hex(cert);
    let sha1        = cert_fingerprint(cert, MessageDigest::sha1());
    let sha256      = cert_fingerprint(cert, MessageDigest::sha256());

    // Build chain array (leaf first, then intermediates/root)
    let chain: Vec<Value> = chain_certs.iter().enumerate().map(|(depth, c)| {
        json!({
            "depth": depth,
            "subject_cn": cert_cn(c.subject_name()),
            "issuer_cn": cert_cn(c.issuer_name()),
            "self_signed": subject_equals_issuer(c),
            "serial": cert_serial_hex(c),
            "not_before": format_asn1_time(c.not_before()),
            "not_after": format_asn1_time(c.not_after()),
            "sha1": cert_fingerprint(c, MessageDigest::sha1()),
            "sha256": cert_fingerprint(c, MessageDigest::sha256()),
            "sans": extract_sans(c),
        })
    }).collect();

    json!({
        "name": name,
        "cert_file": cert_path.display().to_string(),
        "key_file": key_path.display().to_string(),
        "key_exists": key_path.exists(),
        "cn": cn,
        "issuer_cn": issuer_cn,
        "self_signed": self_signed,
        "not_before": not_before,
        "not_after": not_after,
        "sans": sans,
        "serial": serial,
        "sha1": sha1,
        "sha256": sha256,
        "chain": chain,
    })
}

/// Read all PEM-encoded certificates from a block of PEM data (leaf first).
fn read_pem_chain(pem: &[u8]) -> Vec<openssl::x509::X509> {
    let pem_str = match std::str::from_utf8(pem) { Ok(s) => s, Err(_) => return vec![] };
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END:   &str = "-----END CERTIFICATE-----";
    let mut certs = Vec::new();
    let mut rest = pem_str;
    while let Some(start) = rest.find(BEGIN) {
        let chunk = &rest[start..];
        if let Some(end_pos) = chunk.find(END) {
            let block = &chunk[..end_pos + END.len()];
            if let Ok(cert) = openssl::x509::X509::from_pem(block.as_bytes()) {
                certs.push(cert);
            }
            rest = &chunk[end_pos + END.len()..];
        } else {
            break;
        }
    }
    certs
}

/// Format an OpenSSL ASN.1 time as ISO 8601 (e.g. "2025-01-01T00:00:00Z").
fn format_asn1_time(t: &openssl::asn1::Asn1TimeRef) -> String {
    use chrono::NaiveDateTime;
    let s = t.to_string();
    let trimmed = s.trim_end_matches(" GMT");
    for fmt in &["%b %e %T %Y", "%b %d %T %Y"] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(trimmed, fmt) {
            return format!("{}Z", dt.format("%Y-%m-%dT%H:%M:%S"));
        }
    }
    s // fallback: return original string
}

/// Extract the Common Name from an X.509 name.
fn cert_cn(name: &openssl::x509::X509NameRef) -> String {
    use openssl::nid::Nid;
    name.entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

/// Check if a certificate is self-signed (subject name hash == issuer name hash).
fn subject_equals_issuer(cert: &openssl::x509::X509) -> bool {
    cert.subject_name_hash() == cert.issuer_name_hash()
}

/// Format the serial number as colon-separated uppercase hex bytes (matches browser display).
fn cert_serial_hex(cert: &openssl::x509::X509) -> String {
    cert.serial_number()
        .to_bn()
        .ok()
        .map(|bn| {
            let bytes = bn.to_vec();
            if bytes.is_empty() { return String::new(); }
            bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":")
        })
        .unwrap_or_default()
}

/// Compute a fingerprint (SHA-1 or SHA-256) over the DER-encoded certificate.
fn cert_fingerprint(cert: &openssl::x509::X509, md: openssl::hash::MessageDigest) -> String {
    cert.to_der()
        .ok()
        .and_then(|der| openssl::hash::hash(md, &der).ok())
        .map(|d| d.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":"))
        .unwrap_or_default()
}

/// Extract Subject Alternative Names from a certificate.
fn extract_sans(cert: &openssl::x509::X509) -> Vec<String> {
    cert.subject_alt_names()
        .map(|names| {
            names.iter().filter_map(|n| {
                if let Some(dns) = n.dnsname() {
                    Some(format!("DNS:{}", dns))
                } else if let Some(ip) = n.ipaddress() {
                    let addr = if ip.len() == 4 {
                        let mut octets = [0u8; 4];
                        octets.copy_from_slice(ip);
                        std::net::Ipv4Addr::from(octets).to_string()
                    } else if ip.len() == 16 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(ip);
                        std::net::Ipv6Addr::from(octets).to_string()
                    } else {
                        return None;
                    };
                    Some(format!("IP:{}", addr))
                } else {
                    None
                }
            }).collect()
        })
        .unwrap_or_default()
}
