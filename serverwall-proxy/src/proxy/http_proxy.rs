use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use serverwall_core::acl::{AclDecision, PathAcl};
use serverwall_core::config::schema::{BalanceMethod, BotDetectionConfig, CookieSecurityConfig, FrontendConfig, LogFormat, ProtocolType, SecurityHeadersConfig};
use serverwall_core::logging::ApacheLogFormatter;
use serverwall_core::types::Backend;
use serverwall_waf::engine::WafEngine;
use serverwall_waf::rate_limit::{RateLimiter, RateLimitKey};
use serverwall_waf::request::HttpRequestContext;

use crate::pipeline::RequestPipeline;

/// Shared async log writer: Mutex-guarded buffered file writer.
type LogWriter = Arc<tokio::sync::Mutex<tokio::io::BufWriter<tokio::fs::File>>>;

/// HTTP/HTTPS reverse proxy with header manipulation, WAF inspection, and routing.
pub struct HttpProxy {
    waf: Option<Arc<WafEngine>>,
    frontend_config: Arc<FrontendConfig>,
    security_headers: Arc<SecurityHeadersConfig>,
    pipeline: Arc<RequestPipeline>,
    path_acl: Option<Arc<PathAcl>>,
    bot_detection: Arc<BotDetectionConfig>,
    hsts_max_age: Option<u64>,
    hsts_include_subdomains: bool,
    rate_limiters: Vec<Arc<(RateLimiter, RateLimitKey)>>,
    cookie_security: Arc<CookieSecurityConfig>,
    log_writer: Option<LogWriter>,
    log_format: LogFormat,
    /// When true, IPs in the global allow list bypass WAF inspection.
    acl_bypass_waf: bool,
    /// Domains allowed in the Host header (empty = allow all).
    domain_allow: Vec<String>,
    /// Domains blocked in the Host header.
    domain_block: Vec<String>,
}

impl HttpProxy {
    /// Create a new HTTP proxy.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        frontend_config: FrontendConfig,
        security_headers: SecurityHeadersConfig,
        waf: Option<Arc<WafEngine>>,
        pipeline: Arc<RequestPipeline>,
        path_acl: Option<Arc<PathAcl>>,
        bot_detection: BotDetectionConfig,
        hsts_max_age: Option<u64>,
        hsts_include_subdomains: bool,
        rate_limiters: Vec<Arc<(RateLimiter, RateLimitKey)>>,
        cookie_security: CookieSecurityConfig,
        log_writer: Option<LogWriter>,
        log_format: LogFormat,
        acl_bypass_waf: bool,
        domain_allow: Vec<String>,
        domain_block: Vec<String>,
    ) -> Self {
        Self {
            waf,
            frontend_config: Arc::new(frontend_config),
            security_headers: Arc::new(security_headers),
            pipeline,
            path_acl,
            bot_detection: Arc::new(bot_detection),
            hsts_max_age,
            hsts_include_subdomains,
            rate_limiters,
            cookie_security: Arc::new(cookie_security),
            log_writer,
            log_format,
            acl_bypass_waf,
            domain_allow,
            domain_block,
        }
    }

    /// Handle a client connection: parse HTTP, apply WAF, proxy to backend (selected per-request).
    pub async fn handle_connection<S>(
        &self,
        stream: S,
        client_ip: IpAddr,
        ja3_fingerprint: Option<String>,
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let io = TokioIo::new(stream);
        let waf = self.waf.clone();
        let frontend_config = self.frontend_config.clone();
        let security_headers = self.security_headers.clone();
        let pipeline = self.pipeline.clone();
        let path_acl = self.path_acl.clone();
        let bot_detection = self.bot_detection.clone();
        let hsts_max_age = self.hsts_max_age;
        let hsts_include_subdomains = self.hsts_include_subdomains;
        let rate_limiters = self.rate_limiters.clone();
        let cookie_security = self.cookie_security.clone();
        let log_writer = self.log_writer.clone();
        let log_format = self.log_format;
        let acl_bypass_waf = self.acl_bypass_waf;
        let domain_allow = self.domain_allow.clone();
        let domain_block = self.domain_block.clone();

        let service = service_fn(move |req: Request<Incoming>| {
            let waf = waf.clone();
            let frontend_config = frontend_config.clone();
            let security_headers = security_headers.clone();
            let pipeline = pipeline.clone();
            let path_acl = path_acl.clone();
            let bot_detection = bot_detection.clone();
            let rate_limiters = rate_limiters.clone();
            let cookie_security = cookie_security.clone();
            let ja3 = ja3_fingerprint.clone();
            let log_writer = log_writer.clone();
            let domain_allow = domain_allow.clone();
            let domain_block = domain_block.clone();

            async move {
                handle_request(
                    req,
                    client_ip,
                    waf,
                    frontend_config,
                    security_headers,
                    pipeline,
                    path_acl,
                    bot_detection,
                    hsts_max_age,
                    hsts_include_subdomains,
                    rate_limiters,
                    cookie_security,
                    ja3,
                    log_writer,
                    log_format,
                    acl_bypass_waf,
                    domain_allow,
                    domain_block,
                )
                .await
            }
        });

        if let Err(e) = http1::Builder::new()
            .serve_connection(io, service)
            .await
        {
            // Connection reset / broken pipe are normal for HTTP
            let msg = e.to_string();
            if !msg.contains("connection reset")
                && !msg.contains("broken pipe")
                && !msg.contains("connection closed")
            {
                tracing::debug!(error = %e, "HTTP connection error");
            }
        }

        Ok(())
    }
}

/// Hop-by-hop headers that must not be forwarded.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Tech-fingerprinting headers that reveal backend software identity.
const FINGERPRINT_HEADERS: &[&str] = &[
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
    "x-rack-cache",
    "x-pingback",
    "x-powered-cms",
    "x-cf-powered-by",
];

/// Handle a single HTTP request: WAF check, select backend, forward, return response.
#[allow(clippy::too_many_arguments)]
async fn handle_request(
    req: Request<Incoming>,
    client_ip: IpAddr,
    waf: Option<Arc<WafEngine>>,
    frontend_config: Arc<FrontendConfig>,
    security_headers: Arc<SecurityHeadersConfig>,
    pipeline: Arc<RequestPipeline>,
    path_acl: Option<Arc<PathAcl>>,
    bot_detection: Arc<BotDetectionConfig>,
    hsts_max_age: Option<u64>,
    hsts_include_subdomains: bool,
    rate_limiters: Vec<Arc<(RateLimiter, RateLimitKey)>>,
    cookie_security: Arc<CookieSecurityConfig>,
    ja3_fingerprint: Option<String>,
    log_writer: Option<LogWriter>,
    log_format: LogFormat,
    acl_bypass_waf: bool,
    domain_allow: Vec<String>,
    domain_block: Vec<String>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let version = req.version();
    let is_tls = matches!(frontend_config.protocol, ProtocolType::Https);

    // Generate a request ID
    let request_id = uuid::Uuid::new_v4().to_string();

    // Extract headers into a HashMap for WAF inspection
    let mut header_map: HashMap<String, String> = HashMap::new();
    for (name, value) in req.headers() {
        if let Ok(val) = value.to_str() {
            header_map.insert(name.as_str().to_lowercase(), val.to_string());
        }
    }

    // Read the body
    let body_bytes = match req.collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(e) => {
            tracing::debug!(error = %e, "failed to read request body");
            return Ok(error_response(StatusCode::BAD_REQUEST, "Bad Request"));
        }
    };

    // Path ACL check (before WAF, after IP ACL which happens at the listener level).
    if let Some(ref acl) = path_acl {
        let path = uri.path();
        if let Some(AclDecision::Deny) = acl.check(path) {
            tracing::info!(client = %client_ip, path = %path, "request blocked by path ACL");
            return Ok(error_response(StatusCode::FORBIDDEN, "Forbidden"));
        }
    }

    // Domain ACL: check the Host header against allowed/blocked domain lists.
    if !domain_allow.is_empty() || !domain_block.is_empty() {
        let host = header_map.get("host")
            .map(|h| h.split(':').next().unwrap_or(h).to_lowercase())
            .unwrap_or_default();
        if !host.is_empty() {
            if domain_block.iter().any(|d| host == d.to_lowercase()) {
                tracing::info!(client = %client_ip, host = %host, "request blocked by domain ACL (block list)");
                return Ok(error_response(StatusCode::FORBIDDEN, "Forbidden"));
            }
            if !domain_allow.is_empty() && !domain_allow.iter().any(|d| host == d.to_lowercase()) {
                tracing::info!(client = %client_ip, host = %host, "request blocked by domain ACL (not in allow list)");
                return Ok(error_response(StatusCode::FORBIDDEN, "Forbidden"));
            }
        }
    }

    // Bot detection: User-Agent and JA3 fingerprint checks.
    if bot_detection.enabled {
        let ua = header_map.get("user-agent").map(|s| s.as_str()).unwrap_or("");
        if is_blocked_bot(ua, &bot_detection) {
            tracing::info!(client = %client_ip, user_agent = %ua, "request blocked by bot detection");
            return Ok(error_response(StatusCode::FORBIDDEN, "Forbidden"));
        }
        if let Some(ref ja3) = ja3_fingerprint {
            if bot_detection.ja3_fingerprint_block_list.iter().any(|b| b == ja3) {
                tracing::info!(client = %client_ip, ja3 = %ja3, "request blocked by JA3 fingerprint");
                return Ok(error_response(StatusCode::FORBIDDEN, "Forbidden"));
            }
        }
    }

    // HTTP rate limiting
    for rl in &rate_limiters {
        let (limiter, key) = rl.as_ref();
        let k = match key {
            RateLimitKey::ClientIp => client_ip.to_string(),
            RateLimitKey::Header(h) => header_map.get(h.to_lowercase().as_str())
                .cloned()
                .unwrap_or_default(),
        };
        if !k.is_empty() && !limiter.check_key(&k) {
            tracing::info!(client = %client_ip, "request rate-limited");
            return Ok(error_response(StatusCode::TOO_MANY_REQUESTS, "Too Many Requests"));
        }
    }

    // WAF inspection (skipped if client IP is globally allowed and acl_bypass_waf is set)
    let waf_bypassed = acl_bypass_waf && pipeline.is_globally_allowed(client_ip);
    if let Some(ref waf_engine) = waf {
        if frontend_config.waf_enabled && !waf_bypassed {
            let waf_ctx = HttpRequestContext::from_parts(
                method.as_str(),
                &uri.to_string(),
                header_map.clone(),
                body_bytes.clone(),
                client_ip,
                ja3_fingerprint.clone(),
            );

            let verdict = waf_engine.inspect(&waf_ctx);
            if verdict.decision.is_blocked() {
                tracing::info!(
                    client = %client_ip,
                    uri = %uri,
                    anomaly_score = verdict.anomaly_score,
                    matched_rules = ?verdict.matched_rules,
                    "request blocked by WAF",
                );
                return Ok(error_response(StatusCode::FORBIDDEN, "Forbidden"));
            }
        }
    }

    // Select backend: sticky session routes by cookie tag, others use the balancer.
    let sticky = frontend_config.balancer == BalanceMethod::StickySession;
    let cookie_name = &frontend_config.session_cookie;

    let sticky_tag = if sticky {
        parse_cookie(&header_map, cookie_name)
    } else {
        None
    };

    let (backend, _guard) = if let Some(ref tag) = sticky_tag {
        if let Some(b) = pipeline.find_backend_by_tag(tag) {
            let guard = serverwall_core::types::ConnectionGuard::new(b.clone());
            (b, guard)
        } else {
            match pipeline.select_backend(client_ip) {
                Ok(result) => result,
                Err(e) => {
                    tracing::warn!(client = %client_ip, error = %e, "no backend available");
                    return Ok(error_response(StatusCode::BAD_GATEWAY, "Bad Gateway"));
                }
            }
        }
    } else {
        match pipeline.select_backend(client_ip) {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!(client = %client_ip, error = %e, "no backend available");
                return Ok(error_response(StatusCode::BAD_GATEWAY, "Bad Gateway"));
            }
        }
    };

    // Build the outbound request to the backend
    let backend_uri = format!(
        "http://{}{}",
        backend.address,
        uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"),
    );

    let mut builder = hyper::Request::builder()
        .method(method.clone())
        .uri(&backend_uri)
        .version(hyper::Version::HTTP_11);

    // Copy headers, removing hop-by-hop headers
    for (name, value) in &header_map {
        let lower = name.to_lowercase();
        if HOP_BY_HOP_HEADERS.contains(&lower.as_str()) {
            continue;
        }
        if let Ok(header_name) = hyper::header::HeaderName::from_bytes(name.as_bytes()) {
            if let Ok(header_value) = hyper::header::HeaderValue::from_str(value) {
                builder = builder.header(header_name, header_value);
            }
        }
    }

    // Inject proxy headers
    let headers_config = &frontend_config.headers;

    if headers_config.x_forwarded_for {
        let existing = header_map.get("x-forwarded-for");
        let xff = match existing {
            Some(existing) => format!("{}, {}", existing, client_ip),
            None => client_ip.to_string(),
        };
        builder = builder.header("X-Forwarded-For", xff);
    }

    if headers_config.x_real_ip {
        builder = builder.header("X-Real-IP", client_ip.to_string());
    }

    if headers_config.x_forwarded_proto {
        let proto = match frontend_config.protocol {
            serverwall_core::config::schema::ProtocolType::Https => "https",
            _ => "http",
        };
        builder = builder.header("X-Forwarded-Proto", proto);
    }

    if headers_config.x_forwarded_host {
        if let Some(host) = header_map.get("host") {
            builder = builder.header("X-Forwarded-Host", host.as_str());
        }
    }

    if headers_config.x_forwarded_port {
        // Extract port from listen config or Host header
        if let Some(host) = header_map.get("host") {
            if let Some(port_str) = host.rsplit(':').next() {
                builder = builder.header("X-Forwarded-Port", port_str);
            }
        }
    }

    if headers_config.x_request_id {
        builder = builder.header("X-Request-ID", &request_id);
    }

    // Add custom headers
    for custom in &headers_config.custom {
        if let Ok(name) = hyper::header::HeaderName::from_bytes(custom.name.as_bytes()) {
            if let Ok(value) = hyper::header::HeaderValue::from_str(&custom.value) {
                builder = builder.header(name, value);
            }
        }
    }

    let outbound_body = Full::new(Bytes::from(body_bytes));

    let outbound_req = match builder.body(outbound_body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "failed to build outbound request");
            return Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
            ));
        }
    };

    // Connect to backend and send request
    let backend_response = match forward_to_backend(outbound_req, &backend).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!(
                backend_tag = %backend.tag,
                error = %e,
                "failed to forward request to backend",
            );
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "Bad Gateway",
            ));
        }
    };

    // Build response to client
    let (parts, body) = backend_response.into_parts();

    let resp_body = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::debug!(error = %e, "failed to read backend response body");
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "Bad Gateway",
            ));
        }
    };

    // Proxy-side gzip compression
    let wants_gzip = header_map
        .get("accept-encoding")
        .map(|v| v.contains("gzip"))
        .unwrap_or(false);
    let backend_has_encoding = parts.headers.contains_key("content-encoding");
    let content_type = parts.headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let compressible_type = security_headers.compress_types
        .iter()
        .any(|t| content_type.starts_with(t.as_str()));
    let should_compress = security_headers.compress_responses
        && wants_gzip
        && !backend_has_encoding
        && compressible_type
        && resp_body.len() >= security_headers.compress_min_size;

    let (resp_body, did_compress) = if should_compress {
        use flate2::write::GzEncoder;
        use flate2::Compression as GzCompression;
        use std::io::Write;
        let result = (|| {
            let mut enc = GzEncoder::new(Vec::new(), GzCompression::default());
            enc.write_all(&resp_body)?;
            enc.finish()
        })();
        match result {
            Ok(compressed) => (Bytes::from(compressed), true),
            Err(e) => {
                tracing::warn!(error = %e, "gzip compression failed, sending uncompressed");
                (resp_body, false)
            }
        }
    } else {
        (resp_body, false)
    };

    let mut response = Response::builder().status(parts.status).version(hyper::Version::HTTP_11);

    // Copy response headers, removing hop-by-hop and server identification headers
    for (name, value) in &parts.headers {
        let lower = name.as_str().to_lowercase();

        // Remove hop-by-hop headers
        if HOP_BY_HOP_HEADERS.contains(&lower.as_str()) {
            continue;
        }

        // Strip server identification headers; we add our own Server header below.
        if lower == "server" {
            continue;
        }
        // Skip Content-Length from backend when we've rewritten the body via compression.
        if lower == "content-length" && did_compress {
            continue;
        }
        if lower == "x-powered-by" && security_headers.remove_x_powered_by {
            continue;
        }
        if FINGERPRINT_HEADERS.contains(&lower.as_str()) {
            continue;
        }

        // Apply cookie security policy to Set-Cookie headers from the backend.
        if lower == "set-cookie" {
            if let Ok(v) = value.to_str() {
                if let Some(rewritten) = enforce_set_cookie(v, &cookie_security, is_tls) {
                    response = response.header("Set-Cookie", rewritten);
                }
            }
            continue;
        }

        response = response.header(name.clone(), value.clone());
    }

    // Add security response headers
    if security_headers.add_x_content_type_options {
        response = response.header("X-Content-Type-Options", "nosniff");
    }

    if let Some(ref frame_options) = security_headers.add_x_frame_options {
        response = response.header("X-Frame-Options", frame_options.as_str());
    }

    if let Some(ref referrer_policy) = security_headers.add_referrer_policy {
        response = response.header("Referrer-Policy", referrer_policy.as_str());
    }

    if let Some(ref csp) = security_headers.add_content_security_policy {
        response = response.header("Content-Security-Policy", csp.as_str());
    }

    // Inject sticky-session cookie so clients route back to the same backend.
    if sticky {
        let mut cookie_val = format!(
            "{}={}; Path=/; HttpOnly; SameSite=Lax",
            cookie_name, backend.tag
        );
        if is_tls {
            cookie_val.push_str("; Secure");
        }
        response = response.header("Set-Cookie", cookie_val);
    }

    // HSTS (only meaningful for HTTPS frontends; callers pass None for plain HTTP)
    if let Some(max_age) = hsts_max_age {
        let mut hsts = format!("max-age={}", max_age);
        if hsts_include_subdomains { hsts.push_str("; includeSubDomains"); }
        response = response.header("Strict-Transport-Security", hsts);
    }

    if did_compress {
        response = response.header("Content-Encoding", "gzip");
        response = response.header("Vary", "Accept-Encoding");
        response = response.header("Content-Length", resp_body.len().to_string());
    }

    let resp_body_len = resp_body.len() as u64;
    let final_response = match response.body(Full::new(resp_body)) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "failed to build client response");
            return Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
            ));
        }
    };

    // Structured tracing log (always emitted)
    tracing::info!(
        client = %client_ip,
        method = %method,
        uri = %uri,
        version = ?version,
        status = %final_response.status().as_u16(),
        request_id = %request_id,
        backend_tag = %backend.tag,
        ja3 = ja3_fingerprint.as_deref().unwrap_or("-"),
        "HTTP request processed",
    );

    // Access log file (only when configured)
    if let Some(ref writer) = log_writer {
        let status = final_response.status().as_u16();
        let bytes = resp_body_len;
        let line = match log_format {
            LogFormat::Json => {
                format!(
                    "{{\"time\":\"{}\",\"client\":\"{}\",\"method\":\"{}\",\"uri\":\"{}\",\"status\":{},\"bytes\":{},\"backend\":\"{}\"}}\n",
                    chrono::Utc::now().to_rfc3339(),
                    client_ip,
                    method,
                    uri,
                    status,
                    bytes,
                    backend.tag,
                )
            }
            _ => {
                // Apache Combined format for ApacheCombined, ApacheCustom, and other variants
                let formatter = ApacheLogFormatter::new();
                let referer = parts.headers.get("referer").and_then(|v| v.to_str().ok());
                let user_agent = header_map.get("user-agent").map(|s| s.as_str());
                format!("{}\n", formatter.format(client_ip, method.as_str(), uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"), status, bytes, referer, user_agent))
            }
        };
        let mut w = writer.lock().await;
        let _ = w.write_all(line.as_bytes()).await;
        let _ = w.flush().await;
    }

    Ok(final_response)
}

/// Known bad bot User-Agent substrings (common scrapers/scanners/attackers).
const KNOWN_BAD_BOT_SIGNATURES: &[&str] = &[
    "masscan",
    "nikto",
    "sqlmap",
    "nmap",
    "zgrab",
    "python-requests",
    "go-http-client",
    "curl/",
    "wget/",
    "libwww-perl",
    "scrapy",
    "semrushbot",
    "ahrefsbot",
    "mj12bot",
    "dotbot",
    "blexbot",
    "majestic",
    "petalbot",
    "bytespider",
    "claudebot",
];

/// Check whether a User-Agent matches a known-bad bot signature or the config block list.
fn is_blocked_bot(user_agent: &str, config: &BotDetectionConfig) -> bool {
    let ua_lower = user_agent.to_lowercase();

    // Known-good bots are always allowed, even if they happen to match a signature.
    for good in &config.known_good_bots {
        if ua_lower.contains(&good.to_lowercase()) {
            return false;
        }
    }

    // Check built-in bad bot signatures.
    for sig in KNOWN_BAD_BOT_SIGNATURES {
        if ua_lower.contains(sig) {
            return true;
        }
    }

    false
}

/// Rewrite a single `Set-Cookie` header value to enforce the configured cookie security
/// policy. Returns `None` to drop cookies whose name=value exceeds `max_cookie_size`.
fn enforce_set_cookie(value: &str, cfg: &CookieSecurityConfig, is_tls: bool) -> Option<String> {
    let parts: Vec<&str> = value.split(';').collect();
    if parts.is_empty() {
        return Some(value.to_string());
    }
    let name_value = parts[0].trim();

    // Drop cookies whose name=value portion exceeds the configured limit.
    if cfg.max_cookie_size > 0 && name_value.len() > cfg.max_cookie_size {
        return None;
    }

    let mut attrs: Vec<String> = parts[1..].iter().map(|s| s.trim().to_string()).collect();
    let lower: Vec<String> = attrs.iter().map(|s| s.to_lowercase()).collect();

    if cfg.enforce_secure_flag && is_tls && !lower.iter().any(|a| a == "secure") {
        attrs.push("Secure".to_string());
    }
    if cfg.enforce_httponly_flag && !lower.iter().any(|a| a == "httponly") {
        attrs.push("HttpOnly".to_string());
    }
    if let Some(ref samesite) = cfg.enforce_samesite {
        attrs.retain(|a| !a.to_lowercase().starts_with("samesite"));
        attrs.push(format!("SameSite={}", samesite));
    }

    let mut result = name_value.to_string();
    for attr in &attrs {
        result.push_str("; ");
        result.push_str(attr);
    }
    Some(result)
}

/// Parse the value of a named cookie from the `Cookie` header map entry.
fn parse_cookie(headers: &HashMap<String, String>, name: &str) -> Option<String> {
    let cookie_header = headers.get("cookie")?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Forward a request to the backend over a new TCP connection.
async fn forward_to_backend(
    req: Request<Full<Bytes>>,
    backend: &Backend,
) -> anyhow::Result<Response<Incoming>> {
    let stream = TcpStream::connect(backend.address).await?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

    // Spawn the connection driver
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            let msg = e.to_string();
            if !msg.contains("connection closed") && !msg.contains("broken pipe") {
                tracing::debug!(error = %e, "backend connection error");
            }
        }
    });

    let response = sender.send_request(req).await?;
    Ok(response)
}

/// Create an error response with the given status and body text.
fn error_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}
