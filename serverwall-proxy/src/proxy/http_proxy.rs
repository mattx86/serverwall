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
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use serverwall_core::config::schema::{BalanceMethod, FrontendConfig, SecurityHeadersConfig};
use serverwall_core::types::Backend;
use serverwall_waf::engine::WafEngine;
use serverwall_waf::request::HttpRequestContext;

use crate::pipeline::RequestPipeline;

/// HTTP/HTTPS reverse proxy with header manipulation, WAF inspection, and routing.
pub struct HttpProxy {
    waf: Option<Arc<WafEngine>>,
    frontend_config: Arc<FrontendConfig>,
    security_headers: Arc<SecurityHeadersConfig>,
    pipeline: Arc<RequestPipeline>,
}

impl HttpProxy {
    /// Create a new HTTP proxy.
    pub fn new(
        frontend_config: FrontendConfig,
        security_headers: SecurityHeadersConfig,
        waf: Option<Arc<WafEngine>>,
        pipeline: Arc<RequestPipeline>,
    ) -> Self {
        Self {
            waf,
            frontend_config: Arc::new(frontend_config),
            security_headers: Arc::new(security_headers),
            pipeline,
        }
    }

    /// Handle a client connection: parse HTTP, apply WAF, proxy to backend (selected per-request).
    pub async fn handle_connection<S>(
        &self,
        stream: S,
        client_ip: IpAddr,
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let io = TokioIo::new(stream);
        let waf = self.waf.clone();
        let frontend_config = self.frontend_config.clone();
        let security_headers = self.security_headers.clone();
        let pipeline = self.pipeline.clone();

        let service = service_fn(move |req: Request<Incoming>| {
            let waf = waf.clone();
            let frontend_config = frontend_config.clone();
            let security_headers = security_headers.clone();
            let pipeline = pipeline.clone();

            async move {
                handle_request(req, client_ip, waf, frontend_config, security_headers, pipeline)
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
async fn handle_request(
    req: Request<Incoming>,
    client_ip: IpAddr,
    waf: Option<Arc<WafEngine>>,
    frontend_config: Arc<FrontendConfig>,
    security_headers: Arc<SecurityHeadersConfig>,
    pipeline: Arc<RequestPipeline>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let version = req.version();

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

    // WAF inspection
    if let Some(ref waf_engine) = waf {
        if frontend_config.waf_enabled {
            let waf_ctx = HttpRequestContext::from_parts(
                method.as_str(),
                &uri.to_string(),
                header_map.clone(),
                body_bytes.clone(),
                client_ip,
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

    let mut response = Response::builder().status(parts.status).version(hyper::Version::HTTP_11);

    // Copy response headers, removing hop-by-hop and server identification headers
    for (name, value) in &parts.headers {
        let lower = name.as_str().to_lowercase();

        // Remove hop-by-hop headers
        if HOP_BY_HOP_HEADERS.contains(&lower.as_str()) {
            continue;
        }

        // Strip server identification and tech-fingerprinting headers
        if lower == "server" || lower == "x-powered-by" {
            continue;
        }
        if FINGERPRINT_HEADERS.contains(&lower.as_str()) {
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
        let cookie_val = format!(
            "{}={}; Path=/; HttpOnly; SameSite=Lax",
            cookie_name, backend.tag
        );
        response = response.header("Set-Cookie", cookie_val);
    }

    // Add HSTS if configured (handled at the TLS/security config level)
    // The hsts_max_age is in SecurityTlsConfig, not SecurityHeadersConfig,
    // so we skip it here.

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

    // Log the request
    tracing::info!(
        client = %client_ip,
        method = %method,
        uri = %uri,
        version = ?version,
        status = %final_response.status().as_u16(),
        request_id = %request_id,
        backend_tag = %backend.tag,
        "HTTP request processed",
    );

    Ok(final_response)
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
