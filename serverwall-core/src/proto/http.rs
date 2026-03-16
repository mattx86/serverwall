use std::collections::HashMap;
use std::net::IpAddr;

/// A simplified set of HTTP headers represented as a map.
pub type HeaderMap = HashMap<String, String>;

/// Inject proxy-related headers into the header map.
pub fn inject_proxy_headers(headers: &mut HeaderMap, client_ip: IpAddr, host: Option<&str>) {
    headers.insert("X-Forwarded-For".to_string(), client_ip.to_string());
    headers.insert("X-Forwarded-Proto".to_string(), "https".to_string());
    if let Some(h) = host {
        headers.insert("X-Forwarded-Host".to_string(), h.to_string());
    }
}

/// Extract the Host header value from a header map.
pub fn get_host(headers: &HeaderMap) -> Option<&str> {
    headers.get("Host").or_else(|| headers.get("host")).map(|s| s.as_str())
}

/// Remove hop-by-hop headers that should not be forwarded.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let hop_headers = [
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailers",
        "Transfer-Encoding",
        "Upgrade",
    ];
    for h in &hop_headers {
        headers.remove(&h.to_lowercase());
        headers.remove(*h);
    }
}

/// Build a Via header value for proxy identification.
pub fn via_header(protocol_version: &str, proxy_name: &str) -> String {
    format!("{} {}", protocol_version, proxy_name)
}
