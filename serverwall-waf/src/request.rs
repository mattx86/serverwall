use std::collections::HashMap;
use std::net::IpAddr;

/// Normalized HTTP request context used for WAF inspection.
#[derive(Debug, Clone)]
pub struct HttpRequestContext {
    pub method: String,
    pub uri: String,
    pub path: String,
    pub query_string: String,
    pub headers: HashMap<String, String>,
    pub cookies: HashMap<String, String>,
    pub body: Vec<u8>,
    pub remote_addr: IpAddr,
    pub protocol: String,
    /// JA3 TLS fingerprint, if the connection was TLS and the ClientHello was parseable.
    pub ja3_fingerprint: Option<String>,
}

impl HttpRequestContext {
    /// Build a request context from its constituent parts.
    pub fn from_parts(
        method: &str,
        uri: &str,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        client_ip: IpAddr,
        ja3_fingerprint: Option<String>,
    ) -> Self {
        // Split URI into path and query string
        let (path, query_string) = if let Some(idx) = uri.find('?') {
            (uri[..idx].to_string(), uri[idx + 1..].to_string())
        } else {
            (uri.to_string(), String::new())
        };

        // Parse cookies from Cookie header
        let cookies = headers
            .get("cookie")
            .or_else(|| headers.get("Cookie"))
            .map(|cookie_header| {
                cookie_header
                    .split(';')
                    .filter_map(|pair| {
                        let pair = pair.trim();
                        let mut parts = pair.splitn(2, '=');
                        let key = parts.next()?.trim().to_string();
                        let value = parts.next().unwrap_or("").trim().to_string();
                        if key.is_empty() {
                            None
                        } else {
                            Some((key, value))
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Determine protocol from headers or default
        let protocol = if headers.contains_key("x-forwarded-proto") {
            headers["x-forwarded-proto"].clone()
        } else {
            "http".to_string()
        };

        Self {
            method: method.to_uppercase(),
            uri: uri.to_string(),
            path,
            query_string,
            headers,
            cookies,
            body,
            remote_addr: client_ip,
            protocol,
            ja3_fingerprint,
        }
    }

    /// Get the user agent string if present.
    pub fn user_agent(&self) -> Option<&str> {
        self.headers
            .get("user-agent")
            .or_else(|| self.headers.get("User-Agent"))
            .map(|s| s.as_str())
    }

    /// Get the body as a UTF-8 string (lossy).
    pub fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    /// Get the total size of the request body.
    pub fn body_size(&self) -> usize {
        self.body.len()
    }

    /// Get the number of headers.
    pub fn header_count(&self) -> usize {
        self.headers.len()
    }
}
