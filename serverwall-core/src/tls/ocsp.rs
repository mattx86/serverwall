use std::sync::Arc;

use openssl::hash::MessageDigest;
use openssl::ocsp::{OcspCertId, OcspRequest};
use openssl::x509::X509;
use rustls::sign::CertifiedKey;

/// Given a `CertifiedKey`, attempt to fetch an OCSP staple for the leaf
/// certificate and return a new `CertifiedKey` with `ocsp` populated.
///
/// If the cert has no OCSP URL in its AIA extension, or if the fetch fails,
/// the original key is returned unchanged.
pub async fn staple_certified_key(ck: Arc<CertifiedKey>) -> Arc<CertifiedKey> {
    let leaf = match ck.end_entity_cert() {
        Ok(c) => c,
        Err(_) => return ck,
    };

    let ocsp_url = match extract_ocsp_url(leaf.as_ref()) {
        Some(url) => url,
        None => {
            tracing::debug!("no OCSP responder URL found in certificate AIA extension");
            return ck;
        }
    };

    // The issuer cert is the second certificate in the chain (index 1).
    let chain_ders: Vec<Vec<u8>> = ck.cert.iter().skip(1).map(|c| c.as_ref().to_vec()).collect();

    match fetch_ocsp_response(leaf.as_ref(), &chain_ders, &ocsp_url).await {
        Ok(response) => {
            tracing::info!(url = %ocsp_url, bytes = response.len(), "OCSP staple fetched");
            let new_ck = CertifiedKey {
                cert: ck.cert.clone(),
                key: Arc::clone(&ck.key),
                ocsp: Some(response),
            };
            Arc::new(new_ck)
        }
        Err(e) => {
            tracing::warn!(url = %ocsp_url, error = %e, "failed to fetch OCSP staple; continuing without stapling");
            ck
        }
    }
}

/// Extract the OCSP responder URL from the Authority Information Access (AIA)
/// extension of a DER-encoded certificate.
///
/// Uses `X509::to_text()` to get the human-readable OpenSSL output, then parses
/// lines of the form "OCSP - URI:http://..." to find the responder URL.
fn extract_ocsp_url(cert_der: &[u8]) -> Option<String> {
    let x509 = X509::from_der(cert_der).ok()?;
    let text_bytes = x509.to_text().ok()?;
    let text = String::from_utf8_lossy(&text_bytes);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(url) = trimmed.strip_prefix("OCSP - URI:") {
            let url = url.trim();
            if url.starts_with("http") {
                return Some(url.to_string());
            }
        }
    }
    None
}

/// Build an OCSP request for the given leaf certificate and POST it to the
/// OCSP responder, returning the raw DER-encoded response.
async fn fetch_ocsp_response(
    leaf_der: &[u8],
    chain_ders: &[Vec<u8>],
    ocsp_url: &str,
) -> anyhow::Result<Vec<u8>> {
    let leaf = X509::from_der(leaf_der)?;

    let issuer_der = chain_ders.first().ok_or_else(|| {
        anyhow::anyhow!("no issuer certificate in chain; cannot build OCSP request")
    })?;
    let issuer = X509::from_der(issuer_der)?;

    // Build OCSP request
    let cert_id = OcspCertId::from_cert(MessageDigest::sha1(), &leaf, &issuer)
        .map_err(|e| anyhow::anyhow!("failed to build OcspCertId: {}", e))?;

    let mut req = OcspRequest::new()
        .map_err(|e| anyhow::anyhow!("failed to create OcspRequest: {}", e))?;
    req.add_id(cert_id)
        .map_err(|e| anyhow::anyhow!("failed to add cert ID to OcspRequest: {}", e))?;

    let req_der = req
        .to_der()
        .map_err(|e| anyhow::anyhow!("failed to serialize OcspRequest: {}", e))?;

    // POST to OCSP responder
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let response = client
        .post(ocsp_url)
        .header("Content-Type", "application/ocsp-request")
        .body(req_der)
        .send()
        .await?;

    let bytes = response.bytes().await?;
    Ok(bytes.to_vec())
}
