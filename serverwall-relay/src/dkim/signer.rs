use anyhow::{Context, Result};
use mail_auth::common::crypto::{RsaKey, Ed25519Key, SigningKey};
use mail_auth::common::headers::HeaderWriter;
use mail_auth::dkim::{DkimSigner as MailAuthDkimSigner, Done};

use super::key_store::DkimDomainEntry;

/// Signs outbound messages with DKIM.
pub struct DkimSigner {
    _private: (),
}

impl DkimSigner {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Sign a message, returning the message with a prepended DKIM-Signature header.
    ///
    /// `entry`   — the DKIM domain configuration (selector, key file, algorithm)
    /// `message` — raw RFC 5322 message bytes
    pub fn sign(&self, entry: &DkimDomainEntry, message: &[u8]) -> Result<Vec<u8>> {
        let pem = std::fs::read_to_string(&entry.key_file)
            .with_context(|| format!("failed to read DKIM key: {}", entry.key_file.display()))?;

        match entry.algorithm.as_str() {
            "ed25519-sha256" => {
                let key = Ed25519Key::from_pkcs8_der(pem.as_bytes())
                    .map_err(|e| anyhow::anyhow!("failed to parse Ed25519 DKIM key: {e}"))?;
                sign_with_key(key, &entry.domain, &entry.selector, message)
            }
            _ => {
                // Default: rsa-sha256
                let key = RsaKey::from_pkcs8_pem(&pem)
                    .or_else(|_| RsaKey::from_rsa_pem(&pem))
                    .map_err(|e| anyhow::anyhow!("failed to parse RSA DKIM key: {e}"))?;
                sign_with_key(key, &entry.domain, &entry.selector, message)
            }
        }
    }
}

fn sign_with_key<T: SigningKey>(
    key: T,
    domain: &str,
    selector: &str,
    message: &[u8],
) -> Result<Vec<u8>> {
    let signer: MailAuthDkimSigner<T, Done> = MailAuthDkimSigner::from_key(key)
        .domain(domain)
        .selector(selector)
        .headers(["From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type"]);

    let signature = signer
        .sign(message)
        .map_err(|e| anyhow::anyhow!("DKIM signing failed: {e}"))?;

    let sig_header = signature.to_header();

    // Prepend the DKIM-Signature header to the message
    let mut signed = Vec::with_capacity(sig_header.len() + message.len());
    signed.extend_from_slice(sig_header.as_bytes());
    signed.extend_from_slice(message);

    Ok(signed)
}

impl Default for DkimSigner {
    fn default() -> Self {
        Self::new()
    }
}
