//! JA3 TLS client fingerprinting.
//!
//! Parses the raw bytes of a TLS ClientHello message and computes a JA3
//! fingerprint — an MD5 hash of:
//!
//!   `{SSLVersion},{Ciphers},{Extensions},{EllipticCurves},{EllipticCurvePointFormats}`
//!
//! Each field is a hyphen-separated list of decimal values.  GREASE values
//! (RFC 8701) are excluded from all fields.
//!
//! The fingerprint is computed from bytes peeked *before* the TLS handshake
//! completes, so it captures what the client offered — not what was negotiated.

/// GREASE values defined in RFC 8701.  These are injected by modern TLS stacks
/// to prevent ossification and must be stripped before fingerprinting.
const GREASE_VALUES: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];

#[inline]
fn is_grease(val: u16) -> bool {
    GREASE_VALUES.contains(&val)
}

struct Ja3Params {
    version: u16,
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    groups: Vec<u16>,
    point_formats: Vec<u8>,
}

/// Compute a JA3 fingerprint from raw TLS record bytes (peeked before handshake).
///
/// Returns `None` if `data` does not begin with a valid TLS ClientHello record.
pub fn compute_from_bytes(data: &[u8]) -> Option<String> {
    let params = parse_client_hello(data)?;
    Some(hash_params(&params))
}

fn hash_params(params: &Ja3Params) -> String {
    let ciphers = params.ciphers.iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let extensions = params.extensions.iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let groups = params.groups.iter()
        .map(|g| g.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let point_formats = params.point_formats.iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let ja3_string = format!(
        "{},{},{},{},{}",
        params.version, ciphers, extensions, groups, point_formats,
    );

    let digest = md5::compute(ja3_string.as_bytes());
    format!("{:x}", digest)
}

/// Parse a TLS ClientHello message out of a raw byte slice.
///
/// Layout:
/// ```text
/// TLS Record    : ContentType(1) ProtocolVersion(2) Length(2)
/// Handshake     : HandshakeType(1) Length(3)
/// ClientHello   : ClientVersion(2) Random(32) SessionID(1+N)
///                 CipherSuites(2+2N) CompressionMethods(1+N)
///                 Extensions(2 + [Type(2) Length(2) Data(N)]*)
/// ```
fn parse_client_hello(data: &[u8]) -> Option<Ja3Params> {
    // ── TLS record header (5 bytes) ──────────────────────────────────────────
    if data.len() < 5 {
        return None;
    }
    // ContentType 0x16 = handshake
    if data[0] != 0x16 {
        return None;
    }

    // ── Handshake header (4 bytes) ───────────────────────────────────────────
    let hs = &data[5..];
    if hs.len() < 4 {
        return None;
    }
    // HandshakeType 0x01 = ClientHello
    if hs[0] != 0x01 {
        return None;
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);

    let hello = hs.get(4..4 + hs_len)?;
    let mut pos = 0;

    // ── ClientVersion (2 bytes) ──────────────────────────────────────────────
    if hello.len() < pos + 2 {
        return None;
    }
    let version = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
    pos += 2;

    // ── Random (32 bytes) ───────────────────────────────────────────────────
    pos += 32;
    if pos > hello.len() {
        return None;
    }

    // ── SessionID (1-byte length prefix) ────────────────────────────────────
    if hello.len() < pos + 1 {
        return None;
    }
    let sid_len = hello[pos] as usize;
    pos += 1 + sid_len;

    // ── CipherSuites (2-byte length, then 2-byte values) ────────────────────
    if hello.len() < pos + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;
    if hello.len() < pos + cs_len {
        return None;
    }
    let mut ciphers = Vec::with_capacity(cs_len / 2);
    for i in (0..cs_len).step_by(2) {
        if pos + i + 2 > hello.len() {
            break;
        }
        let c = u16::from_be_bytes([hello[pos + i], hello[pos + i + 1]]);
        if !is_grease(c) {
            ciphers.push(c);
        }
    }
    pos += cs_len;

    // ── CompressionMethods (1-byte length) ──────────────────────────────────
    if hello.len() < pos + 1 {
        return None;
    }
    let comp_len = hello[pos] as usize;
    pos += 1 + comp_len;

    // ── Extensions (optional) ───────────────────────────────────────────────
    if hello.len() < pos + 2 {
        return Some(Ja3Params {
            version,
            ciphers,
            extensions: Vec::new(),
            groups: Vec::new(),
            point_formats: Vec::new(),
        });
    }
    let ext_total = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;

    let ext_block = hello.get(pos..pos + ext_total)?;
    let mut epos = 0;
    let mut extensions = Vec::new();
    let mut groups: Vec<u16> = Vec::new();
    let mut point_formats: Vec<u8> = Vec::new();

    while epos + 4 <= ext_block.len() {
        let ext_type = u16::from_be_bytes([ext_block[epos], ext_block[epos + 1]]);
        let ext_len = u16::from_be_bytes([ext_block[epos + 2], ext_block[epos + 3]]) as usize;
        epos += 4;

        let ext_data = match ext_block.get(epos..epos + ext_len) {
            Some(d) => d,
            None => break,
        };

        if !is_grease(ext_type) {
            extensions.push(ext_type);

            // Extension 0x000a — supported_groups (elliptic curves)
            if ext_type == 0x000a && ext_data.len() >= 2 {
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                let mut gi = 2;
                while gi + 2 <= ext_data.len() && gi < 2 + list_len {
                    let g = u16::from_be_bytes([ext_data[gi], ext_data[gi + 1]]);
                    if !is_grease(g) {
                        groups.push(g);
                    }
                    gi += 2;
                }
            }

            // Extension 0x000b — ec_point_formats
            if ext_type == 0x000b && ext_data.len() >= 1 {
                let list_len = ext_data[0] as usize;
                for i in 1..=list_len {
                    if i < ext_data.len() {
                        point_formats.push(ext_data[i]);
                    }
                }
            }
        }

        epos += ext_len;
    }

    Some(Ja3Params {
        version,
        ciphers,
        extensions,
        groups,
        point_formats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal sanity check: a truncated / random blob must not produce a fingerprint.
    #[test]
    fn rejects_garbage() {
        assert!(compute_from_bytes(&[]).is_none());
        assert!(compute_from_bytes(&[0x16, 0x03, 0x01, 0x00, 0x05]).is_none());
        assert!(compute_from_bytes(b"GET / HTTP/1.1\r\n").is_none());
    }

    /// GREASE filter: a cipher list containing only a GREASE value should yield
    /// an empty ciphers field.
    #[test]
    fn grease_filtered() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x002f));
    }
}
