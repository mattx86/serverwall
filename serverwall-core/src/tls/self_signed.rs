use std::path::Path;

/// Generate a self-signed X.509 certificate and write PEM files.
///
/// Writes a 2048-bit RSA certificate valid for 10 years to `cert_path`
/// and the corresponding PKCS#8 private key to `key_path`.
/// The key file is set to mode 0600 on Unix.
///
/// `extra_ips` are additional IP addresses to include in the SAN extension
/// (e.g. all server interface IPs so the cert is valid for direct IP access).
pub fn generate_self_signed_cert(
    cert_path: &Path,
    key_path: &Path,
    cn: &str,
    extra_ips: &[std::net::IpAddr],
) -> anyhow::Result<()> {
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
    use openssl::x509::{X509, X509NameBuilder};

    let rsa = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", cn)?;
    let name = name.build();

    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(3650)?; // 10 years

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    builder.set_pubkey(&pkey)?;

    let basic_constraints = BasicConstraints::new().critical().ca().build()?;
    builder.append_extension(basic_constraints)?;

    let mut san_builder = SubjectAlternativeName::new();
    san_builder.dns(cn);
    san_builder.dns("localhost");
    san_builder.ip("127.0.0.1");
    for ip in extra_ips {
        san_builder.ip(&ip.to_string());
    }
    let san = san_builder.build(&builder.x509v3_context(None, None))?;
    builder.append_extension(san)?;

    builder.sign(&pkey, MessageDigest::sha256())?;
    let cert = builder.build();

    std::fs::write(cert_path, cert.to_pem()?)?;
    std::fs::write(key_path, pkey.private_key_to_pem_pkcs8()?)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}
