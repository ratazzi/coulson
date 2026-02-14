use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use tracing::info;

#[cfg(unix)]
fn write_private_key(path: &Path, data: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to create key file: {}", path.display()))?;
    f.write_all(data.as_bytes())
        .with_context(|| format!("failed to write key file: {}", path.display()))?;
    // Also fix permissions for pre-existing files (mode only applies to newly created files)
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set key file permissions: {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_key(path: &Path, data: &str) -> anyhow::Result<()> {
    fs::write(path, data).with_context(|| format!("failed to write key file: {}", path.display()))
}

pub struct CertManager {
    ca_cert_path: PathBuf,
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
}

impl CertManager {
    pub fn ensure(certs_dir: &Path, domain_suffix: &str) -> anyhow::Result<Self> {
        fs::create_dir_all(certs_dir)
            .with_context(|| format!("failed to create certs dir: {}", certs_dir.display()))?;

        let ca_cert_path = certs_dir.join("ca.crt");
        let ca_key_path = certs_dir.join("ca.key");
        let server_cert_path = certs_dir.join("server.crt");
        let server_key_path = certs_dir.join("server.key");
        let suffix_meta_path = certs_dir.join("server.suffix");

        // Generate CA if not present
        let (ca_params, ca_key_pem, ca_cert_pem, ca_regenerated) = if ca_cert_path.exists()
            && ca_key_path.exists()
        {
            let cert_pem = fs::read_to_string(&ca_cert_path).context("failed to read CA cert")?;
            let key_pem = fs::read_to_string(&ca_key_path).context("failed to read CA key")?;
            (build_ca_params()?, key_pem, cert_pem, false)
        } else {
            info!("generating self-signed CA certificate");
            let ca_params = build_ca_params()?;
            let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
            let cert = ca_params.self_signed(&ca_key)?;
            let cert_pem = cert.pem();
            let key_pem = ca_key.serialize_pem();
            fs::write(&ca_cert_path, &cert_pem).context("failed to write CA cert")?;
            write_private_key(&ca_key_path, &key_pem)?;
            (ca_params, key_pem, cert_pem, true)
        };

        // Re-sign server cert if: CA was regenerated, suffix changed, or cert files missing
        let need_server_cert = ca_regenerated
            || !server_cert_path.exists()
            || !server_key_path.exists()
            || !suffix_matches(&suffix_meta_path, domain_suffix);

        if need_server_cert {
            info!(suffix = domain_suffix, "generating server certificate");
            let (cert_pem, key_pem) =
                generate_server_cert(&ca_params, &ca_key_pem, &ca_cert_pem, domain_suffix)?;
            fs::write(&server_cert_path, &cert_pem).context("failed to write server cert")?;
            write_private_key(&server_key_path, &key_pem)?;
            fs::write(&suffix_meta_path, domain_suffix)
                .context("failed to write suffix metadata")?;
        }

        Ok(Self {
            ca_cert_path,
            server_cert_path,
            server_key_path,
        })
    }

    pub fn ca_path(&self) -> &str {
        self.ca_cert_path.to_str().unwrap_or("")
    }

    pub fn cert_path(&self) -> &str {
        self.server_cert_path.to_str().unwrap_or("")
    }

    pub fn key_path(&self) -> &str {
        self.server_key_path.to_str().unwrap_or("")
    }
}

fn build_ca_params() -> anyhow::Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params
        .distinguished_name
        .push(DnType::CommonName, "Coulson Dev CA");
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    const CA_VALIDITY_DAYS: i64 = 3650; // 10 years
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(CA_VALIDITY_DAYS);

    Ok(params)
}

fn generate_server_cert(
    ca_params: &CertificateParams,
    ca_key_pem: &str,
    ca_cert_pem: &str,
    domain_suffix: &str,
) -> anyhow::Result<(String, String)> {
    let ca_key = KeyPair::from_pem(ca_key_pem)?;
    let issuer = Issuer::from_params(ca_params, &ca_key);

    let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, format!("*.{domain_suffix}"));

    params.subject_alt_names = vec![
        SanType::DnsName(format!("*.{domain_suffix}").try_into()?),
        SanType::DnsName(domain_suffix.to_string().try_into()?),
    ];

    const SERVER_CERT_VALIDITY_DAYS: i64 = 365; // 1 year
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(SERVER_CERT_VALIDITY_DAYS);

    let cert = params.signed_by(&server_key, &issuer)?;
    // Full chain: server cert + CA cert (so clients can verify without having CA pre-installed)
    let chain_pem = format!("{}{}", cert.pem(), ca_cert_pem);
    Ok((chain_pem, server_key.serialize_pem()))
}

/// Check if the stored suffix metadata matches the current domain suffix.
fn suffix_matches(meta_path: &Path, domain_suffix: &str) -> bool {
    match fs::read_to_string(meta_path) {
        Ok(stored) => stored.trim() == domain_suffix,
        Err(_) => false,
    }
}
