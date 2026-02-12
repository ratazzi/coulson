use std::time::Duration;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::store::AppRepository;

#[derive(Debug, Serialize, Deserialize)]
pub struct ShareClaims {
    pub sub: String,
    pub exp: u64,
}

pub struct ShareSigner {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

const SETTINGS_KEY: &str = "share.signing_key";

impl ShareSigner {
    /// Load signing key from settings or generate a new one.
    pub fn load_or_generate(store: &AppRepository) -> anyhow::Result<Self> {
        let pem = match store.get_setting(SETTINGS_KEY)? {
            Some(existing) => existing,
            None => {
                let signing_key = SigningKey::random(&mut OsRng);
                let pem_doc = signing_key
                    .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
                    .map_err(|e| anyhow::anyhow!("failed to export PKCS#8 PEM: {e}"))?;
                let pem_str = pem_doc.to_string();
                store.set_setting(SETTINGS_KEY, &pem_str)?;
                pem_str
            }
        };

        let encoding_key = EncodingKey::from_ec_pem(pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("failed to parse EC private key: {e}"))?;

        // Derive public key PEM from private key for DecodingKey
        let signing_key = SigningKey::from_pkcs8_pem(&pem)
            .map_err(|e| anyhow::anyhow!("failed to parse PKCS#8 PEM: {e}"))?;
        let verifying_key = signing_key.verifying_key();
        let pub_pem = verifying_key
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .map_err(|e| anyhow::anyhow!("failed to export public key PEM: {e}"))?;
        let decoding_key = DecodingKey::from_ec_pem(pub_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("failed to parse EC public key: {e}"))?;

        Ok(Self {
            encoding_key,
            decoding_key,
        })
    }

    /// Create a JWT token for a domain with the given expiry duration.
    pub fn create_token(&self, domain: &str, expires_in: Duration) -> anyhow::Result<String> {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            + expires_in.as_secs();

        let claims = ShareClaims {
            sub: domain.to_string(),
            exp,
        };

        let header = Header::new(Algorithm::ES256);
        let token = jsonwebtoken::encode(&header, &claims, &self.encoding_key)?;
        Ok(token)
    }

    /// Validate a JWT token, returning the claims if valid.
    pub fn validate_token(&self, token: &str) -> Option<ShareClaims> {
        let mut validation = Validation::new(Algorithm::ES256);
        validation.required_spec_claims.remove("aud");
        validation.validate_aud = false;
        validation.leeway = 0;

        jsonwebtoken::decode::<ShareClaims>(token, &self.decoding_key, &validation)
            .ok()
            .map(|data| data.claims)
    }
}

/// Parse a human-readable duration string (e.g. "30m", "2h", "7d") into a Duration.
pub fn parse_duration(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty duration string");
    }

    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: u64 = num_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration: {s}"))?;

    let secs = match unit {
        "m" => num * 60,
        "h" => num * 3600,
        "d" => num * 86400,
        _ => anyhow::bail!("unknown duration unit: {unit}. Use m, h, or d"),
    };

    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use rusqlite::Connection;

    fn test_repo() -> AppRepository {
        let repo = AppRepository {
            conn: Mutex::new(Connection::open_in_memory().expect("open sqlite")),
            domain_suffix: "test".to_string(),
        };
        repo.init_schema().expect("schema");
        repo
    }

    #[test]
    fn load_or_generate_creates_and_reuses_key() {
        let repo = test_repo();
        let signer1 = ShareSigner::load_or_generate(&repo).expect("first load");
        let token = signer1
            .create_token("myapp.test", Duration::from_secs(3600))
            .expect("create token");

        // Second load should reuse the same key and validate the token
        let signer2 = ShareSigner::load_or_generate(&repo).expect("second load");
        let claims = signer2.validate_token(&token).expect("validate");
        assert_eq!(claims.sub, "myapp.test");
    }

    #[test]
    fn expired_token_is_rejected() {
        let repo = test_repo();
        let signer = ShareSigner::load_or_generate(&repo).expect("load");
        // Create token that expired 1 second ago
        let claims = ShareClaims {
            sub: "myapp.test".to_string(),
            exp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 1,
        };
        let header = Header::new(Algorithm::ES256);
        let token =
            jsonwebtoken::encode(&header, &claims, &signer.encoding_key).expect("encode");
        assert!(signer.validate_token(&token).is_none());
    }

    #[test]
    fn parse_duration_works() {
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604800));
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("10x").is_err());
    }
}
