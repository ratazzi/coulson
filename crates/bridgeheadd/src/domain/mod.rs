use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppId(pub String);

impl Default for AppId {
    fn default() -> Self {
        Self(Uuid::now_v7().to_string())
    }
}

impl AppId {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppKind {
    Static,
    Rack,
    Asgi,
    Container,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DomainName(pub String);

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("domain must end with .{0}")]
    InvalidSuffix(String),
    #[error("invalid domain label")]
    InvalidLabel,
}

impl DomainName {
    pub fn parse(input: &str, suffix: &str) -> Result<Self, DomainError> {
        let input = input.trim().to_ascii_lowercase();
        if !input.ends_with(&format!(".{suffix}")) {
            return Err(DomainError::InvalidSuffix(suffix.to_string()));
        }

        let labels = input.trim_end_matches(&format!(".{suffix}"));
        if labels.is_empty() {
            return Err(DomainError::InvalidLabel);
        }
        let re = Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$").expect("regex compile");
        if let Some(rest) = labels.strip_prefix("*.") {
            if rest.is_empty() {
                return Err(DomainError::InvalidLabel);
            }
            for label in rest.split('.') {
                if label.is_empty() || !re.is_match(label) {
                    return Err(DomainError::InvalidLabel);
                }
            }
            return Ok(Self(input));
        }

        for label in labels.split('.') {
            if label.is_empty() || !re.is_match(label) {
                return Err(DomainError::InvalidLabel);
            }
        }

        Ok(Self(input))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackendTarget {
    Tcp { host: String, port: u16 },
    UnixSocket { path: String },
    StaticDir { root: String },
}

impl BackendTarget {
    pub fn to_url_base(&self) -> String {
        match self {
            Self::Tcp { host, port } => format!("http://{host}:{port}"),
            Self::UnixSocket { path } => format!("unix://{path}"),
            Self::StaticDir { root } => format!("file://{root}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSpec {
    pub id: AppId,
    pub name: String,
    pub kind: AppKind,
    pub domain: DomainName,
    pub path_prefix: Option<String>,
    pub target: BackendTarget,
    pub timeout_ms: Option<u64>,
    pub cors_enabled: bool,
    pub basic_auth_user: Option<String>,
    pub basic_auth_pass: Option<String>,
    pub spa_rewrite: bool,
    pub listen_port: Option<u16>,
    pub tunnel_url: Option<String>,
    pub tunnel_exposed: bool,
    pub tunnel_mode: String,
    pub app_tunnel_id: Option<String>,
    pub app_tunnel_domain: Option<String>,
    pub app_tunnel_dns_id: Option<String>,
    pub app_tunnel_creds: Option<String>,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_test_domain() {
        let domain =
            DomainName::parse("myapp.bridgehead.local", "bridgehead.local").expect("valid domain");
        assert_eq!(domain.0, "myapp.bridgehead.local");
    }

    #[test]
    fn rejects_invalid_suffix() {
        let err =
            DomainName::parse("myapp.test", "bridgehead.local").expect_err("must fail");
        assert!(matches!(err, DomainError::InvalidSuffix(_)));
    }

    #[test]
    fn accepts_subdomain_labels() {
        let domain =
            DomainName::parse("www.myapp.bridgehead.local", "bridgehead.local").expect("valid");
        assert_eq!(domain.0, "www.myapp.bridgehead.local");
    }

    #[test]
    fn accepts_wildcard_subdomain() {
        let domain =
            DomainName::parse("*.myapp.bridgehead.local", "bridgehead.local").expect("valid");
        assert_eq!(domain.0, "*.myapp.bridgehead.local");
    }

    #[test]
    fn wildcard_must_have_suffix_labels() {
        let err =
            DomainName::parse("*.bridgehead.local", "bridgehead.local").expect_err("must fail");
        assert!(matches!(err, DomainError::InvalidLabel));
    }
}
