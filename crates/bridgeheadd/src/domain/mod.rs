use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppId(pub String);

impl AppId {
    pub fn new() -> Self {
        Self(Uuid::now_v7().to_string())
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
        if !input.ends_with(&format!(".{suffix}")) {
            return Err(DomainError::InvalidSuffix(suffix.to_string()));
        }

        let labels = input.trim_end_matches(&format!(".{suffix}"));
        if labels.is_empty() {
            return Err(DomainError::InvalidLabel);
        }
        let re = Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$").expect("regex compile");
        for label in labels.split('.') {
            if label.is_empty() || !re.is_match(label) {
                return Err(DomainError::InvalidLabel);
            }
        }

        Ok(Self(input.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackendTarget {
    Tcp { host: String, port: u16 },
}

impl BackendTarget {
    pub fn to_url_base(&self) -> String {
        match self {
            Self::Tcp { host, port } => format!("http://{host}:{port}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSpec {
    pub id: AppId,
    pub name: String,
    pub kind: AppKind,
    pub domain: DomainName,
    pub target: BackendTarget,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_test_domain() {
        let domain = DomainName::parse("myapp.test", "test").expect("valid domain");
        assert_eq!(domain.0, "myapp.test");
    }

    #[test]
    fn rejects_invalid_suffix() {
        let err = DomainName::parse("myapp.local", "test").expect_err("must fail");
        assert!(matches!(err, DomainError::InvalidSuffix(_)));
    }

    #[test]
    fn accepts_subdomain_labels() {
        let domain = DomainName::parse("www.myapp.test", "test").expect("valid");
        assert_eq!(domain.0, "www.myapp.test");
    }
}
