use std::path::Path;

use anyhow::Context;
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use thiserror::Error;
use time::OffsetDateTime;

use crate::domain::{AppId, AppKind, AppSpec, BackendTarget, DomainName};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("domain conflict")]
    DomainConflict,
}

pub struct AppRepository {
    conn: Mutex<Connection>,
}

impl AppRepository {
    pub fn new(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create sqlite dir: {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open sqlite db: {}", path.display()))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn init_schema(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
              version TEXT PRIMARY KEY,
              applied_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS apps (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              kind TEXT NOT NULL,
              domain TEXT NOT NULL UNIQUE,
              target_host TEXT NOT NULL,
              target_port INTEGER NOT NULL,
              enabled INTEGER NOT NULL,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_apps_enabled_domain
            ON apps(enabled, domain);
            "#,
        )?;
        Ok(())
    }

    pub fn insert_static(
        &self,
        name: &str,
        domain: &DomainName,
        target_host: &str,
        target_port: u16,
    ) -> anyhow::Result<AppSpec> {
        let now = OffsetDateTime::now_utc();
        let app = AppSpec {
            id: AppId::new(),
            name: name.to_string(),
            kind: AppKind::Static,
            domain: domain.clone(),
            target: BackendTarget::Tcp {
                host: target_host.to_string(),
                port: target_port,
            },
            enabled: true,
            created_at: now,
            updated_at: now,
        };

        let conn = self.conn.lock();
        let result = conn.execute(
            "INSERT INTO apps (id, name, kind, domain, target_host, target_port, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                app.id.0,
                app.name,
                "static",
                app.domain.0,
                target_host,
                i64::from(target_port),
                if app.enabled { 1 } else { 0 },
                app.created_at.unix_timestamp(),
                app.updated_at.unix_timestamp(),
            ],
        );

        match result {
            Ok(_) => Ok(app),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(StoreError::DomainConflict.into())
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn upsert_static(
        &self,
        name: &str,
        domain: &DomainName,
        target_host: &str,
        target_port: u16,
        enabled: bool,
    ) -> anyhow::Result<AppSpec> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let conn = self.conn.lock();

        let existing_id: Option<String> = conn
            .query_row(
                "SELECT id FROM apps WHERE domain = ?1",
                params![domain.0],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(id) = existing_id {
            conn.execute(
                "UPDATE apps SET name = ?1, target_host = ?2, target_port = ?3, enabled = ?4, updated_at = ?5 WHERE id = ?6",
                params![
                    name,
                    target_host,
                    i64::from(target_port),
                    if enabled { 1 } else { 0 },
                    now,
                    id
                ],
            )?;
        } else {
            let created = AppId::new().0;
            conn.execute(
                "INSERT INTO apps (id, name, kind, domain, target_host, target_port, enabled, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    created,
                    name,
                    "static",
                    domain.0,
                    target_host,
                    i64::from(target_port),
                    if enabled { 1 } else { 0 },
                    now,
                    now,
                ],
            )?;
        }

        let app = conn.query_row(
            "SELECT id,name,kind,domain,target_host,target_port,enabled,created_at,updated_at FROM apps WHERE domain = ?1",
            params![domain.0],
            |row| {
                Ok(AppSpec {
                    id: AppId(row.get(0)?),
                    name: row.get(1)?,
                    kind: AppKind::Static,
                    domain: DomainName(row.get(3)?),
                    target: BackendTarget::Tcp {
                        host: row.get(4)?,
                        port: row.get::<_, i64>(5)? as u16,
                    },
                    enabled: row.get::<_, i64>(6)? == 1,
                    created_at: OffsetDateTime::from_unix_timestamp(row.get::<_, i64>(7)?)
                        .unwrap_or(OffsetDateTime::UNIX_EPOCH),
                    updated_at: OffsetDateTime::from_unix_timestamp(row.get::<_, i64>(8)?)
                        .unwrap_or(OffsetDateTime::UNIX_EPOCH),
                })
            },
        )?;

        Ok(app)
    }

    pub fn delete(&self, app_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let changed = conn.execute("DELETE FROM apps WHERE id = ?1", params![app_id])?;
        Ok(changed > 0)
    }

    pub fn set_enabled(&self, app_id: &str, enabled: bool) -> anyhow::Result<bool> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let conn = self.conn.lock();
        let changed = conn.execute(
            "UPDATE apps SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
            params![if enabled { 1 } else { 0 }, now, app_id],
        )?;
        Ok(changed > 0)
    }

    pub fn list_all(&self) -> anyhow::Result<Vec<AppSpec>> {
        let conn = self.conn.lock();
        Self::query_apps(&conn, false)
    }

    pub fn list_enabled(&self) -> anyhow::Result<Vec<AppSpec>> {
        let conn = self.conn.lock();
        Self::query_apps(&conn, true)
    }

    fn query_apps(conn: &Connection, enabled_only: bool) -> anyhow::Result<Vec<AppSpec>> {
        let sql = if enabled_only {
            "SELECT id,name,kind,domain,target_host,target_port,enabled,created_at,updated_at FROM apps WHERE enabled = 1 ORDER BY domain ASC"
        } else {
            "SELECT id,name,kind,domain,target_host,target_port,enabled,created_at,updated_at FROM apps ORDER BY domain ASC"
        };

        let mut stmt = conn.prepare(sql)?;
        let mut rows = stmt.query([])?;

        let mut apps = Vec::new();
        while let Some(row) = rows.next()? {
            let kind: String = row.get(2)?;
            let kind = match kind.as_str() {
                "static" => AppKind::Static,
                "rack" => AppKind::Rack,
                "asgi" => AppKind::Asgi,
                "container" => AppKind::Container,
                _ => AppKind::Static,
            };

            let created_ts: i64 = row.get(7)?;
            let updated_ts: i64 = row.get(8)?;

            apps.push(AppSpec {
                id: AppId(row.get(0)?),
                name: row.get(1)?,
                kind,
                domain: DomainName(row.get(3)?),
                target: BackendTarget::Tcp {
                    host: row.get(4)?,
                    port: row.get::<_, i64>(5)? as u16,
                },
                enabled: row.get::<_, i64>(6)? == 1,
                created_at: OffsetDateTime::from_unix_timestamp(created_ts)
                    .unwrap_or(OffsetDateTime::UNIX_EPOCH),
                updated_at: OffsetDateTime::from_unix_timestamp(updated_ts)
                    .unwrap_or(OffsetDateTime::UNIX_EPOCH),
            });
        }

        Ok(apps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_list_enabled() {
        let repo = AppRepository {
            conn: Mutex::new(Connection::open_in_memory().expect("open sqlite")),
        };
        repo.init_schema().expect("schema");
        let domain = DomainName("myapp.test".to_string());

        repo.insert_static("myapp", &domain, "127.0.0.1", 9001)
            .expect("insert");
        let apps = repo.list_enabled().expect("list");
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].domain.0, "myapp.test");
    }
}
