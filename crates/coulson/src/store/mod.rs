use std::collections::HashSet;
use std::path::Path;

use anyhow::Context;
use parking_lot::Mutex;
use rusqlite::{params, params_from_iter, types::Value, Connection, OptionalExtension};
use thiserror::Error;
use time::OffsetDateTime;

use tokio::sync::broadcast;

use crate::domain::{AppId, AppKind, AppSpec, BackendTarget, DomainName, TunnelMode};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("domain conflict")]
    DomainConflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanUpsertResult {
    Inserted,
    Updated,
    SkippedManual,
}

pub struct StaticAppInput<'a> {
    pub name: &'a str,
    pub domain: &'a DomainName,
    pub path_prefix: Option<&'a str>,
    pub target_type: &'a str,
    pub target_value: &'a str,
    pub timeout_ms: Option<u64>,
    pub cors_enabled: bool,
    pub force_https: bool,
    pub basic_auth_user: Option<&'a str>,
    pub basic_auth_pass: Option<&'a str>,
    pub spa_rewrite: bool,
    pub listen_port: Option<u16>,
}

pub struct AppRepository {
    pub(crate) conn: Mutex<Connection>,
    pub(crate) domain_suffix: String,
    pub(crate) change_tx: Option<broadcast::Sender<String>>,
}

fn check_insert(result: rusqlite::Result<usize>) -> anyhow::Result<()> {
    match result {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Err(StoreError::DomainConflict.into())
        }
        Err(e) => Err(e.into()),
    }
}

impl AppRepository {
    pub fn set_change_tx(&mut self, tx: broadcast::Sender<String>) {
        self.change_tx = Some(tx);
    }

    fn emit(&self, frames: &str) {
        if let Some(tx) = &self.change_tx {
            let _ = tx.send(frames.to_string());
        }
    }

    pub fn new(path: &Path, domain_suffix: &str) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create sqlite dir: {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open sqlite db: {}", path.display()))?;
        Ok(Self {
            conn: Mutex::new(conn),
            domain_suffix: domain_suffix.to_string(),
            change_tx: None,
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
              id INTEGER PRIMARY KEY,
              name TEXT NOT NULL UNIQUE,
              kind TEXT NOT NULL,
              domain TEXT NOT NULL,
              path_prefix TEXT NOT NULL DEFAULT '',
              target_type TEXT NOT NULL DEFAULT 'tcp',
              target_value TEXT NOT NULL DEFAULT '',
              timeout_ms INTEGER,
              enabled INTEGER NOT NULL,
              scan_managed INTEGER NOT NULL DEFAULT 0,
              scan_source TEXT,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              cors_enabled INTEGER NOT NULL DEFAULT 0,
              force_https INTEGER NOT NULL DEFAULT 0,
              basic_auth_user TEXT,
              basic_auth_pass TEXT,
              spa_rewrite INTEGER NOT NULL DEFAULT 0,
              listen_port INTEGER,
              tunnel_url TEXT,
              tunnel_exposed INTEGER NOT NULL DEFAULT 0,
              tunnel_mode TEXT NOT NULL DEFAULT 'none',
              app_tunnel_id TEXT,
              app_tunnel_domain TEXT,
              app_tunnel_dns_id TEXT,
              app_tunnel_creds TEXT,
              share_auth INTEGER NOT NULL DEFAULT 0,
              inspect_enabled INTEGER NOT NULL DEFAULT 0,
              fs_entry TEXT,
              UNIQUE(domain, path_prefix)
            );

            CREATE INDEX IF NOT EXISTS idx_apps_enabled_domain
            ON apps(enabled, domain);

            CREATE TABLE IF NOT EXISTS settings (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL,
              updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS request_logs (
              id TEXT PRIMARY KEY,
              app_id INTEGER NOT NULL,
              timestamp INTEGER NOT NULL,
              method TEXT NOT NULL,
              path TEXT NOT NULL,
              query_string TEXT,
              request_headers TEXT NOT NULL,
              request_body BLOB,
              status_code INTEGER,
              response_headers TEXT,
              response_body BLOB,
              response_time_ms INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_request_logs_app_ts
              ON request_logs(app_id, timestamp DESC);
            "#,
        )?;

        // Migrations for databases created before all columns existed.
        // New databases already have every column via CREATE TABLE above,
        // so these are no-ops (add_column_if_missing silently skips).
        for sql in [
            "ALTER TABLE apps ADD COLUMN cors_enabled INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE apps ADD COLUMN force_https INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE apps ADD COLUMN basic_auth_user TEXT",
            "ALTER TABLE apps ADD COLUMN basic_auth_pass TEXT",
            "ALTER TABLE apps ADD COLUMN spa_rewrite INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE apps ADD COLUMN listen_port INTEGER",
            "ALTER TABLE apps ADD COLUMN tunnel_url TEXT",
            "ALTER TABLE apps ADD COLUMN tunnel_exposed INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE apps ADD COLUMN tunnel_mode TEXT NOT NULL DEFAULT 'none'",
            "ALTER TABLE apps ADD COLUMN app_tunnel_id TEXT",
            "ALTER TABLE apps ADD COLUMN app_tunnel_domain TEXT",
            "ALTER TABLE apps ADD COLUMN app_tunnel_dns_id TEXT",
            "ALTER TABLE apps ADD COLUMN app_tunnel_creds TEXT",
            "ALTER TABLE apps ADD COLUMN share_auth INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE apps ADD COLUMN inspect_enabled INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE apps ADD COLUMN fs_entry TEXT",
        ] {
            add_column_if_missing(&conn, sql)?;
        }

        migrate_apps_domain_unique_to_route_unique(&conn)?;
        Ok(())
    }

    /// Strip domain suffix from existing rows (idempotent migration).
    pub fn migrate_domain_to_prefix(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let dot_suffix = format!(".{}", self.domain_suffix);
        let suffix_len = dot_suffix.len() as i64;
        let pattern = format!("%{dot_suffix}");
        conn.execute(
            "UPDATE apps SET domain = SUBSTR(domain, 1, LENGTH(domain) - ?1) WHERE domain LIKE ?2",
            params![suffix_len, pattern],
        )?;
        Ok(())
    }

    pub fn insert_static(&self, input: &StaticAppInput) -> anyhow::Result<AppSpec> {
        let now = OffsetDateTime::now_utc();
        let path_prefix_db = path_prefix_to_db(input.path_prefix);
        let domain_db = domain_to_db(&input.domain.0, &self.domain_suffix);

        let conn = self.conn.lock();
        let result = conn.execute(
            "INSERT INTO apps (name, kind, domain, path_prefix, target_type, target_value, timeout_ms, enabled, scan_managed, scan_source, created_at, updated_at, cors_enabled, force_https, basic_auth_user, basic_auth_pass, spa_rewrite, listen_port)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, NULL, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                input.name,
                "static",
                domain_db,
                path_prefix_db,
                input.target_type,
                input.target_value,
                input.timeout_ms.map(|v| v as i64),
                1i64,
                now.unix_timestamp(),
                now.unix_timestamp(),
                if input.cors_enabled { 1 } else { 0 },
                if input.force_https { 1 } else { 0 },
                input.basic_auth_user,
                input.basic_auth_pass,
                if input.spa_rewrite { 1 } else { 0 },
                input.listen_port.map(|v| v as i64),
            ],
        );
        check_insert(result)?;
        let id = conn.last_insert_rowid();

        let target = backend_target_from_db(
            id,
            input.target_type,
            input.target_value,
            "static",
            input.name,
        );
        Ok(AppSpec {
            id: AppId(id),
            name: input.name.to_string(),
            kind: AppKind::Static,
            domain: input.domain.clone(),
            path_prefix: input.path_prefix.map(ToOwned::to_owned),
            target,
            timeout_ms: input.timeout_ms,
            cors_enabled: input.cors_enabled,
            force_https: input.force_https,
            basic_auth_user: input.basic_auth_user.map(ToOwned::to_owned),
            basic_auth_pass: input.basic_auth_pass.map(ToOwned::to_owned),
            spa_rewrite: input.spa_rewrite,
            listen_port: input.listen_port,
            tunnel_url: None,
            tunnel_exposed: false,
            tunnel_mode: TunnelMode::None,
            app_tunnel_id: None,
            app_tunnel_domain: None,
            app_tunnel_dns_id: None,
            app_tunnel_creds: None,
            inspect_enabled: false,
            fs_entry: None,
            enabled: true,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn insert_managed(
        &self,
        name: &str,
        domain: &DomainName,
        app_root: &str,
        kind: &str,
        listen_port: Option<u16>,
    ) -> anyhow::Result<AppSpec> {
        let now = OffsetDateTime::now_utc();
        let domain_db = domain_to_db(&domain.0, &self.domain_suffix);
        let kind_enum = match kind {
            "asgi" => AppKind::Asgi,
            "rack" => AppKind::Rack,
            "node" => AppKind::Node,
            "container" => AppKind::Container,
            _ => AppKind::Static,
        };

        let conn = self.conn.lock();
        let result = conn.execute(
            "INSERT INTO apps (name, kind, domain, path_prefix, target_type, target_value, timeout_ms, enabled, scan_managed, scan_source, created_at, updated_at, listen_port)
             VALUES (?1, ?2, ?3, '', 'managed', ?4, NULL, 1, 0, NULL, ?5, ?6, ?7)",
            params![
                name,
                kind,
                domain_db,
                app_root,
                now.unix_timestamp(),
                now.unix_timestamp(),
                listen_port.map(|v| v as i64),
            ],
        );
        check_insert(result)?;
        let id = conn.last_insert_rowid();

        Ok(AppSpec {
            id: AppId(id),
            name: name.to_string(),
            kind: kind_enum,
            domain: domain.clone(),
            path_prefix: None,
            target: BackendTarget::Managed {
                app_id: id,
                root: app_root.to_string(),
                kind: kind.to_string(),
                name: name.to_string(),
            },
            timeout_ms: None,
            cors_enabled: false,
            force_https: false,
            basic_auth_user: None,
            basic_auth_pass: None,
            spa_rewrite: false,
            listen_port,
            tunnel_url: None,
            tunnel_exposed: false,
            tunnel_mode: TunnelMode::None,
            app_tunnel_id: None,
            app_tunnel_domain: None,
            app_tunnel_dns_id: None,
            app_tunnel_creds: None,
            inspect_enabled: false,
            fs_entry: None,
            enabled: true,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn insert_static_dir(
        &self,
        name: &str,
        domain: &DomainName,
        root: &str,
        listen_port: Option<u16>,
    ) -> anyhow::Result<AppSpec> {
        let now = OffsetDateTime::now_utc();
        let domain_db = domain_to_db(&domain.0, &self.domain_suffix);

        let conn = self.conn.lock();
        let result = conn.execute(
            "INSERT INTO apps (name, kind, domain, path_prefix, target_type, target_value, timeout_ms, enabled, scan_managed, scan_source, created_at, updated_at, listen_port)
             VALUES (?1, 'static', ?2, '', 'static_dir', ?3, NULL, 1, 0, NULL, ?4, ?5, ?6)",
            params![
                name,
                domain_db,
                root,
                now.unix_timestamp(),
                now.unix_timestamp(),
                listen_port.map(|v| v as i64),
            ],
        );
        check_insert(result)?;
        let id = conn.last_insert_rowid();

        Ok(AppSpec {
            id: AppId(id),
            name: name.to_string(),
            kind: AppKind::Static,
            domain: domain.clone(),
            path_prefix: None,
            target: BackendTarget::StaticDir {
                root: root.to_string(),
            },
            timeout_ms: None,
            cors_enabled: false,
            force_https: false,
            basic_auth_user: None,
            basic_auth_pass: None,
            spa_rewrite: false,
            listen_port,
            tunnel_url: None,
            tunnel_exposed: false,
            tunnel_mode: TunnelMode::None,
            app_tunnel_id: None,
            app_tunnel_domain: None,
            app_tunnel_dns_id: None,
            app_tunnel_creds: None,
            inspect_enabled: false,
            fs_entry: None,
            enabled: true,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn upsert_scanned_static(
        &self,
        input: &StaticAppInput,
        enabled: bool,
        source: &str,
        fs_entry: &str,
    ) -> anyhow::Result<(AppSpec, ScanUpsertResult)> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let conn = self.conn.lock();
        let path_prefix_db = path_prefix_to_db(input.path_prefix);
        let domain_db = domain_to_db(&input.domain.0, &self.domain_suffix);

        let existing: Option<(i64, i64)> = conn
            .query_row(
                "SELECT id, scan_managed FROM apps WHERE domain = ?1 AND path_prefix = ?2",
                params![domain_db, path_prefix_db],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let op = match existing {
            Some((_id, 0)) => ScanUpsertResult::SkippedManual,
            Some((id, _)) => {
                conn.execute(
                    "UPDATE apps SET name = ?1, path_prefix = ?2, target_type = ?3, target_value = ?4, timeout_ms = ?5, updated_at = ?6, scan_managed = 1, scan_source = ?7, cors_enabled = ?8, force_https = ?9, basic_auth_user = ?10, basic_auth_pass = ?11, spa_rewrite = ?12, listen_port = ?13, fs_entry = ?14 WHERE id = ?15",
                    params![
                        input.name,
                        path_prefix_db,
                        input.target_type,
                        input.target_value,
                        input.timeout_ms.map(|v| v as i64),
                        now,
                        source,
                        if input.cors_enabled { 1 } else { 0 },
                        if input.force_https { 1 } else { 0 },
                        input.basic_auth_user,
                        input.basic_auth_pass,
                        if input.spa_rewrite { 1 } else { 0 },
                        input.listen_port.map(|v| v as i64),
                        fs_entry,
                        id
                    ],
                )?;
                ScanUpsertResult::Updated
            }
            None => {
                conn.execute(
                    "INSERT INTO apps (name, kind, domain, path_prefix, target_type, target_value, timeout_ms, enabled, scan_managed, scan_source, created_at, updated_at, cors_enabled, force_https, basic_auth_user, basic_auth_pass, spa_rewrite, listen_port, fs_entry)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
                    params![
                        input.name,
                        "static",
                        domain_db,
                        path_prefix_db,
                        input.target_type,
                        input.target_value,
                        input.timeout_ms.map(|v| v as i64),
                        if enabled { 1 } else { 0 },
                        source,
                        now,
                        now,
                        if input.cors_enabled { 1 } else { 0 },
                        if input.force_https { 1 } else { 0 },
                        input.basic_auth_user,
                        input.basic_auth_pass,
                        if input.spa_rewrite { 1 } else { 0 },
                        input.listen_port.map(|v| v as i64),
                        fs_entry,
                    ],
                )?;
                ScanUpsertResult::Inserted
            }
        };

        let suffix = &self.domain_suffix;
        let app = Self::read_app_by_route(&conn, &domain_db, &path_prefix_db, suffix)?;
        Ok((app, op))
    }

    /// Upsert a managed (ASGI, Rack, Node, Docker, etc.) app discovered by the scanner.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_scanned_managed(
        &self,
        name: &str,
        domain: &DomainName,
        app_root: &str,
        kind: &str,
        enabled: bool,
        source: &str,
        fs_entry: &str,
    ) -> anyhow::Result<(AppSpec, ScanUpsertResult)> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let conn = self.conn.lock();
        let path_prefix_db = "";
        let domain_db = domain_to_db(&domain.0, &self.domain_suffix);

        let existing: Option<(i64, i64)> = conn
            .query_row(
                "SELECT id, scan_managed FROM apps WHERE domain = ?1 AND path_prefix = ?2",
                params![domain_db, path_prefix_db],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let op = match existing {
            Some((_id, 0)) => ScanUpsertResult::SkippedManual,
            Some((id, _)) => {
                conn.execute(
                    "UPDATE apps SET name = ?1, kind = ?2, target_type = 'managed', target_value = ?3, updated_at = ?4, scan_managed = 1, scan_source = ?5, fs_entry = ?6 WHERE id = ?7",
                    params![name, kind, app_root, now, source, fs_entry, id],
                )?;
                ScanUpsertResult::Updated
            }
            None => {
                conn.execute(
                    "INSERT INTO apps (name, kind, domain, path_prefix, target_type, target_value, timeout_ms, enabled, scan_managed, scan_source, created_at, updated_at, fs_entry)
                     VALUES (?1, ?2, ?3, ?4, 'managed', ?5, NULL, ?6, 1, ?7, ?8, ?9, ?10)",
                    params![
                        name,
                        kind,
                        domain_db,
                        path_prefix_db,
                        app_root,
                        if enabled { 1 } else { 0 },
                        source,
                        now,
                        now,
                        fs_entry,
                    ],
                )?;
                ScanUpsertResult::Inserted
            }
        };

        let suffix = &self.domain_suffix;
        let app = Self::read_app_by_route(&conn, &domain_db, path_prefix_db, suffix)?;
        Ok((app, op))
    }

    pub fn upsert_scanned_static_dir(
        &self,
        name: &str,
        domain: &DomainName,
        static_root: &str,
        enabled: bool,
        source: &str,
        fs_entry: &str,
    ) -> anyhow::Result<(AppSpec, ScanUpsertResult)> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let conn = self.conn.lock();
        let path_prefix_db = "";
        let domain_db = domain_to_db(&domain.0, &self.domain_suffix);

        let existing: Option<(i64, i64)> = conn
            .query_row(
                "SELECT id, scan_managed FROM apps WHERE domain = ?1 AND path_prefix = ?2",
                params![domain_db, path_prefix_db],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let op = match existing {
            Some((_id, 0)) => ScanUpsertResult::SkippedManual,
            Some((id, _)) => {
                conn.execute(
                    "UPDATE apps SET name = ?1, kind = 'static', target_type = 'static_dir', target_value = ?2, updated_at = ?3, scan_managed = 1, scan_source = ?4, fs_entry = ?5 WHERE id = ?6",
                    params![name, static_root, now, source, fs_entry, id],
                )?;
                ScanUpsertResult::Updated
            }
            None => {
                conn.execute(
                    "INSERT INTO apps (name, kind, domain, path_prefix, target_type, target_value, timeout_ms, enabled, scan_managed, scan_source, created_at, updated_at, fs_entry)
                     VALUES (?1, 'static', ?2, ?3, 'static_dir', ?4, NULL, ?5, 1, ?6, ?7, ?8, ?9)",
                    params![
                        name,
                        domain_db,
                        path_prefix_db,
                        static_root,
                        if enabled { 1 } else { 0 },
                        source,
                        now,
                        now,
                        fs_entry,
                    ],
                )?;
                ScanUpsertResult::Inserted
            }
        };

        let suffix = &self.domain_suffix;
        let app = Self::read_app_by_route(&conn, &domain_db, path_prefix_db, suffix)?;
        Ok((app, op))
    }

    pub fn prune_scanned_not_in(
        &self,
        source: &str,
        active_routes: &HashSet<String>,
    ) -> anyhow::Result<usize> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, domain, path_prefix FROM apps WHERE scan_managed = 1 AND scan_source = ?1",
        )?;
        let mut rows = stmt.query(params![source])?;
        let mut delete_ids: Vec<i64> = Vec::new();

        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let domain_prefix: String = row.get(1)?;
            let path_prefix: String = row.get(2)?;
            let key = route_key(&domain_prefix, &path_prefix);
            if !active_routes.contains(&key) {
                delete_ids.push(id);
            }
        }

        let mut deleted = 0usize;
        for id in &delete_ids {
            deleted += conn.execute("DELETE FROM apps WHERE id = ?1", params![id])?;
        }
        Ok(deleted)
    }

    pub fn delete(&self, app_id: i64) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let changed = conn.execute("DELETE FROM apps WHERE id = ?1", params![app_id])?;
        Ok(changed > 0)
    }

    pub fn set_enabled(&self, app_id: i64, enabled: bool) -> anyhow::Result<bool> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let conn = self.conn.lock();
        let changed = conn.execute(
            "UPDATE apps SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
            params![if enabled { 1 } else { 0 }, now, app_id],
        )?;
        if changed > 0 {
            self.emit("detail-tunnel,detail-features,detail-urls");
        }
        Ok(changed > 0)
    }

    pub fn list_all(&self) -> anyhow::Result<Vec<AppSpec>> {
        let conn = self.conn.lock();
        Self::query_apps(&conn, false, &self.domain_suffix)
    }

    pub fn list_filtered(
        &self,
        managed: Option<bool>,
        domain: Option<&str>,
    ) -> anyhow::Result<Vec<AppSpec>> {
        let domain_db = domain.map(|d| domain_to_db(d, &self.domain_suffix));
        let conn = self.conn.lock();
        Self::query_apps_filtered(&conn, managed, domain_db.as_deref(), &self.domain_suffix)
    }

    pub fn list_enabled(&self) -> anyhow::Result<Vec<AppSpec>> {
        let conn = self.conn.lock();
        Self::query_apps(&conn, true, &self.domain_suffix)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_settings(
        &self,
        app_id: i64,
        cors_enabled: Option<bool>,
        force_https: Option<bool>,
        basic_auth_user: Option<Option<&str>>,
        basic_auth_pass: Option<Option<&str>>,
        spa_rewrite: Option<bool>,
        listen_port: Option<Option<u16>>,
        timeout_ms: Option<Option<u64>>,
    ) -> anyhow::Result<bool> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let conn = self.conn.lock();

        let mut sets = vec!["updated_at = ?1".to_string()];
        let mut idx = 2u32;
        let mut values: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(now)];

        if let Some(v) = cors_enabled {
            sets.push(format!("cors_enabled = ?{idx}"));
            values.push(Box::new(if v { 1i64 } else { 0 }));
            idx += 1;
        }
        if let Some(v) = force_https {
            sets.push(format!("force_https = ?{idx}"));
            values.push(Box::new(if v { 1i64 } else { 0 }));
            idx += 1;
        }
        if let Some(v) = basic_auth_user {
            sets.push(format!("basic_auth_user = ?{idx}"));
            values.push(Box::new(v.map(|s| s.to_string())));
            idx += 1;
        }
        if let Some(v) = basic_auth_pass {
            sets.push(format!("basic_auth_pass = ?{idx}"));
            values.push(Box::new(v.map(|s| s.to_string())));
            idx += 1;
        }
        if let Some(v) = spa_rewrite {
            sets.push(format!("spa_rewrite = ?{idx}"));
            values.push(Box::new(if v { 1i64 } else { 0 }));
            idx += 1;
        }
        if let Some(v) = listen_port {
            sets.push(format!("listen_port = ?{idx}"));
            values.push(Box::new(v.map(|p| p as i64)));
            idx += 1;
        }
        if let Some(v) = timeout_ms {
            sets.push(format!("timeout_ms = ?{idx}"));
            values.push(Box::new(v.map(|t| t as i64)));
            idx += 1;
        }

        let sql = format!("UPDATE apps SET {} WHERE id = ?{idx}", sets.join(", "));
        values.push(Box::new(app_id));

        let params: Vec<&dyn rusqlite::ToSql> = values.iter().map(|v| v.as_ref()).collect();
        let changed = conn.execute(&sql, params.as_slice())?;
        if changed > 0 {
            self.emit("detail-features");
        }
        Ok(changed > 0)
    }

    pub fn get_setting(&self, key: &str) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock();
        let value = conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3",
            params![key, value, now],
        )?;
        Ok(())
    }

    pub fn delete_setting(&self, key: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let changed = conn.execute("DELETE FROM settings WHERE key = ?1", params![key])?;
        Ok(changed > 0)
    }

    pub fn update_tunnel_url(&self, app_id: i64, tunnel_url: Option<&str>) -> anyhow::Result<bool> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let conn = self.conn.lock();
        let changed = conn.execute(
            "UPDATE apps SET tunnel_url = ?1, updated_at = ?2 WHERE id = ?3",
            params![tunnel_url, now, app_id],
        )?;
        if changed > 0 {
            self.emit("detail-tunnel,detail-urls");
        }
        Ok(changed > 0)
    }

    pub fn set_app_tunnel_state(
        &self,
        app_id: i64,
        tunnel_id: Option<&str>,
        tunnel_domain: Option<&str>,
        dns_id: Option<&str>,
        creds_json: Option<&str>,
        mode: TunnelMode,
    ) -> anyhow::Result<bool> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let conn = self.conn.lock();
        let changed = conn.execute(
            "UPDATE apps SET app_tunnel_id = ?1, app_tunnel_domain = ?2, app_tunnel_dns_id = ?3, app_tunnel_creds = ?4, tunnel_mode = ?5, updated_at = ?6 WHERE id = ?7",
            params![tunnel_id, tunnel_domain, dns_id, creds_json, mode.as_str(), now, app_id],
        )?;
        if changed > 0 {
            self.emit("detail-tunnel,detail-urls");
        }
        Ok(changed > 0)
    }

    pub fn set_tunnel_mode(&self, app_id: i64, mode: TunnelMode) -> anyhow::Result<bool> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let conn = self.conn.lock();
        let changed = conn.execute(
            "UPDATE apps SET tunnel_mode = ?1, updated_at = ?2 WHERE id = ?3",
            params![mode.as_str(), now, app_id],
        )?;
        if changed > 0 {
            self.emit("detail-tunnel,detail-urls");
        }
        Ok(changed > 0)
    }

    pub fn list_app_tunnels(&self) -> anyhow::Result<Vec<AppSpec>> {
        let conn = self.conn.lock();
        let sql = format!(
            "SELECT {} FROM apps WHERE tunnel_mode = 'named' AND enabled = 1",
            COLS
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        Self::collect_rows(&mut rows, &self.domain_suffix)
    }

    pub fn list_quick_tunnels(&self) -> anyhow::Result<Vec<AppSpec>> {
        let conn = self.conn.lock();
        let sql = format!(
            "SELECT {} FROM apps WHERE tunnel_mode = 'quick' AND enabled = 1",
            COLS
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        Self::collect_rows(&mut rows, &self.domain_suffix)
    }

    pub fn is_tunnel_exposed(&self, domain_prefix: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM apps WHERE domain = ?1 AND enabled = 1 AND tunnel_mode != 'none'",
            params![domain_prefix],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn is_share_auth_required(&self, domain_prefix: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM apps WHERE domain = ?1 AND enabled = 1 AND share_auth = 1",
            params![domain_prefix],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn set_share_auth(&self, domain_prefix: &str, enabled: bool) -> anyhow::Result<bool> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let conn = self.conn.lock();
        let changed = conn.execute(
            "UPDATE apps SET share_auth = ?1, updated_at = ?2 WHERE domain = ?3",
            params![if enabled { 1 } else { 0 }, now, domain_prefix],
        )?;
        Ok(changed > 0)
    }

    pub fn get_by_id(&self, app_id: i64) -> anyhow::Result<Option<AppSpec>> {
        let conn = self.conn.lock();
        let app = conn
            .query_row(
                &format!("SELECT {} FROM apps WHERE id = ?1", COLS),
                params![app_id],
                |row| row_to_app(row, &self.domain_suffix),
            )
            .optional()?;
        Ok(app)
    }

    pub fn get_by_name(&self, name: &str) -> anyhow::Result<Option<AppSpec>> {
        let conn = self.conn.lock();
        let app = conn
            .query_row(
                &format!("SELECT {} FROM apps WHERE name = ?1", COLS),
                params![name],
                |row| row_to_app(row, &self.domain_suffix),
            )
            .optional()?;
        Ok(app)
    }

    fn read_app_by_route(
        conn: &Connection,
        domain_db: &str,
        path_prefix_db: &str,
        suffix: &str,
    ) -> anyhow::Result<AppSpec> {
        let app = conn.query_row(
            &format!(
                "SELECT {} FROM apps WHERE domain = ?1 AND path_prefix = ?2",
                COLS
            ),
            params![domain_db, path_prefix_db],
            |row| row_to_app(row, suffix),
        )?;
        Ok(app)
    }

    fn query_apps(
        conn: &Connection,
        enabled_only: bool,
        suffix: &str,
    ) -> anyhow::Result<Vec<AppSpec>> {
        let sql = if enabled_only {
            format!("SELECT {} FROM apps WHERE enabled = 1 ORDER BY name ASC, LENGTH(path_prefix) DESC, id ASC", COLS)
        } else {
            format!(
                "SELECT {} FROM apps ORDER BY name ASC, LENGTH(path_prefix) DESC, id ASC",
                COLS
            )
        };

        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        Self::collect_rows(&mut rows, suffix)
    }

    fn query_apps_filtered(
        conn: &Connection,
        managed: Option<bool>,
        domain_db: Option<&str>,
        suffix: &str,
    ) -> anyhow::Result<Vec<AppSpec>> {
        let mut sql = format!("SELECT {} FROM apps", COLS);
        let mut clauses: Vec<&str> = Vec::new();
        let mut values: Vec<Value> = Vec::new();

        if let Some(flag) = managed {
            clauses.push("scan_managed = ?");
            values.push(Value::Integer(if flag { 1 } else { 0 }));
        }
        if let Some(domain) = domain_db {
            clauses.push("domain = ?");
            values.push(Value::Text(domain.to_string()));
        }
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(" ORDER BY name ASC, LENGTH(path_prefix) DESC, id ASC");

        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query(params_from_iter(values.iter()))?;
        Self::collect_rows(&mut rows, suffix)
    }

    fn collect_rows(rows: &mut rusqlite::Rows<'_>, suffix: &str) -> anyhow::Result<Vec<AppSpec>> {
        let mut apps = Vec::new();
        while let Some(row) = rows.next()? {
            apps.push(row_to_app(row, suffix)?);
        }
        Ok(apps)
    }

    // -----------------------------------------------------------------------
    // Inspect (request recording) methods
    // -----------------------------------------------------------------------

    pub fn set_inspect_enabled(&self, app_id: i64, enabled: bool) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE apps SET inspect_enabled = ? WHERE id = ?",
            params![enabled as i64, app_id],
        )?;
        self.emit("detail-features");
        Ok(())
    }

    pub fn insert_request_log(
        &self,
        req: &CapturedRequest,
        max_per_app: usize,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO request_logs (id, app_id, timestamp, method, path, query_string, request_headers, request_body, status_code, response_headers, response_body, response_time_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                req.id,
                req.app_id,
                req.timestamp,
                req.method,
                req.path,
                req.query_string,
                req.request_headers,
                req.request_body,
                req.status_code,
                req.response_headers,
                req.response_body,
                req.response_time_ms,
            ],
        )?;
        // Prune old entries beyond max
        conn.execute(
            "DELETE FROM request_logs WHERE app_id = ?1 AND id NOT IN (SELECT id FROM request_logs WHERE app_id = ?1 ORDER BY timestamp DESC LIMIT ?2)",
            params![req.app_id, max_per_app as i64],
        )?;
        Ok(())
    }

    pub fn list_request_logs(
        &self,
        app_id: i64,
        limit: usize,
    ) -> anyhow::Result<Vec<CapturedRequest>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, app_id, timestamp, method, path, query_string, request_headers, request_body, status_code, response_headers, response_body, response_time_ms FROM request_logs WHERE app_id = ? ORDER BY timestamp DESC LIMIT ?",
        )?;
        let mut rows = stmt.query(params![app_id, limit as i64])?;
        let mut results = Vec::new();
        while let Some(row) = rows.next()? {
            results.push(row_to_captured_request(row)?);
        }
        Ok(results)
    }

    pub fn get_request_log(&self, req_id: &str) -> anyhow::Result<Option<CapturedRequest>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, app_id, timestamp, method, path, query_string, request_headers, request_body, status_code, response_headers, response_body, response_time_ms FROM request_logs WHERE id = ?",
        )?;
        let mut rows = stmt.query(params![req_id])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_captured_request(row)?)),
            None => Ok(None),
        }
    }

    pub fn get_request_logs_by_app_name(
        &self,
        app_name: &str,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<(Vec<CapturedRequest>, i64)> {
        let app = self.get_by_name(app_name)?;
        match app {
            Some(app) => {
                let conn = self.conn.lock();
                let mut stmt = conn.prepare(
                    "SELECT id, app_id, timestamp, method, path, query_string, request_headers, request_body, status_code, response_headers, response_body, response_time_ms FROM request_logs WHERE app_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                )?;
                let mut rows = stmt.query(params![app.id.0, limit as i64, offset as i64])?;
                let mut results = Vec::new();
                while let Some(row) = rows.next()? {
                    results.push(row_to_captured_request(row)?);
                }

                // Get total count
                let mut count_stmt =
                    conn.prepare("SELECT COUNT(*) FROM request_logs WHERE app_id = ?")?;
                let total: i64 = count_stmt.query_row(params![app.id.0], |row| row.get(0))?;

                Ok((results, total))
            }
            None => Ok((vec![], 0)),
        }
    }

    pub fn delete_request_logs_for_app(&self, app_id: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM request_logs WHERE app_id = ?", params![app_id])?;
        Ok(())
    }

    pub fn count_request_logs(&self, app_id: i64) -> anyhow::Result<usize> {
        let conn = self.conn.lock();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM request_logs WHERE app_id = ?",
            params![app_id],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }
}

const COLS: &str = "id,name,kind,domain,path_prefix,target_type,target_value,timeout_ms,enabled,created_at,updated_at,cors_enabled,force_https,basic_auth_user,basic_auth_pass,spa_rewrite,listen_port,tunnel_url,tunnel_mode,app_tunnel_id,app_tunnel_domain,app_tunnel_dns_id,app_tunnel_creds,inspect_enabled,fs_entry";

fn backend_target_from_db(
    id: i64,
    target_type: &str,
    target_value: &str,
    kind: &str,
    name: &str,
) -> BackendTarget {
    match target_type {
        "managed" => BackendTarget::Managed {
            app_id: id,
            root: target_value.to_string(),
            kind: kind.to_string(),
            name: name.to_string(),
        },
        "static_dir" => BackendTarget::StaticDir {
            root: target_value.to_string(),
        },
        "unix_socket" => BackendTarget::UnixSocket {
            path: target_value.to_string(),
        },
        _ => {
            if let Some((host, port_str)) = target_value.rsplit_once(':') {
                BackendTarget::Tcp {
                    host: host.to_string(),
                    port: port_str.parse::<u16>().unwrap_or(0),
                }
            } else {
                BackendTarget::Tcp {
                    host: target_value.to_string(),
                    port: 0,
                }
            }
        }
    }
}

fn row_to_app(row: &rusqlite::Row<'_>, suffix: &str) -> rusqlite::Result<AppSpec> {
    let id_val: i64 = row.get(0)?;
    let kind_str: String = row.get(2)?;
    let kind = match kind_str.as_str() {
        "static" => AppKind::Static,
        "rack" => AppKind::Rack,
        "asgi" => AppKind::Asgi,
        "node" => AppKind::Node,
        "container" => AppKind::Container,
        _ => AppKind::Static,
    };

    let name: String = row.get(1)?;
    let target_type: String = row.get(5)?;
    let target_value: String = row.get(6)?;
    let target = backend_target_from_db(id_val, &target_type, &target_value, &kind_str, &name);

    let created_ts: i64 = row.get(9)?;
    let updated_ts: i64 = row.get(10)?;
    let domain_prefix: String = row.get(3)?;
    let full_domain = domain_from_db(&domain_prefix, suffix);
    let tunnel_mode: TunnelMode = row
        .get::<_, String>(18)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_default();

    Ok(AppSpec {
        id: AppId(id_val),
        name,
        kind,
        domain: DomainName(full_domain),
        path_prefix: path_prefix_from_db(row.get::<_, String>(4)?),
        target,
        timeout_ms: row.get::<_, Option<i64>>(7)?.map(|v| v as u64),
        enabled: row.get::<_, i64>(8)? == 1,
        created_at: OffsetDateTime::from_unix_timestamp(created_ts)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        updated_at: OffsetDateTime::from_unix_timestamp(updated_ts)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        cors_enabled: row.get::<_, i64>(11).unwrap_or(0) == 1,
        force_https: row.get::<_, i64>(12).unwrap_or(0) == 1,
        basic_auth_user: row.get::<_, Option<String>>(13).unwrap_or(None),
        basic_auth_pass: row.get::<_, Option<String>>(14).unwrap_or(None),
        spa_rewrite: row.get::<_, i64>(15).unwrap_or(0) == 1,
        listen_port: row
            .get::<_, Option<i64>>(16)
            .unwrap_or(None)
            .map(|v| v as u16),
        tunnel_url: row.get::<_, Option<String>>(17).unwrap_or(None),
        tunnel_exposed: tunnel_mode.is_exposed(),
        tunnel_mode,
        app_tunnel_id: row.get::<_, Option<String>>(19).unwrap_or(None),
        app_tunnel_domain: row.get::<_, Option<String>>(20).unwrap_or(None),
        app_tunnel_dns_id: row.get::<_, Option<String>>(21).unwrap_or(None),
        app_tunnel_creds: row.get::<_, Option<String>>(22).unwrap_or(None),
        inspect_enabled: row.get::<_, i64>(23).unwrap_or(0) == 1,
        fs_entry: row.get::<_, Option<String>>(24).unwrap_or(None),
    })
}

fn add_column_if_missing(conn: &Connection, sql: &str) -> anyhow::Result<()> {
    match conn.execute(sql, []) {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(_, Some(msg)))
            if msg.contains("duplicate column name") =>
        {
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn path_prefix_to_db(path_prefix: Option<&str>) -> String {
    path_prefix.unwrap_or("").to_string()
}

fn path_prefix_from_db(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Strip `.{suffix}` from a full domain to get the DB prefix.
pub fn domain_to_db(full_domain: &str, suffix: &str) -> String {
    let dot_suffix = format!(".{suffix}");
    full_domain
        .strip_suffix(&dot_suffix)
        .unwrap_or(full_domain)
        .to_string()
}

/// Append `.{suffix}` to a DB prefix to reconstruct the full domain.
fn domain_from_db(prefix: &str, suffix: &str) -> String {
    format!("{prefix}.{suffix}")
}

pub fn route_key(domain: &str, path_prefix_db: &str) -> String {
    format!("{domain}|{path_prefix_db}")
}

fn migrate_apps_domain_unique_to_route_unique(conn: &Connection) -> anyhow::Result<()> {
    let table_sql: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'apps'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let Some(sql) = table_sql else {
        return Ok(());
    };

    // v1 schema had `domain TEXT NOT NULL UNIQUE`, which blocks host+path multi-route.
    if !sql.contains("domain TEXT NOT NULL UNIQUE") {
        return Ok(());
    }

    conn.execute_batch(
        r#"
        BEGIN;
        ALTER TABLE apps RENAME TO apps_old;
        CREATE TABLE apps (
          id INTEGER PRIMARY KEY,
          name TEXT NOT NULL UNIQUE,
          kind TEXT NOT NULL,
          domain TEXT NOT NULL,
          path_prefix TEXT NOT NULL DEFAULT '',
          target_type TEXT NOT NULL DEFAULT 'tcp',
          target_value TEXT NOT NULL DEFAULT '',
          timeout_ms INTEGER,
          enabled INTEGER NOT NULL,
          scan_managed INTEGER NOT NULL DEFAULT 0,
          scan_source TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          UNIQUE(domain, path_prefix)
        );
        INSERT INTO apps (
          id, name, kind, domain, path_prefix, target_type, target_value, timeout_ms,
          enabled, scan_managed, scan_source, created_at, updated_at
        )
        SELECT
          id, name, kind, domain, '', 'tcp',
          COALESCE(target_host, '127.0.0.1') || ':' || COALESCE(target_port, 0),
          NULL, enabled, scan_managed, scan_source, created_at, updated_at
        FROM apps_old;
        DROP TABLE apps_old;
        CREATE INDEX IF NOT EXISTS idx_apps_enabled_domain ON apps(enabled, domain);
        COMMIT;
        "#,
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// CapturedRequest model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize)]
pub struct CapturedRequest {
    pub id: String,
    pub app_id: i64,
    pub timestamp: i64,
    pub method: String,
    pub path: String,
    pub query_string: Option<String>,
    pub request_headers: String,
    pub request_body: Option<Vec<u8>>,
    pub status_code: Option<u16>,
    pub response_headers: Option<String>,
    pub response_body: Option<Vec<u8>>,
    pub response_time_ms: Option<u64>,
}

fn row_to_captured_request(row: &rusqlite::Row<'_>) -> rusqlite::Result<CapturedRequest> {
    Ok(CapturedRequest {
        id: row.get(0)?,
        app_id: row.get(1)?,
        timestamp: row.get(2)?,
        method: row.get(3)?,
        path: row.get(4)?,
        query_string: row.get(5)?,
        request_headers: row.get(6)?,
        request_body: row.get(7)?,
        status_code: row.get::<_, Option<i64>>(8)?.map(|v| v as u16),
        response_headers: row.get(9)?,
        response_body: row.get(10)?,
        response_time_ms: row.get::<_, Option<i64>>(11)?.map(|v| v as u64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_list_enabled() {
        let repo = AppRepository {
            conn: Mutex::new(Connection::open_in_memory().expect("open sqlite")),
            domain_suffix: "coulson.local".to_string(),
            change_tx: None,
        };
        repo.init_schema().expect("schema");
        let domain = DomainName("myapp.coulson.local".to_string());

        repo.insert_static(&StaticAppInput {
            name: "myapp",
            domain: &domain,
            path_prefix: None,
            target_type: "tcp",
            target_value: "127.0.0.1:9001",
            timeout_ms: None,
            cors_enabled: false,
            force_https: false,
            basic_auth_user: None,
            basic_auth_pass: None,
            spa_rewrite: false,
            listen_port: None,
        })
        .expect("insert");
        let apps = repo.list_enabled().expect("list");
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].domain.0, "myapp.coulson.local");
    }

    #[test]
    fn settings_crud() {
        let repo = AppRepository {
            conn: Mutex::new(Connection::open_in_memory().expect("open sqlite")),
            domain_suffix: "coulson.local".to_string(),
            change_tx: None,
        };
        repo.init_schema().expect("schema");

        // Get missing key returns None
        assert_eq!(repo.get_setting("foo").unwrap(), None);

        // Set and get
        repo.set_setting("foo", "bar").unwrap();
        assert_eq!(repo.get_setting("foo").unwrap(), Some("bar".to_string()));

        // Overwrite
        repo.set_setting("foo", "baz").unwrap();
        assert_eq!(repo.get_setting("foo").unwrap(), Some("baz".to_string()));

        // Delete
        assert!(repo.delete_setting("foo").unwrap());
        assert_eq!(repo.get_setting("foo").unwrap(), None);

        // Delete missing key
        assert!(!repo.delete_setting("foo").unwrap());
    }

    #[test]
    fn db_stores_prefix_only() {
        let repo = AppRepository {
            conn: Mutex::new(Connection::open_in_memory().expect("open sqlite")),
            domain_suffix: "coulson.local".to_string(),
            change_tx: None,
        };
        repo.init_schema().expect("schema");
        let domain = DomainName("myapp.coulson.local".to_string());

        repo.insert_static(&StaticAppInput {
            name: "myapp",
            domain: &domain,
            path_prefix: None,
            target_type: "tcp",
            target_value: "127.0.0.1:9001",
            timeout_ms: None,
            cors_enabled: false,
            force_https: false,
            basic_auth_user: None,
            basic_auth_pass: None,
            spa_rewrite: false,
            listen_port: None,
        })
        .expect("insert");

        // Verify raw DB stores only prefix
        let conn = repo.conn.lock();
        let raw: String = conn
            .query_row("SELECT domain FROM apps LIMIT 1", [], |row| row.get(0))
            .expect("query");
        assert_eq!(raw, "myapp");
    }
}
