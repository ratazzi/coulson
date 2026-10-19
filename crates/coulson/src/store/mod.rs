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
    /// Dedicated read connection (WAL mode): readers see the last committed
    /// snapshot and never queue behind a long write transaction — store
    /// reads taken under the process-manager lock must not stall for the
    /// duration of a scan's `StoreTxn`. `None` for in-memory test databases
    /// (falls back to the write connection).
    pub(crate) read_conn: Option<Mutex<Connection>>,
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
        // Write transactions are taken by both the daemon and offline
        // `coulson scan` against the same file; wait out the other side's
        // BEGIN IMMEDIATE instead of failing with SQLITE_BUSY.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        // WAL so the dedicated read connection below can read the last
        // committed snapshot while a write transaction is open.
        let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        let read_conn = Connection::open(path)
            .with_context(|| format!("failed to open sqlite db (read): {}", path.display()))?;
        read_conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(Self {
            conn: Mutex::new(conn),
            read_conn: Some(Mutex::new(read_conn)),
            domain_suffix: domain_suffix.to_string(),
            change_tx: None,
        })
    }

    /// Lock the read connection (or the write connection when no separate
    /// reader exists, e.g. in-memory test databases).
    fn reader(&self) -> parking_lot::MutexGuard<'_, Connection> {
        match &self.read_conn {
            Some(rc) => rc.lock(),
            None => self.conn.lock(),
        }
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
              id INTEGER PRIMARY KEY AUTOINCREMENT,
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
              lan_access INTEGER NOT NULL DEFAULT 0,
              cname TEXT,
              fs_entry TEXT,
              hooks TEXT,
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

        // Structural v1 migration FIRST: it rebuilds `apps` from a hardcoded
        // v1 column list, so it must run against the actual v1 shape. Running
        // it after the additive columns below would silently drop every one
        // of them from the rebuilt table.
        migrate_apps_domain_unique_to_route_unique(&conn)?;

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
            "ALTER TABLE apps ADD COLUMN lan_access INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE apps ADD COLUMN cname TEXT",
            "ALTER TABLE apps ADD COLUMN fs_entry TEXT",
            "ALTER TABLE apps ADD COLUMN hooks TEXT",
        ] {
            add_column_if_missing(&conn, sql)?;
        }

        // Runs last: rebuilds from the live sqlite_master schema text, so it
        // preserves whatever columns exist at this point.
        migrate_apps_id_autoincrement(&conn)?;
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
            lan_access: false,
            cname: None,
            fs_entry: None,
            hooks: None,
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
            "procfile" => AppKind::Procfile,
            "container" | "docker" => AppKind::Container,
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
            lan_access: false,
            cname: None,
            fs_entry: None,
            hooks: None,
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
            lan_access: false,
            cname: None,
            fs_entry: None,
            hooks: None,
            enabled: true,
            created_at: now,
            updated_at: now,
        })
    }

    /// Open a write transaction (`BEGIN IMMEDIATE`) that also holds the
    /// in-process connection lock until commit or drop (rollback).
    ///
    /// "An app exists" spans a DB row plus an apps_root fs entry, and every
    /// mutation of that pair — scan upsert/prune, explicit delete — runs
    /// inside one of these. In-process the connection lock serializes them;
    /// across processes (the daemon vs an offline `coulson scan`) SQLite's
    /// write lock does, so checking the filesystem from inside a write
    /// transaction observes a state no other party can be mutating.
    pub fn begin_write(&self) -> anyhow::Result<StoreTxn<'_>> {
        let conn = self.conn.lock();
        conn.execute_batch("BEGIN IMMEDIATE")?;
        Ok(StoreTxn {
            repo: self,
            conn,
            committed: false,
        })
    }

    pub fn upsert_scanned_static(
        &self,
        input: &StaticAppInput,
        enabled: bool,
        source: &str,
        fs_entry: &str,
        hooks: Option<&crate::hooks::AppHooksConfig>,
    ) -> anyhow::Result<(AppSpec, ScanUpsertResult)> {
        let txn = self.begin_write()?;
        let result = txn.upsert_scanned_static(input, enabled, source, fs_entry, hooks)?;
        txn.commit()?;
        Ok(result)
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
        hooks: Option<&crate::hooks::AppHooksConfig>,
    ) -> anyhow::Result<(AppSpec, ScanUpsertResult)> {
        let txn = self.begin_write()?;
        let result = txn.upsert_scanned_managed(
            name, domain, app_root, kind, enabled, source, fs_entry, hooks,
        )?;
        txn.commit()?;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_scanned_static_dir(
        &self,
        name: &str,
        domain: &DomainName,
        static_root: &str,
        enabled: bool,
        source: &str,
        fs_entry: &str,
        hooks: Option<&crate::hooks::AppHooksConfig>,
    ) -> anyhow::Result<(AppSpec, ScanUpsertResult)> {
        let txn = self.begin_write()?;
        let result = txn.upsert_scanned_static_dir(
            name,
            domain,
            static_root,
            enabled,
            source,
            fs_entry,
            hooks,
        )?;
        txn.commit()?;
        Ok(result)
    }

    /// Remove scan-owned rows whose route disappeared, returning the removed
    /// rows so the caller can tear down their processes and fire `app_stop`
    /// hooks with full route context (after the delete, that data is gone).
    /// Rows whose `fs_entry` is in `protected_fs_entries` are kept: their
    /// entry exists but was unreadable this scan, which is not absence.
    pub fn prune_scanned_not_in(
        &self,
        source: &str,
        active_routes: &HashSet<String>,
        protected_fs_entries: &HashSet<String>,
    ) -> anyhow::Result<Vec<AppSpec>> {
        let txn = self.begin_write()?;
        let result = txn.prune_scanned_not_in(source, active_routes, protected_fs_entries)?;
        txn.commit()?;
        Ok(result)
    }
}

/// See [`AppRepository::begin_write`].
pub struct StoreTxn<'a> {
    repo: &'a AppRepository,
    conn: parking_lot::MutexGuard<'a, Connection>,
    committed: bool,
}

impl Drop for StoreTxn<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }
}

impl StoreTxn<'_> {
    pub fn commit(mut self) -> anyhow::Result<()> {
        self.conn.execute_batch("COMMIT")?;
        self.committed = true;
        Ok(())
    }

    /// Read through the transaction's connection. Process startup uses this
    /// while holding `BEGIN IMMEDIATE` across its final desired-state check and
    /// in-memory group insertion, so an offline scanner cannot commit a prune
    /// in the gap between those two operations.
    pub fn get_by_id(&self, app_id: i64) -> anyhow::Result<Option<AppSpec>> {
        let app = self
            .conn
            .query_row(
                &format!("SELECT {} FROM apps WHERE id = ?1", COLS),
                params![app_id],
                |row| row_to_app(row, &self.repo.domain_suffix),
            )
            .optional()?;
        Ok(app)
    }

    pub fn upsert_scanned_static(
        &self,
        input: &StaticAppInput,
        enabled: bool,
        source: &str,
        fs_entry: &str,
        hooks: Option<&crate::hooks::AppHooksConfig>,
    ) -> anyhow::Result<(AppSpec, ScanUpsertResult)> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let hooks_json: Option<String> = hooks.map(serde_json::to_string).transpose()?;
        let conn = &*self.conn;
        let path_prefix_db = path_prefix_to_db(input.path_prefix);
        let domain_db = domain_to_db(&input.domain.0, &self.repo.domain_suffix);

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
                    "UPDATE apps SET name = ?1, path_prefix = ?2, target_type = ?3, target_value = ?4, timeout_ms = ?5, updated_at = ?6, scan_managed = 1, scan_source = ?7, cors_enabled = ?8, force_https = ?9, basic_auth_user = ?10, basic_auth_pass = ?11, spa_rewrite = ?12, listen_port = ?13, fs_entry = ?14, enabled = ?15, hooks = ?17 WHERE id = ?16",
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
                        if enabled { 1 } else { 0 },
                        id,
                        hooks_json
                    ],
                )?;
                ScanUpsertResult::Updated
            }
            None => {
                conn.execute(
                    "INSERT INTO apps (name, kind, domain, path_prefix, target_type, target_value, timeout_ms, enabled, scan_managed, scan_source, created_at, updated_at, cors_enabled, force_https, basic_auth_user, basic_auth_pass, spa_rewrite, listen_port, fs_entry, hooks)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
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
                        hooks_json,
                    ],
                )?;
                ScanUpsertResult::Inserted
            }
        };

        let suffix = &self.repo.domain_suffix;
        let app = AppRepository::read_app_by_route(conn, &domain_db, &path_prefix_db, suffix)?;
        Ok((app, op))
    }

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
        hooks: Option<&crate::hooks::AppHooksConfig>,
    ) -> anyhow::Result<(AppSpec, ScanUpsertResult)> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let hooks_json: Option<String> = hooks.map(serde_json::to_string).transpose()?;
        let conn = &*self.conn;
        let path_prefix_db = "";
        let domain_db = domain_to_db(&domain.0, &self.repo.domain_suffix);

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
                    "UPDATE apps SET name = ?1, kind = ?2, target_type = 'managed', target_value = ?3, updated_at = ?4, scan_managed = 1, scan_source = ?5, fs_entry = ?6, enabled = ?7, hooks = ?9 WHERE id = ?8",
                    params![name, kind, app_root, now, source, fs_entry, if enabled { 1 } else { 0 }, id, hooks_json],
                )?;
                ScanUpsertResult::Updated
            }
            None => {
                conn.execute(
                    "INSERT INTO apps (name, kind, domain, path_prefix, target_type, target_value, timeout_ms, enabled, scan_managed, scan_source, created_at, updated_at, fs_entry, hooks)
                     VALUES (?1, ?2, ?3, ?4, 'managed', ?5, NULL, ?6, 1, ?7, ?8, ?9, ?10, ?11)",
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
                        hooks_json,
                    ],
                )?;
                ScanUpsertResult::Inserted
            }
        };

        let suffix = &self.repo.domain_suffix;
        let app = AppRepository::read_app_by_route(conn, &domain_db, path_prefix_db, suffix)?;
        Ok((app, op))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_scanned_static_dir(
        &self,
        name: &str,
        domain: &DomainName,
        static_root: &str,
        enabled: bool,
        source: &str,
        fs_entry: &str,
        hooks: Option<&crate::hooks::AppHooksConfig>,
    ) -> anyhow::Result<(AppSpec, ScanUpsertResult)> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let hooks_json: Option<String> = hooks.map(serde_json::to_string).transpose()?;
        let conn = &*self.conn;
        let path_prefix_db = "";
        let domain_db = domain_to_db(&domain.0, &self.repo.domain_suffix);

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
                    "UPDATE apps SET name = ?1, kind = 'static', target_type = 'static_dir', target_value = ?2, updated_at = ?3, scan_managed = 1, scan_source = ?4, fs_entry = ?5, enabled = ?6, hooks = ?8 WHERE id = ?7",
                    params![name, static_root, now, source, fs_entry, if enabled { 1 } else { 0 }, id, hooks_json],
                )?;
                ScanUpsertResult::Updated
            }
            None => {
                conn.execute(
                    "INSERT INTO apps (name, kind, domain, path_prefix, target_type, target_value, timeout_ms, enabled, scan_managed, scan_source, created_at, updated_at, fs_entry, hooks)
                     VALUES (?1, 'static', ?2, ?3, 'static_dir', ?4, NULL, ?5, 1, ?6, ?7, ?8, ?9, ?10)",
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
                        hooks_json,
                    ],
                )?;
                ScanUpsertResult::Inserted
            }
        };

        let suffix = &self.repo.domain_suffix;
        let app = AppRepository::read_app_by_route(conn, &domain_db, path_prefix_db, suffix)?;
        Ok((app, op))
    }

    pub fn prune_scanned_not_in(
        &self,
        source: &str,
        active_routes: &HashSet<String>,
        protected_fs_entries: &HashSet<String>,
    ) -> anyhow::Result<Vec<AppSpec>> {
        let conn = &*self.conn;
        let mut stmt = conn.prepare(
            "SELECT id, domain, path_prefix, fs_entry FROM apps WHERE scan_managed = 1 AND scan_source = ?1",
        )?;
        let mut rows = stmt.query(params![source])?;
        let mut delete_ids: Vec<i64> = Vec::new();

        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let domain_prefix: String = row.get(1)?;
            let path_prefix: String = row.get(2)?;
            let fs_entry: Option<String> = row.get(3)?;
            if fs_entry
                .as_deref()
                .is_some_and(|e| protected_fs_entries.contains(e))
            {
                continue;
            }
            let key = route_key(&domain_prefix, &path_prefix);
            if !active_routes.contains(&key) {
                delete_ids.push(id);
            }
        }

        let mut pruned = Vec::new();
        for id in &delete_ids {
            let app = conn
                .query_row(
                    &format!("DELETE FROM apps WHERE id = ?1 RETURNING {}", COLS),
                    params![id],
                    |row| row_to_app(row, &self.repo.domain_suffix),
                )
                .optional()?;
            if let Some(app) = app {
                pruned.push(app);
            }
        }
        Ok(pruned)
    }

    /// Delete the row and return the removed snapshot in a single
    /// `DELETE … RETURNING` statement — the scanner can rewrite a row in
    /// place, so cleanup (hooks, fs entry) must describe the row actually
    /// removed, not a separately fetched copy.
    pub fn delete_returning(&self, app_id: i64) -> anyhow::Result<Option<AppSpec>> {
        let conn = &*self.conn;
        let app = conn
            .query_row(
                &format!("DELETE FROM apps WHERE id = ?1 RETURNING {}", COLS),
                params![app_id],
                |row| row_to_app(row, &self.repo.domain_suffix),
            )
            .optional()?;
        Ok(app)
    }
}

impl AppRepository {
    pub fn delete(&self, app_id: i64) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let changed = conn.execute("DELETE FROM apps WHERE id = ?1", params![app_id])?;
        Ok(changed > 0)
    }

    /// Transactional variant of [`StoreTxn::delete_returning`] for callers
    /// that have no fs entry to remove alongside the row.
    pub fn delete_returning(&self, app_id: i64) -> anyhow::Result<Option<AppSpec>> {
        let txn = self.begin_write()?;
        let app = txn.delete_returning(app_id)?;
        txn.commit()?;
        Ok(app)
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
        let conn = self.reader();
        Self::query_apps(&conn, false, &self.domain_suffix)
    }

    pub fn list_filtered(
        &self,
        managed: Option<bool>,
        domain: Option<&str>,
    ) -> anyhow::Result<Vec<AppSpec>> {
        let domain_db = domain.map(|d| domain_to_db(d, &self.domain_suffix));
        let conn = self.reader();
        Self::query_apps_filtered(&conn, managed, domain_db.as_deref(), &self.domain_suffix)
    }

    pub fn list_enabled(&self) -> anyhow::Result<Vec<AppSpec>> {
        let conn = self.reader();
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
        lan_access: Option<bool>,
        cname: Option<Option<&str>>,
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
        if let Some(v) = lan_access {
            sets.push(format!("lan_access = ?{idx}"));
            values.push(Box::new(if v { 1i64 } else { 0 }));
            idx += 1;
        }
        if let Some(v) = cname {
            sets.push(format!("cname = ?{idx}"));
            values.push(Box::new(v.map(|s| s.to_string())));
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
        let conn = self.reader();
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
        let conn = self.reader();
        let sql = format!(
            "SELECT {} FROM apps WHERE tunnel_mode = 'named' AND enabled = 1",
            COLS
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        Self::collect_rows(&mut rows, &self.domain_suffix)
    }

    pub fn list_quick_tunnels(&self) -> anyhow::Result<Vec<AppSpec>> {
        let conn = self.reader();
        let sql = format!(
            "SELECT {} FROM apps WHERE tunnel_mode = 'quick' AND enabled = 1",
            COLS
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        Self::collect_rows(&mut rows, &self.domain_suffix)
    }

    pub fn is_tunnel_exposed(&self, domain_prefix: &str) -> anyhow::Result<bool> {
        let conn = self.reader();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM apps WHERE domain = ?1 AND enabled = 1 AND tunnel_mode != 'none'",
            params![domain_prefix],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Return the enabled app route that handles `path` for a domain.
    ///
    /// This only resolves the app identity; per-app runtime configuration is
    /// deliberately read from `.coulson.toml` by the tunnel code instead of
    /// being copied into SQLite.
    pub fn get_enabled_by_route(
        &self,
        domain_prefix: &str,
        path: &str,
    ) -> anyhow::Result<Option<AppSpec>> {
        let conn = self.reader();
        let app = conn
            .query_row(
                &format!(
                    "SELECT {} FROM apps
                     WHERE domain = ?1 AND enabled = 1 AND (
                         path_prefix = '' OR path_prefix = '/' OR path_prefix = ?2 OR (
                             LENGTH(?2) > LENGTH(path_prefix)
                             AND SUBSTR(?2, 1, LENGTH(path_prefix)) = path_prefix
                             AND SUBSTR(?2, LENGTH(path_prefix) + 1, 1) = '/'
                         )
                     )
                     ORDER BY LENGTH(path_prefix) DESC, id ASC
                     LIMIT 1",
                    COLS
                ),
                params![domain_prefix, path],
                |row| row_to_app(row, &self.domain_suffix),
            )
            .optional()?;
        Ok(app)
    }

    pub fn is_share_auth_required(&self, domain_prefix: &str) -> anyhow::Result<bool> {
        let conn = self.reader();
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
        let conn = self.reader();
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
        let conn = self.reader();
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
                req.response_time_ms.map(|v| v as i64),
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
        let conn = self.reader();
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
        let conn = self.reader();
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
                let conn = self.reader();
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
        let conn = self.reader();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM request_logs WHERE app_id = ?",
            params![app_id],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }
}

const COLS: &str = "id,name,kind,domain,path_prefix,target_type,target_value,timeout_ms,enabled,created_at,updated_at,cors_enabled,force_https,basic_auth_user,basic_auth_pass,spa_rewrite,listen_port,tunnel_url,tunnel_mode,app_tunnel_id,app_tunnel_domain,app_tunnel_dns_id,app_tunnel_creds,inspect_enabled,lan_access,cname,fs_entry,hooks";

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
        "procfile" => AppKind::Procfile,
        "container" | "docker" => AppKind::Container,
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
        lan_access: row.get::<_, i64>(24).unwrap_or(0) == 1,
        cname: row.get::<_, Option<String>>(25).unwrap_or(None),
        fs_entry: row.get::<_, Option<String>>(26).unwrap_or(None),
        hooks: row
            .get::<_, Option<String>>(27)
            .unwrap_or(None)
            .and_then(|raw| serde_json::from_str(&raw).ok()),
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

/// Rebuild `apps` with `AUTOINCREMENT` so row ids are never reused after
/// deletion. Without it SQLite hands a deleted maximum id to the next insert,
/// and every consumer keyed by app_id (process groups, per-app hooks, routes)
/// can confuse the replacement app with the removed one. Identity checks
/// remain as defense in depth, but monotonic ids remove the class of races.
///
/// The new table is derived from the live `sqlite_master` text (not a
/// hard-coded column list), so it works for any column set the migrations
/// have produced so far.
fn migrate_apps_id_autoincrement(conn: &Connection) -> anyhow::Result<()> {
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
    if sql.to_uppercase().contains("AUTOINCREMENT") {
        return Ok(());
    }

    let with_autoinc = sql.replacen(
        "id INTEGER PRIMARY KEY",
        "id INTEGER PRIMARY KEY AUTOINCREMENT",
        1,
    );
    let create_new = if with_autoinc.contains("CREATE TABLE IF NOT EXISTS apps") {
        with_autoinc.replacen(
            "CREATE TABLE IF NOT EXISTS apps",
            "CREATE TABLE apps_new",
            1,
        )
    } else {
        with_autoinc.replacen("CREATE TABLE apps", "CREATE TABLE apps_new", 1)
    };
    if create_new == sql || !create_new.contains("AUTOINCREMENT") {
        // Unexpected schema text: skip rather than brick startup; identity
        // checks still guard against id reuse.
        tracing::error!("apps table schema not recognized, skipping AUTOINCREMENT migration");
        return Ok(());
    }

    let mut cols: Vec<String> = Vec::new();
    let mut stmt = conn.prepare("PRAGMA table_info(apps)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for col in rows {
        cols.push(col?);
    }
    drop(stmt);
    let col_list = cols.join(", ");

    conn.execute_batch(&format!(
        r#"
        BEGIN;
        {create_new};
        INSERT INTO apps_new ({col_list}) SELECT {col_list} FROM apps;
        DROP TABLE apps;
        ALTER TABLE apps_new RENAME TO apps;
        CREATE INDEX IF NOT EXISTS idx_apps_enabled_domain ON apps(enabled, domain);
        COMMIT;
        "#
    ))?;

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

/// Request and response bodies are captured up to this many bytes.
pub const CAPTURE_BODY_MAX: usize = 65536;

/// Response metadata derived from a captured request, for list views.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseSummary {
    /// MIME type without parameters, e.g. `application/json`.
    pub content_type: Option<String>,
    /// `Content-Length` when present, else the captured body length.
    pub size: Option<u64>,
    /// The size is a lower bound because the captured body hit the cap.
    pub size_truncated: bool,
}

impl ResponseSummary {
    pub fn size_display(&self) -> Option<String> {
        let size = self.size?;
        let text = if size < 1024 {
            format!("{size} B")
        } else {
            let (value, unit) = if size < 1024 * 1024 {
                (size as f64 / 1024.0, "KB")
            } else {
                (size as f64 / (1024.0 * 1024.0), "MB")
            };
            if value < 10.0 {
                format!("{value:.1} {unit}")
            } else {
                format!("{value:.0} {unit}")
            }
        };
        Some(if self.size_truncated {
            format!("{text}+")
        } else {
            text
        })
    }
}

impl CapturedRequest {
    pub fn response_summary(&self) -> ResponseSummary {
        let Some(headers_json) = self.response_headers.as_deref() else {
            return ResponseSummary {
                content_type: None,
                size: None,
                size_truncated: false,
            };
        };
        let headers: std::collections::HashMap<String, String> =
            serde_json::from_str(headers_json).unwrap_or_default();
        let header = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        let content_type = header("content-type")
            .and_then(|v| v.split(';').next())
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty());
        let body_len = self.response_body.as_ref().map_or(0, |b| b.len());
        let (size, size_truncated) =
            match header("content-length").and_then(|v| v.trim().parse::<u64>().ok()) {
                Some(len) => (len, false),
                None => (body_len as u64, body_len >= CAPTURE_BODY_MAX),
            };
        ResponseSummary {
            content_type,
            size: Some(size),
            size_truncated,
        }
    }
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

    fn captured_response(headers: Option<&str>, body: Option<Vec<u8>>) -> CapturedRequest {
        CapturedRequest {
            id: "r1".into(),
            app_id: 1,
            timestamp: 0,
            method: "GET".into(),
            path: "/".into(),
            query_string: None,
            request_headers: "{}".into(),
            request_body: None,
            status_code: headers.map(|_| 200),
            response_headers: headers.map(Into::into),
            response_body: body,
            response_time_ms: None,
        }
    }

    #[test]
    fn response_summary_prefers_content_length() {
        let req = captured_response(
            Some(r#"{"Content-Type":"application/json; charset=utf-8","content-length":"2048"}"#),
            Some(b"{}".to_vec()),
        );
        let summary = req.response_summary();
        assert_eq!(summary.content_type.as_deref(), Some("application/json"));
        assert_eq!(summary.size, Some(2048));
        assert_eq!(summary.size_display().as_deref(), Some("2.0 KB"));
    }

    #[test]
    fn response_summary_falls_back_to_captured_body() {
        let small = captured_response(Some("{}"), Some(vec![0; 512]));
        assert_eq!(
            small.response_summary().size_display().as_deref(),
            Some("512 B")
        );

        let capped = captured_response(Some("{}"), Some(vec![0; CAPTURE_BODY_MAX]));
        let summary = capped.response_summary();
        assert!(summary.size_truncated);
        assert_eq!(summary.content_type, None);
        assert_eq!(summary.size_display().as_deref(), Some("64 KB+"));

        let pending = captured_response(None, None).response_summary();
        assert_eq!(pending.size_display(), None);
    }

    #[test]
    fn insert_and_list_enabled() {
        let repo = AppRepository {
            conn: Mutex::new(Connection::open_in_memory().expect("open sqlite")),
            read_conn: None,
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
    fn enabled_route_lookup_prefers_longest_boundary_match() {
        let repo = AppRepository {
            conn: Mutex::new(Connection::open_in_memory().expect("open sqlite")),
            read_conn: None,
            domain_suffix: "coulson.local".to_string(),
            change_tx: None,
        };
        repo.init_schema().expect("schema");
        let domain = DomainName("myapp.coulson.local".to_string());

        let root = repo
            .insert_static(&StaticAppInput {
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
            .expect("insert root route");
        let api = repo
            .insert_static(&StaticAppInput {
                name: "myapp-api",
                domain: &domain,
                path_prefix: Some("/api"),
                target_type: "tcp",
                target_value: "127.0.0.1:9002",
                timeout_ms: None,
                cors_enabled: false,
                force_https: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
                listen_port: None,
            })
            .expect("insert api route");

        assert_eq!(
            repo.get_enabled_by_route("myapp", "/api/users")
                .expect("lookup api route")
                .expect("api route")
                .id,
            api.id
        );
        assert_eq!(
            repo.get_enabled_by_route("myapp", "/apiary")
                .expect("lookup root route")
                .expect("root route")
                .id,
            root.id
        );
        assert!(repo
            .get_enabled_by_route("other", "/")
            .expect("lookup missing route")
            .is_none());
    }

    #[test]
    fn rescan_applies_enabled_change_to_managed_route() {
        let repo = AppRepository {
            conn: Mutex::new(Connection::open_in_memory().expect("open sqlite")),
            read_conn: None,
            domain_suffix: "coulson.local".to_string(),
            change_tx: None,
        };
        repo.init_schema().expect("schema");
        let domain = DomainName("myapp.coulson.local".to_string());

        // First scan: enabled
        let (app, op) = repo
            .upsert_scanned_managed(
                "myapp",
                &domain,
                "/srv/myapp",
                "asgi",
                true,
                "fs",
                "entry",
                None,
            )
            .expect("first upsert");
        assert!(matches!(op, ScanUpsertResult::Inserted));
        assert!(app.enabled);

        // Rescan with enabled = false must flip the stored state.
        let (app, op) = repo
            .upsert_scanned_managed(
                "myapp",
                &domain,
                "/srv/myapp",
                "asgi",
                false,
                "fs",
                "entry",
                None,
            )
            .expect("second upsert");
        assert!(matches!(op, ScanUpsertResult::Updated));
        assert!(!app.enabled);
    }

    #[test]
    fn deleted_app_ids_are_never_reused() {
        let repo = AppRepository {
            conn: Mutex::new(Connection::open_in_memory().expect("open sqlite")),
            read_conn: None,
            domain_suffix: "coulson.local".to_string(),
            change_tx: None,
        };
        repo.init_schema().expect("schema");

        let domain = DomainName("appx.coulson.local".to_string());
        let (a, _) = repo
            .upsert_scanned_managed(
                "appx",
                &domain,
                "/srv/appx",
                "procfile",
                true,
                "fs",
                "e",
                None,
            )
            .expect("insert appx");
        assert!(repo.delete(a.id.0).expect("delete appx"));

        // The table is now empty; without AUTOINCREMENT the next insert would
        // reuse appx's id and every app_id-keyed consumer could confuse the
        // replacement with the removed app.
        let domain2 = DomainName("appy.coulson.local".to_string());
        let (b, _) = repo
            .upsert_scanned_managed(
                "appy",
                &domain2,
                "/srv/appy",
                "procfile",
                true,
                "fs",
                "e",
                None,
            )
            .expect("insert appy");
        assert!(b.id.0 > a.id.0, "row id reused after delete");
    }

    #[test]
    fn hooks_persist_on_row_and_survive_delete_returning() {
        let repo = AppRepository {
            conn: Mutex::new(Connection::open_in_memory().expect("open sqlite")),
            read_conn: None,
            domain_suffix: "coulson.local".to_string(),
            change_tx: None,
        };
        repo.init_schema().expect("schema");
        let domain = DomainName("myapp.coulson.local".to_string());

        let hooks = crate::hooks::AppHooksConfig {
            skip_global: true,
            app_stop: Some(crate::hooks::HookActionConfig {
                run: Some("echo stopped".to_string()),
                webhook: None,
            }),
            app_add: None,
            app_remove: None,
            app_start: None,
            app_ready: None,
            app_idle: None,
            tunnel_start: None,
            tunnel_stop: None,
        };
        let (app, _) = repo
            .upsert_scanned_managed(
                "myapp",
                &domain,
                "/srv/myapp",
                "asgi",
                true,
                "fs",
                "e",
                Some(&hooks),
            )
            .expect("upsert");
        // The row is the single source of truth: reads and the deletion
        // snapshot must both carry the hook config of this generation.
        let read = repo.get_by_id(app.id.0).expect("get").expect("row");
        assert!(read.hooks.as_ref().is_some_and(|h| h.skip_global));
        let deleted = repo
            .delete_returning(app.id.0)
            .expect("delete")
            .expect("row existed");
        let dh = deleted.hooks.expect("hooks on deleted snapshot");
        assert_eq!(
            dh.app_stop.and_then(|a| a.run).as_deref(),
            Some("echo stopped")
        );
    }

    #[test]
    fn app_spec_serialization_omits_hooks() {
        let repo = AppRepository {
            conn: Mutex::new(Connection::open_in_memory().expect("open sqlite")),
            read_conn: None,
            domain_suffix: "coulson.local".to_string(),
            change_tx: None,
        };
        repo.init_schema().expect("schema");
        let domain = DomainName("myapp.coulson.local".to_string());
        let hooks = crate::hooks::AppHooksConfig {
            skip_global: false,
            app_stop: Some(crate::hooks::HookActionConfig {
                run: Some("curl -H 'Authorization: Bearer secret'".to_string()),
                webhook: Some("https://example.com/?sig=secret".to_string()),
            }),
            app_add: None,
            app_remove: None,
            app_start: None,
            app_ready: None,
            app_idle: None,
            tunnel_start: None,
            tunnel_stop: None,
        };
        let (app, _) = repo
            .upsert_scanned_managed(
                "myapp",
                &domain,
                "/srv/myapp",
                "asgi",
                true,
                "fs",
                "e",
                Some(&hooks),
            )
            .expect("upsert");
        repo.update_settings(
            app.id.0,
            None,
            None,
            None,
            Some(Some("s3cret-pw")),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("set basic auth pass");
        repo.set_app_tunnel_state(
            app.id.0,
            Some("tid"),
            Some("t.example.com"),
            None,
            Some("{\"tunnel_secret\":\"s3cret-tunnel\"}"),
            TunnelMode::Named,
        )
        .expect("set tunnel creds");
        let read = repo.get_by_id(app.id.0).expect("get").expect("row");
        assert!(read.hooks.is_some(), "hooks must round-trip via the store");
        assert!(read.basic_auth_pass.is_some());
        assert!(read.app_tunnel_creds.is_some());

        // AppSpec flows out through control RPC (`app.list`/`app.get`); hook
        // commands/webhook URLs, the basic-auth password, and the tunnel
        // credential JSON can all carry secrets and must never appear in any
        // serialized form — secrets serialize as presence booleans only.
        let json = serde_json::to_value(&read).expect("serialize");
        assert!(json.get("hooks").is_none(), "hooks leaked: {json}");
        assert!(json.get("basic_auth_pass").is_none());
        assert!(json.get("app_tunnel_creds").is_none());
        assert_eq!(
            json.get("basic_auth_pass_set").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            json.get("app_tunnel_creds_set").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert!(!json.to_string().contains("secret"));
        assert!(!json.to_string().contains("s3cret"));
    }

    #[test]
    fn prune_keeps_rows_of_protected_fs_entries() {
        let repo = AppRepository {
            conn: Mutex::new(Connection::open_in_memory().expect("open sqlite")),
            read_conn: None,
            domain_suffix: "coulson.local".to_string(),
            change_tx: None,
        };
        repo.init_schema().expect("schema");
        let domain = DomainName("appx.coulson.local".to_string());
        repo.upsert_scanned_managed(
            "appx",
            &domain,
            "/srv/appx",
            "asgi",
            true,
            "apps_root",
            "appx",
            None,
        )
        .expect("seed");

        // Route absent from active_routes, but its fs entry is indeterminate
        // (unreadable this scan): the row must survive the prune.
        let mut protected = HashSet::new();
        protected.insert("appx".to_string());
        let pruned = repo
            .prune_scanned_not_in("apps_root", &HashSet::new(), &protected)
            .expect("prune protected");
        assert!(pruned.is_empty());
        assert!(repo.get_by_name("appx").expect("get").is_some());

        // Without protection the same prune removes it.
        let pruned = repo
            .prune_scanned_not_in("apps_root", &HashSet::new(), &HashSet::new())
            .expect("prune");
        assert_eq!(pruned.len(), 1);
        assert!(repo.get_by_name("appx").expect("get").is_none());
    }

    #[test]
    fn store_txn_rolls_back_on_drop() {
        let repo = AppRepository {
            conn: Mutex::new(Connection::open_in_memory().expect("open sqlite")),
            read_conn: None,
            domain_suffix: "coulson.local".to_string(),
            change_tx: None,
        };
        repo.init_schema().expect("schema");
        let domain = DomainName("appx.coulson.local".to_string());

        {
            let txn = repo.begin_write().expect("begin");
            txn.upsert_scanned_managed("appx", &domain, "/srv/appx", "asgi", true, "fs", "e", None)
                .expect("upsert");
            // Dropped without commit — a scan that errors out halfway must
            // leave no partially applied rows behind.
        }
        assert!(repo.get_by_name("appx").expect("get").is_none());
    }

    #[test]
    fn store_txn_commits_multiple_ops_atomically() {
        let repo = AppRepository {
            conn: Mutex::new(Connection::open_in_memory().expect("open sqlite")),
            read_conn: None,
            domain_suffix: "coulson.local".to_string(),
            change_tx: None,
        };
        repo.init_schema().expect("schema");
        let domain_a = DomainName("appa.coulson.local".to_string());
        let domain_b = DomainName("appb.coulson.local".to_string());
        repo.upsert_scanned_managed(
            "appa",
            &domain_a,
            "/srv/appa",
            "asgi",
            true,
            "apps_root",
            "a",
            None,
        )
        .expect("seed appa");

        // One transaction: upsert appb, prune appa (route disappeared).
        let txn = repo.begin_write().expect("begin");
        txn.upsert_scanned_managed(
            "appb",
            &domain_b,
            "/srv/appb",
            "node",
            true,
            "apps_root",
            "b",
            None,
        )
        .expect("upsert appb");
        let mut active = HashSet::new();
        active.insert(route_key("appb", ""));
        let pruned = txn
            .prune_scanned_not_in("apps_root", &active, &HashSet::new())
            .expect("prune");
        txn.commit().expect("commit");

        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned[0].name, "appa");
        assert!(repo.get_by_name("appa").expect("get").is_none());
        assert!(repo.get_by_name("appb").expect("get").is_some());
    }

    #[test]
    fn delete_returning_snapshots_the_row_it_removes() {
        let repo = AppRepository {
            conn: Mutex::new(Connection::open_in_memory().expect("open sqlite")),
            read_conn: None,
            domain_suffix: "coulson.local".to_string(),
            change_tx: None,
        };
        repo.init_schema().expect("schema");
        let domain = DomainName("myapp.coulson.local".to_string());

        let (a, _) = repo
            .upsert_scanned_managed("myapp", &domain, "/srv/a", "node", true, "fs", "e", None)
            .expect("insert");
        // In-place scanner rewrite: same route key keeps the row id but
        // changes identity (root + provider kind).
        let (b, op) = repo
            .upsert_scanned_managed(
                "myapp", &domain, "/srv/b", "procfile", true, "fs", "e", None,
            )
            .expect("rewrite");
        assert!(matches!(op, ScanUpsertResult::Updated));
        assert_eq!(a.id.0, b.id.0);

        // The returned snapshot must be the rewritten row, not a stale fetch.
        let deleted = repo
            .delete_returning(b.id.0)
            .expect("delete")
            .expect("row existed");
        match deleted.target {
            BackendTarget::Managed {
                ref root, ref kind, ..
            } => {
                assert_eq!(root, "/srv/b");
                assert_eq!(kind, "procfile");
            }
            ref other => panic!("unexpected target: {other:?}"),
        }
        assert!(repo.get_by_id(b.id.0).expect("get").is_none());
        // Missing row → None, nothing deleted.
        assert!(repo
            .delete_returning(b.id.0)
            .expect("second delete")
            .is_none());
    }

    #[test]
    fn migrate_v1_domain_unique_schema_preserves_modern_columns() {
        let conn = Connection::open_in_memory().expect("open sqlite");
        // The actual v1 schema: `domain UNIQUE`, host/port target columns,
        // none of the later additive columns.
        conn.execute_batch(
            r#"
            CREATE TABLE apps (
              id INTEGER PRIMARY KEY,
              name TEXT NOT NULL UNIQUE,
              kind TEXT NOT NULL,
              domain TEXT NOT NULL UNIQUE,
              target_host TEXT,
              target_port INTEGER,
              enabled INTEGER NOT NULL,
              scan_managed INTEGER NOT NULL DEFAULT 0,
              scan_source TEXT,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL
            );
            INSERT INTO apps (id, name, kind, domain, target_host, target_port, enabled, created_at, updated_at)
            VALUES (3, 'v1app', 'static', 'v1app', '127.0.0.1', 5006, 1, 0, 0);
            "#,
        )
        .expect("v1 schema");
        let repo = AppRepository {
            conn: Mutex::new(conn),
            read_conn: None,
            domain_suffix: "coulson.local".to_string(),
            change_tx: None,
        };
        // The v1 rebuild must run before the additive-column migrations, or
        // it silently drops every modern column from the rebuilt table.
        repo.init_schema().expect("migrate");

        // Full COLS read works (would fail with `no such column` if the
        // rebuild truncated the schema) and the row content survived.
        let app = repo.get_by_id(3).expect("get").expect("row preserved");
        assert_eq!(app.name, "v1app");
        assert_eq!(app.domain.0, "v1app.coulson.local");
        assert!(app.hooks.is_none());

        // Modern columns are writable — hooks persistence works end to end.
        let domain = DomainName("hooked.coulson.local".to_string());
        let hooks = crate::hooks::AppHooksConfig {
            skip_global: true,
            app_add: None,
            app_remove: None,
            app_start: None,
            app_ready: None,
            app_stop: None,
            app_idle: None,
            tunnel_start: None,
            tunnel_stop: None,
        };
        let (created, _) = repo
            .upsert_scanned_managed(
                "hooked",
                &domain,
                "/srv/hooked",
                "asgi",
                true,
                "fs",
                "e",
                Some(&hooks),
            )
            .expect("upsert on migrated schema");
        let read = repo.get_by_id(created.id.0).expect("get").expect("row");
        assert!(read.hooks.is_some_and(|h| h.skip_global));
    }

    #[test]
    fn migrate_apps_id_autoincrement_rebuilds_and_preserves_rows() {
        let conn = Connection::open_in_memory().expect("open sqlite");
        // Simulate a pre-AUTOINCREMENT database with the route-unique schema.
        conn.execute_batch(
            r#"
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
            INSERT INTO apps (id, name, kind, domain, enabled, created_at, updated_at)
            VALUES (7, 'legacy', 'asgi', 'legacy', 1, 0, 0);
            "#,
        )
        .expect("legacy schema");
        let repo = AppRepository {
            conn: Mutex::new(conn),
            read_conn: None,
            domain_suffix: "coulson.local".to_string(),
            change_tx: None,
        };
        repo.init_schema().expect("migrate");

        let conn = repo.conn.lock();
        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'apps'",
                [],
                |row| row.get(0),
            )
            .expect("table sql");
        assert!(sql.contains("AUTOINCREMENT"), "apps not rebuilt: {sql}");
        let (id, name): (i64, String) = conn
            .query_row("SELECT id, name FROM apps", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .expect("row preserved");
        assert_eq!((id, name.as_str()), (7, "legacy"));
        // The sequence continues above the migrated max id.
        conn.execute(
            "INSERT INTO apps (name, kind, domain, enabled, created_at, updated_at)
             VALUES ('next', 'asgi', 'next', 1, 0, 0)",
            [],
        )
        .expect("insert after migration");
        let next_id: i64 = conn
            .query_row("SELECT id FROM apps WHERE name = 'next'", [], |r| r.get(0))
            .expect("next id");
        assert!(next_id > 7);
    }

    #[test]
    fn settings_crud() {
        let repo = AppRepository {
            conn: Mutex::new(Connection::open_in_memory().expect("open sqlite")),
            read_conn: None,
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
            read_conn: None,
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
