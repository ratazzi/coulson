use std::collections::HashSet;
use std::path::Path;

use anyhow::Context;
use parking_lot::Mutex;
use rusqlite::{params, params_from_iter, types::Value, Connection, OptionalExtension};
use thiserror::Error;
use time::OffsetDateTime;

use crate::domain::{AppId, AppKind, AppSpec, BackendTarget, DomainName};

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
              domain TEXT NOT NULL,
              path_prefix TEXT NOT NULL DEFAULT '',
              target_host TEXT NOT NULL,
              target_port INTEGER NOT NULL,
              timeout_ms INTEGER,
              enabled INTEGER NOT NULL,
              scan_managed INTEGER NOT NULL DEFAULT 0,
              scan_source TEXT,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              UNIQUE(domain, path_prefix)
            );

            CREATE INDEX IF NOT EXISTS idx_apps_enabled_domain
            ON apps(enabled, domain);
            "#,
        )?;
        add_column_if_missing(
            &conn,
            "ALTER TABLE apps ADD COLUMN scan_managed INTEGER NOT NULL DEFAULT 0",
        )?;
        add_column_if_missing(&conn, "ALTER TABLE apps ADD COLUMN scan_source TEXT")?;
        add_column_if_missing(
            &conn,
            "ALTER TABLE apps ADD COLUMN path_prefix TEXT NOT NULL DEFAULT ''",
        )?;
        add_column_if_missing(&conn, "ALTER TABLE apps ADD COLUMN timeout_ms INTEGER")?;
        add_column_if_missing(
            &conn,
            "ALTER TABLE apps ADD COLUMN cors_enabled INTEGER NOT NULL DEFAULT 0",
        )?;
        add_column_if_missing(&conn, "ALTER TABLE apps ADD COLUMN basic_auth_user TEXT")?;
        add_column_if_missing(&conn, "ALTER TABLE apps ADD COLUMN basic_auth_pass TEXT")?;
        add_column_if_missing(
            &conn,
            "ALTER TABLE apps ADD COLUMN spa_rewrite INTEGER NOT NULL DEFAULT 0",
        )?;
        add_column_if_missing(&conn, "ALTER TABLE apps ADD COLUMN static_root TEXT")?;
        add_column_if_missing(&conn, "ALTER TABLE apps ADD COLUMN socket_path TEXT")?;
        migrate_apps_domain_unique_to_route_unique(&conn)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_static(
        &self,
        name: &str,
        domain: &DomainName,
        path_prefix: Option<&str>,
        target_host: &str,
        target_port: u16,
        timeout_ms: Option<u64>,
        cors_enabled: bool,
        basic_auth_user: Option<&str>,
        basic_auth_pass: Option<&str>,
        spa_rewrite: bool,
    ) -> anyhow::Result<AppSpec> {
        let now = OffsetDateTime::now_utc();
        let path_prefix_db = path_prefix_to_db(path_prefix);
        let app = AppSpec {
            id: AppId::new(),
            name: name.to_string(),
            kind: AppKind::Static,
            domain: domain.clone(),
            path_prefix: path_prefix.map(ToOwned::to_owned),
            target: BackendTarget::Tcp {
                host: target_host.to_string(),
                port: target_port,
            },
            timeout_ms,
            cors_enabled,
            basic_auth_user: basic_auth_user.map(ToOwned::to_owned),
            basic_auth_pass: basic_auth_pass.map(ToOwned::to_owned),
            spa_rewrite,
            enabled: true,
            created_at: now,
            updated_at: now,
        };

        let conn = self.conn.lock();
        let result = conn.execute(
            "INSERT INTO apps (id, name, kind, domain, path_prefix, target_host, target_port, timeout_ms, enabled, scan_managed, scan_source, created_at, updated_at, cors_enabled, basic_auth_user, basic_auth_pass, spa_rewrite)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, NULL, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                app.id.0,
                app.name,
                "static",
                app.domain.0,
                path_prefix_db,
                target_host,
                i64::from(target_port),
                app.timeout_ms.map(|v| v as i64),
                if app.enabled { 1 } else { 0 },
                app.created_at.unix_timestamp(),
                app.updated_at.unix_timestamp(),
                if cors_enabled { 1 } else { 0 },
                basic_auth_user,
                basic_auth_pass,
                if spa_rewrite { 1 } else { 0 },
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

    pub fn insert_static_dir(
        &self,
        name: &str,
        domain: &DomainName,
        static_root: &str,
    ) -> anyhow::Result<AppSpec> {
        let now = OffsetDateTime::now_utc();
        let app = AppSpec {
            id: AppId::new(),
            name: name.to_string(),
            kind: AppKind::Static,
            domain: domain.clone(),
            path_prefix: None,
            target: BackendTarget::StaticDir {
                root: static_root.to_string(),
            },
            timeout_ms: None,
            cors_enabled: false,
            basic_auth_user: None,
            basic_auth_pass: None,
            spa_rewrite: false,
            enabled: true,
            created_at: now,
            updated_at: now,
        };

        let conn = self.conn.lock();
        let result = conn.execute(
            "INSERT INTO apps (id, name, kind, domain, path_prefix, target_host, target_port, timeout_ms, enabled, scan_managed, scan_source, created_at, updated_at, cors_enabled, basic_auth_user, basic_auth_pass, spa_rewrite, static_root)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, 0, NULL, ?9, ?10, 0, NULL, NULL, 0, ?11)",
            params![
                app.id.0,
                app.name,
                "static",
                app.domain.0,
                "",
                "",
                0i64,
                1i64,
                app.created_at.unix_timestamp(),
                app.updated_at.unix_timestamp(),
                static_root,
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

    pub fn insert_unix_socket(
        &self,
        name: &str,
        domain: &DomainName,
        path_prefix: Option<&str>,
        socket_path: &str,
        timeout_ms: Option<u64>,
    ) -> anyhow::Result<AppSpec> {
        let now = OffsetDateTime::now_utc();
        let path_prefix_db = path_prefix_to_db(path_prefix);
        let app = AppSpec {
            id: AppId::new(),
            name: name.to_string(),
            kind: AppKind::Static,
            domain: domain.clone(),
            path_prefix: path_prefix.map(ToOwned::to_owned),
            target: BackendTarget::UnixSocket {
                path: socket_path.to_string(),
            },
            timeout_ms,
            cors_enabled: false,
            basic_auth_user: None,
            basic_auth_pass: None,
            spa_rewrite: false,
            enabled: true,
            created_at: now,
            updated_at: now,
        };

        let conn = self.conn.lock();
        let result = conn.execute(
            "INSERT INTO apps (id, name, kind, domain, path_prefix, target_host, target_port, timeout_ms, enabled, scan_managed, scan_source, created_at, updated_at, cors_enabled, basic_auth_user, basic_auth_pass, spa_rewrite, socket_path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, NULL, ?10, ?11, 0, NULL, NULL, 0, ?12)",
            params![
                app.id.0,
                app.name,
                "static",
                app.domain.0,
                path_prefix_db,
                "",
                0i64,
                app.timeout_ms.map(|v| v as i64),
                1i64,
                app.created_at.unix_timestamp(),
                app.updated_at.unix_timestamp(),
                socket_path,
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

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_static(
        &self,
        name: &str,
        domain: &DomainName,
        path_prefix: Option<&str>,
        target_host: &str,
        target_port: u16,
        timeout_ms: Option<u64>,
        cors_enabled: bool,
        basic_auth_user: Option<&str>,
        basic_auth_pass: Option<&str>,
        spa_rewrite: bool,
        enabled: bool,
    ) -> anyhow::Result<AppSpec> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let conn = self.conn.lock();
        let path_prefix_db = path_prefix_to_db(path_prefix);

        let existing_id: Option<String> = conn
            .query_row(
                "SELECT id FROM apps WHERE domain = ?1 AND path_prefix = ?2",
                params![domain.0, path_prefix_db],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(id) = existing_id {
            conn.execute(
                "UPDATE apps SET name = ?1, path_prefix = ?2, target_host = ?3, target_port = ?4, timeout_ms = ?5, enabled = ?6, updated_at = ?7, scan_managed = 0, scan_source = NULL, cors_enabled = ?8, basic_auth_user = ?9, basic_auth_pass = ?10, spa_rewrite = ?11 WHERE id = ?12",
                params![
                    name,
                    path_prefix_db,
                    target_host,
                    i64::from(target_port),
                    timeout_ms.map(|v| v as i64),
                    if enabled { 1 } else { 0 },
                    now,
                    if cors_enabled { 1 } else { 0 },
                    basic_auth_user,
                    basic_auth_pass,
                    if spa_rewrite { 1 } else { 0 },
                    id
                ],
            )?;
        } else {
            let created = AppId::new().0;
            conn.execute(
                "INSERT INTO apps (id, name, kind, domain, path_prefix, target_host, target_port, timeout_ms, enabled, scan_managed, scan_source, created_at, updated_at, cors_enabled, basic_auth_user, basic_auth_pass, spa_rewrite)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, NULL, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    created,
                    name,
                    "static",
                    domain.0,
                    path_prefix_db,
                    target_host,
                    i64::from(target_port),
                    timeout_ms.map(|v| v as i64),
                    if enabled { 1 } else { 0 },
                    now,
                    now,
                    if cors_enabled { 1 } else { 0 },
                    basic_auth_user,
                    basic_auth_pass,
                    if spa_rewrite { 1 } else { 0 },
                ],
            )?;
        }

        let app = Self::read_app_by_route(&conn, &domain.0, &path_prefix_db)?;
        Ok(app)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_scanned_static(
        &self,
        name: &str,
        domain: &DomainName,
        path_prefix: Option<&str>,
        target_host: &str,
        target_port: u16,
        socket_path: Option<&str>,
        timeout_ms: Option<u64>,
        cors_enabled: bool,
        basic_auth_user: Option<&str>,
        basic_auth_pass: Option<&str>,
        spa_rewrite: bool,
        enabled: bool,
        source: &str,
    ) -> anyhow::Result<(AppSpec, ScanUpsertResult)> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let conn = self.conn.lock();
        let path_prefix_db = path_prefix_to_db(path_prefix);

        let existing: Option<(String, i64)> = conn
            .query_row(
                "SELECT id, scan_managed FROM apps WHERE domain = ?1 AND path_prefix = ?2",
                params![domain.0, path_prefix_db],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let op = match existing {
            Some((_id, 0)) => ScanUpsertResult::SkippedManual,
            Some((id, _)) => {
                conn.execute(
                    "UPDATE apps SET name = ?1, path_prefix = ?2, target_host = ?3, target_port = ?4, timeout_ms = ?5, enabled = ?6, updated_at = ?7, scan_managed = 1, scan_source = ?8, cors_enabled = ?9, basic_auth_user = ?10, basic_auth_pass = ?11, spa_rewrite = ?12, socket_path = ?13 WHERE id = ?14",
                    params![
                        name,
                        path_prefix_db,
                        target_host,
                        i64::from(target_port),
                        timeout_ms.map(|v| v as i64),
                        if enabled { 1 } else { 0 },
                        now,
                        source,
                        if cors_enabled { 1 } else { 0 },
                        basic_auth_user,
                        basic_auth_pass,
                        if spa_rewrite { 1 } else { 0 },
                        socket_path,
                        id
                    ],
                )?;
                ScanUpsertResult::Updated
            }
            None => {
                let created = AppId::new().0;
                conn.execute(
                    "INSERT INTO apps (id, name, kind, domain, path_prefix, target_host, target_port, timeout_ms, enabled, scan_managed, scan_source, created_at, updated_at, cors_enabled, basic_auth_user, basic_auth_pass, spa_rewrite, socket_path)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                    params![
                        created,
                        name,
                        "static",
                        domain.0,
                        path_prefix_db,
                        target_host,
                        i64::from(target_port),
                        timeout_ms.map(|v| v as i64),
                        if enabled { 1 } else { 0 },
                        source,
                        now,
                        now,
                        if cors_enabled { 1 } else { 0 },
                        basic_auth_user,
                        basic_auth_pass,
                        if spa_rewrite { 1 } else { 0 },
                        socket_path,
                    ],
                )?;
                ScanUpsertResult::Inserted
            }
        };

        let app = Self::read_app_by_route(&conn, &domain.0, &path_prefix_db)?;
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
        let mut delete_ids: Vec<String> = Vec::new();

        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let domain: String = row.get(1)?;
            let path_prefix: String = row.get(2)?;
            let key = route_key(&domain, &path_prefix);
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

    pub fn list_filtered(
        &self,
        managed: Option<bool>,
        domain: Option<&str>,
    ) -> anyhow::Result<Vec<AppSpec>> {
        let conn = self.conn.lock();
        Self::query_apps_filtered(&conn, managed, domain)
    }

    pub fn list_enabled(&self) -> anyhow::Result<Vec<AppSpec>> {
        let conn = self.conn.lock();
        Self::query_apps(&conn, true)
    }

    pub fn update_settings(
        &self,
        app_id: &str,
        cors_enabled: Option<bool>,
        basic_auth_user: Option<Option<&str>>,
        basic_auth_pass: Option<Option<&str>>,
        spa_rewrite: Option<bool>,
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

        let sql = format!(
            "UPDATE apps SET {} WHERE id = ?{idx}",
            sets.join(", ")
        );
        values.push(Box::new(app_id.to_string()));

        let params: Vec<&dyn rusqlite::ToSql> = values.iter().map(|v| v.as_ref()).collect();
        let changed = conn.execute(&sql, params.as_slice())?;
        Ok(changed > 0)
    }

    fn read_app_by_route(conn: &Connection, domain: &str, path_prefix_db: &str) -> anyhow::Result<AppSpec> {
        let app = conn.query_row(
            &format!("SELECT {} FROM apps WHERE domain = ?1 AND path_prefix = ?2", COLS),
            params![domain, path_prefix_db],
            row_to_app,
        )?;
        Ok(app)
    }

    fn query_apps(conn: &Connection, enabled_only: bool) -> anyhow::Result<Vec<AppSpec>> {
        let sql = if enabled_only {
            format!("SELECT {} FROM apps WHERE enabled = 1 ORDER BY domain ASC, LENGTH(path_prefix) DESC", COLS)
        } else {
            format!("SELECT {} FROM apps ORDER BY domain ASC, LENGTH(path_prefix) DESC", COLS)
        };

        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        Self::collect_rows(&mut rows)
    }

    fn query_apps_filtered(
        conn: &Connection,
        managed: Option<bool>,
        domain: Option<&str>,
    ) -> anyhow::Result<Vec<AppSpec>> {
        let mut sql = format!("SELECT {} FROM apps", COLS);
        let mut clauses: Vec<&str> = Vec::new();
        let mut values: Vec<Value> = Vec::new();

        if let Some(flag) = managed {
            clauses.push("scan_managed = ?");
            values.push(Value::Integer(if flag { 1 } else { 0 }));
        }
        if let Some(domain) = domain {
            clauses.push("domain = ?");
            values.push(Value::Text(domain.to_string()));
        }
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(" ORDER BY domain ASC, LENGTH(path_prefix) DESC");

        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query(params_from_iter(values.iter()))?;
        Self::collect_rows(&mut rows)
    }

    fn collect_rows(rows: &mut rusqlite::Rows<'_>) -> anyhow::Result<Vec<AppSpec>> {
        let mut apps = Vec::new();
        while let Some(row) = rows.next()? {
            apps.push(row_to_app(row)?);
        }
        Ok(apps)
    }
}

const COLS: &str = "id,name,kind,domain,path_prefix,target_host,target_port,timeout_ms,enabled,created_at,updated_at,cors_enabled,basic_auth_user,basic_auth_pass,spa_rewrite,static_root,socket_path";

fn row_to_app(row: &rusqlite::Row<'_>) -> rusqlite::Result<AppSpec> {
    let kind: String = row.get(2)?;
    let kind = match kind.as_str() {
        "static" => AppKind::Static,
        "rack" => AppKind::Rack,
        "asgi" => AppKind::Asgi,
        "container" => AppKind::Container,
        _ => AppKind::Static,
    };

    let created_ts: i64 = row.get(9)?;
    let updated_ts: i64 = row.get(10)?;
    let static_root: Option<String> = row.get::<_, Option<String>>(15).unwrap_or(None);
    let socket_path: Option<String> = row.get::<_, Option<String>>(16).unwrap_or(None);

    let target = if let Some(root) = static_root {
        BackendTarget::StaticDir { root }
    } else if let Some(path) = socket_path {
        BackendTarget::UnixSocket { path }
    } else {
        BackendTarget::Tcp {
            host: row.get(5)?,
            port: row.get::<_, i64>(6)? as u16,
        }
    };

    Ok(AppSpec {
        id: AppId(row.get(0)?),
        name: row.get(1)?,
        kind,
        domain: DomainName(row.get(3)?),
        path_prefix: path_prefix_from_db(row.get::<_, String>(4)?),
        target,
        timeout_ms: row.get::<_, Option<i64>>(7)?.map(|v| v as u64),
        enabled: row.get::<_, i64>(8)? == 1,
        created_at: OffsetDateTime::from_unix_timestamp(created_ts)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        updated_at: OffsetDateTime::from_unix_timestamp(updated_ts)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        cors_enabled: row.get::<_, i64>(11).unwrap_or(0) == 1,
        basic_auth_user: row.get::<_, Option<String>>(12).unwrap_or(None),
        basic_auth_pass: row.get::<_, Option<String>>(13).unwrap_or(None),
        spa_rewrite: row.get::<_, i64>(14).unwrap_or(0) == 1,
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
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          kind TEXT NOT NULL,
          domain TEXT NOT NULL,
          path_prefix TEXT NOT NULL DEFAULT '',
          target_host TEXT NOT NULL,
          target_port INTEGER NOT NULL,
          timeout_ms INTEGER,
          enabled INTEGER NOT NULL,
          scan_managed INTEGER NOT NULL DEFAULT 0,
          scan_source TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          UNIQUE(domain, path_prefix)
        );
        INSERT INTO apps (
          id, name, kind, domain, path_prefix, target_host, target_port, timeout_ms,
          enabled, scan_managed, scan_source, created_at, updated_at
        )
        SELECT
          id, name, kind, domain, '', target_host, target_port, NULL,
          enabled, scan_managed, scan_source, created_at, updated_at
        FROM apps_old;
        DROP TABLE apps_old;
        CREATE INDEX IF NOT EXISTS idx_apps_enabled_domain ON apps(enabled, domain);
        COMMIT;
        "#,
    )?;

    Ok(())
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

        repo.insert_static("myapp", &domain, None, "127.0.0.1", 9001, None, false, None, None, false)
            .expect("insert");
        let apps = repo.list_enabled().expect("list");
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].domain.0, "myapp.test");
    }
}
