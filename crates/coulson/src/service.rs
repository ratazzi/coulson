use thiserror::Error;

use crate::credentials;
use crate::domain::{AppSpec, DomainName, TunnelMode};
use crate::hooks::{HookContext, HookEvent};
use crate::runtime;
use crate::runtime::ScanWarningsFile;
use crate::scanner::{self, ScanStats};
use crate::store::{StaticAppInput, StoreError};
use crate::tunnel;
use crate::SharedState;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("not found")]
    NotFound,
    #[error("domain conflict")]
    DomainConflict,
    #[error("detection failed: {0}")]
    DetectionFailed(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<anyhow::Error> for ServiceError {
    fn from(err: anyhow::Error) -> Self {
        if let Some(StoreError::DomainConflict) = err.downcast_ref::<StoreError>() {
            return ServiceError::DomainConflict;
        }
        ServiceError::Internal(err.to_string())
    }
}

// -- Basic CRUD --

pub fn app_list(state: &SharedState) -> Result<Vec<AppSpec>, ServiceError> {
    state.store.list_all().map_err(ServiceError::from)
}

pub fn app_status(
    state: &SharedState,
    name: Option<&str>,
) -> Result<Vec<crate::app_status::AppStatus>, ServiceError> {
    let apps = app_list(state)?;
    let mut statuses: Vec<_> = apps
        .iter()
        .filter(|app| name.is_none_or(|n| app.name == n || app.domain.0 == n))
        .map(|app| state.app_statuses.snapshot(app))
        .collect();
    if name.is_some() && statuses.is_empty() {
        return Err(ServiceError::NotFound);
    }
    statuses.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(statuses)
}

pub fn app_get_by_name(state: &SharedState, name: &str) -> Result<AppSpec, ServiceError> {
    match state.store.get_by_name(name) {
        Ok(Some(app)) => Ok(app),
        Ok(None) => Err(ServiceError::NotFound),
        Err(e) => Err(ServiceError::Internal(e.to_string())),
    }
}

pub fn app_get_by_id(state: &SharedState, app_id: i64) -> Result<AppSpec, ServiceError> {
    match state.store.get_by_id(app_id) {
        Ok(Some(app)) => Ok(app),
        Ok(None) => Err(ServiceError::NotFound),
        Err(e) => Err(ServiceError::Internal(e.to_string())),
    }
}

pub async fn app_delete(state: &SharedState, app_id: i64) -> Result<(), ServiceError> {
    // Row fetch+delete and process kill form one critical section under the
    // PM lock, serializing deletion against the start paths (which validate
    // the store row under the same lock before committing to a spawn): a
    // start either completes fully before the delete — its group is killed
    // here — or it revalidates after the row is gone and is refused. Nothing
    // is mutated before the delete, so failures need no rollback.
    let app;
    let stopped;
    {
        let mut pm = state.process_manager.lock().await;
        // Row delete and fs-entry removal commit as one write transaction:
        // that pair is what a scan's in-transaction revalidation checks, so
        // removing them non-atomically would let a stale discovery resurrect
        // the app between the two steps. No awaits while the txn is alive.
        {
            let txn = match state.store.begin_write() {
                Ok(txn) => txn,
                Err(e) => return Err(ServiceError::Internal(e.to_string())),
            };
            // `delete_returning` snapshots and deletes in one statement — the
            // scanner can rewrite the row in place, so cleanup and the
            // AppRemove context must describe the row actually removed.
            app = match txn.delete_returning(app_id) {
                Ok(Some(app)) => app,
                Ok(None) => return Err(ServiceError::NotFound),
                Err(e) => return Err(ServiceError::Internal(e.to_string())),
            };
            // A Refused removal (directory, or fs error) aborts the delete:
            // committing would leave the entry in place and the next scan
            // would recreate the app — a success response that lies. The txn
            // rolls back on drop, so nothing has changed. If the commit
            // itself fails after a successful removal, the row rolls back
            // while the entry is gone — the next scan prunes that row, so
            // the state converges to deleted either way.
            if let Some(ref fs_entry) = app.fs_entry {
                if scanner::remove_app_fs_entry(&state.apps_root, fs_entry)
                    == scanner::FsEntryRemoval::Refused
                {
                    return Err(ServiceError::Internal(format!(
                        "apps_root entry '{fs_entry}' was not removed (directory or fs error); \
                         a scan would recreate the app — remove the entry manually and retry"
                    )));
                }
            }
            if let Err(e) = txn.commit() {
                return Err(ServiceError::Internal(e.to_string()));
            }
        }
        // The row is gone and ids are AUTOINCREMENT (never reused), so any
        // group tracked under this id — whichever generation of the row
        // started it, even one from before a managed→static rewrite — is
        // stale: kill unconditionally (a no-op when no group exists). Quiet
        // variant: the post-delete store lookup inside the normal AppStop
        // path would miss the row and drop its route/tunnel fields, so the
        // stop event is built below from the deleted snapshot instead, and
        // sequenced before AppRemove.
        stopped = pm.kill_process_quiet(app_id).await;
    }
    let factory = state.hook_factory();
    // AppStop belongs to the generation that actually ran: context AND hooks
    // come from the stopped group's spawn-time snapshot (the scanner can
    // rewrite a row in place while an older generation is still running).
    // AppRemove intentionally describes the deleted row — the generation the
    // user removed.
    let (stop_ctx, stop_hooks) = match stopped {
        Some(s) => (
            Some(factory.context_for_process(
                HookEvent::AppStop,
                app_id,
                &s.name,
                &s.root,
                &s.kind,
                Some(&s.app_snapshot),
            )),
            s.app_snapshot.hooks,
        ),
        None => (None, None),
    };
    let remove_ctx = factory.context_for_app(HookEvent::AppRemove, &app);
    let remove_hooks = app.hooks.clone();

    // Dispatch before the fallible route reload: the deletion is already
    // committed, and these snapshots are the only source for its lifecycle
    // events — an early return must not drop them. One task, sequential
    // awaits: AppStop strictly precedes AppRemove.
    let hm = state.hook_manager.clone();
    tokio::spawn(async move {
        if let Some(ctx) = stop_ctx {
            hm.fire_with_hooks(&ctx, stop_hooks.as_ref()).await;
        }
        hm.fire_with_hooks(&remove_ctx, remove_hooks.as_ref()).await;
    });
    state
        .reload_routes()
        .map_err(|e| ServiceError::Internal(e.to_string()))?;
    Ok(())
}

pub fn app_set_enabled(
    state: &SharedState,
    app_id: i64,
    enabled: bool,
) -> Result<(), ServiceError> {
    match state.store.set_enabled(app_id, enabled) {
        Ok(true) => {
            state
                .reload_routes()
                .map_err(|e| ServiceError::Internal(e.to_string()))?;
            Ok(())
        }
        Ok(false) => Err(ServiceError::NotFound),
        Err(e) => Err(ServiceError::Internal(e.to_string())),
    }
}

/// Fire `app_add` hooks for newly discovered apps. Call after `reload_routes()`.
pub fn fire_app_add_hooks(state: &SharedState, added_apps: &[crate::domain::AppSpec]) {
    for app in added_apps {
        let ctx = state.hook_factory().context_for_app(HookEvent::AppAdd, app);
        let hooks = app.hooks.clone();
        let hm = state.hook_manager.clone();
        tokio::spawn(async move { hm.fire_with_hooks(&ctx, hooks.as_ref()).await });
    }
}

/// Stop processes belonging to scan-pruned rows and fire their `app_stop`
/// hooks. The event is built entirely from the stopped group's spawn-time
/// snapshot — the generation that actually ran — so an in-place row rewrite
/// between spawn and prune cannot substitute another generation's context or
/// hooks. Without this teardown, the reaper's reconcile would stop the
/// process a tick later.
pub async fn teardown_pruned_apps(state: &SharedState, pruned_apps: &[crate::domain::AppSpec]) {
    for app in pruned_apps {
        let killed = {
            let mut pm = state.process_manager.lock().await;
            pm.kill_process_quiet(app.id.0).await
        };
        let Some(stopped) = killed else {
            continue;
        };
        let ctx = state.hook_factory().context_for_process(
            HookEvent::AppStop,
            app.id.0,
            &stopped.name,
            &stopped.root,
            &stopped.kind,
            Some(&stopped.app_snapshot),
        );
        let hooks = stopped.app_snapshot.hooks;
        let hm = state.hook_manager.clone();
        tokio::spawn(async move {
            hm.fire_with_hooks(&ctx, hooks.as_ref()).await;
        });
    }
}

pub async fn apps_scan(state: &SharedState) -> Result<ScanStats, ServiceError> {
    let result =
        scanner::sync_from_apps_root(state).map_err(|e| ServiceError::Internal(e.to_string()))?;
    // Consume the teardown snapshots first: the rows and hook registrations
    // are already gone, so no fallible step (warnings write, route reload)
    // may run before this or an early return would drop them.
    teardown_pruned_apps(state, &result.pruned_apps).await;
    runtime::write_scan_warnings(&state.scan_warnings_path, &result.stats)
        .map_err(|e| ServiceError::Internal(e.to_string()))?;
    state
        .reload_routes()
        .map_err(|e| ServiceError::Internal(e.to_string()))?;

    fire_app_add_hooks(state, &result.added_apps);

    let ctx = HookContext {
        event: HookEvent::ScanComplete,
        app_id: None,
        app_name: None,
        app_domain: None,
        app_root: None,
        app_urls: Vec::new(),
        app_kind: None,
        tunnel_url: None,
    };
    let hm = state.hook_manager.clone();
    tokio::spawn(async move { hm.fire(&ctx).await });

    Ok(result.stats)
}

pub fn apps_warnings(state: &SharedState) -> Result<Option<ScanWarningsFile>, ServiceError> {
    runtime::read_scan_warnings(&state.scan_warnings_path)
        .map_err(|e| ServiceError::Internal(e.to_string()))
}

// -- Settings Update --

pub struct UpdateSettingsParams {
    pub cors_enabled: Option<bool>,
    pub force_https: Option<bool>,
    pub basic_auth_user: Option<Option<String>>,
    pub basic_auth_pass: Option<Option<String>>,
    pub spa_rewrite: Option<bool>,
    pub listen_port: Option<Option<u16>>,
    pub timeout_ms: Option<Option<u64>>,
    pub lan_access: Option<bool>,
    pub cname: Option<Option<String>>,
}

pub fn app_update_settings(
    state: &SharedState,
    app_id: i64,
    params: &UpdateSettingsParams,
) -> Result<(), ServiceError> {
    // Normalize and validate cname before passing to store
    let cname_normalized = match &params.cname {
        Some(Some(raw)) => {
            let normalized = normalize_cname(raw)?;
            if normalized.is_empty() {
                Some(None) // treat empty/whitespace-only as clear
            } else {
                validate_cname_unique(state, app_id, &normalized)?;
                Some(Some(normalized))
            }
        }
        Some(None) => Some(None), // explicit clear
        None => None,             // not provided
    };
    match state.store.update_settings(
        app_id,
        params.cors_enabled,
        params.force_https,
        params.basic_auth_user.as_ref().map(|v| v.as_deref()),
        params.basic_auth_pass.as_ref().map(|v| v.as_deref()),
        params.spa_rewrite,
        params.listen_port,
        params.timeout_ms,
        params.lan_access,
        cname_normalized.as_ref().map(|v| v.as_deref()),
    ) {
        Ok(true) => {
            state
                .reload_routes()
                .map_err(|e| ServiceError::Internal(e.to_string()))?;
            Ok(())
        }
        Ok(false) => Err(ServiceError::NotFound),
        Err(e) => Err(ServiceError::Internal(e.to_string())),
    }
}

// -- Create --

#[derive(Debug, serde::Deserialize)]
pub struct CreateAppParams {
    pub name: String,
    pub domain: String,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default = "default_target_type")]
    pub target_type: String,
    #[serde(default)]
    pub target_value: String,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub cors_enabled: bool,
    #[serde(default)]
    pub force_https: bool,
    #[serde(default)]
    pub basic_auth_user: Option<String>,
    #[serde(default)]
    pub basic_auth_pass: Option<String>,
    #[serde(default)]
    pub spa_rewrite: bool,
    #[serde(default)]
    pub listen_port: Option<u16>,
}

fn default_target_type() -> String {
    "tcp".to_string()
}

pub fn app_create(state: &SharedState, params: &CreateAppParams) -> Result<AppSpec, ServiceError> {
    if params.name.trim().is_empty() {
        return Err(ServiceError::InvalidParams(
            "name cannot be empty".to_string(),
        ));
    }
    if !params
        .name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(ServiceError::InvalidParams(
            "name must contain only alphanumeric characters, hyphens, underscores, or dots"
                .to_string(),
        ));
    }
    if params.target_value.is_empty() {
        return Err(ServiceError::InvalidParams(
            "target_value cannot be empty".to_string(),
        ));
    }

    let domain = DomainName::parse(&params.domain, &state.domain_suffix)
        .map_err(|e| ServiceError::InvalidParams(e.to_string()))?;

    if matches!(params.timeout_ms, Some(0)) {
        return Err(ServiceError::InvalidParams(
            "timeout_ms must be > 0".to_string(),
        ));
    }

    if let Some(port) = params.listen_port {
        if port == 0 {
            return Err(ServiceError::InvalidParams(
                "listen_port must be > 0".to_string(),
            ));
        }
    }

    // Type-specific validation
    match params.target_type.as_str() {
        "tcp" => {
            let (_, port_str) = params.target_value.rsplit_once(':').unwrap_or(("", ""));
            match port_str.parse::<u16>() {
                Ok(p) if p > 0 => {}
                _ => {
                    return Err(ServiceError::InvalidParams(format!(
                        "tcp target_value must be host:port (port > 0), got: {}",
                        params.target_value
                    )));
                }
            }
        }
        "static_dir" => {
            let root = std::path::Path::new(&params.target_value);
            if !root.is_dir() {
                return Err(ServiceError::InvalidParams(format!(
                    "static_dir target is not a directory: {}",
                    params.target_value
                )));
            }
        }
        "unix_socket" => {
            let sock = std::path::Path::new(&params.target_value);
            if !sock.exists() {
                return Err(ServiceError::InvalidParams(format!(
                    "unix_socket target does not exist: {}",
                    params.target_value
                )));
            }
        }
        other => {
            return Err(ServiceError::InvalidParams(format!(
                "unknown target_type: {other}, must be tcp/static_dir/unix_socket"
            )));
        }
    }

    let path_prefix = normalize_path_prefix(params.path_prefix.as_deref())
        .map_err(ServiceError::InvalidParams)?;

    let app = state
        .store
        .insert_static(&StaticAppInput {
            name: &params.name,
            domain: &domain,
            path_prefix: path_prefix.as_deref(),
            target_type: &params.target_type,
            target_value: &params.target_value,
            timeout_ms: params.timeout_ms,
            cors_enabled: params.cors_enabled,
            force_https: params.force_https,
            basic_auth_user: params.basic_auth_user.as_deref(),
            basic_auth_pass: params.basic_auth_pass.as_deref(),
            spa_rewrite: params.spa_rewrite,
            listen_port: params.listen_port,
        })
        .map_err(ServiceError::from)?;

    state
        .reload_routes()
        .map_err(|e| ServiceError::Internal(e.to_string()))?;

    let ctx = state
        .hook_factory()
        .context_for_app(HookEvent::AppAdd, &app);
    let hm = state.hook_manager.clone();
    tokio::spawn(async move { hm.fire(&ctx).await });

    Ok(app)
}

pub fn app_create_from_folder(state: &SharedState, path: &str) -> Result<AppSpec, ServiceError> {
    let folder = std::path::Path::new(path);
    if !folder.is_dir() {
        return Err(ServiceError::InvalidParams(format!(
            "path is not a directory: {path}"
        )));
    }

    let folder_name = folder.file_name().and_then(|n| n.to_str()).unwrap_or("app");
    let name = scanner::sanitize_name(folder_name);
    let domain_str = format!("{}.{}", name, state.domain_suffix);
    let domain = DomainName::parse(&domain_str, &state.domain_suffix)
        .map_err(|e| ServiceError::InvalidParams(e.to_string()))?;

    let insert_and_reload = |result: anyhow::Result<AppSpec>| -> Result<AppSpec, ServiceError> {
        let app = result.map_err(ServiceError::from)?;
        state
            .reload_routes()
            .map_err(|e| ServiceError::Internal(e.to_string()))?;
        Ok(app)
    };

    let insert_tcp = |target_value: &str| -> Result<AppSpec, ServiceError> {
        let input = StaticAppInput {
            name: &name,
            domain: &domain,
            path_prefix: None,
            target_type: "tcp",
            target_value,
            timeout_ms: None,
            cors_enabled: false,
            force_https: false,
            basic_auth_user: None,
            basic_auth_pass: None,
            spa_rewrite: false,
            listen_port: None,
        };
        insert_and_reload(state.store.insert_static(&input))
    };

    // 1. .coulson.toml — use shared manifest parser
    if let Some(result) = scanner::parse_toml_manifest(folder) {
        let info = result.map_err(|e| ServiceError::Internal(e.to_string()))?;

        // Override name/domain from manifest if specified
        let effective_name = info.name.unwrap_or_else(|| name.clone());
        let effective_domain = if let Some(prefix) = &info.domain_prefix {
            let domain_str = format!("{prefix}.{}", state.domain_suffix);
            DomainName::parse(&domain_str, &state.domain_suffix)
                .map_err(|e| ServiceError::InvalidParams(e.to_string()))?
        } else {
            domain.clone()
        };

        // Check if a provider can handle this (managed app)
        if let Some((_prov, detected)) = state
            .provider_registry
            .detect(folder, Some(&info.manifest_json))
            .map_err(|e| ServiceError::Internal(e.to_string()))?
        {
            let root_str = folder.to_string_lossy().to_string();
            return insert_and_reload(state.store.insert_managed(
                &effective_name,
                &effective_domain,
                &root_str,
                &detected.kind,
                None,
            ));
        }

        // Reject multi-route manifests — scanner handles them via symlink + scan
        if info.route_count > 1 {
            return Err(ServiceError::InvalidParams(
                "manifest defines multiple [[routes]]; use symlink + scanner for multi-route import"
                    .to_string(),
            ));
        }

        // Static route from manifest (port, socket, or first route target)
        if !info.target_value.is_empty() {
            let input = StaticAppInput {
                name: &effective_name,
                domain: &effective_domain,
                path_prefix: info.path_prefix.as_deref(),
                target_type: &info.target_type,
                target_value: &info.target_value,
                timeout_ms: info.timeout_ms,
                cors_enabled: info.cors_enabled,
                force_https: info.force_https,
                basic_auth_user: info.basic_auth_user.as_deref(),
                basic_auth_pass: info.basic_auth_pass.as_deref(),
                spa_rewrite: info.spa_rewrite,
                listen_port: info.listen_port,
            };
            return insert_and_reload(state.store.insert_static(&input));
        }
    }

    // 2. .coulson (pow format)
    let coulson_file = folder.join(".coulson");
    if coulson_file.exists() {
        let raw = std::fs::read_to_string(&coulson_file)
            .map_err(|e| ServiceError::Internal(e.to_string()))?;
        if let Some(target_value) = parse_first_route_target(&raw) {
            return insert_tcp(&target_value);
        }
    }

    // 3. Provider registry auto-detect
    if let Some((_prov, detected)) = state
        .provider_registry
        .detect(folder, None)
        .map_err(|e| ServiceError::Internal(e.to_string()))?
    {
        let root_str = folder.to_string_lossy().to_string();
        return insert_and_reload(state.store.insert_managed(
            &name,
            &domain,
            &root_str,
            &detected.kind,
            None,
        ));
    }

    // 4. public/ subdirectory
    let public_dir = folder.join("public");
    if public_dir.is_dir() {
        let root_str = public_dir.to_string_lossy().to_string();
        return insert_and_reload(
            state
                .store
                .insert_static_dir(&name, &domain, &root_str, None),
        );
    }

    // 5. index.html
    if folder.join("index.html").exists() {
        let root_str = folder.to_string_lossy().to_string();
        return insert_and_reload(
            state
                .store
                .insert_static_dir(&name, &domain, &root_str, None),
        );
    }

    // 6. Nothing detected
    Err(ServiceError::DetectionFailed(format!(
        "could not detect app type for: {path}"
    )))
}

// -- Default App --

pub fn set_default_app(state: &SharedState, app_name: Option<&str>) -> Result<(), ServiceError> {
    match app_name {
        Some(raw) => {
            let name = raw.trim().to_ascii_lowercase();
            if name.is_empty() {
                return Err(ServiceError::InvalidParams(
                    "default_app cannot be empty".to_string(),
                ));
            }
            state
                .store
                .set_setting("default_app", &name)
                .map_err(|e| ServiceError::Internal(e.to_string()))?;
            Ok(())
        }
        None => {
            state
                .store
                .delete_setting("default_app")
                .map_err(|e| ServiceError::Internal(e.to_string()))?;
            Ok(())
        }
    }
}

// -- Tunnel Mode --

pub struct TunnelModeResult {
    pub tunnel_mode: TunnelMode,
    pub tunnel_url: Option<String>,
    pub tunnel_id: Option<String>,
    pub tunnel_domain: Option<String>,
    pub dns_record_id: Option<String>,
    pub reconnected: bool,
}

pub async fn app_set_tunnel_mode(
    state: &SharedState,
    app_id: i64,
    new_mode: TunnelMode,
    tunnel_domain_param: Option<&str>,
    tunnel_token_param: Option<&str>,
    auto_dns: bool,
) -> Result<TunnelModeResult, ServiceError> {
    let app = app_get_by_id(state, app_id)?;
    let old_mode = &app.tunnel_mode;

    // Early return for no-op mode transitions (None→None, Global→Global).
    // Quick→Quick proceeds to allow idempotent recovery (restart crashed tunnel).
    // Named→Named proceeds to allow reconnect/domain change.
    if *old_mode == new_mode && matches!(new_mode, TunnelMode::None | TunnelMode::Global) {
        return Ok(TunnelModeResult {
            tunnel_mode: new_mode,
            tunnel_url: None,
            tunnel_id: None,
            tunnel_domain: None,
            dns_record_id: None,
            reconnected: false,
        });
    }

    // Pre-validate named mode params before teardown
    if new_mode == TunnelMode::Named {
        let has_domain = tunnel_domain_param
            .filter(|s| !s.trim().is_empty())
            .is_some()
            || app.app_tunnel_domain.is_some();
        if !has_domain {
            return Err(ServiceError::InvalidParams(
                "app_tunnel_domain is required for named tunnel mode".to_string(),
            ));
        }
        // Validate credentials availability before committing to teardown
        let has_decoded_token = tunnel_token_param
            .filter(|s| !s.trim().is_empty())
            .and_then(|t| tunnel::decode_tunnel_token(t).ok())
            .is_some();
        let has_saved_creds = app
            .app_tunnel_creds
            .as_ref()
            .and_then(|c| serde_json::from_str::<tunnel::TunnelCredentials>(c).ok())
            .is_some();
        let has_cf_config = {
            let token =
                credentials::get_api_token().map_err(|e| ServiceError::Internal(e.to_string()))?;
            let account = state
                .store
                .get_setting("cf.account_id")
                .map_err(|e| ServiceError::Internal(e.to_string()))?;
            token.is_some() && account.is_some()
        };
        if !has_decoded_token && !has_saved_creds && !has_cf_config {
            return Err(ServiceError::InvalidParams(
                "named tunnel requires a valid token, saved credentials, or CF API configuration"
                    .to_string(),
            ));
        }
    }

    let named_domain_changed = new_mode == TunnelMode::Named
        && *old_mode == TunnelMode::Named
        && tunnel_domain_param.is_some()
        && tunnel_domain_param != app.app_tunnel_domain.as_deref();

    let quick_restart = new_mode == TunnelMode::Quick && *old_mode == TunnelMode::Quick;
    if *old_mode != new_mode || named_domain_changed || quick_restart {
        let routing = routing_for_app(&app, state.listen_http.port(), &state.apps_root);

        // Teardown old mode (best-effort)
        match old_mode {
            TunnelMode::Quick | TunnelMode::Named | TunnelMode::Global => {
                fire_tunnel_hook(HookEvent::TunnelStop, &app, state, None);
            }
            TunnelMode::None => {}
        }
        match old_mode {
            TunnelMode::Quick => {
                let _ = tunnel::stop_tunnel(&state.tunnels, app_id);
                let _ = state.store.update_tunnel_url(app_id, None);
                let _ = state.store.set_tunnel_mode(app_id, TunnelMode::None);
            }
            TunnelMode::Named => {
                let _ = tunnel::stop_app_named_tunnel(&state.app_tunnels, app_id);
                let _ = state.store.set_tunnel_mode(app_id, TunnelMode::None);
            }
            TunnelMode::Global => {
                let _ = state.store.set_tunnel_mode(app_id, TunnelMode::None);
            }
            TunnelMode::None => {}
        }

        // Setup new mode
        match new_mode {
            TunnelMode::Quick => {
                match tunnel::start_quick_tunnel(state.tunnels.clone(), app_id, routing).await {
                    Ok(hostname) => {
                        let url = format!("https://{hostname}");
                        state
                            .store
                            .update_tunnel_url(app_id, Some(&url))
                            .map_err(|e| ServiceError::Internal(e.to_string()))?;
                        state
                            .store
                            .set_tunnel_mode(app_id, TunnelMode::Quick)
                            .map_err(|e| ServiceError::Internal(e.to_string()))?;
                        let _ = state.reload_routes();
                        fire_tunnel_hook(HookEvent::TunnelStart, &app, state, Some(&url));
                        return Ok(TunnelModeResult {
                            tunnel_mode: TunnelMode::Quick,
                            tunnel_url: Some(url),
                            tunnel_id: None,
                            tunnel_domain: None,
                            dns_record_id: None,
                            reconnected: false,
                        });
                    }
                    Err(e) => {
                        let _ = state.change_tx.send("detail-tunnel".to_string());
                        return Err(ServiceError::Internal(e.to_string()));
                    }
                }
            }
            TunnelMode::Named => {
                let tunnel_domain = tunnel_domain_param
                    .filter(|s| !s.trim().is_empty())
                    .or(app.app_tunnel_domain.as_deref())
                    .ok_or_else(|| {
                        ServiceError::InvalidParams(
                            "app_tunnel_domain is required for named tunnel mode".to_string(),
                        )
                    })?
                    .to_string();

                // Try token decode
                let decoded_token = tunnel_token_param
                    .filter(|s| !s.trim().is_empty())
                    .and_then(|t| tunnel::decode_tunnel_token(t).ok());

                // Reconnect using saved creds (if no new token and domain didn't change)
                if let Some(tunnel_creds) = app
                    .app_tunnel_creds
                    .as_ref()
                    .filter(|_| !named_domain_changed && decoded_token.is_none())
                {
                    let creds: tunnel::TunnelCredentials = serde_json::from_str(tunnel_creds)
                        .map_err(|e| ServiceError::Internal(e.to_string()))?;
                    let tid = creds.tunnel_id.clone();
                    match tunnel::start_app_named_tunnel(
                        state.app_tunnels.clone(),
                        app_id,
                        creds,
                        tunnel_domain.clone(),
                        routing,
                    )
                    .await
                    {
                        Ok(_) => {
                            let _ = state.store.set_app_tunnel_state(
                                app_id,
                                app.app_tunnel_id.as_deref(),
                                Some(&tunnel_domain),
                                None,
                                app.app_tunnel_creds.as_deref(),
                                TunnelMode::Named,
                            );
                            let _ = state.reload_routes();
                            let tunnel_url = format!("https://{tunnel_domain}");
                            fire_tunnel_hook(
                                HookEvent::TunnelStart,
                                &app,
                                state,
                                Some(&tunnel_url),
                            );
                            return Ok(TunnelModeResult {
                                tunnel_mode: TunnelMode::Named,
                                tunnel_url: None,
                                tunnel_id: Some(tid),
                                tunnel_domain: Some(tunnel_domain),
                                dns_record_id: None,
                                reconnected: true,
                            });
                        }
                        Err(e) => {
                            let _ = state.change_tx.send("detail-tunnel".to_string());
                            return Err(ServiceError::Internal(e.to_string()));
                        }
                    }
                }

                // Token-based connect
                if let Some(credentials) = decoded_token {
                    let tunnel_id = credentials.tunnel_id.clone();
                    match tunnel::start_app_named_tunnel(
                        state.app_tunnels.clone(),
                        app_id,
                        credentials.clone(),
                        tunnel_domain.clone(),
                        routing,
                    )
                    .await
                    {
                        Ok(_) => {
                            let creds_json = serde_json::to_string(&credentials)
                                .map_err(|e| ServiceError::Internal(e.to_string()))?;
                            state
                                .store
                                .set_app_tunnel_state(
                                    app_id,
                                    Some(&tunnel_id),
                                    Some(&tunnel_domain),
                                    None,
                                    Some(&creds_json),
                                    TunnelMode::Named,
                                )
                                .map_err(|e| ServiceError::Internal(e.to_string()))?;
                            let _ = state.reload_routes();
                            let tunnel_url = format!("https://{tunnel_domain}");
                            fire_tunnel_hook(
                                HookEvent::TunnelStart,
                                &app,
                                state,
                                Some(&tunnel_url),
                            );
                            return Ok(TunnelModeResult {
                                tunnel_mode: TunnelMode::Named,
                                tunnel_url: None,
                                tunnel_id: Some(tunnel_id),
                                tunnel_domain: Some(tunnel_domain),
                                dns_record_id: None,
                                reconnected: false,
                            });
                        }
                        Err(e) => {
                            let _ = state.change_tx.send("detail-tunnel".to_string());
                            return Err(ServiceError::Internal(e.to_string()));
                        }
                    }
                }

                // API-based: create tunnel via CF API (token from keychain)
                let api_token = credentials::get_api_token()
                    .map_err(|e| ServiceError::Internal(e.to_string()))?
                    .ok_or_else(|| {
                        ServiceError::InvalidParams(
                            "CF credentials not configured, run tunnel.configure first".to_string(),
                        )
                    })?;
                let account_id = match state
                    .store
                    .get_setting("cf.account_id")
                    .map_err(|e| ServiceError::Internal(e.to_string()))?
                {
                    Some(id) => id,
                    None => tunnel::named::resolve_account_id(&api_token)
                        .await
                        .map_err(|e| {
                            ServiceError::InvalidParams(format!(
                                "cf.account_id not configured, auto-detect failed: {e}"
                            ))
                        })?,
                };

                let tunnel_name = format!("coulson-{app_id}");
                let (credentials, tunnel_id) =
                    tunnel::named::create_named_tunnel(&api_token, &account_id, &tunnel_name)
                        .await
                        .map_err(|e| ServiceError::Internal(e.to_string()))?;

                let mut dns_record_id: Option<String> = None;
                let mut zone_id_used: Option<String> = None;
                if auto_dns {
                    match tunnel::named::find_zone_id(&api_token, &tunnel_domain).await {
                        Ok(zid) => {
                            zone_id_used = Some(zid.clone());
                            match tunnel::named::create_dns_cname(
                                &api_token,
                                &zid,
                                &tunnel_domain,
                                &tunnel_id,
                            )
                            .await
                            {
                                Ok(rid) => dns_record_id = Some(rid),
                                Err(e) => {
                                    let _ = tunnel::named::delete_named_tunnel(
                                        &api_token,
                                        &account_id,
                                        &tunnel_id,
                                    )
                                    .await;
                                    return Err(ServiceError::Internal(format!(
                                        "failed to create DNS CNAME: {e}"
                                    )));
                                }
                            }
                        }
                        Err(e) => {
                            let _ = tunnel::named::delete_named_tunnel(
                                &api_token,
                                &account_id,
                                &tunnel_id,
                            )
                            .await;
                            return Err(ServiceError::Internal(format!(
                                "failed to find zone for domain: {e}"
                            )));
                        }
                    }
                }

                if let Err(e) = tunnel::start_app_named_tunnel(
                    state.app_tunnels.clone(),
                    app_id,
                    credentials.clone(),
                    tunnel_domain.clone(),
                    routing,
                )
                .await
                {
                    if let (Some(rid), Some(zid)) = (&dns_record_id, &zone_id_used) {
                        let _ = tunnel::named::delete_dns_record(&api_token, zid, rid).await;
                    }
                    let _ = tunnel::named::delete_named_tunnel(&api_token, &account_id, &tunnel_id)
                        .await;
                    return Err(ServiceError::Internal(e.to_string()));
                }

                let creds_json = serde_json::to_string(&credentials)
                    .map_err(|e| ServiceError::Internal(e.to_string()))?;
                state
                    .store
                    .set_app_tunnel_state(
                        app_id,
                        Some(&tunnel_id),
                        Some(&tunnel_domain),
                        dns_record_id.as_deref(),
                        Some(&creds_json),
                        TunnelMode::Named,
                    )
                    .map_err(|e| ServiceError::Internal(e.to_string()))?;
                let _ = state.reload_routes();
                let tunnel_url = format!("https://{tunnel_domain}");
                fire_tunnel_hook(HookEvent::TunnelStart, &app, state, Some(&tunnel_url));
                return Ok(TunnelModeResult {
                    tunnel_mode: TunnelMode::Named,
                    tunnel_url: None,
                    tunnel_id: Some(tunnel_id),
                    tunnel_domain: Some(tunnel_domain),
                    dns_record_id,
                    reconnected: false,
                });
            }
            TunnelMode::Global => {
                state
                    .store
                    .set_tunnel_mode(app_id, new_mode)
                    .map_err(|e| ServiceError::Internal(e.to_string()))?;
                let _ = state.reload_routes();
                // Global mode: app is now reachable via the global named tunnel
                let tunnel_url = state
                    .named_tunnel
                    .lock()
                    .as_ref()
                    .map(|h| format!("https://{}.{}", app.name, h.tunnel_domain));
                fire_tunnel_hook(HookEvent::TunnelStart, &app, state, tunnel_url.as_deref());
            }
            TunnelMode::None => {
                state
                    .store
                    .set_tunnel_mode(app_id, new_mode)
                    .map_err(|e| ServiceError::Internal(e.to_string()))?;
                let _ = state.reload_routes();
            }
        }
    }

    Ok(TunnelModeResult {
        tunnel_mode: new_mode,
        tunnel_url: None,
        tunnel_id: None,
        tunnel_domain: None,
        dns_record_id: None,
        reconnected: false,
    })
}

// -- Helpers --

pub fn routing_for_app(
    app: &AppSpec,
    proxy_port: u16,
    apps_root: &std::path::Path,
) -> tunnel::transport::TunnelRouting {
    tunnel::transport::TunnelRouting::FixedHost {
        local_host: app.domain.0.clone(),
        local_proxy_port: proxy_port,
        config_path: tunnel::proxy::config_path_for_app(app, apps_root),
    }
}

pub fn normalize_path_prefix(input: Option<&str>) -> Result<Option<String>, String> {
    let Some(raw) = input else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if !trimmed.starts_with('/') {
        return Err("path_prefix must start with '/'".to_string());
    }
    if trimmed.len() > 1 && trimmed.ends_with('/') {
        return Ok(Some(trimmed.trim_end_matches('/').to_string()));
    }
    Ok(Some(trimmed.to_string()))
}

/// Normalize and validate a cname. Returns the cleaned hostname or an error
/// for inputs that contain schemes, paths, or invalid characters.
fn normalize_cname(raw: &str) -> Result<String, ServiceError> {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() {
        return Ok(String::new());
    }
    // Reject scheme prefixes
    if s.contains("://") {
        return Err(ServiceError::InvalidParams(
            "cname must be a bare hostname, not a URL".to_string(),
        ));
    }
    // Strip port suffix (e.g. "foo.com:443" -> "foo.com")
    let host = s.split(':').next().unwrap_or("");
    // Reject paths
    if host.contains('/') {
        return Err(ServiceError::InvalidParams(
            "cname must be a bare hostname without path".to_string(),
        ));
    }
    if host.is_empty() {
        return Err(ServiceError::InvalidParams(
            "cname cannot be empty or port-only".to_string(),
        ));
    }
    // Validate hostname labels
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ServiceError::InvalidParams(format!(
                "invalid hostname label in cname: {host}"
            )));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(ServiceError::InvalidParams(format!(
                "invalid character in cname: {host}"
            )));
        }
    }
    Ok(host.to_string())
}

/// Validate that a cname doesn't conflict with any existing domain or cname.
fn validate_cname_unique(
    state: &SharedState,
    app_id: i64,
    cname: &str,
) -> Result<(), ServiceError> {
    let apps = state.store.list_all().map_err(ServiceError::from)?;
    for app in &apps {
        if app.id.0 == app_id {
            continue; // skip self
        }
        if app.domain.0 == cname {
            return Err(ServiceError::DomainConflict);
        }
        if app.cname.as_deref() == Some(cname) {
            return Err(ServiceError::DomainConflict);
        }
    }
    // Also check .localhost aliases
    let suffix = &state.domain_suffix;
    for app in &apps {
        if app.id.0 == app_id {
            continue;
        }
        if let Some(prefix) = app.domain.0.strip_suffix(&format!(".{suffix}")) {
            if format!("{prefix}.localhost") == cname {
                return Err(ServiceError::DomainConflict);
            }
        }
    }
    Ok(())
}

/// Fire a tunnel lifecycle hook (TunnelStart / TunnelStop) for a per-app tunnel.
fn fire_tunnel_hook(
    event: HookEvent,
    app: &AppSpec,
    state: &SharedState,
    tunnel_url: Option<&str>,
) {
    let mut ctx = state.hook_factory().context_for_app(event, app);
    // Override tunnel_url with the freshly obtained value (may not be in DB yet)
    if let Some(url) = tunnel_url {
        ctx.tunnel_url = Some(url.to_string());
        if !ctx.app_urls.contains(&url.to_string()) {
            ctx.app_urls.push(url.to_string());
        }
    }
    let hooks = app.hooks.clone();
    let hm = state.hook_manager.clone();
    tokio::spawn(async move { hm.fire_with_hooks(&ctx, hooks.as_ref()).await });
}

/// Parse the first route target from a pow-format file content.
fn parse_first_route_target(raw: &str) -> Option<String> {
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let target_token = if parts[0].starts_with('/') {
            parts.get(1).copied()
        } else {
            Some(parts[0])
        };
        if let Some(token) = target_token {
            // bare port
            if let Ok(port) = token.parse::<u16>() {
                if port > 0 {
                    return Some(format!("127.0.0.1:{port}"));
                }
            }
            // host:port
            if let Some((host, port_str)) = token.rsplit_once(':') {
                let host = host
                    .strip_prefix("http://")
                    .or_else(|| host.strip_prefix("https://"))
                    .unwrap_or(host);
                if let Ok(port) = port_str.parse::<u16>() {
                    if port > 0 && !host.is_empty() {
                        return Some(format!("{host}:{port}"));
                    }
                }
            }
        }
        break;
    }
    None
}
