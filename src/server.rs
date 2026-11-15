//! axum HTTP 服务：路由、鉴权、限流、静态前端与全部 API 端点。

use crate::auth;
use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::model::{append_lines_of, operators_of, prepend_lines_of, Proxy};
use crate::pipeline::{self, Request as PipelineRequest};
use crate::processor::{self, ArtifactLookup};
use crate::ratelimit::RateLimiter;
use crate::scheduler;
use crate::share::{self, ShareResolver};
use crate::store::{self, Store};
use crate::util::{get_str, merge_into, JMap};
use axum::body::{Bytes, Body};
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rust_embed::RustEmbed;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

#[derive(RustEmbed)]
#[folder = "web/dist"]
struct Assets;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub store: Arc<Store>,
    pub share: Arc<ShareResolver>,
    pub login_limiter: RateLimiter,
    pub download_limiter: RateLimiter,
}

#[derive(Clone)]
struct Username(String);

type ApiResult = AppResult<Response>;

fn internal_err<E: std::fmt::Display>(e: E) -> AppError {
    AppError::internal(e.to_string())
}

impl AppState {
    pub fn new(cfg: Config, store: Arc<Store>) -> Self {
        let share = Arc::new(ShareResolver::new(store.clone()));
        Self {
            cfg: Arc::new(cfg),
            store,
            share,
            login_limiter: RateLimiter::new(10, StdDuration::from_secs(15 * 60)),
            download_limiter: RateLimiter::new(120, StdDuration::from_secs(60)),
        }
    }
}

fn p(cfg: &Config, path: &str) -> String {
    format!("{}{}", cfg.path_prefix, path)
}

fn json_response(v: Value) -> Response {
    Json(v).into_response()
}

fn ok(msg: &str) -> Response {
    json_response(json!({"message": msg}))
}

/// 显式插入响应头（避免依赖元组 IntoResponseParts 的具体实现）。
fn header_response(body: impl Into<Body>, pairs: &[(&str, String)]) -> Response {
    let mut resp = Response::new(body.into());
    for (k, v) in pairs {
        if let (Ok(name), Ok(val)) = (
            axum::http::HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            resp.headers_mut().insert(name, val);
        }
    }
    resp
}

fn body_map(b: &Bytes) -> Result<JMap, AppError> {
    serde_json::from_slice::<Value>(b)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .ok_or_else(|| AppError::bad_request("invalid request body"))
}

pub fn build_router(state: AppState) -> Router {
    let cfg = state.cfg.clone();

    let authed = Router::new()
        .route(&p(&cfg, "/api/me"), get(handle_me))
        .route(&p(&cfg, "/api/subs"), get(handle_list_subs).post(handle_create_sub))
        .route(&p(&cfg, "/api/sub/{name}"), get(handle_get_sub).patch(handle_patch_sub).delete(handle_delete_sub))
        .route(&p(&cfg, "/api/sub/{name}/update"), post(handle_update_sub))
        .route(&p(&cfg, "/api/collections"), get(handle_list_collections).post(handle_create_collection))
        .route(&p(&cfg, "/api/col/{name}"), get(handle_get_collection).patch(handle_patch_collection).delete(handle_delete_collection))
        .route(&p(&cfg, "/api/files"), get(handle_list_files).post(handle_create_file))
        .route(&p(&cfg, "/api/file/{name}"), get(handle_get_file).patch(handle_patch_file).delete(handle_delete_file))
        .route(&p(&cfg, "/api/node-info/{name}"), get(handle_node_info))
        .route(&p(&cfg, "/api/tokens"), get(handle_list_tokens))
        .route(&p(&cfg, "/api/token"), post(handle_create_token))
        .route(&p(&cfg, "/api/token/{token}"), axum::routing::delete(handle_delete_token))
        .route(&p(&cfg, "/api/targets"), get(handle_targets))
        .route(&p(&cfg, "/api/settings"), get(handle_get_settings).patch(handle_patch_settings))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    let public = Router::new()
        .route(&p(&cfg, "/api/login"), post(handle_login))
        .route(&p(&cfg, "/download/{name}"), get(handle_download))
        .route(&p(&cfg, "/api/file/{name}/raw"), get(handle_file_raw))
        .route(&p(&cfg, "/share/sub/{name}"), get(handle_share_sub))
        .route(&p(&cfg, "/share/col/{name}"), get(handle_share_col))
        .route(&p(&cfg, "/share/file/{name}"), get(handle_share_file));

    public
        .merge(authed)
        .fallback(static_fallback)
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn(quiet_logger))
        .with_state(state)
}

// ---------------- 中间件 ----------------

async fn security_headers(req: Request<Body>, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    h.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    h.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
    resp
}

async fn quiet_logger(req: Request<Body>, next: Next) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let start = Instant::now();
    let resp = next.run(req).await;
    if resp.status().as_u16() >= 400 {
        tracing::warn!("{} {} {} ({:?})", resp.status().as_u16(), method, path, start.elapsed());
    }
    resp
}

async fn auth_middleware(State(state): State<AppState>, mut req: Request<Body>, next: Next) -> Response {
    let header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let token = header.strip_prefix("Bearer ").unwrap_or("");
    if token.is_empty() {
        return AppError::unauthorized("missing bearer token").into_response();
    }
    match auth::validate_token(&state.cfg.jwt_secret, token) {
        Ok(u) => {
            req.extensions_mut().insert(Username(u));
            next.run(req).await
        }
        Err(_) => AppError::unauthorized("invalid token").into_response(),
    }
}

fn rate_limit_guard(limiter: &RateLimiter, addr: &SocketAddr, prefix: &str) -> Result<(), Response> {
    let key = format!("{}:{}", prefix, addr.ip());
    let (allowed, retry) = limiter.allow(&key);
    if allowed {
        Ok(())
    } else {
        Err(AppError::too_many("too many requests, please try again later", retry))
    }
}

// ---------------- 认证 ----------------

async fn handle_login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> ApiResult {
    let key = format!("login:{}", addr.ip());
    let (allowed, retry) = state.login_limiter.allow(&key);
    if !allowed {
        return Ok(AppError::too_many("too many login attempts, please try again later", retry));
    }
    let m = body_map(&body)?;
    let u = get_str(&m, "username");
    let pw = get_str(&m, "password");
    let user_ok = auth::constant_time_equal(&u, &state.cfg.admin_username);
    let pass_ok = auth::constant_time_equal(&pw, &state.cfg.admin_password);
    if !user_ok || !pass_ok {
        return Err(AppError::unauthorized("invalid credentials"));
    }
    let token = auth::sign_token(&state.cfg.jwt_secret, &u, state.cfg.token_ttl_hours)
        .map_err(|_| AppError::internal("sign token failed"))?;
    state.login_limiter.reset(&key);
    Ok(json_response(json!({"token": token, "username": u})))
}

async fn handle_me(user: axum::Extension<Username>) -> ApiResult {
    Ok(json_response(json!({"username": user.0.0})))
}

// ---------------- 订阅 ----------------

async fn handle_list_subs(State(state): State<AppState>) -> ApiResult {
    let subs = state.store.list_subs().map_err(internal_err)?;
    Ok(json_response(Value::Array(subs.into_iter().map(Value::Object).collect())))
}

fn validate_sub_body(body: &mut JMap) -> Result<(), AppError> {
    let src = {
        let s = get_str(body, "source");
        if s.is_empty() {
            body.insert("source".into(), json!("remote"));
            "remote".to_string()
        } else {
            s
        }
    };
    match src.as_str() {
        "local" => {
            if get_str(body, "content").trim().is_empty() {
                return Err(AppError::bad_request("本地订阅需要填写内容"));
            }
            body.insert("url".into(), json!(""));
            body.insert("updateCron".into(), json!(""));
        }
        "remote" => {
            if get_str(body, "url").trim().is_empty() {
                return Err(AppError::bad_request("远程订阅需要填写 URL"));
            }
            body.insert("content".into(), json!(""));
            let cron = get_str(body, "updateCron").trim().to_string();
            if !cron.is_empty() {
                if !scheduler::valid(&cron) {
                    return Err(AppError::bad_request("定时更新表达式无效，应为标准 5 段 cron 格式，例如 0 0 * * *"));
                }
                body.insert("updateCron".into(), json!(cron));
            }
        }
        _ => return Err(AppError::bad_request("source 必须是 local 或 remote")),
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), AppError> {
    if name.trim().is_empty() {
        return Err(AppError::bad_request("name is required"));
    }
    if name.contains('/') {
        return Err(AppError::bad_request("name 不能包含 / 字符"));
    }
    Ok(())
}

async fn handle_create_sub(State(state): State<AppState>, body: Bytes) -> ApiResult {
    let mut body = body_map(&body)?;
    let name = get_str(&body, "name").trim().to_string();
    validate_name(&name)?;
    validate_sub_body(&mut body)?;
    if state.store.get_sub(&name).map_err(internal_err)?.is_some() {
        return Err(AppError::conflict("subscription already exists"));
    }
    let position = {
        let v = get_str(&body, "position");
        if v.is_empty() { "bottom".to_string() } else { v }
    };
    state.store.upsert_sub(&name, &body, &position).map_err(internal_err)?;
    let mut resp = json!({"message": "success", "name": name});
    if get_str(&body, "source") == "remote" {
        if let Err(e) = state.share.refresh_cache(&body, &name).await {
            resp["warning"] = json!(format!("订阅已保存，但拉取订阅链接失败：{}", e));
        }
    }
    Ok(json_response(resp))
}

async fn handle_get_sub(State(state): State<AppState>, Path(name): Path<String>) -> ApiResult {
    let sub = state.store.get_sub(&name).map_err(internal_err)?
        .ok_or_else(|| AppError::not_found("subscription not found"))?;
    Ok(json_response(Value::Object(sub)))
}

async fn handle_patch_sub(
    State(state): State<AppState>,
    Path(name): Path<String>,
    body: Bytes,
) -> ApiResult {
    let patch = body_map(&body)?;
    let mut existing = state.store.get_sub(&name).map_err(internal_err)?
        .ok_or_else(|| AppError::not_found("subscription not found"))?;

    let new_name = match patch.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() && n != name => {
            validate_name(n)?;
            if state.store.get_sub(n).map_err(internal_err)?.is_some() {
                return Err(AppError::conflict("name already taken"));
            }
            n.to_string()
        }
        _ => name.clone(),
    };
    let old_url = get_str(&existing, "url");
    let old_ua = get_str(&existing, "ua");
    let old_source = get_str(&existing, "source");
    merge_into(&mut existing, &patch);
    if new_name != name {
        existing.insert("name".into(), json!(new_name));
    }
    if let Some(src) = patch.get("source").and_then(|v| v.as_str()) {
        match src {
            "local" => {
                if !patch.contains_key("url") {
                    existing.insert("url".into(), json!(""));
                }
                existing.insert("updateCron".into(), json!(""));
                existing.insert("cachedContent".into(), json!(""));
                existing.insert("cachedAt".into(), json!(0));
            }
            "remote" => {
                if !patch.contains_key("content") {
                    existing.insert("content".into(), json!(""));
                }
            }
            _ => {}
        }
    }
    validate_sub_body(&mut existing)?;
    if get_str(&existing, "source") == "remote" {
        let identity_changed = get_str(&existing, "url") != old_url
            || get_str(&existing, "ua") != old_ua
            || old_source != "remote";
        if identity_changed {
            existing.insert("cachedContent".into(), json!(""));
            existing.insert("cachedAt".into(), json!(0));
        }
    }

    if new_name != name {
        let data = existing.clone();
        let old = name.clone();
        let nn = new_name.clone();
        let ok = state.store.with_tx(move |tx| {
            if !store::rename_tx(tx, "subs", &old, &nn, &data)? {
                return Err(anyhow::anyhow!("name conflict"));
            }
            let cols = store::list_tx(tx, "collections")?;
            for mut col in cols {
                let mut changed = false;
                if let Some(Value::Array(subs)) = col.get_mut("subscriptions") {
                    for v in subs.iter_mut() {
                        if v.as_str() == Some(old.as_str()) {
                            *v = json!(nn);
                            changed = true;
                        }
                    }
                }
                if changed {
                    let cname = get_str(&col, "name");
                    store::upsert_tx(tx, "collections", &cname, &col)?;
                }
            }
            Ok(())
        });
        match ok {
            Ok(_) => {}
            Err(e) if e.to_string().contains("conflict") => return Err(AppError::conflict("name already taken")),
            Err(e) => return Err(AppError::internal(format!("save failed: {}", e))),
        }
    } else {
        state.store.upsert_sub(&name, &existing, "bottom").map_err(internal_err)?;
    }

    let mut resp = json!({"message": "success", "name": new_name});
    if get_str(&existing, "source") == "remote" {
        if let Err(e) = state.share.refresh_cache(&existing, &new_name).await {
            resp["warning"] = json!(format!("订阅已保存，但拉取订阅链接失败：{}", e));
        }
    }
    Ok(json_response(resp))
}

async fn handle_delete_sub(State(state): State<AppState>, Path(name): Path<String>) -> ApiResult {
    if state.store.get_sub(&name).map_err(internal_err)?.is_none() {
        return Err(AppError::not_found("subscription not found"));
    }
    let n = name.clone();
    state.store.with_tx(move |tx| {
        store::delete_tx(tx, "subs", &n)?;
        let cols = store::list_tx(tx, "collections")?;
        for mut col in cols {
            let mut changed = false;
            if let Some(Value::Array(subs)) = col.get_mut("subscriptions") {
                let before = subs.len();
                subs.retain(|v| v.as_str() != Some(n.as_str()));
                changed = before != subs.len();
            }
            if changed {
                let cname = get_str(&col, "name");
                store::upsert_tx(tx, "collections", &cname, &col)?;
            }
        }
        Ok(())
    }).map_err(|e| AppError::internal(format!("delete failed: {}", e)))?;
    Ok(ok("success"))
}

async fn handle_update_sub(State(state): State<AppState>, Path(name): Path<String>) -> ApiResult {
    let rec = state.store.get_sub(&name).map_err(internal_err)?
        .ok_or_else(|| AppError::not_found("subscription not found"))?;
    if get_str(&rec, "source") != "remote" || get_str(&rec, "url").is_empty() {
        return Err(AppError::bad_request("本地订阅无需更新"));
    }
    let cached_at = state.share.refresh_cache(&rec, &name).await
        .map_err(|e| AppError::bad_gateway(format!("更新失败：{}", e)))?;
    Ok(json_response(json!({"message": "success", "cachedAt": cached_at})))
}

async fn handle_node_info(State(state): State<AppState>, Path(name): Path<String>) -> ApiResult {
    let rec = state.store.get_sub(&name).map_err(internal_err)?
        .ok_or_else(|| AppError::not_found("subscription not found"))?;
    let proxies = state.share.preview_sub(&rec).await
        .map_err(|e| AppError::bad_gateway(e.to_string()))?;
    Ok(json_response(Value::Array(proxies.into_iter().map(|p| p.into_value()).collect())))
}

// ---------------- 组合订阅 ----------------

async fn handle_list_collections(State(state): State<AppState>) -> ApiResult {
    let v = state.store.list_collections().map_err(internal_err)?;
    Ok(json_response(Value::Array(v.into_iter().map(Value::Object).collect())))
}

async fn handle_create_collection(State(state): State<AppState>, body: Bytes) -> ApiResult {
    let body = body_map(&body)?;
    let name = get_str(&body, "name").trim().to_string();
    validate_name(&name)?;
    if state.store.get_collection(&name).map_err(internal_err)?.is_some() {
        return Err(AppError::conflict("collection already exists"));
    }
    let position = {
        let v = get_str(&body, "position");
        if v.is_empty() { "bottom".to_string() } else { v }
    };
    state.store.upsert_collection(&name, &body, &position).map_err(internal_err)?;
    Ok(json_response(json!({"message": "success", "name": name})))
}

async fn handle_get_collection(State(state): State<AppState>, Path(name): Path<String>) -> ApiResult {
    let v = state.store.get_collection(&name).map_err(internal_err)?
        .ok_or_else(|| AppError::not_found("collection not found"))?;
    Ok(json_response(Value::Object(v)))
}

async fn handle_patch_collection(
    State(state): State<AppState>,
    Path(name): Path<String>,
    body: Bytes,
) -> ApiResult {
    let patch = body_map(&body)?;
    let mut existing = state.store.get_collection(&name).map_err(internal_err)?
        .ok_or_else(|| AppError::not_found("collection not found"))?;
    let new_name = match patch.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() && n != name => {
            validate_name(n)?;
            if state.store.get_collection(n).map_err(internal_err)?.is_some() {
                return Err(AppError::conflict("name already taken"));
            }
            n.to_string()
        }
        _ => name.clone(),
    };
    merge_into(&mut existing, &patch);
    if new_name != name {
        existing.insert("name".into(), json!(new_name));
        if !state.store.rename_collection(&name, &new_name, &existing).map_err(internal_err)? {
            return Err(AppError::conflict("name already taken"));
        }
    } else {
        state.store.upsert_collection(&name, &existing, "bottom").map_err(internal_err)?;
    }
    Ok(json_response(json!({"message": "success", "name": new_name})))
}

async fn handle_delete_collection(State(state): State<AppState>, Path(name): Path<String>) -> ApiResult {
    if state.store.get_collection(&name).map_err(internal_err)?.is_none() {
        return Err(AppError::not_found("collection not found"));
    }
    state.store.delete_collection(&name).map_err(internal_err)?;
    Ok(ok("success"))
}

// ---------------- 文件 ----------------

fn validate_file_body(body: &JMap) -> Result<(), AppError> {
    if get_str(body, "name").trim().is_empty() {
        return Err(AppError::bad_request("请输入文件名"));
    }
    Ok(())
}

async fn handle_list_files(State(state): State<AppState>) -> ApiResult {
    let v = state.store.list_files().map_err(internal_err)?;
    Ok(json_response(Value::Array(v.into_iter().map(Value::Object).collect())))
}

async fn handle_create_file(State(state): State<AppState>, body: Bytes) -> ApiResult {
    let body = body_map(&body)?;
    let name = get_str(&body, "name").trim().to_string();
    validate_name(&name)?;
    validate_file_body(&body)?;
    if state.store.get_file(&name).map_err(internal_err)?.is_some() {
        return Err(AppError::conflict("file already exists"));
    }
    let position = {
        let v = get_str(&body, "position");
        if v.is_empty() { "bottom".to_string() } else { v }
    };
    state.store.upsert_file(&name, &body, &position).map_err(internal_err)?;
    Ok(json_response(json!({"message": "success", "name": name})))
}

async fn handle_get_file(State(state): State<AppState>, Path(name): Path<String>) -> ApiResult {
    let v = state.store.get_file(&name).map_err(internal_err)?
        .ok_or_else(|| AppError::not_found("file not found"))?;
    Ok(json_response(Value::Object(v)))
}

async fn handle_patch_file(
    State(state): State<AppState>,
    Path(name): Path<String>,
    body: Bytes,
) -> ApiResult {
    let patch = body_map(&body)?;
    let mut existing = state.store.get_file(&name).map_err(internal_err)?
        .ok_or_else(|| AppError::not_found("file not found"))?;
    let new_name = match patch.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() && n != name => {
            if state.store.get_file(n).map_err(internal_err)?.is_some() {
                return Err(AppError::conflict("name already taken"));
            }
            n.to_string()
        }
        _ => name.clone(),
    };
    merge_into(&mut existing, &patch);
    validate_file_body(&existing)?;
    if new_name != name {
        existing.insert("name".into(), json!(new_name));
        if !state.store.rename_file(&name, &new_name, &existing).map_err(internal_err)? {
            return Err(AppError::conflict("name already taken"));
        }
    } else {
        state.store.upsert_file(&name, &existing, "bottom").map_err(internal_err)?;
    }
    Ok(json_response(json!({"message": "success", "name": new_name})))
}

async fn handle_delete_file(State(state): State<AppState>, Path(name): Path<String>) -> ApiResult {
    if state.store.get_file(&name).map_err(internal_err)?.is_none() {
        return Err(AppError::not_found("file not found"));
    }
    state.store.delete_file(&name).map_err(internal_err)?;
    Ok(ok("success"))
}

async fn handle_file_raw(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult {
    if !authorize_download(&state, &headers, q.get("token").map(|s| s.as_str()), &["file"], &name) {
        return Err(AppError::unauthorized("unauthorized"));
    }
    let rec = state.store.get_file(&name).map_err(internal_err)?
        .ok_or_else(|| AppError::not_found("file not found"))?;
    let content = get_str(&rec, "content");
    Ok(header_response(content, &[
        ("Content-Type", "text/plain; charset=utf-8".to_string()),
        ("Cache-Control", "no-store".to_string()),
    ]))
}

// ---------------- Token / Targets / Settings ----------------

async fn handle_list_tokens(State(state): State<AppState>) -> ApiResult {
    let v = state.store.list_tokens().map_err(internal_err)?;
    Ok(json_response(Value::Array(v.into_iter().map(Value::Object).collect())))
}

async fn handle_create_token(State(state): State<AppState>, body: Bytes) -> ApiResult {
    let body = body_map(&body)?;
    let kind = get_str(&body, "type");
    if !matches!(kind.as_str(), "sub" | "col" | "file") {
        return Err(AppError::bad_request("type must be sub, col or file"));
    }
    let mut opts = body.clone();
    if kind != "file" {
        let target = get_str(&body, "target");
        let target = if target.is_empty() { "mihomo".to_string() } else { target };
        if !crate::producer::known(&target) {
            return Err(AppError::bad_request(format!("unsupported target: {}", target)));
        }
        opts.insert("target".into(), json!(target));
    }
    let name = get_str(&body, "name");
    let exists = match kind.as_str() {
        "sub" => state.store.get_sub(&name).map_err(internal_err)?.is_some(),
        "col" => state.store.get_collection(&name).map_err(internal_err)?.is_some(),
        _ => state.store.get_file(&name).map_err(internal_err)?.is_some(),
    };
    if !exists {
        return Err(AppError::not_found(format!("{} not found", kind)));
    }
    let payload = share::build_token_payload(&kind, &name, &opts);
    if !state.store.insert_token(&payload).map_err(internal_err)? {
        return Err(AppError::conflict("token already exists"));
    }
    Ok(json_response(Value::Object(payload)))
}

async fn handle_delete_token(State(state): State<AppState>, Path(token): Path<String>) -> ApiResult {
    state.store.delete_token(&token).map_err(internal_err)?;
    Ok(ok("success"))
}

async fn handle_targets() -> ApiResult {
    Ok(json_response(json!(crate::model::canonical_targets())))
}

async fn handle_get_settings(State(state): State<AppState>) -> ApiResult {
    let v = state.store.get_settings().map_err(internal_err)?;
    Ok(json_response(Value::Object(v)))
}

async fn handle_patch_settings(State(state): State<AppState>, body: Bytes) -> ApiResult {
    let patch = body_map(&body)?;
    let mut existing = state.store.get_settings().map_err(internal_err)?;
    merge_into(&mut existing, &patch);
    state.store.save_settings(&existing).map_err(internal_err)?;
    Ok(ok("success"))
}

// ---------------- 下载 / 分享 ----------------

fn content_type_for(target: &str) -> &'static str {
    match target.to_lowercase().as_str() {
        "json" | "sing-box" | "singbox" => "application/json; charset=utf-8",
        "clash" | "clash.meta" | "clashmeta" | "meta" | "mihomo" | "stash" => "text/yaml; charset=utf-8",
        _ => "text/plain; charset=utf-8",
    }
}

fn file_ext(target: &str) -> &'static str {
    match target.to_lowercase().as_str() {
        "json" | "sing-box" | "singbox" => "json",
        "clash" | "clash.meta" | "clashmeta" | "meta" | "mihomo" | "stash" => "yaml",
        "v2ray" | "v2" | "uri" => "txt",
        _ => "conf",
    }
}

fn render_preview(title: &str, body: &str) -> Response {
    let html = format!(
        "<!doctype html>\n<html lang=\"zh\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>{}</title>\n<style>\n:root{{color-scheme:light}}\nhtml,body{{margin:0;padding:0;background:#ffffff}}\npre{{margin:0;padding:16px;white-space:pre-wrap;word-break:break-all;font-family:ui-monospace,SFMono-Regular,Consolas,\"Liberation Mono\",Menlo,monospace;font-size:12px;line-height:1.5;color:#1f2328}}\n</style>\n</head>\n<body>\n<pre>{}</pre>\n</body>\n</html>",
        crate::util::html_escape(title),
        crate::util::html_escape(body)
    );
    header_response(html, &[
        ("Content-Type", "text/html; charset=utf-8".to_string()),
        ("Cache-Control", "no-store".to_string()),
    ])
}

fn attachment(name: &str, target: &str, body: String) -> Response {
    header_response(body, &[
        ("Content-Disposition", format!("attachment; filename=\"{}.{}\"", name, file_ext(target))),
        ("Content-Type", content_type_for(target).to_string()),
        ("Cache-Control", "no-store".to_string()),
    ])
}

fn authorize_download(
    state: &AppState,
    headers: &HeaderMap,
    token_q: Option<&str>,
    kinds: &[&str],
    name: &str,
) -> bool {
    if let Some(h) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(t) = h.strip_prefix("Bearer ") {
            return auth::validate_token(&state.cfg.jwt_secret, t).is_ok();
        }
    }
    if let Some(t) = token_q.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if auth::validate_token(&state.cfg.jwt_secret, t).is_ok() {
            return true;
        }
        if let Ok(Some(rec)) = state.share.lookup(t) {
            if !name.is_empty() && get_str(&rec, "name") != name {
                return false;
            }
            if !kinds.is_empty() {
                let tk = get_str(&rec, "type");
                if !kinds.contains(&tk.as_str()) {
                    return false;
                }
            }
            return true;
        }
    }
    false
}

/// 安装一次性的「从订阅添加节点」查找器（需运行在 spawn_blocking 上下文中）。
fn ensure_artifact_lookup(state: &AppState) {
    let share = state.share.clone();
    let lookup: Arc<ArtifactLookup> = Arc::new(move |kind, name| {
        let share = share.clone();
        let handle = tokio::runtime::Handle::current();
        handle.block_on(async move { share.lookup_artifact_proxies(kind, name).await })
    });
    processor::set_artifact_lookup(lookup);
}

async fn handle_download(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult {
    if let Err(resp) = rate_limit_guard(&state.download_limiter, &addr, "download") {
        return Ok(resp);
    }
    let target = q.get("target").map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("mihomo").to_string();
    if !authorize_download(&state, &headers, q.get("token").map(|s| s.as_str()), &["sub", "col"], &name) {
        return Err(AppError::unauthorized("unauthorized"));
    }
    ensure_artifact_lookup(&state);
    let preview = q.get("preview").map(|s| s.as_str()) == Some("1");

    if let Some(rec) = state.store.get_sub(&name).map_err(internal_err)? {
        let raw = state.share.fetch_sub(&rec).await
            .map_err(|e| AppError::bad_gateway(format!("fetch failed: {}", e)))?;
        let ops = operators_of(&rec);
        let prepend = prepend_lines_of(&rec);
        let append = append_lines_of(&rec);
        let sub_name = get_str(&rec, "name");
        let sub_display = get_str(&rec, "displayName");
        let t = target.clone();
        let body = tokio::task::spawn_blocking(move || {
            pipeline::process(&PipelineRequest {
                raw,
                target: t,
                operators: ops,
                prepend_lines: prepend,
                append_lines: append,
                sub_name,
                sub_display_name: sub_display,
                ..Default::default()
            })
        })
        .await
        .map_err(|e| AppError::internal(format!("pipeline failed: {}", e)))?
        .map_err(|e| AppError::bad_request(e.to_string()))?;
        return Ok(if preview {
            render_preview(&format!("{}.{}", name, file_ext(&target)), &body)
        } else {
            attachment(&name, &target, body)
        });
    }

    let rec = state.store.get_collection(&name).map_err(internal_err)?
        .ok_or_else(|| AppError::not_found("subscription or collection not found"))?;
    let proxies = state.share.collection_proxies(&rec).await
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    if proxies.is_empty() {
        return Err(AppError::bad_request(format!("组合订阅 {} 中不含有效节点", name)));
    }
    let ops = operators_of(&rec);
    let prepend = prepend_lines_of(&rec);
    let append = append_lines_of(&rec);
    let t = target.clone();
    let body = tokio::task::spawn_blocking(move || {
        pipeline::process_proxies(proxies, &t, None, &ops, &prepend, &append)
    })
    .await
    .map_err(|e| AppError::internal(format!("pipeline failed: {}", e)))?
    .map_err(|e| AppError::bad_request(e.to_string()))?;
    Ok(if preview {
        render_preview(&format!("{}.{}", name, file_ext(&target)), &body)
    } else {
        attachment(&name, &target, body)
    })
}

async fn share_download(
    state: AppState,
    addr: SocketAddr,
    kind: &str,
    name: String,
    headers: HeaderMap,
    q: HashMap<String, String>,
) -> ApiResult {
    if let Err(resp) = rate_limit_guard(&state.download_limiter, &addr, "download") {
        return Ok(resp);
    }
    let token = q.get("token").map(|s| s.trim()).unwrap_or("");
    if token.is_empty() {
        return Err(AppError::bad_request("missing token"));
    }
    let rec = state.share.lookup(token).map_err(internal_err)?
        .ok_or_else(|| AppError::unauthorized("invalid token"))?;
    if get_str(&rec, "type") != kind || get_str(&rec, "name") != name {
        return Err(AppError::unauthorized("token does not match target"));
    }
    let preview = q.get("preview").map(|s| s.as_str()) == Some("1");

    if kind == "file" {
        state.share.check_and_consume(token).map_err(|e| AppError::bad_request(e.to_string()))?;
        let frec = state.store.get_file(&name).map_err(internal_err)?
            .ok_or_else(|| AppError::not_found("file not found"))?;
        let body = get_str(&frec, "content");
        return Ok(if preview {
            render_preview(&name, &body)
        } else {
            header_response(body, &[
                ("Content-Disposition", format!("attachment; filename=\"{}\"", name)),
                ("Content-Type", "text/plain; charset=utf-8".to_string()),
                ("Cache-Control", "no-store".to_string()),
            ])
        });
    }

    ensure_artifact_lookup(&state);
    let target = q.get("target").map(|s| s.trim()).filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            let t = get_str(&rec, "target");
            if t.is_empty() { "mihomo".to_string() } else { t }
        });
    let t2 = target.clone();
    let tok = token.to_string();
    let share = state.share.clone();
    let body = tokio::task::spawn_blocking(move || {
        let handle = tokio::runtime::Handle::current();
        handle.block_on(async move { share.resolve(&tok, &t2).await })
    })
    .await
    .map_err(|e| AppError::internal(format!("resolve failed: {}", e)))?
    .map_err(|e| AppError::bad_request(e.to_string()))?;
    let _ = headers;
    Ok(if preview {
        render_preview(&format!("{}.{}", name, file_ext(&target)), &body)
    } else {
        attachment(&name, &target, body)
    })
}

async fn handle_share_sub(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult {
    share_download(state, addr, "sub", name, headers, q).await
}

async fn handle_share_col(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult {
    share_download(state, addr, "col", name, headers, q).await
}

async fn handle_share_file(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult {
    share_download(state, addr, "file", name, headers, q).await
}

// ---------------- 静态前端 ----------------

async fn static_fallback(State(state): State<AppState>, uri: Uri, req: Request<Body>) -> Response {
    if req.method() != axum::http::Method::GET {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = uri.path().to_string();
    if path.starts_with("/api/") {
        return (StatusCode::NOT_FOUND, Json(json!({"message": "not found"}))).into_response();
    }
    let prefix = &state.cfg.path_prefix;
    let rel: String;
    if !prefix.is_empty() {
        if path == *prefix {
            let target = format!("{}/", prefix);
            return Redirect::permanent(&target).into_response();
        } else if path == format!("{}/", prefix) {
            rel = "index.html".to_string();
        } else if let Some(stripped) = path.strip_prefix(&format!("{}/", prefix)) {
            rel = stripped.to_string();
        } else {
            return StatusCode::NOT_FOUND.into_response();
        }
    } else {
        rel = path.trim_start_matches('/').to_string();
    }
    let rel = if rel.is_empty() { "index.html".to_string() } else { rel };

    if let Some(file) = Assets::get(&rel) {
        let mime = mime_guess::from_path(&rel).first_or_octet_stream();
        let mut resp = Response::new(Body::from(file.data.into_owned()));
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(mime.as_ref()).unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        );
        return resp;
    }
    match Assets::get("index.html") {
        Some(index) => {
            let mut resp = Response::new(Body::from(index.data.into_owned()));
            resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
            resp
        }
        None => (StatusCode::NOT_FOUND, "frontend not built").into_response(),
    }
}

pub async fn serve(state: AppState) -> anyhow::Result<()> {
    let addr = state.cfg.listen_addr();
    if !state.cfg.path_prefix.is_empty() {
        tracing::info!("subx listening on {} (panel under {}{}/)", addr, addr, state.cfg.path_prefix);
    } else {
        tracing::info!("subx listening on {}", addr);
    }
    if state.cfg.is_default_admin() {
        tracing::warn!("WARNING: admin account is using the default credentials \"admin:admin\" — set the `auth` environment variable to a strong value before exposing this server to the network");
    }
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

#[allow(dead_code)]
fn unused_proxy(_p: &Proxy) {}
