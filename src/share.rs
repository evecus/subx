//! 分享 token 生成 / 校验 / 解析，以及订阅节点的获取与预览。

use crate::downloader::Downloader;
use crate::model::{operators_of, string_lines, Proxy};
use crate::pipeline::{self, Request};
use crate::processor::Context;
use crate::store::Store;
use crate::util::{get_bool, get_i64, get_str, merge_into, value_str, JMap};
use anyhow::{anyhow, Result};
use rand::RngCore;
use serde_json::{json, Value};
use std::sync::Arc;

pub fn random_token() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// 构造 token 记录（对齐 Go share.BuildTokenPayload）。
pub fn build_token_payload(kind: &str, name: &str, opts: &JMap) -> JMap {
    let mut t = JMap::new();
    t.insert("token".into(), json!(random_token()));
    t.insert("type".into(), json!(kind));
    t.insert("name".into(), json!(name));
    t.insert("createdAt".into(), json!(crate::util::now_millis()));
    t.insert("usedCount".into(), json!(0));
    let mode = {
        let m = get_str(opts, "mode");
        if m.is_empty() { "duration".to_string() } else { m }
    };
    t.insert("mode".into(), json!(mode.clone()));
    let target = get_str(opts, "target");
    if !target.is_empty() {
        t.insert("target".into(), json!(target));
    }
    match mode.as_str() {
        "duration" => {
            let seconds = get_i64(opts, "seconds");
            let permanent = get_bool(opts, "permanent");
            if permanent || seconds < 0 {
                t.insert("expiresIn".into(), json!("permanent"));
                t.insert("exp".into(), json!(0));
            } else {
                let s = if seconds == 0 { 3600 * 24 * 7 } else { seconds };
                t.insert("expiresIn".into(), json!(format!("{}s", s)));
                t.insert("exp".into(), json!(crate::util::now_millis() + s * 1000));
            }
        }
        "datetime" => {
            let exp = get_i64(opts, "exp");
            if exp > 0 {
                t.insert("exp".into(), json!(exp));
            }
        }
        "count" => {
            let count = get_i64(opts, "count");
            if count > 0 {
                t.insert("count".into(), json!(count));
            }
        }
        _ => {}
    }
    t
}

#[derive(Clone)]
pub struct ShareResolver {
    pub store: Arc<Store>,
    pub downloader: Downloader,
}

impl ShareResolver {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store, downloader: Downloader::new() }
    }

    fn default_ua(&self) -> String {
        self.store.get_settings().ok().map(|s| get_str(&s, "defaultUserAgent")).unwrap_or_default()
    }

    pub fn lookup(&self, token: &str) -> Result<Option<JMap>> {
        self.store.get_token(token)
    }

    /// 订阅原文本：content -> cachedContent -> URL 实时拉取。
    pub async fn fetch_sub(&self, sub: &JMap) -> Result<String> {
        self.downloader.fetch(sub, &self.default_ua()).await
    }

    /// 绕过缓存、强制实时拉取（保存 / 手动更新 / cron 用）。
    pub async fn fetch_live(&self, sub: &JMap) -> Result<String> {
        let url = get_str(sub, "url");
        if url.is_empty() {
            return Err(anyhow!("订阅没有 URL"));
        }
        self.downloader.fetch_url(&url, &get_str(sub, "ua"), &self.default_ua()).await
    }

    pub async fn preview_sub(&self, sub: &JMap) -> Result<Vec<Proxy>> {
        let raw = self.fetch_sub(sub).await?;
        Ok(pipeline::parse(&raw))
    }

    /// 单个订阅：解析 + 打源标签 + 应用订阅自身的 process。
    pub async fn sub_proxies(&self, sub: &JMap) -> Result<Vec<Proxy>> {
        let raw = self.fetch_sub(sub).await?;
        let mut proxies = pipeline::parse(&raw);
        let name = get_str(sub, "name");
        let display = get_str(sub, "displayName");
        for p in &mut proxies {
            p.set("_subName", name.clone());
            p.set("_subDisplayName", display.clone());
        }
        crate::processor::apply(proxies, &operators_of(sub), &Context::default())
    }

    /// 组合订阅：按顺序合并各子订阅（各自 process 已应用），失败的跳过。
    pub async fn collection_proxies(&self, col: &JMap) -> Result<Vec<Proxy>> {
        let names = crate::util::get_str_array(col, "subscriptions");
        let mut out = Vec::new();
        for name in names {
            let rec = match self.store.get_sub(&name) {
                Ok(Some(r)) => r,
                _ => continue,
            };
            if let Ok(mut ps) = self.sub_proxies(&rec).await {
                out.append(&mut ps);
            }
        }
        let cname = get_str(col, "name");
        let cdisplay = get_str(col, "displayName");
        for p in &mut out {
            p.set("_collectionName", cname.clone());
            p.set("_collectionDisplayName", cdisplay.clone());
        }
        Ok(out)
    }

    /// “从订阅添加节点”操作符的后端查找。
    pub async fn lookup_artifact_proxies(&self, kind: &str, name: &str) -> Result<Vec<Proxy>> {
        if matches!(kind, "collection" | "col") {
            let rec = self.store.get_collection(name)?
                .ok_or_else(|| anyhow!("找不到组合订阅 {}", name))?;
            let mut proxies = self.collection_proxies(&rec).await?;
            if proxies.is_empty() {
                return Err(anyhow!("组合订阅 {} 中不含有效节点", name));
            }
            proxies = crate::processor::apply(proxies, &operators_of(&rec), &Context::default())?;
            Ok(proxies)
        } else {
            let rec = self.store.get_sub(name)?
                .ok_or_else(|| anyhow!("找不到订阅 {}", name))?;
            let proxies = self.sub_proxies(&rec).await?;
            if proxies.is_empty() {
                return Err(anyhow!("订阅 {} 中不含有效节点", name));
            }
            Ok(proxies)
        }
    }

    /// 校验 token 并（count 模式）原子递增使用次数，供纯文件分享使用。
    pub fn check_and_consume(&self, token: &str) -> Result<()> {
        let rec = self.lookup(token)?.ok_or_else(|| anyhow!("invalid token"))?;
        if !crate::model::token_usable(&rec) {
            return Err(anyhow!("token expired"));
        }
        self.consume(token, &rec)
    }

    fn consume(&self, token: &str, rec: &JMap) -> Result<()> {
        if get_str(rec, "mode") == "count" {
            let mut updated = rec.clone();
            updated.insert("usedCount".into(), json!(get_i64(rec, "usedCount") + 1));
            self.store.update_token(&updated)?;
        }
        let _ = token;
        Ok(())
    }

    /// 解析分享下载：校验 token -> 产出目标格式 -> 消耗次数。
    pub async fn resolve(&self, token: &str, target: &str) -> Result<String> {
        let rec = self.lookup(token)?.ok_or_else(|| anyhow!("invalid token"))?;
        if !crate::model::token_usable(&rec) {
            return Err(anyhow!("token expired"));
        }
        let operators = crate::model::operators_of(&rec);
        let prepend = string_lines(&rec, "prependLines");
        let append = string_lines(&rec, "appendLines");

        let body = match get_str(&rec, "type").as_str() {
            "sub" => {
                let name = get_str(&rec, "name");
                let sub = self.store.get_sub(&name)?
                    .ok_or_else(|| anyhow!("subscription {:?} not found", name))?;
                let raw = self.fetch_sub(&sub).await?;
                pipeline::process(&Request {
                    raw,
                    target: target.to_string(),
                    operators,
                    prepend_lines: prepend,
                    append_lines: append,
                    ..Default::default()
                })?
            }
            "col" => {
                let name = get_str(&rec, "name");
                let col = self.store.get_collection(&name)?
                    .ok_or_else(|| anyhow!("组合订阅 {:?} 不存在", name))?;
                let proxies = self.collection_proxies(&col).await?;
                if proxies.is_empty() {
                    return Err(anyhow!("组合订阅 {} 中不含有效节点", name));
                }
                pipeline::process_proxies(proxies, target, None, &operators, &prepend, &append)?
            }
            other => return Err(anyhow!("unsupported token type: {}", other)),
        };
        self.consume(token, &rec)?;
        Ok(body)
    }

    /// 把实时拉取的内容写入订阅记录的缓存字段并持久化。
    pub async fn refresh_cache(&self, sub: &JMap, name: &str) -> Result<i64> {
        let content = self.fetch_live(sub).await?;
        let mut rec = self.store.get_sub(name)?.unwrap_or_else(|| sub.clone());
        merge_into(&mut rec, &{
            let mut m = JMap::new();
            m.insert("cachedContent".into(), Value::String(content));
            m.insert("cachedAt".into(), json!(crate::util::now_millis()));
            m
        });
        self.store.upsert_sub(name, &rec, "bottom")?;
        Ok(crate::util::get_i64(&rec, "cachedAt"))
    }
}

#[allow(dead_code)]
fn unused_value(v: &Value) -> String { value_str(v) }
