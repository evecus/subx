//! 订阅内容下载：本地内容 / 缓存快照 / 远程 URL 三级回退。

use crate::util::{get_str, JMap};
use anyhow::{anyhow, Result};
use std::time::Duration;

pub const FALLBACK_UA: &str = "clash.meta/v1.19.23";
pub const MAX_DOWNLOAD_SIZE: usize = 16 << 20;

#[derive(Clone)]
pub struct Downloader {
    client: reqwest::Client,
}

impl Downloader {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { client }
    }

    /// 对齐 Go Client.Fetch：content -> cachedContent -> 实时拉取 URL。
    pub async fn fetch(&self, sub: &JMap, default_ua: &str) -> Result<String> {
        let content = get_str(sub, "content");
        if !content.is_empty() {
            return Ok(content);
        }
        let cached = get_str(sub, "cachedContent");
        if !cached.is_empty() {
            return Ok(cached);
        }
        let url = get_str(sub, "url");
        if url.is_empty() {
            return Err(anyhow!("sub has no url"));
        }
        self.fetch_url(&url, &get_str(sub, "ua"), default_ua).await
    }

    /// 实时 GET，绕过缓存。UA 优先级：显式 ua > defaultUA > FallbackUA。
    pub async fn fetch_url(&self, url: &str, ua: &str, default_ua: &str) -> Result<String> {
        let ua = if !ua.is_empty() {
            ua
        } else if !default_ua.is_empty() {
            default_ua
        } else {
            FALLBACK_UA
        };
        let resp = self
            .client
            .get(url)
            .header("User-Agent", ua)
            .header("Accept", "*/*")
            .send()
            .await
            .map_err(|e| anyhow!("fetch {}: {}", url, e))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(anyhow!("unexpected status {} from {}", status.as_u16(), url));
        }
        let bytes = resp.bytes().await?;
        if bytes.len() > MAX_DOWNLOAD_SIZE {
            return Err(anyhow!("subscription content exceeds 16MB"));
        }
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}
