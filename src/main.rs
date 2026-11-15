//! Subx —— Sub-Store 订阅转换服务的 Rust 后端重写。

// 保留一批通用工具函数（供后续扩展解析/产出协议使用），不视为死代码。
#![allow(dead_code)]

mod auth;
mod config;
mod downloader;
mod error;
mod ech;
mod model;
mod xhttp;
mod parser;
mod pipeline;
mod producer;
mod processor;
mod ratelimit;
mod scheduler;
mod server;
mod share;
mod store;
mod util;

#[cfg(test)]
mod tests;

use crate::config::Config;
use crate::server::AppState;
use crate::store::Store;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::load();
    let store = Arc::new(Store::open(&cfg.db_path)?);
    let state = AppState::new(cfg, store.clone());

    scheduler::Runner::start(store, state.share.clone());
    server::serve(state).await
}
