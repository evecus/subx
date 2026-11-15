//! 进程内固定窗口限流（对齐 Go internal/server/ratelimit.go）。

use axum::extract::connect_info::ConnectInfo;
use axum::http::Request;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Visitor {
    count: usize,
    window_end: Instant,
}

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, Visitor>>>,
    limit: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            limit,
            window,
        }
    }

    /// 返回 (是否允许, 距离窗口重置剩余秒数)。
    pub fn allow(&self, key: &str) -> (bool, i64) {
        let mut map = self.inner.lock();
        let now = Instant::now();
        // 惰性清理过期项，避免后台任务依赖
        if map.len() > 512 {
            map.retain(|_, v| now <= v.window_end);
        }
        let v = map.entry(key.to_string()).or_insert_with(|| Visitor {
            count: 0,
            window_end: now + self.window,
        });
        if now > v.window_end {
            v.count = 0;
            v.window_end = now + self.window;
        }
        v.count += 1;
        let remaining = v.window_end.saturating_duration_since(now).as_secs() as i64;
        (v.count <= self.limit, remaining)
    }

    pub fn reset(&self, key: &str) {
        self.inner.lock().remove(key);
    }
}

/// 从 axum 注入的 ConnectInfo 取客户端 IP（对齐 gin 默认不信任代理头的行为）。
pub fn client_ip<B>(req: &Request<B>) -> String {
    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        return addr.ip().to_string();
    }
    "unknown".to_string()
}
