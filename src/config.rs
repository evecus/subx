//! 运行期配置，全部来自环境变量（对齐 Go internal/config/config.go）。

use rand::RngCore;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub path_prefix: String,
    pub data_dir: String,
    pub db_path: String,
    pub jwt_secret: String,
    pub token_ttl_hours: i64,
    pub admin_username: String,
    pub admin_password: String,
}

fn getenv(key: &str, fallback: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => fallback.to_string(),
    }
}

fn getenv_int(key: &str, fallback: i64) -> i64 {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v.trim().parse().unwrap_or(fallback),
        _ => fallback,
    }
}

/// 规范化 URL 前缀：保证以 '/' 开头、不以 '/' 结尾，压缩连续的 '/'。
pub fn normalize_path_prefix(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() || raw == "/" {
        return String::new();
    }
    let parts: Vec<&str> = raw
        .split(|c: char| c == '/' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .collect();
    if parts.is_empty() {
        return String::new();
    }
    format!("/{}", parts.join("/"))
}

/// auth = "username:password"；同时兼容 README 里的 user / password 两个变量。
fn parse_auth() -> (String, String) {
    let raw = getenv("auth", "admin:admin");
    if raw != "admin:admin" {
        if let Some((u, p)) = raw.split_once(':') {
            if !u.is_empty() && !p.is_empty() {
                return (u.to_string(), p.to_string());
            }
        }
        return ("admin".to_string(), "admin".to_string());
    }
    let user = getenv("user", "admin");
    let pass = getenv("password", "admin");
    (user, pass)
}

fn load_or_create_jwt_secret(data_dir: &str) -> String {
    if let Ok(v) = std::env::var("jwt_secret") {
        if !v.is_empty() {
            return v;
        }
    }
    let path = Path::new(data_dir).join("jwt_secret");
    if let Ok(b) = std::fs::read(&path) {
        if !b.is_empty() {
            return String::from_utf8_lossy(&b).to_string();
        }
    }
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    let secret = buf.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    if std::fs::create_dir_all(data_dir).is_ok() {
        let _ = std::fs::write(&path, secret.as_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
    secret
}

impl Config {
    pub fn load() -> Self {
        let data_dir = getenv("data_dir", "./data");
        let (admin_username, admin_password) = parse_auth();
        Self {
            host: getenv("host", "0.0.0.0"),
            port: getenv_int("port", 3000) as u16,
            path_prefix: normalize_path_prefix(&getenv("base_path", "")),
            db_path: Path::new(&data_dir).join("subx.db").to_string_lossy().to_string(),
            jwt_secret: load_or_create_jwt_secret(&data_dir),
            data_dir,
            token_ttl_hours: getenv_int("token_ttl_hours", 24 * 7),
            admin_username,
            admin_password,
        }
    }

    pub fn listen_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn is_default_admin(&self) -> bool {
        self.admin_username == "admin" && self.admin_password == "admin"
    }
}
