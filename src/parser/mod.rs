//! 订阅解析器：预处理（base64 / SSD / Clash YAML / FullConfig）与逐行节点解析。
//! 统一产出 crate::model::Proxy（mihomo 风格的动态字段对象）。

pub mod lines;
pub mod normalize;
pub mod uri;

use crate::model::Proxy;
use crate::util::{base64_decode, base64_encode, query_escape, JMap};
use once_cell_lite::Lazy;
use regex::Regex;
use serde_json::{json, Value};

// 用简化的一次性静态正则，避免重复编译
mod once_cell_lite {
    pub struct Lazy<T> {
        cell: std::sync::OnceLock<T>,
        init: fn() -> T,
    }
    impl<T> Lazy<T> {
        pub const fn new(init: fn() -> T) -> Self {
            Self { cell: std::sync::OnceLock::new(), init }
        }
        pub fn get(&self) -> &T {
            self.cell.get_or_init(self.init)
        }
    }
    impl<T> std::ops::Deref for Lazy<T> {
        type Target = T;
        fn deref(&self) -> &T { self.get() }
    }
}

static DECODED_CONTENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^\w+(?:://|\s*?=\s*?)\w+").unwrap());
static URI_PROTOCOL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?im)^\w+://\w+").unwrap());
static SHORT_ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"short-id:([ \t]*[^#\n,}]*)").unwrap());
static FULL_CONFIG_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?im)(?:^\[server_local|Proxy\])([\s\S]+?)^\[.+?\](\r?\n|$)").unwrap());
static FULL_CONFIG_TEST_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^(\[server_local\]|\[Proxy\])").unwrap());

const BASE64_MARKERS: &[&str] = &[
    "dm1lc3M", "c3NyOi8v", "c29ja3M6Ly", "dHJvamFu", "c3M6Ly", "c3NkOi8v",
    "c2hhZG93", "aHR0c", "dmxlc3M=", "aHlzdGVyaWEy", "aHkyOi8v", "d2lyZWd1YXJkOi8v",
    "d2c6Ly8=", "dHVpYzovLw==",
];

pub fn yaml_to_value(raw: &str) -> Option<Value> {
    serde_yaml::from_str::<Value>(raw).ok()
}

/// 对齐 Go normalizeClashYaml：强制给 short-id 加引号，避免 YAML 把 08/0088 当数字。
fn normalize_clash_yaml(raw: &str) -> String {
    if !raw.contains("proxies:") || !raw.contains("short-id:") {
        return raw.to_string();
    }
    if yaml_to_value(raw).is_none() {
        return raw.to_string();
    }
    SHORT_ID_RE
        .replace_all(raw, |caps: &regex::Captures| {
            let value = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let t = value.trim();
            if t.is_empty() {
                return "short-id: \"\"".to_string();
            }
            if t.len() >= 2
                && ((t.starts_with('\'') && t.ends_with('\'')) || (t.starts_with('"') && t.ends_with('"')))
            {
                return format!("short-id: {}", t);
            }
            if t == "null" {
                return "short-id: null".to_string();
            }
            format!("short-id: \"{}\"", t)
        })
        .to_string()
}

/// 检测订阅格式并把原始文本规范化为「一行一个节点」的形式。
pub fn preprocess(raw: &str) -> String {
    // 1. HTML 页面 —— 明确不是订阅
    if raw.starts_with("<!DOCTYPE html>") || raw.starts_with("<!doctype html>") {
        return String::new();
    }

    // 2. Clash YAML（含 proxies: 数组）
    if raw.contains("proxies") {
        let normalized = normalize_clash_yaml(raw);
        if let Some(doc) = yaml_to_value(&normalized) {
            let has_proxies = doc.get("proxies").and_then(|v| v.as_array()).is_some();
            let has_groups = doc.get("proxy-groups").and_then(|v| v.as_array()).is_some();
            if has_proxies || has_groups {
                let mut out = Vec::new();
                if let Some(arr) = doc.get("proxies").and_then(|v| v.as_array()) {
                    for p in arr {
                        if p.is_object() {
                            out.push(p.to_string());
                        }
                    }
                }
                return out.join("\n");
            }
        }
    }

    // 3. 已知 base64 订阅
    if !URI_PROTOCOL_RE.is_match(raw) && BASE64_MARKERS.iter().any(|k| raw.contains(k)) {
        if let Some(decoded) = base64_decode(raw) {
            if DECODED_CONTENT_RE.is_match(&decoded) {
                return decoded;
            }
        }
    }

    // 4. SSD
    if let Some(payload) = raw.strip_prefix("ssd://") {
        return ssd_parse(payload).unwrap_or_else(|| raw.to_string());
    }

    // 5. 完整配置（[server_local] / [Proxy] 段）
    if FULL_CONFIG_TEST_RE.is_match(raw) {
        if let Some(caps) = FULL_CONFIG_RE.captures(raw) {
            return caps.get(1).map(|m| m.as_str()).unwrap_or(raw).to_string();
        }
    }

    // 6. 兜底 base64
    if let Some(decoded) = base64_decode(raw) {
        if DECODED_CONTENT_RE.is_match(&decoded) {
            return decoded;
        }
    }
    raw.to_string()
}

fn ssd_parse(payload: &str) -> Option<String> {
    let info = base64_decode(payload)?;
    let doc: Value = match serde_json::from_str(&info) {
        Ok(v) => v,
        Err(_) => crate::util::json_loose(&info).unwrap_or(Value::Null),
    };
    let obj = doc.as_object()?;
    let default_port = crate::util::value_i64(obj.get("port").unwrap_or(&Value::Null));
    let method = crate::util::get_str(obj, "encryption");
    let password = crate::util::get_str(obj, "password");
    let servers = obj.get("servers")?.as_array()?;
    let mut lines = Vec::new();
    for (i, srv) in servers.iter().enumerate() {
        let m = srv.as_object()?;
        let cipher = {
            let v = crate::util::get_str(m, "encryption");
            if v.is_empty() { method.clone() } else { v }
        };
        let pwd = {
            let v = crate::util::get_str(m, "password");
            if v.is_empty() { password.clone() } else { v }
        };
        let port = {
            let v = crate::util::get_i64(m, "port");
            if v > 0 { v } else { default_port }
        };
        let tag = {
            let v = crate::util::get_str(m, "remarks");
            if v.is_empty() { i.to_string() } else { v }
        };
        let userinfo = base64_encode(&format!("{}:{}", cipher, pwd));
        let mut line = format!("ss://{}@{}:{}", userinfo, crate::util::get_str(m, "server"), port);
        let plugin = crate::util::get_str(m, "plugin");
        let plugin_opts = crate::util::get_str(m, "plugin_options");
        if !plugin_opts.is_empty() {
            line.push_str(&format!("/?plugin={}", query_escape(&format!("{};{}", plugin, plugin_opts))));
        }
        line.push_str(&format!("#{}", tag));
        lines.push(line);
    }
    Some(lines.join("\n"))
}

/// 完整流水线入口：预处理 + 解析。
pub fn parse(raw: &str) -> Vec<Proxy> {
    parse_text(&preprocess(raw))
}

/// 逐行解析，跳过无法识别的行。
pub fn parse_text(raw: &str) -> Vec<Proxy> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(mut p) = parse_line(line) {
            // 统一吸收 Xray 风格（echConfigList / echForceQuery / echSockopt）字段
            crate::ech::absorb_all_ech(&mut p);
            // 对齐 Sub-Store parseAll：hysteria2 带 obfs 但无 obfs-password 的节点丢弃
            if p.type_() == "hysteria2"
                && !p.get_str("obfs").is_empty()
                && p.get_str("obfs-password").is_empty()
            {
                continue;
            }
            out.push(p);
        }
    }
    out
}

fn parse_line(line: &str) -> Option<Proxy> {
    // URI 形态：scheme://...
    if let Some((scheme, _)) = line.split_once("://") {
        if !scheme.is_empty()
            && scheme.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
        {
            if let Some(p) = uri::parse_uri(line) {
                return Some(normalize::normalize_proxy(p));
            }
        }
    }
    // Clash 内联 JSON / YAML 对象
    if let Some(p) = lines::parse_clash_line(line) {
        return Some(normalize::normalize_proxy(p));
    }
    // Surge / Loon / QX 配置行
    if let Some(p) = lines::parse_config_line(line) {
        return Some(normalize::normalize_proxy(p));
    }
    None
}

/// 工具：把 JSON 对象值插入 Proxy 字段（跳过 null）。
pub fn set_from_obj(p: &mut Proxy, obj: &JMap) {
    for (k, v) in obj {
        if !v.is_null() {
            p.set_value(k, v.clone());
        }
    }
}

pub fn arr_of_strings(v: &str) -> Value {
    let parts: Vec<Value> = v
        .split(',')
        .map(|s| json!(s.trim()))
        .filter(|s| s.as_str().map(|x| !x.is_empty()).unwrap_or(false))
        .collect();
    Value::Array(parts)
}
