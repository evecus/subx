//! 公共工具函数：base64、URL 编解码、查询串解析、JSON 数值/字符串转换等。
//! 行为对齐 Go 版 internal/parser/util.go 与 internal/model/proxy.go。

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use percent_encoding::percent_decode_str;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub type JMap = Map<String, Value>;

pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// 尝试标准 / URL-safe / 无填充四种 base64 变体解码。
pub fn base64_decode(s: &str) -> Option<String> {
    let s = s.trim();
    let attempts = [
        STANDARD.decode(s),
        URL_SAFE.decode(s),
        STANDARD_NO_PAD.decode(s),
        URL_SAFE_NO_PAD.decode(s),
    ];
    for b in attempts.into_iter().flatten() {
        if let Ok(text) = String::from_utf8(b) {
            return Some(text);
        }
    }
    None
}

pub fn base64_decode_or_self(s: &str) -> String {
    base64_decode(s).unwrap_or_else(|| s.to_string())
}

pub fn base64_encode(s: &str) -> String {
    STANDARD.encode(s.as_bytes())
}

pub fn base64_encode_bytes(b: &[u8]) -> String {
    STANDARD.encode(b)
}

/// 等价于 Go 的 url.PathUnescape：'+' 不转成空格。非法转义保持原样。
pub fn url_decode(s: &str) -> String {
    let decoded = percent_decode_str(s).decode_utf8_lossy().to_string();
    // decode_utf8_lossy 对非法 % 序列会保留原字符，语义与 PathUnescape 相近
    decoded
}

/// 等价于 Go 的 url.QueryUnescape：'+' -> 空格。
pub fn query_decode(s: &str) -> String {
    let replaced = s.replace('+', " ");
    percent_decode_str(&replaced).decode_utf8_lossy().to_string()
}

/// 等价于 Go 的 url.QueryEscape（form 编码，空格 -> '+'）。
pub fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// 等价于 Go 的 url.PathEscape（空格 -> %20，'+' 也编码）。
pub fn path_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// 解析查询串为 key -> value（value 已按 QueryUnescape 解码）。
pub fn parse_query(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    let q = query.strip_prefix('?').unwrap_or(query);
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, val) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        params.insert(key.to_string(), query_decode(val));
    }
    params
}

/// 拆分 host:port，支持 IPv6 方括号。
pub fn split_host_port(hostport: &str) -> (String, String, bool) {
    let s = hostport.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(idx) = rest.find(']') {
            let host = rest[..idx].to_string();
            let tail = &rest[idx + 1..];
            let port = tail.strip_prefix(':').unwrap_or("").to_string();
            return (host, port, true);
        }
        return (s.to_string(), String::new(), false);
    }
    match s.rfind(':') {
        Some(idx) => (s[..idx].to_string(), s[idx + 1..].to_string(), true),
        None => (s.to_string(), String::new(), false),
    }
}

pub fn parse_ip(s: &str) -> Option<IpAddr> {
    s.trim_matches(|c| c == '[' || c == ']').parse().ok()
}

pub fn is_ip(s: &str) -> bool {
    parse_ip(s).is_some()
}

pub fn is_ipv4(s: &str) -> bool {
    matches!(parse_ip(s), Some(IpAddr::V4(_)))
}

pub fn is_ipv6(s: &str) -> bool {
    matches!(parse_ip(s), Some(IpAddr::V6(_)))
}

/// 对齐 Go model.Proxy.GetString / producer 的 str()：任意 JSON 值转字符串。
pub fn value_str(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Array(_) | Value::Object(_) => v.to_string(),
    }
}

pub fn get_str(m: &JMap, key: &str) -> String {
    match m.get(key) {
        Some(v) => value_str(v),
        None => String::new(),
    }
}

/// 对齐 Go model.Proxy.GetInt：数字 / 数字字符串都能取。
pub fn value_i64(v: &Value) -> i64 {
    match v {
        Value::Number(n) => n.as_i64().unwrap_or_else(|| n.as_f64().unwrap_or(0.0) as i64),
        Value::String(s) => s.trim().parse::<i64>().unwrap_or_else(|_| {
            s.trim().parse::<f64>().unwrap_or(0.0) as i64
        }),
        Value::Bool(b) => {
            if *b {
                1
            } else {
                0
            }
        }
        _ => 0,
    }
}

pub fn get_i64(m: &JMap, key: &str) -> i64 {
    m.get(key).map(value_i64).unwrap_or(0)
}

pub fn get_bool(m: &JMap, key: &str) -> bool {
    match m.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true" || s == "1",
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0) != 0.0,
        _ => false,
    }
}

pub fn get_map(m: &JMap, key: &str) -> Option<JMap> {
    m.get(key).and_then(|v| v.as_object()).cloned()
}

pub fn get_array(m: &JMap, key: &str) -> Option<Vec<Value>> {
    m.get(key).and_then(|v| v.as_array()).cloned()
}

pub fn get_str_array(m: &JMap, key: &str) -> Vec<String> {
    get_array(m, key)
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect()
}

/// 对齐 Go 的 jsTruthy：JS 语义的真值判断。
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().unwrap_or(0.0) != 0.0,
        Value::String(s) => !s.is_empty() && s != "0" && s != "false",
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

pub fn as_map(v: &Value) -> JMap {
    v.as_object().cloned().unwrap_or_default()
}

pub fn to_slice(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::Null => vec![],
        other => vec![other.clone()],
    }
}

pub fn to_string_slice(v: &Value) -> Vec<String> {
    to_slice(v).iter().map(value_str).filter(|s| !s.is_empty()).collect()
}

/// 宽松 JSON 解析：去掉 // 注释与尾随逗号后重试。
pub fn json_loose(s: &str) -> Option<Value> {
    if let Ok(v) = serde_json::from_str::<Value>(s) {
        return Some(v);
    }
    let mut cleaned = String::new();
    for line in s.lines() {
        let t = line.trim_start();
        if t.starts_with("//") {
            continue;
        }
        cleaned.push_str(line);
        cleaned.push('\n');
    }
    // 去掉对象/数组最后一个元素后的逗号
    let re = regex::Regex::new(r",(\s*[}\]])").ok()?;
    let cleaned = re.replace_all(&cleaned, "$1").to_string();
    serde_json::from_str::<Value>(&cleaned).ok()
}

pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// 把 src 的所有键覆盖写入 dst（对齐 Go 的 PATCH 合并语义）。
pub fn merge_into(dst: &mut JMap, src: &JMap) {
    for (k, v) in src {
        dst.insert(k.clone(), v.clone());
    }
}

pub fn join_nonempty(lines: &[String]) -> String {
    lines
        .iter()
        .filter(|l| !l.trim().is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

/// 从任意 Value 中取字符串切片（用于操作符参数）。
pub fn args_get_str(args: &Value, key: &str) -> String {
    args.as_object()
        .map(|m| get_str(m, key))
        .unwrap_or_default()
}

pub fn args_get_bool(args: &Value, key: &str, default: bool) -> bool {
    match args.as_object().and_then(|m| m.get(key)) {
        Some(v) => truthy(v),
        None => default,
    }
}

pub fn args_get_i64(args: &Value, key: &str, default: i64) -> i64 {
    match args.as_object().and_then(|m| m.get(key)) {
        Some(v) => value_i64(v),
        None => default,
    }
}

pub fn is_true(s: &str) -> bool {
    let s = s.trim().to_lowercase();
    matches!(s.as_str(), "true" | "1" | "yes" | "on")
}

/// 统一小写并去空白。
pub fn lower(s: &str) -> String {
    s.trim().to_lowercase()
}
