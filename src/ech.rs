//! ECH（Encrypted Client Hello）完整协商。
//!
//! 对齐 Go 版 `internal/parser/xhttp_utils.go`（ech-utils.js）与
//! `internal/producer/normalize.go`：Xray 的 `echConfigList / echForceQuery /
//! echSockopt` 与 mihomo 的 `ech-opts` 双向转换；sing-box 的 PEM 行归一化。

use crate::util::{get_str, JMap};
use regex::Regex;
use serde_json::{json, Value};

const DEFAULT_ECH_DNS: &str = "https://dns.alidns.com/dns-query";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrayEchParsed {
    /// "config"（裸 ECH 配置）或 "dns"（DoH 查询形式）
    pub kind: String,
    pub config: String,
    pub dns: String,
    pub query_server_name: String,
}

/// 解析 Xray `echConfigList`：`ECHCONFIG` 或 `server+https://.../dns-query`。
pub fn parse_xray_ech_config_list(v: Option<&Value>) -> Option<XrayEchParsed> {
    let s = v?.as_str()?.trim();
    if s.is_empty() {
        return None;
    }
    if !s.contains("://") {
        return Some(XrayEchParsed {
            kind: "config".into(),
            config: s.to_string(),
            dns: String::new(),
            query_server_name: String::new(),
        });
    }
    let parts: Vec<&str> = s.split('+').collect();
    match parts.len() {
        1 if !parts[0].trim().is_empty() => Some(XrayEchParsed {
            kind: "dns".into(),
            config: String::new(),
            dns: parts[0].trim().to_string(),
            query_server_name: String::new(),
        }),
        2 if !parts[0].trim().is_empty() && !parts[1].trim().is_empty() => Some(XrayEchParsed {
            kind: "dns".into(),
            config: String::new(),
            dns: parts[1].trim().to_string(),
            query_server_name: parts[0].trim().to_string(),
        }),
        _ => None,
    }
}

pub fn force_query_valid(v: Option<&Value>) -> bool {
    matches!(v.and_then(|x| x.as_str()), Some("none" | "half" | "full"))
}

/// Xray 字段 -> mihomo `ech-opts`（解析器侧）。
pub fn build_mihomo_ech_opts(
    ech_config_list: Option<&Value>,
    force_query: Option<&Value>,
    sockopt: Option<&Value>,
) -> Option<JMap> {
    let parsed = parse_xray_ech_config_list(ech_config_list)?;
    let mut m = JMap::new();
    m.insert("enable".into(), json!(true));
    if parsed.kind == "config" {
        m.insert("config".into(), json!(parsed.config));
    } else {
        m.insert("_dns".into(), json!(parsed.dns));
        if !parsed.query_server_name.is_empty() {
            m.insert("query-server-name".into(), json!(parsed.query_server_name));
        }
    }
    if let Some(v) = force_query {
        if force_query_valid(Some(v)) {
            m.insert("_force-query".into(), v.clone());
        }
    }
    if let Some(v) = sockopt {
        if v.is_object() {
            m.insert("_sockopt".into(), v.clone());
        }
    }
    Some(m)
}

/// mihomo `ech-opts.enable` 语义：bool / 整数 != 0；字符串不转换。
pub fn is_mihomo_ech_enabled(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n
            .as_f64()
            .map(|f| f == f.trunc() && f != 0.0)
            .unwrap_or(false),
        _ => false,
    }
}

/// mihomo `ech-opts` -> Xray TLS 字段（产出器侧）。
pub fn build_xray_ech_fields(ech_opts: Option<&JMap>, fallback: &str) -> JMap {
    let mut out = JMap::new();
    let Some(eo) = ech_opts else {
        if !fallback.is_empty() {
            out.insert("echConfigList".into(), json!(fallback));
        }
        return out;
    };
    if !is_mihomo_ech_enabled(eo.get("enable")) {
        return out;
    }
    let qsn = get_str(eo, "query-server-name");
    let config = get_str(eo, "config");
    let dns = get_str(eo, "_dns");
    let config_list = if !config.is_empty() {
        config
    } else if !dns.is_empty() {
        if qsn.is_empty() {
            dns.clone()
        } else {
            format!("{}+{}", qsn, dns)
        }
    } else if !qsn.is_empty() {
        format!("{}+{}", qsn, DEFAULT_ECH_DNS)
    } else {
        String::new()
    };
    if !config_list.is_empty() {
        out.insert("echConfigList".into(), json!(config_list));
    }
    if let Some(v) = eo.get("_force-query") {
        if force_query_valid(Some(v)) && !config_list.is_empty() {
            out.insert("echForceQuery".into(), v.clone());
        }
    }
    if let Some(v) = eo.get("_sockopt") {
        if v.is_object() && !config_list.is_empty() {
            out.insert("echSockopt".into(), v.clone());
        }
    }
    out
}

pub fn build_xray_ech_config_list(ech_opts: Option<&JMap>, fallback: &str) -> String {
    build_xray_ech_fields(ech_opts, fallback)
        .get("echConfigList")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// sing-box `tls.ech.config`：把字符串/数组归一为 PEM 行数组；
/// 缺少 BEGIN 行时自动包裹 `-----BEGIN/END ECH CONFIGS-----`。
pub fn normalize_pem_lines(v: &Value) -> Option<Vec<Value>> {
    let items: Vec<&Value> = match v {
        Value::Array(a) => a.iter().collect(),
        other => vec![other],
    };
    let mut lines: Vec<String> = Vec::new();
    for item in items {
        let mut s = crate::util::value_str(item).trim().to_string();
        s = s.replace("\\r\\n", "\n").replace("\\n", "\n");
        if s.is_empty() {
            continue;
        }
        s = s.replace("\r\n", "\n");
        for line in s.split('\n') {
            let t = line.trim();
            if !t.is_empty() {
                lines.push(t.to_string());
            }
        }
    }
    if lines.is_empty() {
        return None;
    }
    let begin_re = Regex::new(r"^-----BEGIN [A-Za-z0-9 -]+-----$").ok()?;
    let has_begin = lines.iter().any(|l| begin_re.is_match(l));
    let mut out: Vec<Value> = Vec::with_capacity(lines.len() + 2);
    if !has_begin {
        out.push(json!("-----BEGIN ECH CONFIGS-----"));
    }
    for l in lines {
        out.push(json!(l));
    }
    if !has_begin {
        out.push(json!("-----END ECH CONFIGS-----"));
    }
    Some(out)
}

/// 把 Xray 风格的 `echConfigList` 等字段并入 Proxy（供 JSON/URI 解析共用）。
pub fn absorb_xray_ech(p: &mut crate::model::Proxy, tls: &JMap) {
    if p.get_map("ech-opts").is_some() {
        return;
    }
    if let Some(opts) = build_mihomo_ech_opts(
        tls.get("echConfigList"),
        tls.get("echForceQuery"),
        tls.get("echSockopt"),
    ) {
        p.set_value("ech-opts", Value::Object(opts));
        if let Some(s) = tls.get("echConfigList").and_then(|v| v.as_str()) {
            p.set("_echConfigList", s);
        }
    }
}

/// 从 Proxy 顶层或任意嵌套对象里寻找 Xray ECH 字段并转成 mihomo `ech-opts`。
pub fn absorb_all_ech(p: &mut crate::model::Proxy) {
    if p.get_map("ech-opts").is_some() {
        return;
    }
    let snapshot = p.fields().clone();
    for v in snapshot.values() {
        if let Some(m) = v.as_object() {
            if m.contains_key("echConfigList")
                || m.contains_key("echForceQuery")
                || m.contains_key("echSockopt")
            {
                absorb_xray_ech(p, m);
                return;
            }
        }
    }
    absorb_xray_ech(p, &snapshot);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_ech_roundtrip() {
        let v = json!("ech.example.com+https://1.1.1.1/dns-query");
        let parsed = parse_xray_ech_config_list(Some(&v)).unwrap();
        assert_eq!(parsed.kind, "dns");
        assert_eq!(parsed.query_server_name, "ech.example.com");
        let opts = build_mihomo_ech_opts(Some(&v), Some(&json!("half")), None).unwrap();
        assert_eq!(opts.get("_dns").unwrap(), "https://1.1.1.1/dns-query");
        let fields = build_xray_ech_fields(Some(&opts), "");
        assert_eq!(
            fields.get("echConfigList").unwrap(),
            "ech.example.com+https://1.1.1.1/dns-query"
        );
        assert_eq!(fields.get("echForceQuery").unwrap(), "half");
    }

    #[test]
    fn pem_wrapping() {
        let lines = normalize_pem_lines(&json!("AAA\nBBB")).unwrap();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], "-----BEGIN ECH CONFIGS-----");
        let already = normalize_pem_lines(&json!("-----BEGIN ECH CONFIGS-----\nAAA")).unwrap();
        assert_eq!(already.len(), 2);
    }
}
