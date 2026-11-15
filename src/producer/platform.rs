//! Egern / Surge Mac 平台专有字段的通用透传产出。
//!
//! 对齐 Go 版 `internal/producer/egern.go` / `surgemac.go` 的输出形态，但
//! 专有字段不逐项硬编码：节点上的平台容器（`egern-opts` / `surge-mac-opts`
//! 等）与任何非基础字段统一按键名规则透传到目标平台，避免新增字段时丢失。

use crate::model::Proxy;
use crate::producer::lines;
use crate::util::{base64_encode, get_str, value_str, JMap};
use anyhow::Result;
use serde_json::{json, Value};

const EGERN_TYPES: &[&str] = &[
    "http", "https", "socks5", "ss", "ssr", "trojan", "hysteria2", "vless", "vmess",
    "tuic", "wireguard", "anytls", "ssh", "snell",
];

/// 内部字段（不会下发到任何平台产出）。
const INTERNAL: &[&str] = &[
    "subName", "collectionName", "id", "resolved", "no-resolve", "_resolved",
    "_subName", "_subDisplayName", "_collectionName", "_collectionDisplayName",
    "supported", "_echConfigList", "_h2", "_vcn", "_dns", "_network",
    "_domain_resolver", "_dns_server", "_ech", "_force-query", "_sockopt",
];

/// 基础协议字段：由平台产出器本身负责，不重复进入「专有字段」集合，
/// 但在 Egern 的对象里仍会原样保留。
const BASE: &[&str] = &[
    "type", "name", "server", "port", "password", "cipher", "uuid", "udp", "tls",
    "sni", "skip-cert-verify", "alpn", "client-fingerprint", "network", "flow",
    "plugin", "plugin-opts", "reality-opts", "ech-opts", "xhttp-opts", "ws-opts",
    "h2-opts", "http-opts", "grpc-opts", "httpupgrade-opts", "quic-opts", "smux",
    "obfs", "obfs-password", "up", "down", "protocol", "obfs-param", "protocol-param",
    "username", "ip", "ipv6", "mtu", "private-key", "public-key", "pre-shared-key",
    "reserved", "allowed-ips", "persistent-keepalive", "ports", "auth-str", "token",
    "version", "congestion-controller", "udp-relay-mode", "packet-encoding", "tfo",
    "fast-open", "disable-sni", "dialer-proxy", "detour", "ip-version", "ca", "ca-str",
    "insecure", "uot", "udp-over-tcp", "alterId", "servername", "peer", "encryption",
];

fn containers(platform: &str) -> &'static [&'static str] {
    match platform {
        "egern" => &["egern-opts", "egern", "_egern", "_egernOpts"],
        _ => &[
            "surge-mac-opts", "surgeMacOpts", "_surgemac", "_surgeMac",
            "external-opts", "_externalOpts", "mihomo-opts", "_mihomoOpts",
        ],
    }
}

fn normalize_key(k: &str, platform: &str) -> String {
    let prefix = match platform {
        "egern" => "egern-",
        _ => "surge-mac-",
    };
    let s = k.strip_prefix(prefix).unwrap_or(k);
    s.replace('_', "-")
}

/// 收集平台专有字段：容器优先，其次顶层非基础字段。
pub fn platform_fields(p: &Proxy, platform: &str) -> JMap {
    let mut out = JMap::new();
    for key in containers(platform) {
        if let Some(m) = p.get_map(key) {
            for (k, v) in m {
                out.insert(normalize_key(&k, platform), v.clone());
            }
        }
    }
    let skip: Vec<&str> = containers(platform).to_vec();
    for (k, v) in p.fields() {
        if k.starts_with('_') || INTERNAL.contains(&k.as_str()) || BASE.contains(&k.as_str()) {
            continue;
        }
        if skip.contains(&k.as_str()) {
            continue;
        }
        let nk = normalize_key(k, platform);
        out.entry(nk).or_insert_with(|| v.clone());
    }
    out
}

fn egern_key(typ: &str) -> String {
    match typ {
        "ss" => "shadowsocks",
        "ssr" => "shadowsocksr",
        "https" => "http",
        "hy2" | "hysteria2" => "hysteria2",
        other => other,
    }
    .to_string()
}

pub fn produce_egern(proxies: &[Proxy], _options: Option<&JMap>) -> Result<String> {
    let mut out = String::from("proxies:\n");
    for p in proxies {
        if !EGERN_TYPES.contains(&p.type_().as_str()) {
            continue;
        }
        let mut inner = p.fields().clone();
        inner.remove("type");
        for k in INTERNAL {
            inner.remove(*k);
        }
        // Egern：tls 且无 sni 时把 sni 补成 server（对齐 egern.js）
        if p.get_bool("tls") && get_str(&inner, "sni").trim().is_empty() {
            inner.insert("sni".into(), json!(p.server()));
        }
        // 平台专有字段通用透传（容器字段本身不下发）
        let fields = platform_fields(p, "egern");
        for (k, v) in fields {
            inner.insert(k, v);
        }
        for key in containers("egern") {
            inner.remove(*key);
        }
        let mut wrapped = JMap::new();
        wrapped.insert(egern_key(&p.type_()), Value::Object(inner));
        out.push_str("  - ");
        out.push_str(&serde_json::to_string(&Value::Object(wrapped)).unwrap_or_default());
        out.push('\n');
    }
    Ok(out)
}

fn clean_name(s: &str) -> String {
    s.replace('=', "").replace(',', "").trim().to_string()
}

fn quote(v: &str) -> String {
    if v.contains(',') || v.contains(' ') || v.contains('"') {
        format!("\"{}\"", v.replace('"', "\\\""))
    } else {
        v.to_string()
    }
}

fn opt_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Array(a) => a.iter().map(value_str).collect::<Vec<_>>().join(","),
        Value::Object(_) => value.to_string(),
    }
}

/// `external` 行：基础字段按 Go 顺序输出，其余专有字段通用透传。
fn external_line(p: &Proxy, fields: &JMap) -> String {
    // 通用透传：平台容器字段与顶层字段合并后统一读取
    let mut all = p.fields().clone();
    for (k, v) in fields {
        all.insert(k.clone(), v.clone());
    }
    let exec = get_str(&all, "exec");
    let local_port = get_str(&all, "local-port");
    if exec.is_empty() || local_port.is_empty() {
        return String::new();
    }
    let mut line = format!(
        "{} = external,exec=\"{}\",local-port={}",
        clean_name(&p.name()),
        exec,
        local_port
    );
    if let Some(Value::Array(args)) = all.get("args") {
        for a in args {
            line.push_str(&format!(",args=\"{}\"", opt_string(a)));
        }
    }
    if let Some(Value::Array(addrs)) = all.get("addresses") {
        for a in addrs {
            line.push_str(&format!(",addresses={}", opt_string(a)));
        }
    }
    for (key, alias) in [
        ("no-error-alert", "no-error-alert"),
        ("udp", "udp-relay"),
        ("tfo", "tfo"),
        ("test-url", "test-url"),
        ("block-quic", "block-quic"),
    ] {
        if let Some(v) = all.get(key) {
            line.push_str(&format!(",{}={}", alias, opt_string(v)));
        } else if key == "tfo" {
            if let Some(v) = all.get("fast-open") {
                line.push_str(&format!(",tfo={}", opt_string(v)));
            }
        }
    }
    let handled = [
        "exec", "local-port", "args", "addresses", "no-error-alert", "udp", "tfo",
        "fast-open", "test-url", "block-quic", "type", "name", "server", "port",
    ];
    for (k, v) in &all {
        if handled.contains(&k.as_str())
            || k.starts_with('_')
            || INTERNAL.contains(&k.as_str())
            || containers("surge-mac").contains(&k.as_str())
        {
            continue;
        }
        line.push_str(&format!(",{}={}", k.replace('_', "-"), quote(&opt_string(v))));
    }
    line
}

fn mihomo_external_line(p: &Proxy, options: Option<&JMap>, name: &str, exec: &str, local_port: i64) -> String {
    // 用 mihomo 配置块构造 base64 参数（对齐 surgemac.js 的 External Proxy Program）
    let clash_block = crate::producer::clash::produce_clash("mihomo", std::slice::from_ref(p), None)
        .unwrap_or_default();
    let mut proxies: Vec<Value> = Vec::new();
    for line in clash_block.lines().skip(1) {
        let raw = line.trim().trim_start_matches("- ").trim();
        if let Ok(v) = serde_json::from_str::<Value>(raw) {
            proxies.push(v);
        }
    }
    if proxies.is_empty() {
        return String::new();
    }
    let mut config = JMap::new();
    config.insert("mixed-port".into(), json!(local_port));
    config.insert("mode".into(), json!("global"));
    config.insert("proxies".into(), Value::Array(proxies.clone()));
    config.insert(
        "proxy-groups".into(),
        json!([{
            "name": "PROXY",
            "type": "select",
            "proxies": proxies.iter().filter_map(|x| x.get("name")).cloned().collect::<Vec<_>>()
        }]),
    );
    config.insert(
        "dns".into(),
        json!({
            "enable": true,
            "nameserver": ["180.76.76.76", "52.80.52.52", "119.28.28.28", "223.6.6.6"],
            "nameserver-policy": {}
        }),
    );
    if let Some(Value::Object(extra)) = options.and_then(|o| o.get("mihomoConfig")) {
        for (k, v) in extra {
            config.insert(k.clone(), v.clone());
        }
    }
    let b64 = base64_encode(&serde_json::to_string(&Value::Object(config)).unwrap_or_default());
    let mut line = format!(
        "{} = external,exec=\"{}\",local-port={}",
        clean_name(name), exec, local_port
    );
    line.push_str(",args=\"-config\"");
    line.push_str(&format!(",args=\"{}\"", b64));
    line.push_str(",udp-relay=true");
    line
}

fn surge_mac_line(p: &Proxy, options: Option<&JMap>) -> String {
    if p.type_() == "external" {
        let fields = platform_fields(p, "surge-mac");
        return external_line(p, &fields);
    }
    let mihomo_external = options
        .and_then(|o| o.get("mihomoExternal"))
        .map(crate::util::truthy)
        .unwrap_or(false)
        || p.get("_mihomoExternal").map(crate::util::truthy).unwrap_or(false);
    if mihomo_external {
        let local_port = options
            .and_then(|o| o.get("localPort"))
            .map(crate::util::value_i64)
            .filter(|n| *n > 0)
            .unwrap_or_else(|| {
                let v = p.get_i64("_localPort");
                if v > 0 { v.min(65535) } else { 65535 }
            });
        let exec = options
            .and_then(|o| o.get("exec"))
            .map(opt_string)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| p.get_str("exec"));
        let exec = if exec.is_empty() { "mihomo".to_string() } else { exec };
        let line = mihomo_external_line(p, options, &p.name(), &exec, local_port);
        if !line.is_empty() {
            return line;
        }
    }
    // 基础 Surge 行 + 平台专有字段通用透传
    let mut line = lines::produce_surge("surge-mac", std::slice::from_ref(p));
    if line.is_empty() {
        if options.and_then(|o| o.get("useMihomoExternal")).map(crate::util::truthy).unwrap_or(false) {
            return mihomo_external_line(p, options, &p.name(), "mihomo", 65535);
        }
        return String::new();
    }
    for (k, v) in platform_fields(p, "surge-mac") {
        line.push_str(&format!(", {}={}", k, quote(&opt_string(&v))));
    }
    line
}

pub fn produce_surgemac(proxies: &[Proxy], options: Option<&JMap>) -> Result<String> {
    let mut lines_out: Vec<String> = Vec::new();
    for p in proxies {
        let line = surge_mac_line(p, options);
        if !line.is_empty() {
            lines_out.push(line);
        }
    }
    // `_merged` 合并节点（对齐 surgemac.js 的 merged external）
    if let Some(merged) = options.and_then(|o| o.get("_merged")).and_then(|v| v.as_object()) {
        let local_port = options
            .and_then(|o| o.get("localPort"))
            .map(crate::util::value_i64)
            .unwrap_or(0);
        if local_port >= 1 {
            let name = get_str(merged, "name");
            let exec = get_str(merged, "exec");
            let mut config = merged
                .get("config")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            config.insert("mixed-port".into(), json!(local_port));
            let b64 = base64_encode(&serde_json::to_string(&Value::Object(config)).unwrap_or_default());
            let mut line = format!(
                "{} = external,exec=\"{}\",local-port={}",
                clean_name(&name), exec, local_port
            );
            line.push_str(",args=\"-config\"");
            line.push_str(&format!(",args=\"{}\"", b64));
            line.push_str(",udp-relay=true");
            lines_out.push(line);
        }
    }
    Ok(lines_out.join("\n"))
}
