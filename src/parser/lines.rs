//! 单行配置解析：Clash 内联 JSON/YAML 对象、Surge / Loon / Quantumult X 行。

use crate::model::Proxy;
use crate::parser::yaml_to_value;
use crate::util::{is_true, value_str, JMap};
use serde_json::{json, Value};
use std::collections::HashMap;

/// Clash 单行：JSON 对象或 YAML map，必须带 type。
pub fn parse_clash_line(line: &str) -> Option<Proxy> {
    let t = line.trim();
    let t = t.strip_prefix('-').unwrap_or(t).trim();
    if t.is_empty() {
        return None;
    }
    let obj: Value = if t.starts_with('{') {
        serde_json::from_str(t).ok()?
    } else {
        yaml_to_value(t)?
    };
    let m = obj.as_object()?;
    let typ = value_str(m.get("type")?).to_lowercase();
    if typ.is_empty() {
        return None;
    }
    let mut p = Proxy::new();
    p.set("type", typ.clone());
    for (k, v) in m {
        match k.as_str() {
            "udp" => p.set("udp", crate::util::truthy(v)),
            "skip-cert-verify" | "allow-insecure" => p.set("skip-cert-verify", crate::util::truthy(v)),
            "port" => p.set("port", crate::util::value_i64(v)),
            "tls" => p.set("tls", crate::util::truthy(v)),
            _ => p.set_value(k, v.clone()),
        }
    }
    if typ == "vmess" && !p.get_str("cipher").is_empty() {
        p.set("cipher", crate::parser::normalize::normalize_vmess_security(&p.get_str("cipher")));
    }
    if p.get_str("name").is_empty() {
        p.set("name", format!("{} {}", typ, p.get_str("server")));
    }
    Some(p)
}

const QX_TYPES: &[&str] = &[
    "ss", "ssr", "vmess", "vless", "trojan", "http", "https", "socks", "socks5",
    "socks5-tls", "tuic", "hysteria", "hysteria2", "hy2", "wireguard", "wg",
    "snell", "anytls", "shadowsocks", "shadowsocksr",
];

fn split_assignment(line: &str) -> Option<(&str, &str)> {
    let mut in_quote = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' | '\'' => in_quote = !in_quote,
            '=' if !in_quote => return Some((&line[..i], &line[i + 1..])),
            _ => {}
        }
    }
    None
}

/// 按逗号切分，保留引号内的逗号；去掉每项首尾空白与包裹引号。
pub fn split_fields(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut quote_char = '"';
    for c in s.chars() {
        if (c == '"' || c == '\'') && (!in_quote || c == quote_char) {
            if in_quote {
                in_quote = false;
            } else {
                in_quote = true;
                quote_char = c;
            }
            cur.push(c);
        } else if c == ',' && !in_quote {
            out.push(cur.trim().to_string());
            cur.clear();
        } else {
            cur.push(c);
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out.into_iter().map(|s| strip_quotes(&s)).collect()
}

pub fn strip_quotes(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2 {
        let first = t.chars().next().unwrap();
        let last = t.chars().last().unwrap();
        if (first == '"' || first == '\'') && first == last {
            return t[1..t.len() - 1].to_string();
        }
    }
    t.to_string()
}

fn parse_kv_fields(fields: &[String]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for f in fields {
        if let Some((k, v)) = split_assignment(f) {
            let key = strip_quotes(k.trim()).to_lowercase();
            let val = strip_quotes(v.trim());
            map.insert(key, val);
        }
    }
    map
}

fn opt<'a>(m: &'a HashMap<String, String>, keys: &[&str]) -> &'a str {
    for k in keys {
        if let Some(v) = m.get(*k) {
            if !v.is_empty() {
                return v.as_str();
            }
        }
    }
    ""
}

/// Surge / Loon / QX 配置行统一入口。
pub fn parse_config_line(line: &str) -> Option<Proxy> {
    let (left, right) = split_assignment(line)?;
    let left = strip_quotes(left.trim());
    if left.is_empty() {
        return None;
    }
    let fields = split_fields(right);
    if fields.is_empty() {
        return None;
    }
    let lk = left.to_lowercase();
    if QX_TYPES.contains(&lk.as_str()) {
        parse_qx(&lk, &fields)
    } else {
        parse_surge_loon(&left, &fields)
    }
}

fn parse_surge_loon(name: &str, fields: &[String]) -> Option<Proxy> {
    let typ = strip_quotes(fields[0].trim()).to_lowercase();
    if fields.len() < 3 {
        return None;
    }
    let server = strip_quotes(fields[1].trim());
    let port = strip_quotes(fields[2].trim()).parse::<i64>().unwrap_or(0);
    let opts = parse_kv_fields(&fields[3..]);
    let mut p = Proxy::new();
    p.set("type", normalize_line_type(&typ));
    p.set("server", server);
    p.set("port", port);
    if !name.is_empty() {
        p.set("name", name);
    }
    p.set("udp", true);
    apply_surge_loon_opts(&mut p, &opts, &typ);
    Some(p)
}

fn parse_qx(typ: &str, fields: &[String]) -> Option<Proxy> {
    let addr = strip_quotes(fields[0].trim());
    let (host, port_s, ok) = crate::util::split_host_port(&addr);
    if !ok {
        return None;
    }
    let opts = parse_kv_fields(&fields[1..]);
    let mut p = Proxy::new();
    p.set("type", normalize_line_type(typ));
    p.set("server", host);
    p.set("port", port_s.parse::<i64>().unwrap_or(0));
    let name = opt(&opts, &["remarks", "remark", "tag", "name"]);
    if !name.is_empty() {
        p.set("name", name);
    }
    p.set("udp", true);
    apply_surge_loon_opts(&mut p, &opts, typ);
    Some(p)
}

fn normalize_line_type(t: &str) -> String {
    match t {
        "shadowsocks" => "ss".into(),
        "shadowsocksr" => "ssr".into(),
        "hy2" | "hysteria2" => "hysteria2".into(),
        "wg" => "wireguard".into(),
        "https" | "http" => "http".into(),
        "socks" | "socks5" | "socks5-tls" => "socks5".into(),
        "trojan-go" => "trojan".into(),
        other => other.to_string(),
    }
}

/// 把 Surge/Loon/QX 行参数映射到统一的 Proxy 字段。
fn apply_surge_loon_opts(p: &mut Proxy, opts: &HashMap<String, String>, typ: &str) {
    let typ = normalize_line_type(typ);
    // 通用认证字段
    let cipher = opt(opts, &["cipher", "encrypt-method", "method", "encryption", "security"]);
    if !cipher.is_empty() {
        p.set("cipher", cipher);
    }
    let password = opt(opts, &["password", "passwd", "auth", "auth-str", "token"]);
    if !password.is_empty() {
        p.set("password", password);
    }
    let uuid = opt(opts, &["username", "uuid", "id", "user"]);
    if !uuid.is_empty() {
        if typ == "vmess" || typ == "vless" || typ == "tuic" {
            p.set("uuid", uuid);
        } else {
            p.set("username", uuid);
        }
    }
    if typ == "vmess" || typ == "vless" {
        let aid = opt(opts, &["alterid", "alter-id", "aid"]);
        if !aid.is_empty() {
            p.set("alterId", aid.parse::<i64>().unwrap_or(0));
        }
        let flow = opt(opts, &["flow", "xtls-flow"]);
        if !flow.is_empty() {
            p.set("flow", flow);
        }
    }
    if typ == "tuic" || typ == "hysteria" || typ == "hysteria2" {
        let ver = opt(opts, &["version", "tuic-version"]);
        if !ver.is_empty() {
            p.set("version", ver);
        }
        let cc = opt(opts, &["congestion-controller", "congestion_control", "congestion-control"]);
        if !cc.is_empty() {
            p.set("congestion-controller", cc);
        }
    }
    for (k, to) in [("up", "up"), ("down", "down"), ("upmbps", "up"), ("downmbps", "down")] {
        let v = opt(opts, &[k]);
        if !v.is_empty() {
            p.set(to, v);
        }
    }
    let ports = opt(opts, &["ports", "port-hopping", "mport"]);
    if !ports.is_empty() {
        p.set("ports", ports);
    }
    let obfs = opt(opts, &["obfs", "obfs-mode"]);
    if !obfs.is_empty() && !matches!(obfs, "none" | "false") {
        p.set("obfs", obfs);
    }
    let obfs_pwd = opt(opts, &["obfs-password", "obfspassword", "obfs_password"]);
    if !obfs_pwd.is_empty() {
        p.set("obfs-password", obfs_pwd);
    }

    // TLS 相关
    let tls_on = opt(opts, &["tls", "over-tls", "secure"]);
    if is_true(tls_on) || opt(opts, &["sni", "servername", "peer"]).len() > 0 && matches!(typ.as_str(), "trojan" | "hysteria2" | "tuic") {
        p.set("tls", true);
    }
    let sni = opt(opts, &["sni", "servername", "peer", "host"]);
    if !sni.is_empty() && !sni.contains(',') {
        p.set("sni", sni);
    }
    let insecure = opt(opts, &["skip-cert-verify", "allow-insecure", "insecure", "allowinsecure"]);
    if !insecure.is_empty() {
        p.set("skip-cert-verify", is_true(insecure));
    }
    let alpn = opt(opts, &["alpn"]);
    if !alpn.is_empty() {
        p.set_value("alpn", crate::parser::arr_of_strings(alpn));
    }
    let fp = opt(opts, &["fp", "client-fingerprint", "fingerprint"]);
    if !fp.is_empty() {
        p.set("client-fingerprint", fp);
    }
    let pbk = opt(opts, &["pbk", "public-key", "reality-public-key"]);
    if !pbk.is_empty() {
        let mut reality = JMap::new();
        reality.insert("public-key".into(), json!(pbk));
        let sid = opt(opts, &["sid", "short-id"]);
        if !sid.is_empty() {
            reality.insert("short-id".into(), json!(sid));
        }
        p.set_value("reality-opts", Value::Object(reality));
        p.set("tls", true);
    }
    let tfo = opt(opts, &["tfo", "fast-open"]);
    if !tfo.is_empty() {
        p.set("tfo", is_true(tfo));
    }

    // 传输层（ws / grpc / h2 / http / xhttp）
    let ws = opt(opts, &["ws", "websocket"]);
    let net = opt(opts, &["network", "net", "transport"]);
    let network = if is_true(ws) { "ws".to_string() } else { net.to_lowercase() };
    if !network.is_empty() && network != "tcp" && network != "false" {
        p.set("network", network.clone());
        let mut top = JMap::new();
        let path = opt(opts, &["ws-path", "path", "service-name", "servicename", "grpc-service-name"]);
        if !path.is_empty() {
            if network == "grpc" {
                top.insert("grpc-service-name".into(), json!(path));
            } else {
                top.insert("path".into(), json!(path));
            }
        }
        let host = opt(opts, &["ws-headers", "headers", "host-header"]);
        if !host.is_empty() {
            let mut headers = JMap::new();
            // 形如 "Host: example.com" 或 "Host=example.com"
            let hv = host.replace(':', "=");
            if let Some((k, v)) = hv.split_once('=') {
                headers.insert(k.trim().to_string(), json!(v.trim()));
            } else {
                headers.insert("Host".into(), json!(host));
            }
            top.insert("headers".into(), Value::Object(headers));
        }
        if !top.is_empty() {
            p.set_value(&format!("{}-opts", network), Value::Object(top));
        }
    }

    // shadow-tls（Surge/Loon 语法）
    let st_ver = opt(opts, &["shadow-tls-version", "shadowtls-version"]);
    let st_sni = opt(opts, &["shadow-tls-sni", "shadowtls-sni"]);
    let st_pwd = opt(opts, &["shadow-tls-password", "shadowtls-password"]);
    if !st_ver.is_empty() || !st_sni.is_empty() || !st_pwd.is_empty() {
        let mut po = JMap::new();
        if !st_ver.is_empty() {
            po.insert("version".into(), json!(st_ver.parse::<i64>().unwrap_or(2)));
        }
        if !st_sni.is_empty() {
            po.insert("host".into(), json!(st_sni));
        }
        if !st_pwd.is_empty() {
            po.insert("password".into(), json!(st_pwd));
        }
        p.set("plugin", "shadow-tls");
        p.set_value("plugin-opts", Value::Object(po));
    }

    // SS 插件（obfs / v2ray-plugin）
    if typ == "ss" {
        let plugin = opt(opts, &["plugin"]);
        if !plugin.is_empty() {
            let mut po = JMap::new();
            let mode = opt(opts, &["obfs", "plugin-mode", "mode"]);
            if !mode.is_empty() {
                po.insert("mode".into(), json!(mode));
            }
            let phost = opt(opts, &["obfs-host", "plugin-host"]);
            if !phost.is_empty() {
                po.insert("host".into(), json!(phost));
            }
            p.set("plugin", if plugin.contains("v2ray") { "v2ray-plugin" } else if plugin.contains("shadow") { "shadow-tls" } else { "obfs" });
            if !po.is_empty() {
                p.set_value("plugin-opts", Value::Object(po));
            }
        }
    }

    // WireGuard
    if typ == "wireguard" {
        for (k, to) in [
            ("private-key", "private-key"), ("public-key", "public-key"),
            ("pre-shared-key", "pre-shared-key"), ("ip", "ip"), ("ipv6", "ipv6"),
            ("mtu", "mtu"), ("keepalive", "persistent-keepalive"),
            ("allowed-ips", "allowed-ips"),
        ] {
            let v = opt(opts, &[k]);
            if !v.is_empty() {
                if to == "mtu" || to == "persistent-keepalive" {
                    p.set(to, v.parse::<i64>().unwrap_or(0));
                } else {
                    p.set(to, v);
                }
            }
        }
    }

    // 其余未识别参数按 kebab-case 透传，避免信息丢失
    for (k, v) in opts {
        if v.is_empty() {
            continue;
        }
        let key = k.replace('_', "-");
        if !p.has(&key) && !is_consumed_key(&key) {
            p.set(&key, v.clone());
        }
    }
}

fn is_consumed_key(k: &str) -> bool {
    matches!(
        k,
        "remarks" | "remark" | "tag" | "name" | "encrypt-method" | "method" | "encryption"
            | "passwd" | "username" | "id" | "user" | "alterid" | "aid" | "skip-cert-verify"
            | "allowinsecure" | "allow-insecure" | "insecure" | "servername" | "peer" | "host"
            | "ws" | "websocket" | "ws-path" | "ws-headers" | "path" | "headers" | "servicename"
            | "service-name" | "grpc-service-name" | "obfs-host" | "obfspassword" | "obfsparam"
            | "protoparam" | "fast-open" | "over-tls" | "secure" | "udp-relay" | "udp"
            | "shadow-tls-version" | "shadow-tls-sni" | "shadow-tls-password" | "plugin"
            | "plugin-mode" | "plugin-host" | "port-hopping" | "mport" | "auth-str" | "token"
    )
}
