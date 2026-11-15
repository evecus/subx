//! 解析后的字段规范化，对齐 Go 版 parser/normalize.go 的 lastParse 逻辑。

use crate::model::Proxy;
use crate::util::{is_ip, truthy, value_str, JMap};
use serde_json::{json, Value};

pub fn normalize_proxy(mut p: Proxy) -> Proxy {
    normalize_opt_keys(&mut p);

    // udp 统一为 bool，默认 true
    let udp = match p.get("udp") {
        Some(Value::String(s)) => !matches!(s.to_lowercase().as_str(), "false" | "off" | "0"),
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0) != 0.0,
        _ => true,
    };
    p.set("udp", udp);

    // 类型统一小写
    let typ = p.type_().trim().to_lowercase();
    p.set("type", typ.clone());

    if let Some(c) = p.get("cipher").cloned() {
        p.set("cipher", value_str(&c).to_lowercase());
    }
    if let Some(Value::Number(_)) = p.get("password") {
        let s = p.get_str("password");
        p.set("password", s);
    }
    if typ == "ss" && p.get_str("cipher") == "none" && !truthy(p.get("password").unwrap_or(&Value::Null)) {
        p.set("password", "");
    }
    if p.has("interface") {
        let v = p.get("interface").cloned().unwrap_or(Value::Null);
        p.set_value("interface-name", v);
        p.delete("interface");
    }
    let port = p.port();
    if port > 0 {
        p.set("port", port);
    }
    let server = p.get_str("server").trim().trim_start_matches('[').trim_end_matches(']').to_string();
    if !server.is_empty() {
        p.set("server", server);
    }

    // servername / dialer-proxy / benchmark 等别名
    if (typ == "vmess" || typ == "vless") && !p.get_str("servername").is_empty() {
        let sni = p.get_str("servername");
        p.set("sni", sni);
        p.delete("servername");
    }
    for (from, to) in [
        ("server-cert-fingerprint", "tls-fingerprint"),
        ("fingerprint", "tls-fingerprint"),
        ("dialer-proxy", "underlying-proxy"),
        ("benchmark-url", "test-url"),
        ("benchmark-timeout", "test-timeout"),
    ] {
        if let Some(v) = p.get(from).cloned() {
            if !v.is_null() && value_str(&v) != "" {
                if to == "tls-fingerprint" && p.get_str("tls-fingerprint").is_empty() {
                    p.set_value(to, v);
                } else if to != "tls-fingerprint" {
                    p.set_value(to, v);
                }
            }
        }
    }
    if typ == "vmess" {
        if !p.get_str("cipher").is_empty() {
            p.set("cipher", normalize_vmess_security(&p.get_str("cipher")));
        }
    }

    // shadow-tls-opts -> plugin
    if matches!(typ.as_str(), "vmess" | "vless" | "trojan" | "anytls") {
        if let Some(opts) = p.get_map("shadow-tls-opts") {
            let mut plugin_opts = JMap::new();
            if !p.get_str("sni").is_empty() {
                plugin_opts.insert("host".into(), json!(p.get_str("sni")));
            }
            for k in ["password", "version"] {
                if let Some(v) = opts.get(k) {
                    plugin_opts.insert(k.into(), v.clone());
                }
            }
            p.set("plugin", "shadow-tls");
            p.set_value("plugin-opts", Value::Object(plugin_opts));
            p.delete("shadow-tls-opts");
        }
    }
    if p.get_str("plugin") == "shadow-tls" {
        if let Some(mut opts) = p.get_map("plugin-opts") {
            if let Some(alpn) = p.get("alpn").cloned() {
                if truthy(&alpn) && !opts.contains_key("alpn") {
                    opts.insert("alpn".into(), alpn);
                    p.set_value("plugin-opts", Value::Object(opts));
                }
            }
            p.delete("alpn");
        }
    }

    // network 默认值
    match typ.as_str() {
        "trojan" | "vmess" | "vless" => {
            if !p.has("network") {
                p.set("network", "tcp");
            }
            if typ == "vmess" && !p.has("cipher") {
                p.set("cipher", "none");
            }
            if typ == "vmess" && !p.has("alterId") {
                p.set("alterId", 0);
            }
        }
        _ => {}
    }

    // 强制开启 tls 的协议
    if matches!(
        typ.as_str(),
        "trojan" | "tuic" | "hysteria" | "hysteria2" | "juicity" | "anytls" | "trusttunnel"
            | "h2-connect" | "naive" | "masque" | "shadowquic"
    ) {
        p.set("tls", true);
    }

    // ws-path / ws-headers -> ws-opts
    if p.get_str("network") == "ws" {
        if !p.has("ws-opts") && (p.has("ws-path") || p.has("ws-headers")) {
            let mut opts = JMap::new();
            if let Some(v) = p.get("ws-path").cloned() { opts.insert("path".into(), v); }
            if let Some(v) = p.get("ws-headers").cloned() { opts.insert("headers".into(), v); }
            p.set_value("ws-opts", Value::Object(opts));
        }
        p.delete("ws-path");
        p.delete("ws-headers");
    }

    // 传输层 opts 归一化
    let network = p.get_str("network");
    if !network.is_empty() {
        let key = format!("{}-opts", network);
        if let Some(mut opts) = p.get_map(&key) {
            if let Some(path) = opts.get("path").cloned() {
                opts.insert("path".into(), normalize_transport_path(&path));
            }
            // host -> Host（非 h2）
            if network != "h2" {
                if let Some(Value::Object(mut headers)) = opts.get("headers").cloned() {
                    if !headers.contains_key("Host") {
                        if let Some(v) = headers.remove("host") {
                            headers.insert("Host".into(), v);
                            opts.insert("headers".into(), Value::Object(headers));
                        }
                    }
                }
            }
            if network == "h2" {
                let host = opts.get("host").cloned().or_else(|| {
                    opts.get("headers").and_then(|h| h.as_object()).and_then(|h| {
                        h.get("host").or_else(|| h.get("Host")).cloned()
                    })
                });
                if let Some(h) = host {
                    if !matches!(&h, Value::String(s) if s.is_empty()) && !h.is_array() {
                        opts.insert("host".into(), json!([h]));
                    }
                }
                if let Some(Value::Object(mut headers)) = opts.get("headers").cloned() {
                    headers.remove("host");
                    headers.remove("Host");
                    if headers.is_empty() {
                        opts.remove("headers");
                    } else {
                        opts.insert("headers".into(), Value::Object(headers));
                    }
                }
                if let Some(Value::Array(a)) = opts.get("path").cloned() {
                    if let Some(first) = a.first() {
                        opts.insert("path".into(), first.clone());
                    }
                }
            }
            p.set_value(&key, Value::Object(opts));
        }
    }

    // xudp / packet-addr -> packet-encoding
    if matches!(typ.as_str(), "vmess" | "vless") && !p.has("packet-encoding") {
        if p.get_bool("xudp") {
            p.set("packet-encoding", "xudp");
        } else if p.get_bool("packet-addr") {
            p.set("packet-encoding", "packetaddr");
        }
    }

    // alpn 字符串 -> 数组
    if let Some(Value::String(s)) = p.get("alpn").cloned() {
        if !s.is_empty() {
            let arr: Vec<Value> = s.split(',').map(|x| json!(x.trim())).filter(|v| v.as_str().map(|s| !s.is_empty()).unwrap_or(false)).collect();
            p.set_value("alpn", Value::Array(arr));
        }
    }

    // allowInsecure -> skip-cert-verify
    if p.has("allowInsecure") {
        let b = truthy(p.get("allowInsecure").unwrap_or(&Value::Null));
        p.set("skip-cert-verify", b);
        p.delete("allowInsecure");
    }

    // sni fallback（对齐原版：显式空字符串不触发）
    let sni_val = p.get("sni").cloned();
    let explicit_empty = matches!(&sni_val, Some(Value::String(s)) if s.is_empty());
    if p.get_bool("tls") && !truthy(sni_val.as_ref().unwrap_or(&Value::Null)) && !explicit_empty {
        if !network.is_empty() {
            let key = format!("{}-opts", network);
            if let Some(opts) = p.get_map(&key) {
                let mut host: Option<Value> = None;
                if network == "h2" {
                    host = opts.get("host").cloned();
                } else if let Some(h) = opts.get("headers").and_then(|v| v.as_object()) {
                    host = h.get("Host").cloned();
                }
                if let Some(Value::Array(a)) = &host {
                    host = a.first().cloned();
                }
                if let Some(Value::String(s)) = host {
                    if !s.is_empty() {
                        p.set("sni", s);
                    }
                }
            }
        }
        if !p.has("sni") && !is_ip(&p.get_str("server")) && !p.get_str("server").is_empty() {
            p.set("sni", p.get_str("server"));
        }
    }

    // 非 tls 的 ws/http 域名节点补 transport Host
    if !p.get_bool("tls") && matches!(network.as_str(), "ws" | "http") && !is_ip(&p.get_str("server")) {
        let key = format!("{}-opts", network);
        let mut opts = p.get_map(&key).unwrap_or_default();
        let need = opts
            .get("headers")
            .and_then(|v| v.as_object())
            .map(|h| !h.contains_key("Host") && !h.contains_key("host"))
            .unwrap_or(true);
        if need {
            let mut headers = opts.get("headers").and_then(|v| v.as_object()).cloned().unwrap_or_default();
            headers.insert("Host".into(), json!(p.get_str("server")));
            opts.insert("headers".into(), Value::Object(headers));
            p.set_value(&key, Value::Object(opts));
        }
    }

    // WireGuard 字段互映射与 peer 回填
    if typ == "wireguard" {
        wireguard_aliases(&mut p);
        backfill_wireguard_peers(&mut p);
    }

    // name 兜底
    if p.get_str("name").trim().is_empty() {
        p.set("name", format!("{} {}:{}", typ, p.get_str("server"), p.port()));
    }
    p
}

fn normalize_opt_keys(p: &mut Proxy) {
    let keys: Vec<String> = p.fields().keys().cloned().collect();
    for key in keys {
        let lk = key.to_lowercase();
        if !lk.ends_with("-opts") {
            continue;
        }
        let value = p.get(&key).cloned().unwrap_or(Value::Null);
        if key != lk {
            if !p.has(&lk) {
                p.set_value(&lk, value.clone());
            }
            p.delete(&key);
        }
        if let Some(Value::Object(m)) = p.get(&lk).cloned() {
            let mut normalized = JMap::new();
            for (k, v) in m {
                let low = k.to_lowercase();
                if !normalized.contains_key(&low) {
                    normalized.insert(low, v);
                }
            }
            p.set_value(&lk, Value::Object(normalized));
        }
    }
}

fn normalize_transport_path(v: &Value) -> Value {
    match v {
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                json!("/")
            } else if t.starts_with('/') {
                json!(t)
            } else {
                json!(format!("/{}", t))
            }
        }
        other => other.clone(),
    }
}

pub fn normalize_vmess_security(cipher: &str) -> String {
    match cipher.trim().to_lowercase().as_str() {
        "" | "auto" | "none" | "zero" => {
            if cipher.is_empty() { "auto".into() } else { cipher.trim().to_lowercase() }
        }
        "aes-128-gcm" => "aes-128-gcm".into(),
        "chacha20-ietf-poly1305" | "chacha20-poly1305" => "chacha20-poly1305".into(),
        _ => "auto".into(),
    }
}

fn wireguard_aliases(p: &mut Proxy) {
    for (a, b) in [
        ("keepalive", "persistent-keepalive"),
        ("preshared-key", "pre-shared-key"),
    ] {
        let va = p.get_str(a);
        let vb = p.get_str(b);
        if !va.is_empty() && p.get(b).is_none() {
            p.set(b, va);
        } else if !vb.is_empty() && p.get(a).is_none() {
            p.set(a, vb);
        }
    }
}

fn backfill_wireguard_peers(p: &mut Proxy) {
    let peers = match p.get_array("peers") {
        Some(v) => v,
        None => return,
    };
    let valid = peers.iter().any(|peer| {
        peer.as_object()
            .map(|m| truthy(m.get("ip").unwrap_or(&Value::Null)) || truthy(m.get("ipv6").unwrap_or(&Value::Null)))
            .unwrap_or(false)
    });
    if !valid {
        return;
    }
    if let Some(first) = peers.first().and_then(|v| v.as_object()) {
        for key in ["ip", "ipv6"] {
            if !truthy(p.get(key).unwrap_or(&Value::Null)) {
                if let Some(v) = first.get(key) {
                    if truthy(v) {
                        p.set_value(key, v.clone());
                    }
                }
            }
        }
    }
}
