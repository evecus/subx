//! 行式配置产出：Surge / SurgeMac / Surfboard / Loon / Quantumult X。

use crate::model::Proxy;
use crate::util::JMap;
use serde_json::Value;

fn clean_name(s: &str) -> String {
    s.replace('=', "").replace(',', "").trim().to_string()
}

fn quote_if_needed(s: &str) -> String {
    if s.contains(',') || s.contains(' ') || s.contains('"') {
        format!("\"{}\"", s.replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

fn alpn_str(p: &Proxy) -> String {
    match p.get("alpn") {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(","),
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    }
}

fn transport(p: &Proxy) -> (String, String, String) {
    let net = p.get_str("network");
    let key = format!("{}-opts", net);
    let opts = p.get_map(&key).unwrap_or_default();
    let path = crate::util::get_str(&opts, "path");
    let path = if path.is_empty() { crate::util::get_str(&opts, "grpc-service-name") } else { path };
    let host = opts
        .get("headers")
        .and_then(|v| v.as_object())
        .and_then(|h| h.get("Host").or_else(|| h.get("host")))
        .map(crate::util::value_str)
        .unwrap_or_default();
    (net, path, host)
}

/// 构造 Surge 风格的参数列表。
fn surge_opts(p: &Proxy, target: &str) -> Vec<String> {
    let mut o: Vec<(String, String)> = Vec::new();
    let typ = p.type_();
    let push = |o: &mut Vec<(String, String)>, k: &str, v: String| {
        if !v.is_empty() {
            o.push((k.to_string(), v));
        }
    };
    match typ.as_str() {
        "ss" => {
            push(&mut o, "encrypt-method", p.get_str("cipher"));
            push(&mut o, "password", p.get_str("password"));
            let plugin = p.get_str("plugin");
            if !plugin.is_empty() {
                let mut po = Vec::new();
                if let Some(opts) = p.get_map("plugin-opts") {
                    for (k, v) in &opts {
                        po.push(format!("{}={}", k, crate::util::value_str(v)));
                    }
                }
                push(&mut o, "plugin", if po.is_empty() { plugin.clone() } else { format!("{};{}", plugin, po.join(";")) });
                push(&mut o, "obfs", p.get_map("plugin-opts").map(|m| crate::util::get_str(&m, "mode")).unwrap_or_default());
            }
        }
        "ssr" => {
            push(&mut o, "encrypt-method", p.get_str("cipher"));
            push(&mut o, "password", p.get_str("password"));
            push(&mut o, "protocol", p.get_str("protocol"));
            push(&mut o, "obfs", p.get_str("obfs"));
            push(&mut o, "protocol-param", p.get_str("protocol-param"));
            push(&mut o, "obfs-param", p.get_str("obfs-param"));
        }
        "vmess" | "vless" => {
            push(&mut o, "username", p.get_str("uuid"));
            push(&mut o, "password", p.get_str("password"));
            push(&mut o, "encrypt-method", p.get_str("cipher"));
            push(&mut o, "flow", p.get_str("flow"));
            if let Some(r) = p.get_map("reality-opts") {
                push(&mut o, "pbk", crate::util::get_str(&r, "public-key"));
                push(&mut o, "sid", crate::util::get_str(&r, "short-id"));
            }
        }
        "trojan" | "anytls" => {
            push(&mut o, "password", p.get_str("password"));
        }
        "hysteria2" => {
            push(&mut o, "password", p.get_str("password"));
            push(&mut o, "up", p.get_str("up"));
            push(&mut o, "down", p.get_str("down"));
            push(&mut o, "obfs", p.get_str("obfs"));
            push(&mut o, "obfs-password", p.get_str("obfs-password"));
            push(&mut o, "ports", p.get_str("ports"));
        }
        "hysteria" => {
            push(&mut o, "auth-str", p.get_str("auth-str"));
            push(&mut o, "up", p.get_str("up"));
            push(&mut o, "down", p.get_str("down"));
            push(&mut o, "protocol", p.get_str("protocol"));
        }
        "tuic" => {
            push(&mut o, "username", p.get_str("uuid"));
            push(&mut o, "password", p.get_str("password"));
            push(&mut o, "version", p.get_str("version"));
            push(&mut o, "congestion-controller", p.get_str("congestion-controller"));
        }
        "socks5" | "http" => {
            push(&mut o, "username", p.get_str("username"));
            push(&mut o, "password", p.get_str("password"));
        }
        "wireguard" => {
            push(&mut o, "private-key", p.get_str("private-key"));
            push(&mut o, "public-key", p.get_str("public-key"));
            push(&mut o, "pre-shared-key", p.get_str("pre-shared-key"));
            push(&mut o, "ip", p.get_str("ip"));
            push(&mut o, "ipv6", p.get_str("ipv6"));
            push(&mut o, "mtu", p.get_str("mtu"));
        }
        _ => {}
    }
    if p.get_bool("tls") {
        push(&mut o, "tls", "true".into());
    }
    push(&mut o, "sni", p.get_str("sni"));
    if p.get_bool("skip-cert-verify") {
        push(&mut o, "skip-cert-verify", "true".into());
    }
    let alpn = alpn_str(p);
    push(&mut o, "alpn", alpn);
    push(&mut o, "client-fingerprint", p.get_str("client-fingerprint"));
    let (net, path, host) = transport(p);
    if !net.is_empty() && net != "tcp" {
        if net == "ws" {
            push(&mut o, "ws", "true".into());
        } else {
            push(&mut o, "network", net.clone());
        }
        push(&mut o, "ws-path", path.clone());
        if net == "grpc" {
            push(&mut o, "grpc-service-name", path);
        }
        if !host.is_empty() {
            push(&mut o, "ws-headers", format!("Host:{}", host));
        }
    }
    if p.get_bool("tfo") {
        push(&mut o, "tfo", "true".into());
    }
    if target == "loon" {
        push(&mut o, "udp", if p.get_bool("udp") { "true".into() } else { "false".into() });
    }
    o.into_iter()
        .map(|(k, v)| format!("{}={}", k, quote_if_needed(&v)))
        .collect()
}

fn surge_line(p: &Proxy, target: &str) -> Option<String> {
    let typ = p.type_();
    let name = clean_name(&p.name());
    let mut parts = vec![typ.clone(), p.server(), p.port().to_string()];
    parts.extend(surge_opts(p, target));
    Some(format!("{} = {}", name, parts.join(", ")))
}

pub fn produce_surge(target: &str, proxies: &[Proxy]) -> String {
    proxies.iter().filter_map(|p| surge_line(p, target)).collect::<Vec<_>>().join("\n")
}

pub fn produce_surfboard(proxies: &[Proxy]) -> String {
    produce_surge("surfboard", proxies)
}

pub fn produce_loon(proxies: &[Proxy]) -> String {
    produce_surge("loon", proxies)
}

/// Quantumult X 行格式：`type = server:port, key=value, ..., tag=name`。
pub fn produce_qx(proxies: &[Proxy]) -> String {
    let mut lines = Vec::new();
    for p in proxies {
        let typ = match p.type_().as_str() {
            "ss" => "ss", "ssr" => "ssr", "vmess" => "vmess", "vless" => "vless",
            "trojan" => "trojan", "http" => "http", "socks5" => "socks5",
            "hysteria2" => "hysteria2", "tuic" => "tuic", "wireguard" => "wireguard",
            "anytls" => "anytls", _ => continue,
        };
        let mut fields = vec![format!("{}:{}", p.server(), p.port())];
        let mut o = surge_opts(p, "qx");
        // QX 使用 tag 作为备注，且不接受 Surge 的 ws= 开关
        o.retain(|s| !s.starts_with("ws=") && !s.starts_with("network=") && !s.starts_with("grpc-service-name="));
        fields.extend(o);
        fields.push(format!("tag={}", quote_if_needed(&clean_name(&p.name()))));
        lines.push(format!("{} = {}", typ, fields.join(", ")));
    }
    lines.join("\n")
}

#[allow(dead_code)]
fn unused_map(_m: &JMap) {}
