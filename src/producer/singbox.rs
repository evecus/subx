//! sing-box (>=1.12) JSON 产出：outbounds / endpoints 结构。

use crate::model::Proxy;
use crate::producer::{drop_internal_fields, include_unsupported};
use crate::util::JMap;
use anyhow::Result;
use serde_json::{json, Value};

pub fn produce_singbox(proxies: &[Proxy], options: Option<&JMap>) -> Result<String> {
    let include = include_unsupported(options);
    let mut outbounds: Vec<Value> = Vec::new();
    let mut endpoints: Vec<Value> = Vec::new();
    for p in proxies {
        let mut c = p.deep_clone();
        drop_internal_fields(&mut c);
        let mut items = produce_one(&c, include);
        for item in items.drain(..) {
            if matches!(item.get("type").and_then(|v| v.as_str()), Some("wireguard") | Some("tailscale")) {
                endpoints.push(item);
            } else {
                outbounds.push(item);
            }
        }
    }
    let out = json!({ "outbounds": outbounds, "endpoints": endpoints });
    Ok(serde_json::to_string_pretty(&out)?)
}

fn base(p: &Proxy, typ: &str) -> JMap {
    let mut m = JMap::new();
    m.insert("type".into(), json!(typ));
    m.insert("tag".into(), json!(p.name()));
    m.insert("server".into(), json!(p.server()));
    m.insert("server_port".into(), json!(p.port()));
    m
}

fn transport(p: &Proxy) -> Option<Value> {
    let net = p.get_str("network");
    if net.is_empty() || net == "tcp" {
        return None;
    }
    let key = format!("{}-opts", net);
    let opts = p.get_map(&key).unwrap_or_default();
    let mut t = JMap::new();
    let net_sb = match net.as_str() {
        "ws" => "ws", "grpc" => "grpc", "h2" => "http", "http" => "http",
        "httpupgrade" => "httpupgrade", "xhttp" => "xhttp", "quic" => "quic",
        other => other,
    };
    t.insert("type".into(), json!(net_sb));
    if let Some(path) = opts.get("path") {
        t.insert("path".into(), path.clone());
    }
    if let Some(sn) = opts.get("grpc-service-name") {
        t.insert("service_name".into(), sn.clone());
    }
    if let Some(mode) = opts.get("mode") {
        t.insert("mode".into(), mode.clone());
    }
    if let Some(headers) = opts.get("headers").and_then(|h| h.as_object()) {
        let mut hm = JMap::new();
        for (k, v) in headers {
            hm.insert(k.clone(), v.clone());
        }
        t.insert("headers".into(), Value::Object(hm));
    }
    Some(Value::Object(t))
}

fn tls(p: &Proxy) -> Option<Value> {
    if !p.get_bool("tls") {
        return None;
    }
    let mut t = JMap::new();
    t.insert("enabled".into(), json!(true));
    if !p.get_str("sni").is_empty() {
        t.insert("server_name".into(), json!(p.get_str("sni")));
    }
    if p.get_bool("skip-cert-verify") {
        t.insert("insecure".into(), json!(true));
    }
    if let Some(a) = p.get("alpn").cloned() {
        t.insert("alpn".into(), a);
    }
    let fp = p.get_str("client-fingerprint");
    if !fp.is_empty() {
        t.insert("utls".into(), json!({ "enabled": true, "fingerprint": fp }));
    }
    if let Some(r) = p.get_map("reality-opts") {
        let mut reality = JMap::new();
        reality.insert("enabled".into(), json!(true));
        reality.insert("public_key".into(), json!(crate::util::get_str(&r, "public-key")));
        let sid = crate::util::get_str(&r, "short-id");
        if !sid.is_empty() {
            reality.insert("short_id".into(), json!(sid));
        }
        t.insert("reality".into(), Value::Object(reality));
    }
    Some(Value::Object(t))
}

fn attach_common(m: &mut JMap, p: &Proxy) {
    if let Some(t) = transport(p) {
        m.insert("transport".into(), t);
    }
    if let Some(t) = tls(p) {
        m.insert("tls".into(), t);
    }
    if p.get_bool("udp") {
        // sing-box 默认支持 UDP，无需显式字段
    }
    if let Some(v) = p.get("packet-encoding") {
        m.insert("packet_encoding".into(), v.clone());
    }
    if let Some(v) = p.get("tfo") {
        m.insert("tcp_fast_open".into(), v.clone());
    }
    if let Some(v) = p.get("udp-over-tcp") {
        m.insert("udp_over_tcp".into(), v.clone());
    }
}

fn produce_one(p: &Proxy, _include: bool) -> Vec<Value> {
    let mut items = Vec::new();
    let typ = p.type_();
    match typ.as_str() {
        "ss" => {
            let mut m = base(p, "shadowsocks");
            m.insert("method".into(), json!(p.get_str("cipher")));
            m.insert("password".into(), json!(p.get_str("password")));
            let plugin = p.get_str("plugin");
            if !plugin.is_empty() && plugin != "shadow-tls" {
                m.insert("plugin".into(), json!(plugin));
                if let Some(opts) = p.get_map("plugin-opts") {
                    let mut po = JMap::new();
                    for (k, v) in opts {
                        po.insert(k.replace('-', "_"), v.clone());
                    }
                    m.insert("plugin_opts".into(), Value::Object(po));
                }
            }
            // shadow-tls 链式：先产出 shadowtls outbound，再让 ss 走 detour
            if plugin == "shadow-tls" {
                if let Some(opts) = p.get_map("plugin-opts") {
                    let mut st = JMap::new();
                    st.insert("type".into(), json!("shadowtls"));
                    st.insert("tag".into(), json!(format!("{}-shadowtls", p.name())));
                    st.insert("version".into(), json!(crate::util::get_i64(&opts, "version").max(2)));
                    st.insert("password".into(), json!(crate::util::get_str(&opts, "password")));
                    st.insert("server".into(), json!(p.server()));
                    st.insert("server_port".into(), json!(p.port()));
                    if let Some(t) = tls(p) {
                        st.insert("tls".into(), t);
                    }
                    items.push(Value::Object(st));
                    m.insert("detour".into(), json!(format!("{}-shadowtls", p.name())));
                }
            }
            attach_common(&mut m, p);
            items.push(Value::Object(m));
        }
        "vmess" | "vless" => {
            let mut m = base(p, &typ);
            m.insert("uuid".into(), json!(p.get_str("uuid")));
            if typ == "vmess" {
                m.insert("security".into(), json!(p.get_str("cipher")));
                m.insert("alter_id".into(), json!(p.get_i64("alterId")));
            } else if !p.get_str("flow").is_empty() {
                m.insert("flow".into(), json!(p.get_str("flow")));
            }
            attach_common(&mut m, p);
            items.push(Value::Object(m));
        }
        "trojan" => {
            let mut m = base(p, "trojan");
            m.insert("password".into(), json!(p.get_str("password")));
            attach_common(&mut m, p);
            items.push(Value::Object(m));
        }
        "hysteria2" => {
            let mut m = base(p, "hysteria2");
            m.insert("password".into(), json!(p.get_str("password")));
            for (k, to) in [("up", "up_mbps"), ("down", "down_mbps")] {
                if let Ok(n) = p.get_str(k).parse::<i64>() {
                    m.insert(to.into(), json!(n));
                }
            }
            let obfs = p.get_str("obfs");
            if !obfs.is_empty() {
                m.insert("obfs".into(), json!({ "type": obfs, "password": p.get_str("obfs-password") }));
            }
            attach_common(&mut m, p);
            items.push(Value::Object(m));
        }
        "hysteria" => {
            let mut m = base(p, "hysteria");
            m.insert("auth_str".into(), json!(p.get_str("auth-str")));
            for (k, to) in [("up", "up_mbps"), ("down", "down_mbps")] {
                if let Ok(n) = p.get_str(k).parse::<i64>() {
                    m.insert(to.into(), json!(n));
                }
            }
            attach_common(&mut m, p);
            items.push(Value::Object(m));
        }
        "tuic" => {
            let mut m = base(p, "tuic");
            m.insert("uuid".into(), json!(p.get_str("uuid")));
            m.insert("password".into(), json!(p.get_str("password")));
            if !p.get_str("congestion-controller").is_empty() {
                m.insert("congestion_control".into(), json!(p.get_str("congestion-controller")));
            }
            if !p.get_str("udp-relay-mode").is_empty() {
                m.insert("udp_relay_mode".into(), json!(p.get_str("udp-relay-mode")));
            }
            attach_common(&mut m, p);
            items.push(Value::Object(m));
        }
        "wireguard" => {
            let mut m = JMap::new();
            m.insert("type".into(), json!("wireguard"));
            m.insert("tag".into(), json!(p.name()));
            m.insert("private_key".into(), json!(p.get_str("private-key")));
            let mut addr = Vec::new();
            for k in ["ip", "ipv6"] {
                let v = p.get_str(k);
                if !v.is_empty() {
                    addr.push(json!(v));
                }
            }
            if !addr.is_empty() {
                m.insert("address".into(), Value::Array(addr));
            }
            let mut peer = JMap::new();
            peer.insert("server".into(), json!(p.server()));
            peer.insert("server_port".into(), json!(p.port()));
            peer.insert("public_key".into(), json!(p.get_str("public-key")));
            if !p.get_str("pre-shared-key").is_empty() {
                peer.insert("pre_shared_key".into(), json!(p.get_str("pre-shared-key")));
            }
            if let Some(r) = p.get("reserved").cloned() {
                peer.insert("reserved".into(), r);
            }
            if let Some(a) = p.get("allowed-ips").cloned() {
                peer.insert("allowed_ips".into(), a);
            }
            peer.insert("persistent_keepalive_interval".into(), json!(p.get_i64("persistent-keepalive")));
            m.insert("peers".into(), json!([peer]));
            if p.get_i64("mtu") > 0 {
                m.insert("mtu".into(), json!(p.get_i64("mtu")));
            }
            items.push(Value::Object(m));
        }
        "socks5" | "http" => {
            let mut m = base(p, if typ == "socks5" { "socks" } else { "http" });
            if !p.get_str("username").is_empty() {
                m.insert("username".into(), json!(p.get_str("username")));
            }
            if !p.get_str("password").is_empty() {
                m.insert("password".into(), json!(p.get_str("password")));
            }
            attach_common(&mut m, p);
            items.push(Value::Object(m));
        }
        "anytls" => {
            let mut m = base(p, "anytls");
            m.insert("password".into(), json!(p.get_str("password")));
            attach_common(&mut m, p);
            items.push(Value::Object(m));
        }
        "ssh" => {
            let mut m = base(p, "ssh");
            m.insert("user".into(), json!(p.get_str("username")));
            m.insert("password".into(), json!(p.get_str("password")));
            attach_common(&mut m, p);
            items.push(Value::Object(m));
        }
        _ => {
            // 未知协议：保留原始字段的通用 outbound（尽量不丢节点）
            let mut m = base(p, &typ);
            for (k, v) in p.fields() {
                if !m.contains_key(k) && !matches!(k.as_str(), "type" | "name" | "server" | "port") {
                    m.insert(k.clone(), v.clone());
                }
            }
            attach_common(&mut m, p);
            items.push(Value::Object(m));
        }
    }
    items
}
