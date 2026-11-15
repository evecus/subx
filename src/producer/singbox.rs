//! sing-box (>=1.12) 全链路组合产出。
//!
//! 对齐 Go 版 `internal/producer/singbox.go`：每个节点走完整的通用 parser 链
//! （ip-version / domain-resolver / detour / network / tfo / multiplex / uot /
//! packet-encoding）+ TLS（含 ECH 完整协商）+ transport，再做链式组合
//! （ShadowTLS detour、WireGuard/Tailscale endpoints）；任何一步失败则整组
//! 丢弃该节点（对齐 JS try/catch）。

use crate::ech;
use crate::model::Proxy;
use crate::producer::include_unsupported;
use crate::util::{get_i64, get_str, truthy, value_i64, value_str, JMap};
use anyhow::Result;
use serde_json::{json, Value};

const IP_VERSIONS: &[(&str, &str)] = &[
    ("ipv4", "ipv4_only"), ("ipv6", "ipv6_only"),
    ("v4-only", "ipv4_only"), ("v6-only", "ipv6_only"),
    ("ipv4-prefer", "prefer_ipv4"), ("ipv6-prefer", "prefer_ipv6"),
    ("prefer-v4", "prefer_ipv4"), ("prefer-v6", "prefer_ipv6"),
];

const UTLS_FINGERPRINTS: &[&str] = &[
    "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android",
    "random", "randomized",
];

pub fn produce_singbox(proxies: &[Proxy], options: Option<&JMap>) -> Result<String> {
    let include = include_unsupported(options);
    let mut list: Vec<Value> = Vec::new();
    for p in proxies {
        let start = list.len();
        match produce_one(p, include) {
            Ok(items) => list.extend(items),
            Err(_) => list.truncate(start), // 整组回滚，不产出半截配置
        }
    }
    let mut outbounds = Vec::new();
    let mut endpoints = Vec::new();
    for item in list {
        match item.get("type").and_then(|v| v.as_str()) {
            Some("wireguard") | Some("tailscale") => endpoints.push(item),
            _ => outbounds.push(item),
        }
    }
    Ok(serde_json::to_string_pretty(&json!({
        "outbounds": outbounds,
        "endpoints": endpoints
    }))?)
}

fn base(p: &Proxy, typ: &str) -> JMap {
    let mut m = JMap::new();
    m.insert("type".into(), json!(typ));
    m.insert("tag".into(), json!(p.name()));
    m.insert("server".into(), json!(p.server()));
    m.insert("server_port".into(), json!(p.port()));
    m
}

fn tval(p: &Proxy, key: &str) -> Option<Value> {
    p.get(key).filter(|v| !v.is_null()).cloned()
}

fn truthy_at(p: &Proxy, key: &str) -> bool {
    p.get(key).map(truthy).unwrap_or(false)
}

// ---------------- 通用 parser 链 ----------------

fn common(p: &Proxy, out: &mut JMap) {
    // ip-version + _dns_server -> domain_resolver
    if let Some((_, strategy)) = IP_VERSIONS.iter().find(|(k, _)| *k == p.get_str("ip-version")) {
        if let Some(v) = tval(p, "_dns_server") {
            if !value_str(&v).trim().is_empty() {
                let mut dr = JMap::new();
                dr.insert("server".into(), v);
                dr.insert("strategy".into(), json!(strategy));
                out.insert("domain_resolver".into(), Value::Object(dr));
            }
        }
    }
    // _domain_resolver 覆盖式合并
    if let Some(v) = tval(p, "_domain_resolver") {
        let mut merged = out
            .get("domain_resolver")
            .and_then(|x| x.as_object())
            .cloned()
            .unwrap_or_default();
        match v {
            Value::String(s) => {
                merged.insert("server".into(), json!(s));
            }
            Value::Object(m) => {
                for (k, v) in m {
                    merged.insert(k, v);
                }
            }
            _ => return,
        }
        out.insert("domain_resolver".into(), Value::Object(merged));
    }
    // detour / dialer-proxy
    let detour = if truthy_at(p, "dialer-proxy") {
        tval(p, "dialer-proxy")
    } else {
        tval(p, "detour")
    };
    if let Some(v) = detour {
        out.insert("detour".into(), v);
    }
    // network（udp=false -> tcp）
    if let Some(Value::String(n)) = p.get("_network") {
        if n == "tcp" || n == "udp" {
            out.insert("network".into(), json!(n));
        }
    } else if matches!(p.get("udp"), Some(Value::Bool(false))) {
        out.insert("network".into(), json!("tcp"));
    }
    // tcp fast open
    if truthy_at(p, "tfo") || truthy_at(p, "fast-open") || truthy_at(p, "tcp-fast-open") {
        out.insert("tcp_fast_open".into(), json!(true));
    }
    // multiplex / smux + brutal
    if let Some(smux) = p.get_map("smux") {
        if truthy(smux.get("enabled").unwrap_or(&Value::Null)) {
            let mut mp = JMap::new();
            mp.insert("enabled".into(), json!(true));
            for (src, dst) in [
                ("protocol", "protocol"),
                ("max-connections", "max_connections"),
                ("max-streams", "max_streams"),
                ("min-streams", "min_streams"),
            ] {
                if let Some(v) = smux.get(src).filter(|v| truthy(v)) {
                    mp.insert(dst.into(), if src == "protocol" { v.clone() } else { json!(value_i64(v)) });
                }
            }
            if truthy(smux.get("padding").unwrap_or(&Value::Null)) {
                mp.insert("padding".into(), json!(true));
            }
            if let Some(bo) = smux.get("brutal-opts").and_then(|v| v.as_object()) {
                if truthy(bo.get("up").unwrap_or(&Value::Null)) || truthy(bo.get("down").unwrap_or(&Value::Null)) {
                    let mut brutal = JMap::new();
                    brutal.insert("enabled".into(), json!(true));
                    for (src, dst) in [("up", "up_mbps"), ("down", "down_mbps")] {
                        if let Some(v) = bo.get(src).filter(|v| truthy(v)) {
                            brutal.insert(dst.into(), json!(value_i64(v)));
                        }
                    }
                    mp.insert("brutal".into(), Value::Object(brutal));
                }
            }
            out.insert("multiplex".into(), Value::Object(mp));
        }
    }
    // udp over tcp
    if truthy_at(p, "uot") {
        out.insert("udp_over_tcp".into(), json!(true));
    } else if truthy_at(p, "udp-over-tcp") {
        let version = if truthy_at(p, "udp-over-tcp-version")
            && value_i64(p.get("udp-over-tcp-version").unwrap()) != 1
        {
            2
        } else {
            1
        };
        let mut u = JMap::new();
        u.insert("enabled".into(), json!(true));
        u.insert("version".into(), json!(version));
        out.insert("udp_over_tcp".into(), Value::Object(u));
    }
    if let Some(v) = tval(p, "packet-encoding") {
        out.insert("packet_encoding".into(), v);
    }
}

// ---------------- TLS（含 ECH 完整协商） ----------------

fn tls(p: &Proxy, out: &mut JMap) {
    let mut t = JMap::new();
    if truthy_at(p, "tls") {
        t.insert("enabled".into(), json!(true));
    }
    for k in ["servername", "peer", "sni"] {
        if let Some(v) = tval(p, k) {
            if !value_str(&v).trim().is_empty() {
                t.insert("server_name".into(), v);
            }
        }
    }
    if truthy_at(p, "skip-cert-verify") || truthy_at(p, "insecure") {
        t.insert("insecure".into(), json!(true));
    }
    if truthy_at(p, "disable-sni") {
        t.insert("disable_sni".into(), json!(true));
    }
    if let Some(v) = tval(p, "alpn") {
        t.insert("alpn".into(), match v {
            Value::String(_) => Value::Array(vec![v]),
            other => other,
        });
    }
    if let Some(v) = tval(p, "ca") {
        t.insert("certificate_path".into(), v);
    }
    for k in ["ca_str", "ca-str"] {
        if let Some(v) = tval(p, k) {
            t.insert("certificate".into(), Value::Array(vec![v]));
        }
    }
    if let Some(ro) = p.get_map("reality-opts") {
        let mut reality = JMap::new();
        reality.insert("enabled".into(), json!(true));
        if let Some(v) = ro.get("public-key").filter(|v| truthy(v)) {
            reality.insert("public_key".into(), v.clone());
        }
        if let Some(v) = ro.get("short-id").filter(|v| truthy(v)) {
            reality.insert("short_id".into(), v.clone());
        }
        t.insert("reality".into(), Value::Object(reality));
        let mut utls = JMap::new();
        utls.insert("enabled".into(), json!(true));
        t.insert("utls".into(), Value::Object(utls));
    }
    if !matches!(p.type_().as_str(), "hysteria" | "hysteria2" | "tuic") {
        if let Some(v) = tval(p, "client-fingerprint") {
            let fp = value_str(&v).trim().to_lowercase();
            if UTLS_FINGERPRINTS.contains(&fp.as_str()) {
                let mut utls = t.get("utls").and_then(|v| v.as_object()).cloned().unwrap_or_default();
                utls.insert("enabled".into(), json!(true));
                utls.insert("fingerprint".into(), json!(fp));
                t.insert("utls".into(), Value::Object(utls));
            }
        }
    }
    // ECH：优先 _ech 原样透传，否则把 mihomo ech-opts 完整协商成 sing-box tls.ech
    if let Some(Value::Object(m)) = p.get("_ech") {
        t.insert("ech".into(), Value::Object(m.clone()));
    } else if let Some(eo) = p.get_map("ech-opts") {
        let mut e = JMap::new();
        if let Some(v) = eo.get("enable") {
            e.insert("enabled".into(), v.clone());
        }
        if let Some(v) = eo.get("config") {
            if let Some(lines) = ech::normalize_pem_lines(v) {
                e.insert("config".into(), Value::Array(lines));
            }
        }
        for (src, dst) in [
            ("query-server-name", "query_server_name"),
            ("config-path", "config_path"),
            ("fragment", "fragment"),
            ("fragment-fallback-delay", "fragment_fallback_delay"),
            ("record-fragment", "record_fragment"),
            ("pq-signature-schemes-enabled", "pq_signature_schemes_enabled"),
            ("pq-signature-schemes", "pq_signature_schemes"),
        ] {
            if let Some(v) = eo.get(src) {
                e.insert(dst.into(), v.clone());
            }
        }
        t.insert("ech".into(), Value::Object(e));
    }
    if let Some(Value::Array(a)) = p.get("_curve_preferences") {
        t.insert("curve_preferences".into(), Value::Array(a.clone()));
    }
    if truthy_at(p, "_fragment") {
        t.insert("fragment".into(), json!(true));
    }
    if let Some(v) = tval(p, "_fragment_fallback_delay") {
        t.insert("fragment_fallback_delay".into(), v);
    }
    if truthy_at(p, "_record_fragment") {
        t.insert("record_fragment".into(), json!(true));
    }
    for k in [
        "_certificate", "_certificate_path", "_certificate_public_key_sha256",
        "_client_certificate", "_client_certificate_path", "_client_key", "_client_key_path",
    ] {
        if let Some(v) = tval(p, k) {
            t.insert(k.trim_start_matches('_').into(), v);
        }
    }
    let enabled = t.get("enabled").cloned().unwrap_or(Value::Null);
    if truthy(&enabled) {
        out.insert("tls".into(), Value::Object(t));
    } else {
        out.remove("tls");
    }
}

// ---------------- transport ----------------

fn header_array(m: &JMap) -> JMap {
    let mut out = JMap::new();
    for (k, v) in m {
        let arr = match v {
            Value::Array(a) => a.clone(),
            Value::Null => continue,
            other => vec![other.clone()],
        };
        out.insert(k.clone(), Value::Array(arr));
    }
    out
}

fn transport(p: &Proxy, out: &mut JMap) -> Result<()> {
    let net = p.get_str("network");
    if net.is_empty() || net == "tcp" {
        return Ok(());
    }
    let key = format!("{}-opts", net);
    let opts = p.get_map(&key).unwrap_or_default();
    let mut t = JMap::new();
    match net.as_str() {
        "ws" => {
            t.insert("type".into(), json!("ws"));
            let mut headers = header_array(
                &opts.get("headers").and_then(|v| v.as_object()).cloned().unwrap_or_default(),
            );
            if !headers.is_empty() && !headers.contains_key("Host") && !headers.contains_key("host") {
                anyhow::bail!("Host header is missing");
            }
            if let Some(host) = headers.remove("Host").or_else(|| headers.remove("host")) {
                if let Some(first) = host.as_array().and_then(|a| a.first()) {
                    t.insert("host".into(), first.clone());
                }
                headers.insert("Host".into(), host);
            }
            if let Some(v) = opts.get("early-data-header-name") {
                t.insert("early_data_header_name".into(), v.clone());
            }
            if let Some(v) = opts.get("max-early-data").filter(|v| truthy(v)) {
                t.insert("max_early_data".into(), json!(value_i64(v)));
            }
            if let Some(v) = opts.get("path") {
                t.insert("path".into(), v.clone());
            }
            // path 上的 ?ed=NNNN 早期数据参数
            if let Some(Value::String(path)) = t.get("path").cloned() {
                if let Some(idx) = path.find("?ed=").or_else(|| path.find("&ed=")) {
                    let rest = &path[idx + 4..];
                    let n: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if !n.is_empty() {
                        if let Ok(size) = n.parse::<i64>() {
                            t.insert("max_early_data".into(), json!(size));
                            t.insert("early_data_header_name".into(), json!("Sec-WebSocket-Protocol"));
                            t.insert("path".into(), json!(path[..idx].to_string()));
                        }
                    }
                }
            }
            // insecure 时用 Host 作为 server_name
            if truthy_at(p, "skip-cert-verify") && !t.contains_key("host") {
                // no-op：Host 已在上面拆出
            }
            if truthy(opts.get("v2ray-http-upgrade").unwrap_or(&Value::Null)) {
                t.insert("type".into(), json!("httpupgrade"));
                t.remove("max_early_data");
                t.remove("early_data_header_name");
            }
            for (k, v) in &headers {
                let val = match v {
                    Value::Array(a) if a.len() == 1 => a[0].clone(),
                    other => other.clone(),
                };
                t.entry(k.clone()).or_insert(val);
            }
            if let Some(mut tls_map) = out.get("tls").and_then(|v| v.as_object()).cloned() {
                if truthy(tls_map.get("insecure").unwrap_or(&Value::Null)) && t.contains_key("host") {
                    tls_map.insert("server_name".into(), t.get("host").unwrap().clone());
                    out.insert("tls".into(), Value::Object(tls_map));
                }
            }
        }
        "http" | "h2" => {
            t.insert("type".into(), json!("http"));
            if let Some(v) = opts.get("host") {
                t.insert("host".into(), v.clone());
            } else if let Some(h) = opts.get("headers").and_then(|v| v.as_object()) {
                if let Some(v) = h.get("Host").or_else(|| h.get("host")) {
                    t.insert("host".into(), v.clone());
                }
            }
            if let Some(v) = opts.get("path") {
                t.insert("path".into(), v.clone());
            }
            if let Some(v) = opts.get("method") {
                t.insert("method".into(), v.clone());
            }
            let headers = header_array(&opts.get("headers").and_then(|v| v.as_object()).cloned().unwrap_or_default());
            if !headers.is_empty() {
                t.insert("headers".into(), Value::Object(headers));
            }
        }
        "grpc" => {
            t.insert("type".into(), json!("grpc"));
            if let Some(v) = opts.get("grpc-service-name") {
                t.insert("service_name".into(), v.clone());
            }
        }
        "httpupgrade" => {
            t.insert("type".into(), json!("httpupgrade"));
            if let Some(v) = opts.get("path") {
                t.insert("path".into(), v.clone());
            }
            if let Some(v) = opts.get("host") {
                t.insert("host".into(), v.clone());
            }
            let headers = header_array(&opts.get("headers").and_then(|v| v.as_object()).cloned().unwrap_or_default());
            if !headers.is_empty() {
                t.insert("headers".into(), Value::Object(headers));
            }
        }
        "quic" => {
            t.insert("type".into(), json!("quic"));
        }
        other => {
            t.insert("type".into(), json!(other));
            for (k, v) in &opts {
                if !matches!(k.as_str(), "headers") {
                    t.insert(k.replace('-', "_"), v.clone());
                }
            }
        }
    }
    out.insert("transport".into(), Value::Object(t));
    Ok(())
}

fn attach_common(m: &mut JMap, p: &Proxy) -> Result<()> {
    common(p, m);
    tls(p, m);
    transport(p, m)?;
    Ok(())
}

// ---------------- 协议字段 ----------------

/// mihomo 键 -> sing-box 键的专有字段透传表。
const PASSTHROUGH: &[(&str, &str)] = &[
    ("up", "up_mbps"), ("down", "down_mbps"),
    ("recv-window-conn", "recv_window_conn"), ("recv-window", "recv_window"),
    ("disable-mtu-discovery", "disable_mtu_discovery"),
    ("hop-interval", "hop_interval"), ("heartbeat-interval", "heartbeat_interval"),
    ("request-timeout", "request_timeout"), ("max-open-streams", "max_open_streams"),
    ("reduce-rtt", "reduce_rtt"), ("zero-rtt-handshake", "zero_rtt_handshake"),
    ("congestion-controller", "congestion_control"),
    ("udp-relay-mode", "udp_relay_mode"), ("udp-fragment", "udp_fragment"),
    ("idle-session-check-interval", "idle_session_check_interval"),
    ("idle-session-timeout", "idle_session_timeout"), ("min-idle-session", "min_idle_session"),
    ("insecure-concurrency", "insecure_concurrency"),
    ("disable-chrome-parrot", "disable_chrome_parrot"),
    ("global-padding", "global_padding"), ("authenticated-length", "authenticated_length"),
    ("private-key-passphrase", "private_key_passphrase"),
    ("host-key", "host_key"), ("host-key-algorithms", "host_key_algorithms"),
    ("client-metadata", "client_metadata"), ("extra-headers", "extra_headers"),
    ("obfs-host", "obfs_host"), ("obfs-mode", "obfs_mode"), ("obfs-param", "obfs_param"),
    ("protocol-param", "protocol_param"), ("private-key-path", "private_key_path"),
    ("peer-public-key", "peer_public_key"), ("pre-shared-key", "pre_shared_key"),
    ("system-interface-mtu", "system_interface_mtu"), ("udp-over-stream", "udp_over_stream"),
    ("bbr-profile", "bbr_profile"), ("quic-congestion-control", "quic_congestion_control"),
    ("quic-proxy-mode", "quic_proxy_mode"), ("workers", "workers"), ("reuse", "reuse"),
    ("disable-reuse", "disable_reuse"), ("disable-mtu-discovery", "disable_mtu_discovery"),
];

fn passthrough(m: &mut JMap, p: &Proxy) {
    for (src, dst) in PASSTHROUGH {
        if let Some(v) = tval(p, src) {
            m.insert((*dst).into(), v);
        }
    }
    // 下划线前缀字段直接去掉前缀透传（_dns_server 等内部字段除外）
    for (k, v) in p.fields() {
        if let Some(rest) = k.strip_prefix('_') {
            if !matches!(rest, "dns_server" | "domain_resolver" | "network" | "ech" | "certificate"
                | "certificate_path" | "certificate_public_key_sha256" | "client_certificate"
                | "client_certificate_path" | "client_key" | "client_key_path" | "fragment"
                | "fragment_fallback_delay" | "record_fragment" | "curve_preferences")
                && !m.contains_key(rest)
            {
                m.insert(rest.to_string(), v.clone());
            }
        }
    }
}

fn shadow_tls_opts(p: &Proxy) -> Option<JMap> {
    if p.get_str("plugin") == "shadow-tls" {
        if let Some(o) = p.get_map("plugin-opts") {
            return Some(o);
        }
    }
    if let Some(o) = p.get_map("shadow-tls-opts") {
        return Some(o);
    }
    // stream shadow-tls：vmess/vless/trojan/snell 的 plugin-opts 带 password
    if matches!(p.type_().as_str(), "vmess" | "vless" | "trojan" | "snell") {
        if let Some(o) = p.get_map("plugin-opts") {
            if o.contains_key("password") || o.contains_key("version") {
                return Some(o);
            }
        }
    }
    None
}

fn shadow_tls_outbound(p: &Proxy, opts: &JMap) -> JMap {
    let mut st = JMap::new();
    st.insert("type".into(), json!("shadowtls"));
    st.insert("tag".into(), json!(format!("{}_shadowtls", p.name())));
    let version = get_i64(opts, "version").max(1);
    st.insert("version".into(), json!(if version == 0 { 2 } else { version }));
    st.insert("password".into(), json!(get_str(opts, "password")));
    st.insert("server".into(), json!(p.server()));
    st.insert("server_port".into(), json!(p.port()));
    let mut holder = JMap::new();
    tls(p, &mut holder);
    if let Some(tls_val) = holder.remove("tls") {
        st.insert("tls".into(), tls_val);
    }
    st
}

fn produce_one(p: &Proxy, include: bool) -> Result<Vec<Value>> {
    let typ = p.type_();
    // 平台限制（对齐 Go singBoxProduceOne）
    if p.get_str("network") == "xhttp" {
        anyhow::bail!("sing-box does not support xhttp");
    }
    if typ == "vless" {
        let enc = p.get_str("encryption");
        if !enc.is_empty() && enc != "none" {
            anyhow::bail!("VLESS encryption is not supported");
        }
        let flow = p.get_str("flow");
        if !flow.is_empty() && flow != "xtls-rprx-vision" {
            anyhow::bail!("unsupported VLESS flow");
        }
    }
    if typ == "vmess" {
        let nw = p.get_str("network");
        if !nw.is_empty() && !matches!(nw.as_str(), "tcp" | "ws" | "grpc" | "h2" | "http") {
            anyhow::bail!("unsupported vmess network");
        }
    }
    if typ == "trojan" && !p.get_str("flow").is_empty() {
        anyhow::bail!("unsupported trojan flow");
    }
    if typ == "socks5" && truthy_at(p, "tls") {
        anyhow::bail!("socks5 with tls is not supported");
    }
    if typ == "tuic" && !p.get_str("token").is_empty() {
        anyhow::bail!("TUIC v4 is not supported");
    }
    if typ == "ssr" && !include {
        anyhow::bail!("ssr is not supported");
    }

    // stream ShadowTLS 链式前置校验
    let stream_st = shadow_tls_opts(p);
    let mut st_out: Option<JMap> = None;
    if let Some(opts) = &stream_st {
        let version_raw = opts.get("version").cloned().unwrap_or(json!(0));
        let version = value_i64(&version_raw);
        let enabled = truthy(opts.get("password").unwrap_or(&Value::Null)) || version != 0;
        if enabled {
            if matches!(typ.as_str(), "vmess" | "vless" | "trojan") {
                if p.get_map("reality-opts").is_some() {
                    anyhow::bail!("cannot chain ShadowTLS with Reality");
                }
                if (typ == "vmess" || typ == "vless") && p.get_str("network") == "h2" {
                    anyhow::bail!("cannot chain ShadowTLS with h2");
                }
                if typ == "vless" && p.get_str("flow") == "xtls-rprx-vision" {
                    anyhow::bail!("cannot chain ShadowTLS with xtls-rprx-vision");
                }
                if version != 0 && !(1..=3).contains(&version) {
                    anyhow::bail!("unsupported shadow-tls version");
                }
                if typ == "anytls" {
                    anyhow::bail!("cannot replace AnyTLS TLS with ShadowTLS");
                }
                st_out = Some(shadow_tls_outbound(p, opts));
            } else if typ == "snell" {
                st_out = Some(shadow_tls_outbound(p, opts));
            }
        }
    }

    let mut items: Vec<Value> = Vec::new();
    let mut m = match typ.as_str() {
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
                        po.insert(k.replace('-', "_"), v);
                    }
                    m.insert("plugin_opts".into(), Value::Object(po));
                }
            }
            if plugin == "shadow-tls" {
                if let Some(opts) = p.get_map("plugin-opts") {
                    let st = shadow_tls_outbound(p, &opts);
                    m.insert("detour".into(), json!(format!("{}_shadowtls", p.name())));
                    items.push(Value::Object(st));
                }
            }
            m
        }
        "ssr" => {
            let mut m = base(p, "shadowsocksr");
            for (src, dst) in [("cipher", "method"), ("password", "password"),
                ("obfs", "obfs"), ("protocol", "protocol")] {
                m.insert(dst.into(), json!(p.get_str(src)));
            }
            m
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
            m
        }
        "trojan" => {
            let mut m = base(p, "trojan");
            m.insert("password".into(), json!(p.get_str("password")));
            m
        }
        "hysteria" => {
            let mut m = base(p, "hysteria");
            m.insert("auth_str".into(), json!(p.get_str("auth-str")));
            m
        }
        "hysteria2" => {
            let mut m = base(p, "hysteria2");
            m.insert("password".into(), json!(p.get_str("password")));
            let obfs = p.get_str("obfs");
            if !obfs.is_empty() {
                let mut o = JMap::new();
                o.insert("type".into(), json!(obfs));
                o.insert("password".into(), json!(p.get_str("obfs-password")));
                m.insert("obfs".into(), Value::Object(o));
            }
            if let Some(ports) = p.get("ports") {
                let arr: Vec<Value> = crate::util::to_slice(ports)
                    .iter()
                    .map(|v| json!(value_str(v)))
                    .collect();
                if !arr.is_empty() {
                    m.insert("server_ports".into(), Value::Array(arr));
                }
            }
            m
        }
        "tuic" => {
            let mut m = base(p, "tuic");
            m.insert("uuid".into(), json!(p.get_str("uuid")));
            m.insert("password".into(), json!(p.get_str("password")));
            m
        }
        "anytls" => {
            let mut m = base(p, "anytls");
            m.insert("password".into(), json!(p.get_str("password")));
            m
        }
        "http" | "socks5" => {
            let mut m = base(p, if typ == "socks5" { "socks" } else { "http" });
            for k in ["username", "password"] {
                if !p.get_str(k).is_empty() {
                    m.insert(k.into(), json!(p.get_str(k)));
                }
            }
            m
        }
        "ssh" => {
            let mut m = base(p, "ssh");
            m.insert("user".into(), json!(p.get_str("username")));
            m.insert("password".into(), json!(p.get_str("password")));
            m
        }
        "snell" => {
            let mut m = base(p, "snell");
            m.insert("password".into(), json!(p.get_str("password")));
            if let Some(v) = tval(p, "version") {
                m.insert("version".into(), v);
            }
            m
        }
        "naive" => {
            let mut m = base(p, "naive");
            m.insert("username".into(), json!(p.get_str("username")));
            m.insert("password".into(), json!(p.get_str("password")));
            m
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
            for (src, dst) in [("pre-shared-key", "pre_shared_key"), ("reserved", "reserved"),
                ("allowed-ips", "allowed_ips"), ("persistent-keepalive", "persistent_keepalive_interval")] {
                if let Some(v) = tval(p, src) {
                    peer.insert(dst.into(), v);
                }
            }
            m.insert("peers".into(), Value::Array(vec![Value::Object(peer)]));
            if p.get_i64("mtu") > 0 {
                m.insert("mtu".into(), json!(p.get_i64("mtu")));
            }
            m
        }
        "tailscale" => {
            let mut m = JMap::new();
            m.insert("type".into(), json!("tailscale"));
            m.insert("tag".into(), json!(p.name()));
            for (k, v) in p.fields() {
                if !matches!(k.as_str(), "type" | "name" | "server" | "port") && !k.starts_with('_') {
                    m.insert(k.replace('-', "_"), v.clone());
                }
            }
            m
        }
        _ => {
            if !include {
                anyhow::bail!("unsupported proxy type");
            }
            // includeUnsupported 时未知协议通用透传，尽量不丢节点
            let mut m = base(p, &typ);
            for (k, v) in p.fields() {
                if !m.contains_key(k)
                    && !matches!(k.as_str(), "type" | "name" | "server" | "port")
                    && !k.starts_with('_')
                {
                    m.insert(k.replace('-', "_"), v.clone());
                }
            }
            m
        }
    };

    passthrough(&mut m, p);
    attach_common(&mut m, p)?;
    items.insert(0, Value::Object(m));

    // stream ShadowTLS：主链路 detour 到 shadowtls，并去掉自身 tls
    if let Some(st) = st_out {
        if let Some(Value::Object(main)) = items.get_mut(0) {
            main.insert("detour".into(), json!(format!("{}_shadowtls", p.name())));
            main.remove("tls");
        }
        items.push(Value::Object(st));
    }
    // includeUnsupported：name-cert-verify -> tls.certificate_server_name
    if include {
        if let Some(v) = tval(p, "name-cert-verify") {
            for item in &mut items {
                if let Value::Object(o) = item {
                    if let Some(tls_map) = o.get_mut("tls").and_then(|v| v.as_object_mut()) {
                        tls_map.insert("certificate_server_name".into(), v.clone());
                    }
                }
            }
        }
    }
    Ok(items)
}
