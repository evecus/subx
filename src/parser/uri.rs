//! 各协议 URI 解析，产出统一的 Proxy 动态字段对象。

use crate::model::Proxy;
use crate::parser::arr_of_strings;
use crate::util::{
    base64_decode, base64_decode_or_self, get_str, is_true, parse_query, query_decode,
    split_host_port, url_decode, value_str, JMap,
};
use serde_json::{json, Value};
use std::collections::HashMap;

pub struct UriParts {
    pub userinfo: String,
    pub host: String,
    pub port: i64,
    pub path: String,
    pub query: HashMap<String, String>,
    pub name: String,
}

/// 解析 `userinfo@host:port/path?query#name`。
pub fn parse_uri_parts(payload: &str) -> Option<UriParts> {
    let (main, frag) = match payload.split_once('#') {
        Some((m, f)) => (m, url_decode(f)),
        None => (payload, String::new()),
    };
    let (before_q, query_str) = match main.split_once('?') {
        Some((b, q)) => (b, q),
        None => (main, ""),
    };
    let query = parse_query(query_str);
    let (hostport, path) = match before_q.find('/') {
        Some(i) => (&before_q[..i], before_q[i..].to_string()),
        None => (before_q, String::new()),
    };
    let (userinfo, hp) = match hostport.rfind('@') {
        Some(i) => (hostport[..i].to_string(), hostport[i + 1..].to_string()),
        None => (String::new(), hostport.to_string()),
    };
    let (host, port_str, ok) = split_host_port(&hp);
    if !ok || host.is_empty() {
        return None;
    }
    let port = port_str.parse::<i64>().unwrap_or(0);
    let mut name = frag;
    if name.is_empty() {
        name = query.get("remarks").or_else(|| query.get("remark")).cloned().unwrap_or_default();
    }
    Some(UriParts { userinfo, host, port, path, query, name })
}

pub fn parse_uri(line: &str) -> Option<Proxy> {
    let (scheme, payload) = line.split_once("://")?;
    let scheme = scheme.to_lowercase();
    match scheme.as_str() {
        "ss" => parse_ss(payload),
        "ssr" => parse_ssr(payload),
        "vmess" => parse_vmess(payload),
        "vless" => parse_vless(payload),
        "trojan" | "trojan-go" => parse_trojan(payload, &scheme),
        "hysteria" => parse_hysteria(payload),
        "hysteria2" | "hy2" => parse_hysteria2(payload),
        "tuic" => parse_tuic(payload),
        "wireguard" | "wg" => parse_wireguard(payload),
        "socks" | "socks5" | "socks5h" | "socks4" => parse_socks(payload, &scheme),
        "http" | "https" => parse_http(payload, &scheme),
        "anytls" => parse_anytls(payload),
        "snell" | "ssh" | "naive" | "juicity" | "mieru" | "masque" | "sudoku"
        | "shadowquic" | "trusttunnel" | "h2-connect" | "gost-relay" | "direct" => {
            parse_generic(payload, &scheme)
        }
        _ => None,
    }
}

fn q<'a>(parts: &'a UriParts, key: &str) -> &'a str {
    parts.query.get(key).map(|s| s.as_str()).unwrap_or("")
}

fn q_any<'a>(parts: &'a UriParts, keys: &[&str]) -> &'a str {
    for k in keys {
        let v = q(parts, k);
        if !v.is_empty() {
            return v;
        }
    }
    ""
}

fn base_node(typ: &str, parts: &UriParts) -> Proxy {
    let mut p = Proxy::new();
    p.set("type", typ);
    p.set("server", parts.host.clone());
    p.set("port", parts.port);
    p.set("udp", true);
    if !parts.name.is_empty() {
        p.set("name", parts.name.clone());
    }
    p
}

fn apply_common_query(p: &mut Proxy, parts: &UriParts) {
    for (from, to) in [
        ("sni", "sni"), ("peer", "sni"), ("servername", "sni"),
        ("fp", "client-fingerprint"), ("client-fingerprint", "client-fingerprint"),
        ("pcs", "tls-fingerprint"),
        ("allowInsecure", "skip-cert-verify"), ("insecure", "skip-cert-verify"),
        ("allow-insecure", "skip-cert-verify"),
        ("packetEncoding", "packet-encoding"),
        ("congestion_control", "congestion-controller"),
        ("udp_relay_mode", "udp-relay-mode"),
        ("reduce_rtt", "reduce-rtt"),
        ("disable_sni", "disable-sni"),
        ("max_open_streams", "max-open-streams"),
        ("heartbeat_interval", "heartbeat-interval"),
        ("request_timeout", "request-timeout"),
        ("recv_window_conn", "recv-window-conn"),
        ("recv_window", "recv-window"),
        ("disable_mtu_discovery", "disable-mtu-discovery"),
        ("fast_open", "fast-open"),
        ("obfsPassword", "obfs-password"), ("obfs_password", "obfs-password"),
        ("pinSHA256", "pin-sha256"),
        ("hop_interval", "hop-interval"),
    ] {
        let v = q(parts, from);
        if v.is_empty() {
            continue;
        }
        let val = match to {
            "skip-cert-verify" | "reduce-rtt" | "disable-sni" | "disable-mtu-discovery" | "fast-open" => {
                json!(is_true(v))
            }
            "sni" | "client-fingerprint" | "tls-fingerprint" | "packet-encoding" => json!(v),
            _ => json!(v),
        };
        if !p.has(to) || p.get_str(to).is_empty() {
            p.set_value(to, val);
        }
    }
    let alpn = q_any(parts, &["alpn", "alpns"]);
    if !alpn.is_empty() && !p.has("alpn") {
        p.set_value("alpn", arr_of_strings(alpn));
    }
    let ua = q(parts, "ua");
    if !ua.is_empty() {
        p.set("user-agent", ua);
    }
}

fn apply_transport(p: &mut Proxy, parts: &UriParts) {
    let network = q_any(parts, &["type", "network", "net", "headerType"]);
    let network = network.to_lowercase();
    if network.is_empty() || network == "tcp" || network == "none" || network == "raw" {
        return;
    }
    p.set("network", network.clone());
    let path = q_any(parts, &["path", "ws-path", "serviceName", "service-name"]);
    let host = q_any(parts, &["host", "ws-host", "Host", "authority"]);
    let key = format!("{}-opts", network);
    let mut opts = JMap::new();
    match network.as_str() {
        "ws" | "http" | "h2" | "httpupgrade" | "xhttp" => {
            if !path.is_empty() {
                opts.insert("path".into(), json!(path));
            }
            let mut headers = JMap::new();
            if !host.is_empty() {
                headers.insert("Host".into(), json!(host));
            }
            if !headers.is_empty() {
                opts.insert("headers".into(), Value::Object(headers));
            }
            if network == "xhttp" {
                let mode = q_any(parts, &["mode", "xhttpMode"]);
                if !mode.is_empty() {
                    opts.insert("mode".into(), json!(mode));
                }
            }
        }
        "grpc" => {
            if !path.is_empty() {
                opts.insert("grpc-service-name".into(), json!(path));
            }
        }
        "quic" => {}
        _ => {}
    }
    if !opts.is_empty() {
        p.set_value(&key, Value::Object(opts));
    }
}

// ---------------- SS ----------------

fn parse_ss(payload: &str) -> Option<Proxy> {
    let (main, frag) = match payload.split_once('#') {
        Some((m, f)) => (m, url_decode(f)),
        None => (payload, String::new()),
    };
    // legacy：整体 base64(method:password@host:port)
    let expanded = if !main.contains('@') {
        let decoded = base64_decode(main)?;
        if !decoded.contains('@') {
            return None;
        }
        decoded
    } else {
        main.to_string()
    };
    let parts = parse_uri_parts(&format!("{}#{}", expanded, frag))?;
    let mut p = base_node("ss", &parts);

    let userinfo = parts.userinfo.clone();
    let decoded_user = base64_decode(&userinfo).unwrap_or_else(|| url_decode(&userinfo));
    let (cipher, password) = if let Some((c, pw)) = decoded_user.split_once(':') {
        (c.to_string(), pw.to_string())
    } else if let Some((c, pw)) = userinfo.split_once(':') {
        (c.to_string(), pw.to_string())
    } else {
        return None;
    };
    p.set("cipher", cipher);
    p.set("password", password);

    // plugin 参数（可能在 path 后，也可能在 query 中）
    let plugin_raw = {
        let mut v = q(&parts, "plugin").to_string();
        if v.is_empty() && parts.path.contains("plugin=") {
            let pq = parse_query(parts.path.split_once('?').map(|x| x.1).unwrap_or(""));
            v = pq.get("plugin").cloned().unwrap_or_default();
        }
        v
    };
    if !plugin_raw.is_empty() {
        apply_ss_plugin(&mut p, &plugin_raw);
    }
    // 额外的 SIP002 参数
    for (k, to) in [
        ("udp", "udp"), ("tfo", "tfo"), ("fast-open", "tfo"),
        ("udp-over-tcp", "udp-over-tcp"), ("plugin-opts", "plugin-opts"),
    ] {
        let v = q(&parts, k);
        if !v.is_empty() {
            if to == "udp" || to == "tfo" || to == "udp-over-tcp" {
                p.set(to, is_true(v));
            } else {
                p.set(to, v);
            }
        }
    }
    apply_common_query(&mut p, &parts);
    Some(p)
}

fn apply_ss_plugin(p: &mut Proxy, raw: &str) {
    let mut it = raw.splitn(2, ';');
    let name = it.next().unwrap_or("").trim();
    let opts_raw = it.next().unwrap_or("").trim();
    let opts = parse_query(opts_raw);
    let mut plugin_opts = JMap::new();
    for (k, v) in &opts {
        if !v.is_empty() {
            plugin_opts.insert(k.clone(), json!(v));
        }
    }
    let (plugin_name, mode) = match name {
        "simple-obfs" | "obfs-local" | "obfs" => ("obfs", opts.get("obfs").cloned().unwrap_or_else(|| "http".into())),
        "v2ray-plugin" => ("v2ray-plugin", opts.get("mode").cloned().unwrap_or_default()),
        "shadow-tls" => ("shadow-tls", String::new()),
        "restls" => ("restls", String::new()),
        other => (other, String::new()),
    };
    p.set("plugin", plugin_name);
    if plugin_name == "obfs" {
        plugin_opts.insert("mode".into(), json!(mode));
        if let Some(h) = opts.get("obfs-host") {
            plugin_opts.insert("host".into(), json!(h));
        }
    }
    if plugin_name == "shadow-tls" {
        if let Some(h) = opts.get("host") {
            plugin_opts.insert("host".into(), json!(h));
        }
        if let Some(pw) = opts.get("password") {
            plugin_opts.insert("password".into(), json!(pw));
        }
        if let Some(v) = opts.get("version") {
            plugin_opts.insert("version".into(), json!(v));
        }
    }
    if !plugin_opts.is_empty() {
        p.set_value("plugin-opts", Value::Object(plugin_opts));
    }
}

// ---------------- SSR ----------------

fn parse_ssr(payload: &str) -> Option<Proxy> {
    let decoded = base64_decode(payload.trim_end_matches('#').split('#').next().unwrap_or(payload))?;
    let (main, query) = match decoded.split_once("/?") {
        Some((m, q)) => (m, parse_query(q)),
        None => (decoded.as_str(), HashMap::new()),
    };
    let fields: Vec<&str> = main.split(':').collect();
    if fields.len() < 6 {
        return None;
    }
    let mut p = Proxy::new();
    p.set("type", "ssr");
    p.set("server", fields[0]);
    p.set("port", fields[1].parse::<i64>().unwrap_or(0));
    p.set("protocol", fields[2]);
    p.set("cipher", fields[3]);
    p.set("obfs", fields[4]);
    p.set("password", base64_decode_or_self(fields[5]));
    for (k, to) in [
        ("protoparam", "protocol-param"), ("protocol-param", "protocol-param"),
        ("obfsparam", "obfs-param"), ("obfs-param", "obfs-param"),
        ("remarks", "name"), ("udp", "udp"), ("uot", "udp-over-tcp"),
        ("tfo", "tfo"),
    ] {
        if let Some(v) = query.get(k) {
            if to == "udp" || to == "tfo" || to == "udp-over-tcp" {
                p.set(to, is_true(v));
            } else {
                let dec = base64_decode_or_self(v);
                p.set(to, dec);
            }
        }
    }
    p.set("udp", true);
    Some(p)
}

// ---------------- VMess ----------------

fn parse_vmess(payload: &str) -> Option<Proxy> {
    let decoded = base64_decode(payload.split('#').next().unwrap_or(payload))?;
    let obj: Value = match serde_json::from_str(&decoded) {
        Ok(v) => v,
        Err(_) => crate::util::json_loose(&decoded).unwrap_or(Value::Null),
    };
    let m = obj.as_object()?;
    if m.get("add").is_none() && m.get("server").is_none() {
        // 兼容 vmess://uuid@host:port?... 形式
        return parse_vmess_uri(payload);
    }
    let mut p = Proxy::new();
    p.set("type", "vmess");
    p.set("server", get_str(m, "add").or_alt(get_str(m, "server")));
    p.set("port", crate::util::value_i64(m.get("port").unwrap_or(&Value::Null)));
    p.set("uuid", get_str(m, "id").or_alt(get_str(m, "uuid")));
    p.set("alterId", crate::util::value_i64(m.get("aid").unwrap_or(&Value::Null)));
    p.set("name", get_str(m, "ps").or_alt(get_str(m, "name")));
    let scy = get_str(m, "scy").or_alt(get_str(m, "security")).or_alt(get_str(m, "cipher"));
    if !scy.is_empty() {
        p.set("cipher", scy);
    }
    let net = get_str(m, "net").or_alt(get_str(m, "network"));
    if !net.is_empty() && net != "tcp" {
        p.set("network", net);
    }
    let tls = get_str(m, "tls");
    if tls == "tls" || tls == "true" {
        p.set("tls", true);
    }
    for (k, to) in [("sni", "sni"), ("servername", "sni"), ("host", "host"), ("fp", "client-fingerprint")] {
        let v = get_str(m, k);
        if !v.is_empty() {
            p.set(to, v);
        }
    }
    if let Some(v) = m.get("alpn").filter(|v| !v.is_null()) {
        p.set_value("alpn", arr_of_strings(&value_str(v).trim_matches(|c| c == '[' || c == ']')));
    }
    let path = get_str(m, "path");
    let host = get_str(m, "host").or_alt(get_str(m, "sni"));
    let net = p.get_str("network");
    if !net.is_empty() && net != "tcp" {
        let key = format!("{}-opts", net);
        let mut opts = JMap::new();
        if !path.is_empty() {
            if net == "grpc" {
                opts.insert("grpc-service-name".into(), json!(path));
            } else {
                opts.insert("path".into(), json!(path));
            }
        }
        if !host.is_empty() {
            let mut headers = JMap::new();
            headers.insert("Host".into(), json!(host));
            opts.insert("headers".into(), Value::Object(headers));
        }
        if !opts.is_empty() {
            p.set_value(&key, Value::Object(opts));
        }
    }
    p.set("udp", true);
    Some(p)
}

fn parse_vmess_uri(payload: &str) -> Option<Proxy> {
    let parts = parse_uri_parts(payload)?;
    let mut p = base_node("vmess", &parts);
    p.set("uuid", parts.userinfo.clone());
    apply_common_query(&mut p, &parts);
    apply_transport(&mut p, &parts);
    let sec = q_any(&parts, &["security", "tls"]);
    if sec == "tls" || is_true(sec) {
        p.set("tls", true);
    }
    Some(p)
}

/// 取第一个非空字符串的小工具。
trait OrAlt {
    fn or_alt(self, other: String) -> String;
}
impl OrAlt for String {
    fn or_alt(self, other: String) -> String {
        if self.is_empty() { other } else { self }
    }
}

// ---------------- VLESS ----------------

fn parse_vless(payload: &str) -> Option<Proxy> {
    let decoded_payload = if !payload.contains('@') {
        // Shadowrocket 风格：base64(userinfo@host:port)?query
        let (b, tail) = payload.split_once('?').unwrap_or((payload, ""));
        let d = base64_decode(b)?;
        format!("{}?{}", d, tail)
    } else {
        payload.to_string()
    };
    let parts = parse_uri_parts(&decoded_payload)?;
    let mut uuid = url_decode(&parts.userinfo);
    if !payload.contains('@') {
        // Shadowrocket 的 "cipher:uuid" 前缀
        if let Some((_, u)) = uuid.split_once(':') {
            uuid = u.to_string();
        }
    }
    let mut p = base_node("vless", &parts);
    p.set("uuid", uuid);
    let security = q_any(&parts, &["security", "encryption"]).to_lowercase();
    let pbk = q_any(&parts, &["pbk", "public-key", "publicKey"]);
    if security != "none" && (!security.is_empty() || !pbk.is_empty()) {
        p.set("tls", true);
    }
    if is_true(q(&parts, "tls")) {
        p.set("tls", true);
    }
    if !pbk.is_empty() {
        let mut reality = JMap::new();
        reality.insert("public-key".into(), json!(pbk));
        let sid = q_any(&parts, &["sid", "short-id", "shortId"]);
        if !sid.is_empty() {
            reality.insert("short-id".into(), json!(sid));
        }
        p.set_value("reality-opts", Value::Object(reality));
    }
    let flow = q(&parts, "flow");
    if !flow.is_empty() {
        p.set("flow", flow);
    }
    let ech = q(&parts, "ech");
    if !ech.is_empty() {
        p.set("_echConfigList", ech);
        let mut ech_opts = JMap::new();
        ech_opts.insert("enable".into(), json!(true));
        ech_opts.insert("config".into(), json!(ech));
        p.set_value("ech-opts", Value::Object(ech_opts));
    }
    apply_common_query(&mut p, &parts);
    apply_transport(&mut p, &parts);
    if p.get_str("network").is_empty() {
        p.set("network", "tcp");
    }
    Some(p)
}

// ---------------- Trojan ----------------

fn parse_trojan(payload: &str, _scheme: &str) -> Option<Proxy> {
    let parts = parse_uri_parts(payload)?;
    let mut p = base_node("trojan", &parts);
    p.set("password", url_decode(&parts.userinfo));
    p.set("tls", true);
    apply_common_query(&mut p, &parts);
    apply_transport(&mut p, &parts);
    if p.get_str("network").is_empty() {
        p.set("network", "tcp");
    }
    Some(p)
}

// ---------------- Hysteria ----------------

fn parse_hysteria(payload: &str) -> Option<Proxy> {
    let parts = parse_uri_parts(payload)?;
    let mut p = base_node("hysteria", &parts);
    let auth = q_any(&parts, &["auth", "auth-str", "auth_str"]);
    let auth = if auth.is_empty() { url_decode(&parts.userinfo) } else { auth.to_string() };
    if !auth.is_empty() {
        p.set("auth-str", auth);
    }
    for (k, to) in [
        ("up", "up"), ("upmbps", "up"), ("down", "down"), ("downmbps", "down"),
        ("protocol", "protocol"), ("obfs", "obfs"),
        ("recv-window-conn", "recv-window-conn"), ("recv-window", "recv-window"),
    ] {
        let v = q(&parts, k);
        if !v.is_empty() {
            p.set(to, v);
        }
    }
    apply_common_query(&mut p, &parts);
    Some(p)
}

fn parse_hysteria2(payload: &str) -> Option<Proxy> {
    let parts = parse_uri_parts(payload)?;
    let mut p = base_node("hysteria2", &parts);
    let auth = q_any(&parts, &["auth", "password", "auth-str"]);
    let auth = if auth.is_empty() { url_decode(&parts.userinfo) } else { auth.to_string() };
    if !auth.is_empty() {
        p.set("password", auth);
    }
    for (k, to) in [
        ("up", "up"), ("upmbps", "up"), ("down", "down"), ("downmbps", "down"),
        ("obfs", "obfs"), ("obfsPassword", "obfs-password"),
        ("obfs-password", "obfs-password"), ("ports", "ports"), ("mport", "ports"),
    ] {
        let v = q(&parts, k);
        if !v.is_empty() {
            p.set(to, v);
        }
    }
    apply_common_query(&mut p, &parts);
    Some(p)
}

// ---------------- TUIC ----------------

fn parse_tuic(payload: &str) -> Option<Proxy> {
    let parts = parse_uri_parts(payload)?;
    let mut p = base_node("tuic", &parts);
    let ui = url_decode(&parts.userinfo);
    if let Some((uuid, password)) = ui.split_once(':') {
        p.set("uuid", uuid);
        p.set("password", password);
    } else if !ui.is_empty() {
        p.set("uuid", ui);
    }
    for (k, to) in [
        ("version", "version"), ("token", "token"),
        ("congestion_control", "congestion-controller"),
        ("congestion-controller", "congestion-controller"),
        ("udp_relay_mode", "udp-relay-mode"), ("udp-relay-mode", "udp-relay-mode"),
        ("max_open_streams", "max-open-streams"), ("max-open-streams", "max-open-streams"),
        ("heartbeat_interval", "heartbeat-interval"), ("request_timeout", "request-timeout"),
        ("gc_interval", "gc-interval"), ("gc_lifetime", "gc-lifetime"),
    ] {
        let v = q(&parts, k);
        if !v.is_empty() {
            p.set(to, v);
        }
    }
    apply_common_query(&mut p, &parts);
    Some(p)
}

// ---------------- WireGuard ----------------

fn parse_wireguard(payload: &str) -> Option<Proxy> {
    let parts = parse_uri_parts(payload)?;
    let mut p = base_node("wireguard", &parts);
    let pk = {
        let ui = parts.userinfo.clone();
        base64_decode(&ui).unwrap_or_else(|| url_decode(&ui))
    };
    if !pk.is_empty() {
        p.set("private-key", pk);
    }
    for (k, to) in [
        ("private-key", "private-key"), ("private_key", "private-key"),
        ("public-key", "public-key"), ("public_key", "public-key"), ("peer", "public-key"),
        ("pre-shared-key", "pre-shared-key"), ("preshared-key", "pre-shared-key"),
        ("ip", "ip"), ("address", "ip"), ("ipv6", "ipv6"),
        ("mtu", "mtu"), ("keepalive", "persistent-keepalive"),
        ("persistent-keepalive", "persistent-keepalive"),
        ("reserved", "reserved"),
    ] {
        let v = q(&parts, k);
        if !v.is_empty() {
            if to == "mtu" || to == "persistent-keepalive" {
                p.set(to, v.parse::<i64>().unwrap_or(0));
            } else {
                p.set(to, v);
            }
        }
    }
    let reserved = q(&parts, "reserved");
    if !reserved.is_empty() {
        let arr: Vec<Value> = reserved.split(',').filter_map(|s| s.trim().parse::<i64>().ok()).map(|n| json!(n)).collect();
        if !arr.is_empty() {
            p.set_value("reserved", Value::Array(arr));
        }
    }
    let peer_pub = q_any(&parts, &["public-key", "peer"]);
    if !peer_pub.is_empty() {
        let mut peer = JMap::new();
        peer.insert("server".into(), json!(parts.host));
        peer.insert("port".into(), json!(parts.port));
        peer.insert("public-key".into(), json!(peer_pub));
        let ps = q_any(&parts, &["pre-shared-key", "preshared-key"]);
        if !ps.is_empty() {
            peer.insert("pre-shared-key".into(), json!(ps));
        }
        let allowed = q_any(&parts, &["allowed-ips", "allowed_ips"]);
        if !allowed.is_empty() {
            peer.insert("allowed-ips".into(), arr_of_strings(allowed));
        }
        p.set_value("peers", json!([peer]));
    }
    apply_common_query(&mut p, &parts);
    Some(p)
}

// ---------------- SOCKS / HTTP / AnyTLS ----------------

fn parse_socks(payload: &str, scheme: &str) -> Option<Proxy> {
    let parts = parse_uri_parts(payload)?;
    let mut p = base_node("socks5", &parts);
    let ui = url_decode(&parts.userinfo);
    if let Some((u, pw)) = ui.split_once(':') {
        p.set("username", u);
        p.set("password", pw);
    }
    if scheme == "https" || is_true(q(&parts, "tls")) {
        p.set("tls", true);
    }
    apply_common_query(&mut p, &parts);
    Some(p)
}

fn parse_http(payload: &str, scheme: &str) -> Option<Proxy> {
    let parts = parse_uri_parts(payload)?;
    let mut p = base_node("http", &parts);
    let ui = url_decode(&parts.userinfo);
    if let Some((u, pw)) = ui.split_once(':') {
        p.set("username", u);
        p.set("password", pw);
    }
    if scheme == "https" {
        p.set("tls", true);
        let host = q_any(&parts, &["sni", "peer"]);
        if !host.is_empty() {
            p.set("sni", host);
        }
    }
    apply_common_query(&mut p, &parts);
    Some(p)
}

fn parse_anytls(payload: &str) -> Option<Proxy> {
    let parts = parse_uri_parts(payload)?;
    let mut p = base_node("anytls", &parts);
    p.set("password", url_decode(&parts.userinfo));
    apply_common_query(&mut p, &parts);
    Some(p)
}

// ---------------- 其它协议通用解析 ----------------

fn parse_generic(payload: &str, scheme: &str) -> Option<Proxy> {
    let parts = parse_uri_parts(payload)?;
    let typ = match scheme {
        "trojan-go" => "trojan",
        "wg" => "wireguard",
        "h2-connect" => "h2-connect",
        other => other,
    };
    let mut p = base_node(typ, &parts);
    let ui = url_decode(&parts.userinfo);
    if let Some((u, pw)) = ui.split_once(':') {
        p.set("uuid", u);
        p.set("password", pw);
    } else if !ui.is_empty() {
        p.set("password", ui);
    }
    for (k, v) in &parts.query {
        if v.is_empty() || matches!(k.as_str(), "remarks" | "remark") {
            continue;
        }
        let key = k.replace('_', "-");
        if !p.has(&key) {
            p.set(&key, v.clone());
        }
    }
    apply_common_query(&mut p, &parts);
    apply_transport(&mut p, &parts);
    Some(p)
}

/// 供 producer 复用：把 query 参数值解码。
pub fn decode_query_value(s: &str) -> String {
    query_decode(s)
}
