//! JSON / URI / V2Ray 产出，以及单节点 URI 生成（ToURI）。

use crate::ech;
use crate::model::Proxy;
use crate::util::{base64_encode, is_ipv6, path_escape, query_escape, JMap};
use crate::xhttp;
use serde_json::{json as j, Value};

pub fn produce_json(proxies: &[Proxy]) -> String {
    proxies
        .iter()
        .map(|p| serde_json::to_string(p.fields()).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn produce_uri(proxies: &[Proxy]) -> String {
    proxies.iter().filter_map(|p| {
        let s = to_uri(p);
        if s.is_empty() { None } else { Some(s) }
    }).collect::<Vec<_>>().join("\n")
}

pub fn produce_v2ray(proxies: &[Proxy]) -> String {
    base64_encode(&produce_uri(proxies))
}

struct Query {
    pairs: Vec<(String, String)>,
}
impl Query {
    fn new() -> Self { Self { pairs: Vec::new() } }
    fn push(&mut self, k: &str, v: &str) {
        if !v.is_empty() {
            self.pairs.push((k.to_string(), v.to_string()));
        }
    }
    fn flag(&mut self, k: &str, cond: bool, val: &str) {
        if cond { self.push(k, val); }
    }
    fn build(&self) -> String {
        self.pairs.iter().map(|(k, v)| format!("{}={}", k, query_escape(v))).collect::<Vec<_>>().join("&")
    }
}

fn host_port(p: &Proxy) -> String {
    let s = p.server();
    if is_ipv6(&s) && !s.starts_with('[') {
        format!("[{}]:{}", s, p.port())
    } else {
        format!("{}:{}", s, p.port())
    }
}

fn fragment(p: &Proxy) -> String {
    let name = p.name();
    if name.is_empty() {
        String::new()
    } else {
        format!("#{}", path_escape(&name))
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
    let network = p.get_str("network");
    if network.is_empty() || network == "tcp" {
        return (String::new(), String::new(), String::new());
    }
    let key = format!("{}-opts", network);
    let opts = p.get_map(&key).unwrap_or_default();
    let path = crate::util::get_str(&opts, "path");
    let path = if path.is_empty() { crate::util::get_str(&opts, "grpc-service-name") } else { path };
    let host = opts
        .get("headers")
        .and_then(|h| h.as_object())
        .and_then(|h| h.get("Host").or_else(|| h.get("host")))
        .map(crate::util::value_str)
        .unwrap_or_else(|| crate::util::get_str(&opts, "host"));
    (network, path, host)
}

fn append_common(q: &mut Query, p: &Proxy) {
    let sni = p.get_str("sni");
    q.push("sni", &sni);
    q.push("fp", &p.get_str("client-fingerprint"));
    q.push("alpn", &alpn_str(p));
    q.flag("allowInsecure", p.get_bool("skip-cert-verify"), "1");
    q.push("tfo", if p.get_bool("tfo") { "1" } else { "" });
    q.push("ech", &ech::build_xray_ech_config_list(
        p.get_map("ech-opts").as_ref(),
        &p.get_str("_echConfigList"),
    ));
}

/// 把单个 Proxy 转换成 URI；不支持的类型返回空串（由调用方跳过）。
pub fn to_uri(p: &Proxy) -> String {
    let typ = p.type_();
    match typ.as_str() {
        "ss" => ss_uri(p),
        "ssr" => ssr_uri(p),
        "vmess" => vmess_uri(p),
        "vless" => vless_uri(p),
        "trojan" => trojan_uri(p),
        "hysteria2" => hysteria2_uri(p),
        "hysteria" => hysteria_uri(p),
        "tuic" => tuic_uri(p),
        "wireguard" => wireguard_uri(p),
        "socks5" => socks_uri(p),
        "http" => http_uri(p),
        "anytls" => anytls_uri(p),
        _ => String::new(),
    }
}

fn ss_uri(p: &Proxy) -> String {
    let userinfo = base64_encode(&format!("{}:{}", p.get_str("cipher"), p.get_str("password")));
    let mut out = format!("ss://{}@{}", userinfo, host_port(p));
    let plugin = p.get_str("plugin");
    if !plugin.is_empty() {
        let mut parts = vec![plugin.clone()];
        if let Some(opts) = p.get_map("plugin-opts") {
            for (k, v) in &opts {
                if !matches!(k.as_str(), "mode" | "host" | "path") || !crate::util::value_str(v).is_empty() {
                    parts.push(format!("{}={}", k, crate::util::value_str(v)));
                }
            }
        }
        out.push_str(&format!("/?plugin={}", query_escape(&parts.join(";"))));
    }
    out.push_str(&fragment(p));
    out
}

fn ssr_uri(p: &Proxy) -> String {
    let mut payload = format!(
        "{}:{}:{}:{}:{}:{}",
        p.server(), p.port(), p.get_str("protocol"), p.get_str("cipher"),
        p.get_str("obfs"), base64_encode(&p.get_str("password"))
    );
    let mut q = Vec::new();
    if !p.name().is_empty() {
        q.push(format!("remarks={}", base64_encode(&p.name())));
    }
    if !p.get_str("protocol-param").is_empty() {
        q.push(format!("protoparam={}", base64_encode(&p.get_str("protocol-param"))));
    }
    if !p.get_str("obfs-param").is_empty() {
        q.push(format!("obfsparam={}", base64_encode(&p.get_str("obfs-param"))));
    }
    payload.push_str("/?");
    payload.push_str(&q.join("&"));
    format!("ssr://{}", base64_encode(&payload))
}

fn vmess_uri(p: &Proxy) -> String {
    let (network, path, host) = transport(p);
    let mut obj = JMap::new();
    obj.insert("v".into(), j!("2"));
    obj.insert("ps".into(), j!(p.name()));
    obj.insert("add".into(), j!(p.server()));
    obj.insert("port".into(), j!(p.port()));
    obj.insert("id".into(), j!(p.get_str("uuid")));
    obj.insert("aid".into(), j!(p.get_i64("alterId")));
    obj.insert("scy".into(), j!(p.get_str("cipher")));
    obj.insert("net".into(), j!(if network.is_empty() { "tcp" } else { &network }));
    obj.insert("type".into(), j!("none"));
    if !host.is_empty() { obj.insert("host".into(), j!(host)); }
    if !path.is_empty() { obj.insert("path".into(), j!(path)); }
    obj.insert("tls".into(), j!(if p.get_bool("tls") { "tls" } else { "" }));
    if !p.get_str("sni").is_empty() { obj.insert("sni".into(), j!(p.get_str("sni"))); }
    let alpn = alpn_str(p);
    if !alpn.is_empty() { obj.insert("alpn".into(), j!(alpn)); }
    if !p.get_str("client-fingerprint").is_empty() { obj.insert("fp".into(), j!(p.get_str("client-fingerprint"))); }
    format!("vmess://{}", base64_encode(&serde_json::to_string(&Value::Object(obj)).unwrap_or_default()))
}

fn vless_uri(p: &Proxy) -> String {
    let (network, path, host) = transport(p);
    let mut q = Query::new();
    q.push("encryption", "none");
    let reality = p.get_map("reality-opts");
    let security = if reality.is_some() { "reality" } else if p.get_bool("tls") { "tls" } else { "none" };
    q.push("security", security);
    if !network.is_empty() { q.push("type", &network); }
    if !path.is_empty() { q.push("path", &path); }
    if !host.is_empty() { q.push("host", &host); }
    if network == "grpc" && !path.is_empty() { q.push("serviceName", &path); }
    q.push("flow", &p.get_str("flow"));
    q.push("fp", &p.get_str("client-fingerprint"));
    q.push("alpn", &alpn_str(p));
    if let Some(r) = reality {
        q.push("pbk", &crate::util::get_str(&r, "public-key"));
        q.push("sid", &crate::util::get_str(&r, "short-id"));
    }
    q.flag("allowInsecure", p.get_bool("skip-cert-verify"), "1");
    // ECH 完整协商：ech-opts -> echConfigList（含 DoH / force-query / sockopt）
    q.push("ech", &ech::build_xray_ech_config_list(
        p.get_map("ech-opts").as_ref(),
        &p.get_str("_echConfigList"),
    ));
    // xhttp 结构化 extra（含 downloadSettings 继承）
    if p.get_str("network") == "xhttp" {
        if let Some(extra) = xhttp::build_structured_extra(p) {
            q.push("extra", &serde_json::to_string(&Value::Object(extra)).unwrap_or_default());
        }
    }
    let query = q.build();
    format!("vless://{}@{}{}{}{}", p.get_str("uuid"), host_port(p), if query.is_empty() { "" } else { "?" }, query, fragment(p))
}

fn trojan_uri(p: &Proxy) -> String {
    let (network, path, host) = transport(p);
    let mut q = Query::new();
    append_common(&mut q, p);
    if !network.is_empty() { q.push("type", &network); }
    if !path.is_empty() { q.push("path", &path); }
    if !host.is_empty() { q.push("host", &host); }
    let query = q.build();
    format!("trojan://{}@{}{}{}{}", query_escape(&p.get_str("password")), host_port(p), if query.is_empty() { "" } else { "?" }, query, fragment(p))
}

fn hysteria2_uri(p: &Proxy) -> String {
    let mut q = Query::new();
    append_common(&mut q, p);
    q.push("obfs", &p.get_str("obfs"));
    q.push("obfs-password", &p.get_str("obfs-password"));
    q.push("up", &p.get_str("up"));
    q.push("down", &p.get_str("down"));
    q.push("ports", &p.get_str("ports"));
    let query = q.build();
    format!("hysteria2://{}@{}{}{}{}", query_escape(&p.get_str("password")), host_port(p), if query.is_empty() { "" } else { "?" }, query, fragment(p))
}

fn hysteria_uri(p: &Proxy) -> String {
    let mut q = Query::new();
    q.push("auth", &p.get_str("auth-str"));
    append_common(&mut q, p);
    q.push("up", &p.get_str("up"));
    q.push("down", &p.get_str("down"));
    q.push("protocol", &p.get_str("protocol"));
    q.push("obfs", &p.get_str("obfs"));
    let query = q.build();
    format!("hysteria://{}{}{}{}", host_port(p), if query.is_empty() { "" } else { "?" }, query, fragment(p))
}

fn tuic_uri(p: &Proxy) -> String {
    let mut q = Query::new();
    q.push("version", &p.get_str("version"));
    q.push("congestion_control", &p.get_str("congestion-controller"));
    q.push("udp_relay_mode", &p.get_str("udp-relay-mode"));
    append_common(&mut q, p);
    q.flag("reduce_rtt", p.get_bool("reduce-rtt"), "1");
    let ui = format!("{}:{}", p.get_str("uuid"), p.get_str("password"));
    let query = q.build();
    format!("tuic://{}@{}{}{}{}", ui, host_port(p), if query.is_empty() { "" } else { "?" }, query, fragment(p))
}

fn wireguard_uri(p: &Proxy) -> String {
    let mut q = Query::new();
    q.push("public-key", &p.get_str("public-key"));
    q.push("pre-shared-key", &p.get_str("pre-shared-key"));
    q.push("ip", &p.get_str("ip"));
    q.push("ipv6", &p.get_str("ipv6"));
    q.push("mtu", &p.get_str("mtu"));
    q.push("keepalive", &p.get_str("persistent-keepalive"));
    if let Some(Value::Array(a)) = p.get("reserved") {
        let s = a.iter().map(crate::util::value_str).collect::<Vec<_>>().join(",");
        q.push("reserved", &s);
    }
    let ui = base64_encode(&p.get_str("private-key"));
    let query = q.build();
    format!("wireguard://{}@{}{}{}{}", ui, host_port(p), if query.is_empty() { "" } else { "?" }, query, fragment(p))
}

fn socks_uri(p: &Proxy) -> String {
    let u = p.get_str("username");
    let pw = p.get_str("password");
    let ui = if u.is_empty() && pw.is_empty() { String::new() } else { format!("{}:{}@", query_escape(&u), query_escape(&pw)) };
    format!("socks5://{}{}{}", ui, host_port(p), fragment(p))
}

fn http_uri(p: &Proxy) -> String {
    let u = p.get_str("username");
    let pw = p.get_str("password");
    let ui = if u.is_empty() && pw.is_empty() { String::new() } else { format!("{}:{}@", query_escape(&u), query_escape(&pw)) };
    let scheme = if p.get_bool("tls") { "https" } else { "http" };
    format!("{}://{}{}{}", scheme, ui, host_port(p), fragment(p))
}

fn anytls_uri(p: &Proxy) -> String {
    let mut q = Query::new();
    append_common(&mut q, p);
    let query = q.build();
    format!("anytls://{}@{}{}{}{}", query_escape(&p.get_str("password")), host_port(p), if query.is_empty() { "" } else { "?" }, query, fragment(p))
}
