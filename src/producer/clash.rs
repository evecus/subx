//! Clash 家族（clash / mihomo / stash / shadowrocket）与 Egern 产出。
//! 统一 Proxy 本身就是 mihomo 风格，主要工作是平台过滤 + 生成 proxies: 块。

use crate::model::Proxy;
use crate::producer::{drop_internal_fields, include_unsupported};
use crate::util::JMap;
use anyhow::Result;

const CLASH_ORIGINAL_TYPES: &[&str] = &[
    "ss", "ssr", "vmess", "vless", "socks5", "http", "snell", "trojan", "wireguard",
];

fn clash_filter(p: &Proxy, target: &str, options: Option<&JMap>) -> bool {
    if include_unsupported(options) {
        return true;
    }
    if target == "clash" {
        if !CLASH_ORIGINAL_TYPES.contains(&p.type_().as_str()) {
            return false;
        }
        if p.type_() == "vless" && (!p.get_str("flow").is_empty() || p.get_map("reality-opts").is_some()) {
            return false;
        }
        if p.has("underlying-proxy") || p.has("dialer-proxy") {
            return false;
        }
    }
    true
}

fn clash_map(mut p: Proxy) -> Proxy {
    drop_internal_fields(&mut p);
    // 保证关键字段类型正确
    if p.has("port") {
        p.set("port", p.port());
    }
    if p.has("tls") {
        p.set("tls", p.get_bool("tls"));
    }
    if p.has("skip-cert-verify") {
        p.set("skip-cert-verify", p.get_bool("skip-cert-verify"));
    }
    if p.has("udp") {
        p.set("udp", p.get_bool("udp"));
    }
    // servername 别名
    if !p.get_str("servername").is_empty() && p.get_str("sni").is_empty() {
        p.set("sni", p.get_str("servername"));
        p.delete("servername");
    }
    p
}

fn proxy_list_block(list: &[Proxy]) -> String {
    let mut out = String::from("proxies:\n");
    for p in list {
        out.push_str("  - ");
        out.push_str(&serde_json::to_string(p.fields()).unwrap_or_default());
        out.push('\n');
    }
    out
}

pub fn produce_clash(target: &str, proxies: &[Proxy], options: Option<&JMap>) -> Result<String> {
    let list: Vec<Proxy> = proxies
        .iter()
        .filter(|p| clash_filter(p, target, options))
        .cloned()
        .map(clash_map)
        .collect();
    Ok(proxy_list_block(&list))
}
