//! 产出器：把统一 Proxy 列表转换成目标平台的配置文本。

pub mod clash;
pub mod lines;
pub mod platform;
pub mod singbox;
pub mod uri;

use crate::model::{canonical_targets, Proxy, Target};
use crate::util::{get_bool, is_ip, lower, JMap};
use anyhow::{anyhow, Result};
use rand::Rng;
use serde_json::Value;

pub fn canonical() -> Vec<Target> {
    canonical_targets()
}

pub fn known(name: &str) -> bool {
    matches!(
        lower(name).as_str(),
        "json" | "uri" | "v2ray" | "v2" | "clash" | "mihomo" | "meta" | "clashmeta"
            | "clash.meta" | "stash" | "surge" | "surge-mac" | "surgemac" | "surfboard"
            | "loon" | "shadowrocket" | "qx" | "sing-box" | "singbox" | "egern"
    )
}

pub fn produce(target: &str, proxies: &[Proxy], options: Option<&JMap>) -> Result<String> {
    let t = lower(target);
    if !known(&t) {
        return Err(anyhow!("unsupported target: {}", target));
    }
    let list = prepare(proxies, &t, options);
    match t.as_str() {
        "json" => Ok(uri::produce_json(&list)),
        "uri" => Ok(uri::produce_uri(&list)),
        "v2ray" | "v2" => Ok(uri::produce_v2ray(&list)),
        "clash" | "mihomo" | "meta" | "clashmeta" | "clash.meta" | "stash" | "shadowrocket" => {
            clash::produce_clash(&t, &list, options)
        }
        "egern" => platform::produce_egern(&list, options),
        "sing-box" | "singbox" => singbox::produce_singbox(&list, options),
        "qx" => Ok(lines::produce_qx(&list)),
        "surge" => Ok(lines::produce_surge(&t, &list)),
        "surge-mac" | "surgemac" => platform::produce_surgemac(&list, options),
        "surfboard" => Ok(lines::produce_surfboard(&list)),
        "loon" => Ok(lines::produce_loon(&list)),
        _ => Err(anyhow!("unsupported target: {}", target)),
    }
}

fn is_qx_like(t: &str) -> bool {
    matches!(t, "qx" | "quantumultx" | "shadowrocket")
}

pub fn include_unsupported(options: Option<&JMap>) -> bool {
    options
        .and_then(|o| o.get("include-unsupported-proxy"))
        .map(crate::util::truthy)
        .unwrap_or(false)
}

/// 对齐 Go producer/produce.go 的 prepareProxies：过滤 + 深拷贝 + 通用归一化。
pub fn prepare(proxies: &[Proxy], target: &str, options: Option<&JMap>) -> Vec<Proxy> {
    let include = include_unsupported(options);
    let mut out = Vec::new();
    for p in proxies {
        if !include {
            if let Some(supported) = p.supported() {
                if matches!(supported.get(target), Some(Value::Bool(false))) {
                    continue;
                }
            }
        }
        if !include && p.is_ss_over_tls() && !is_qx_like(target) {
            continue;
        }
        if p.type_() == "vless" {
            if let Some(reality) = p.get_map("reality-opts") {
                if crate::util::get_str(&reality, "public-key").trim().is_empty() {
                    continue;
                }
            }
        }
        let mut c = p.deep_clone();
        if let Some(resolved) = c.get("resolved").cloned() {
            c.set_value("_resolved", resolved);
        }
        if c.get_str("name").trim().is_empty() {
            c.set("name", format!("{} {}:{}", c.type_(), c.server(), c.port()));
        }
        if get_bool(c.fields(), "disable-sni") {
            match target {
                "surge" | "surgemac" | "shadowrocket" => c.set("sni", "off"),
                _ if c.type_() != "tuic" && target != "sing-box" && target != "singbox" => {
                    if is_ip(&c.server()) {
                        c.set("sni", c.server());
                    } else {
                        c.set("sni", "127.0.0.1");
                    }
                }
                _ => {}
            }
        }
        if let Some(ports) = c.get("ports").cloned() {
            let mut s = crate::util::value_str(&ports);
            if !matches!(target, "meta" | "clashmeta" | "clash.meta" | "mihomo") {
                s = s.replace('/', ",");
            }
            c.set("ports", s.clone());
            if c.port() == 0 {
                c.set("port", random_port(&s));
            }
        }
        if c.type_() == "wireguard" {
            normalize_wireguard_interface(&mut c);
        }
        // xhttp download-settings 的 Reality 继承 / stream-one 过滤（对齐 Go produce.go）
        let mihomo = matches!(
            target,
            "clash" | "mihomo" | "meta" | "clashmeta" | "clash.meta" | "stash" | "shadowrocket"
        );
        if !crate::xhttp::filter_or_inherit(&mut c, mihomo) {
            continue;
        }
        drop_internal_fields(&mut c);
        out.push(c);
    }
    out
}

pub fn drop_internal_fields(p: &mut Proxy) {
    for k in [
        "subName", "collectionName", "id", "resolved", "no-resolve", "_resolved",
        "_subName", "_subDisplayName", "_collectionName", "_collectionDisplayName",
        "supported", "_echConfigList", "_h2", "_vcn",
    ] {
        p.delete(k);
    }
}

fn random_port(ports: &str) -> i64 {
    let parts: Vec<&str> = ports.split(|c| c == ',' || c == '/').filter(|s| !s.trim().is_empty()).collect();
    if parts.is_empty() {
        return 0;
    }
    let idx = rand::thread_rng().gen_range(0..parts.len());
    parts[idx].trim().parse::<i64>().unwrap_or(0)
}

fn normalize_wireguard_interface(p: &mut Proxy) {
    // 统一 ip / ipv6 的 CIDR 表示，其余字段保持透传
    for key in ["ip", "ipv6"] {
        if let Some(v) = p.get(key).cloned() {
            if let Value::String(s) = v {
                let t = s.trim().to_string();
                if !t.is_empty() && !t.contains('/') {
                    p.set(key, format!("{}/{}", t, if key == "ip" { 32 } else { 128 }));
                }
            }
        }
    }
}
