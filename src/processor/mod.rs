//! 操作符流水线：过滤、排序、重命名、去重、域名解析、引用合并等。

use crate::model::{Operator, Proxy};
use crate::util::{truthy, value_str, JMap};
use anyhow::{anyhow, Result};
use parking_lot::Mutex;
use rand::seq::SliceRandom;
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

#[derive(Default, Clone)]
pub struct Context {
    pub source: JMap,
}

pub type ArtifactLookup = dyn Fn(&str, &str) -> Result<Vec<Proxy>> + Send + Sync;
static ARTIFACT_LOOKUP: OnceLock<Arc<ArtifactLookup>> = OnceLock::new();

pub fn set_artifact_lookup(f: Arc<ArtifactLookup>) {
    let _ = ARTIFACT_LOOKUP.set(f);
}

fn to_map(v: &Value) -> JMap {
    v.as_object().cloned().unwrap_or_default()
}

fn str_arg(m: &JMap, key: &str, def: &str) -> String {
    match m.get(key) {
        Some(v) if !v.is_null() => {
            let s = value_str(v);
            if s.is_empty() { def.to_string() } else { s }
        }
        _ => def.to_string(),
    }
}

fn bool_arg(m: &JMap, key: &str, def: bool) -> bool {
    match m.get(key) {
        Some(v) => truthy(v),
        None => def,
    }
}

fn string_slice(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().map(value_str).collect(),
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        _ => vec![],
    }
}

fn build_regex(s: &str) -> Option<Regex> {
    Regex::new(s).ok()
}

fn is_ascii(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii())
}

fn is_placeholder_name(s: &str) -> bool {
    ["网址", "流量", "时间", "应急", "过期", "Bandwidth", "expire"].iter().any(|k| s.contains(k))
}

/// 对齐 Go 的 Apply：过滤类不拷贝，其它类先深拷贝。
pub fn apply(proxies: Vec<Proxy>, operators: &[Operator], _ctx: &Context) -> Result<Vec<Proxy>> {
    let mut out = proxies;
    for op in operators {
        if op.disabled {
            continue;
        }
        let is_filter = op.typ.contains("Filter");
        let input = if is_filter { out } else { out.iter().map(|p| p.deep_clone()).collect() };
        out = apply_one(&op.typ, &op.args, input)?;
    }
    Ok(out)
}

pub fn useless_filter(proxies: Vec<Proxy>) -> Vec<Proxy> {
    proxies.into_iter().filter(|p| {
        for key in ["cipher", "password"] {
            let v = p.get_str(key);
            if !v.is_empty() && !is_ascii(&v) {
                return false;
            }
        }
        let network = p.get_str("network");
        if !network.is_empty() {
            let opts = p.get_map(&format!("{}-opts", network)).unwrap_or_default();
            let host = opts.get("headers").and_then(|h| h.as_object()).and_then(|h| h.get("Host").or_else(|| h.get("host")));
            if let Some(h) = host {
                let s = value_str(h);
                if !s.is_empty() && !is_ascii(&s) {
                    return false;
                }
            }
        }
        if is_placeholder_name(&p.name()) {
            return false;
        }
        true
    }).collect()
}

fn flag_map() -> &'static [(&'static str, &'static str)] {
    &[
        ("HK", "🇭🇰"), ("TW", "🇹🇼"), ("US", "🇺🇸"), ("SG", "🇸🇬"), ("JP", "🇯🇵"),
        ("UK", "🇬🇧"), ("DE", "🇩🇪"), ("KR", "🇰🇷"), ("RU", "🇷🇺"), ("CA", "🇨🇦"),
        ("AU", "🇦🇺"), ("FR", "🇫🇷"), ("IN", "🇮🇳"), ("NL", "🇳🇱"), ("TR", "🇹🇷"),
        ("BR", "🇧🇷"), ("CN", "🇨🇳"), ("MO", "🇲🇴"), ("TH", "🇹🇭"), ("VN", "🇻🇳"),
        ("PH", "🇵🇭"), ("ID", "🇮🇩"), ("MY", "🇲🇾"), ("MX", "🇲🇽"), ("IT", "🇮🇹"),
        ("ES", "🇪🇸"), ("SE", "🇸🇪"), ("NO", "🇳🇴"), ("FI", "🇫🇮"), ("DK", "🇩🇰"),
        ("PL", "🇵🇱"), ("CH", "🇨🇭"), ("AT", "🇦🇹"), ("BE", "🇧🇪"), ("IE", "🇮🇪"),
        ("CZ", "🇨🇿"), ("PT", "🇵🇹"), ("GR", "🇬🇷"), ("IL", "🇮🇱"), ("AE", "🇦🇪"),
        ("SA", "🇸🇦"), ("NG", "🇳🇬"), ("ZA", "🇿🇦"), ("AR", "🇦🇷"), ("CL", "🇨🇱"),
        ("CO", "🇨🇴"), ("NZ", "🇳🇿"),
    ]
}

fn get_flag(name: &str) -> String {
    flag_map().iter().find(|(_, e)| name.starts_with(e)).map(|(_, e)| e.to_string()).unwrap_or_default()
}

fn infer_flag(name: &str) -> String {
    let low = name.to_lowercase();
    let kws: &[(&str, &str)] = &[
        ("HK", "香港"), ("HK", "hongkong"), ("HK", "hk"), ("TW", "台湾"), ("TW", "taiwan"),
        ("JP", "日本"), ("JP", "japan"), ("US", "美国"), ("US", "united"), ("US", "usa"),
        ("SG", "新加坡"), ("SG", "singapore"), ("KR", "韩国"), ("KR", "korea"),
        ("UK", "英国"), ("UK", "uk"), ("DE", "德国"), ("DE", "germany"),
    ];
    for (code, kw) in kws {
        if low.contains(kw) {
            return flag_map().iter().find(|(c, _)| *c == *code).map(|(_, e)| e.to_string()).unwrap_or_default();
        }
    }
    String::new()
}

fn contains(haystack: &Value, needle: &str) -> bool {
    match haystack {
        Value::Array(a) => a.iter().any(|v| value_str(v) == needle),
        other => value_str(other) == needle,
    }
}

fn match_rule(rule: &JMap, p: &Proxy) -> bool {
    let op = crate::util::get_str(rule, "operator");
    if op.is_empty() {
        let attr = crate::util::get_str(rule, "attr");
        let prop = crate::util::get_str(rule, "proposition");
        let value = rule.get("value").cloned().unwrap_or(Value::Null);
        let field = p.get(&attr).cloned().unwrap_or(Value::Null);
        return match prop.as_str() {
            "IN" => contains(&value, &value_str(&field)),
            "CONTAINS" => p.get_str(&attr).contains(&value_str(&value)),
            "EQUALS" => value_str(&field) == value_str(&value),
            "EXISTS" => true,
            _ => false,
        };
    }
    let children = rule.get("child").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    match op.as_str() {
        "AND" => children.iter().all(|c| c.as_object().map(|m| match_rule(m, p)).unwrap_or(false)),
        "OR" => children.iter().any(|c| c.as_object().map(|m| match_rule(m, p)).unwrap_or(false)),
        "NOT" => children.first().and_then(|c| c.as_object()).map(|m| !match_rule(m, p)).unwrap_or(false),
        _ => false,
    }
}

fn join_fields(p: &Proxy, fields: &[String]) -> String {
    fields.iter().map(|f| {
        p.get(f).map(value_str).unwrap_or_else(|| "-".to_string())
    }).collect::<Vec<_>>().join("_")
}

fn apply_one(name: &str, args: &Value, mut proxies: Vec<Proxy>) -> Result<Vec<Proxy>> {
    let m = to_map(args);
    match name {
        "Useless Filter" => Ok(useless_filter(proxies)),

        "Region Filter" => {
            let keep = bool_arg(&m, "keep", true);
            let regions: HashSet<String> = string_slice(m.get("value")).into_iter().map(|s| s.to_uppercase()).collect();
            Ok(proxies.into_iter().filter(|p| {
                let flag = get_flag(&p.name());
                let matched = flag_map().iter().any(|(c, e)| *e == flag && regions.contains(*c));
                matched == keep
            }).collect())
        }

        "Regex Filter" => {
            let keep = bool_arg(&m, "keep", true);
            let regexes: Vec<Regex> = string_slice(m.get("regex")).iter().filter_map(|s| build_regex(s)).collect();
            Ok(proxies.into_iter().filter(|p| {
                let matched = regexes.iter().any(|re| re.is_match(&p.name()));
                matched == keep
            }).collect())
        }

        "Type Filter" => {
            let keep = bool_arg(&m, "keep", true);
            let types: HashSet<String> = string_slice(m.get("value")).into_iter().collect();
            Ok(proxies.into_iter().filter(|p| types.contains(&p.type_()) == keep).collect())
        }

        "Conditional Filter" => {
            let rule = m.get("rule").and_then(|v| v.as_object()).cloned()
                .ok_or_else(|| anyhow!("conditional filter requires a rule"))?;
            Ok(proxies.into_iter().filter(|p| match_rule(&rule, p)).collect())
        }

        "Quick Setting Operator" => {
            if truthy(m.get("useless").unwrap_or(&Value::Null)) {
                proxies = useless_filter(proxies);
                proxies.retain(|p| p.port() > 0 && p.port() <= 65535);
            }
            for p in &mut proxies {
                for key in ["udp", "tfo"] {
                    if let Some(v) = m.get(key) {
                        match value_str(v).as_str() {
                            "ENABLED" => p.set(key, true),
                            "DISABLED" => p.set(key, false),
                            _ => {}
                        }
                    }
                }
                if let Some(v) = m.get("scert") {
                    p.set("skip-cert-verify", truthy(v));
                }
                if let Some(v) = m.get("ip-version") {
                    if !value_str(v).is_empty() {
                        p.set_value("ip-version", v.clone());
                    }
                }
            }
            Ok(proxies)
        }

        "Flag Operator" => {
            let mode = str_arg(&m, "mode", "");
            let tw = str_arg(&m, "tw", "");
            for p in &mut proxies {
                let name = p.name();
                let flag = get_flag(&name);
                let no_flag = name.trim_start_matches(&flag).trim().to_string();
                if mode == "remove" {
                    p.set("name", no_flag);
                    continue;
                }
                let mut new_flag = flag;
                if new_flag.is_empty() {
                    let code = p.get_str("_subName").to_uppercase();
                    new_flag = flag_map().iter().find(|(c, _)| *c == code).map(|(_, e)| e.to_string()).unwrap_or_default();
                }
                if new_flag.is_empty() {
                    new_flag = infer_flag(&name);
                }
                if tw == "ws" {
                    new_flag = new_flag.replace("🇹🇼", "🇼🇸");
                } else if tw.is_empty() && new_flag == "🇹🇼" {
                    new_flag = "🇨🇳".to_string();
                }
                p.set("name", format!("{} {}", new_flag, no_flag).trim().to_string());
            }
            Ok(proxies)
        }

        "Sort Operator" => {
            let order = str_arg(&m, "order", "asc");
            match order.as_str() {
                "random" => proxies.shuffle(&mut rand::thread_rng()),
                "desc" => proxies.sort_by(|a, b| b.name().cmp(&a.name())),
                _ => proxies.sort_by(|a, b| a.name().cmp(&b.name())),
            }
            Ok(proxies)
        }

        "Regex Sort Operator" => {
            let exprs: Vec<Regex> = match args {
                Value::Array(a) => a.iter().map(value_str).filter_map(|s| build_regex(&s)).collect(),
                _ => string_slice(m.get("expressions")).iter().filter_map(|s| build_regex(s)).collect(),
            };
            let order = str_arg(&m, "order", "asc");
            proxies.sort_by(|a, b| {
                let rank = |s: &str| -> usize {
                    exprs.iter().position(|re| re.is_match(s)).map(|i| i + 1).unwrap_or(0)
                };
                let ri = rank(&a.name());
                let rj = rank(&b.name());
                if ri > 0 && rj == 0 { return std::cmp::Ordering::Less; }
                if rj > 0 && ri == 0 { return std::cmp::Ordering::Greater; }
                if ri > 0 && rj > 0 { return ri.cmp(&rj); }
                if order == "original" { return std::cmp::Ordering::Equal; }
                if order == "desc" { return b.name().cmp(&a.name()); }
                a.name().cmp(&b.name())
            });
            Ok(proxies)
        }

        "Regex Rename Operator" | "Regex Delete Operator" => {
            let delete_mode = name == "Regex Delete Operator";
            let mut rules: Vec<(Regex, String)> = Vec::new();
            if delete_mode {
                for s in string_slice(Some(args)) {
                    if let Some(re) = build_regex(&s) {
                        rules.push((re, String::new()));
                    }
                }
            } else if let Some(arr) = args.as_array() {
                for item in arr {
                    let im = to_map(item);
                    let expr = crate::util::get_str(&im, "expr");
                    let now = value_str(im.get("now").unwrap_or(&Value::Null));
                    if let Some(re) = build_regex(&expr) {
                        rules.push((re, now));
                    }
                }
            }
            for p in &mut proxies {
                let mut new_name = p.name();
                for (re, now) in &rules {
                    new_name = re.replace_all(&new_name, now.as_str()).to_string();
                }
                p.set("name", new_name.trim().to_string());
            }
            Ok(proxies)
        }

        "Handle Duplicate Operator" => {
            let action = str_arg(&m, "action", "rename");
            let template = str_arg(&m, "template", "0 1 2 3 4 5 6 7 8 9");
            let link = str_arg(&m, "link", "-");
            let position = str_arg(&m, "position", "back");
            let mut fields = string_slice(m.get("field"));
            if fields.is_empty() { fields = vec!["name".to_string()]; }
            let numbers: Vec<&str> = template.split(' ').collect();
            if action == "delete" {
                let mut seen = HashSet::new();
                Ok(proxies.into_iter().filter(|p| seen.insert(join_fields(p, &fields))).collect())
            } else {
                let mut counter: HashMap<String, usize> = HashMap::new();
                let mut max_len = 1usize;
                for p in &proxies {
                    let c = counter.entry(join_fields(p, &fields)).or_insert(0);
                    *c += 1;
                    max_len = max_len.max(c.to_string().len());
                }
                let mut increment: HashMap<String, usize> = HashMap::new();
                for p in &mut proxies {
                    let key = join_fields(p, &fields);
                    if *counter.get(&key).unwrap_or(&0) <= 1 { continue; }
                    let cnt = increment.entry(key).or_insert(1);
                    let mut n = *cnt;
                    *cnt += 1;
                    let mut num = String::new();
                    let mut digits = 0usize;
                    if n == 0 { n = 1; }
                    while n > 0 {
                        let idx = n % 10;
                        let tok = numbers.get(idx).copied().unwrap_or("0");
                        num = format!("{}{}", tok, num);
                        n /= 10;
                        digits += 1;
                    }
                    while digits < max_len {
                        num = format!("{}{}", numbers.first().copied().unwrap_or("0"), num);
                        digits += 1;
                    }
                    let old = p.name();
                    if position == "front" {
                        p.set("name", format!("{}{}{}", num, link, old));
                    } else {
                        p.set("name", format!("{}{}{}", old, link, num));
                    }
                }
                Ok(proxies)
            }
        }

        "Resolve Domain Operator" => {
            resolve_domain(&m, &mut proxies);
            Ok(proxies)
        }

        // Go 版 Script Filter/Operator 为占位实现（不执行脚本），保持一致
        "Script Filter" | "Script Operator" => Ok(proxies),

        "Add Proxies From Subscription Operator" => {
            let source_type = str_arg(&m, "sourceType", "subscription");
            let source_name = str_arg(&m, "sourceName", "");
            if source_name.is_empty() {
                return Err(anyhow!("sourceName is required"));
            }
            let position = str_arg(&m, "position", "replace");
            let lookup = ARTIFACT_LOOKUP.get()
                .ok_or_else(|| anyhow!("artifact lookup unavailable"))?;
            let extra = lookup(&source_type, &source_name)?;
            Ok(match position.as_str() {
                "front" => { let mut v = extra; v.extend(proxies); v }
                "back" => { let mut v = proxies; v.extend(extra); v }
                _ => extra,
            })
        }

        other => Err(anyhow!("unknown operator: {}", other)),
    }
}

// ---- 域名解析（系统 DNS 版本） ----

static DNS_CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn resolve_domain(m: &JMap, proxies: &mut Vec<Proxy>) {
    let cache = DNS_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let ip_version = str_arg(m, "ip-version", "").to_lowercase();
    let remove_failed = bool_arg(m, "removeFailed", false);
    let no_cache = bool_arg(m, "no-cache", false) || bool_arg(m, "noCache", false);
    let ipv4_only = ip_version.contains("ipv4") || crate::util::get_str(m, "filter").contains("IPv4");
    let ipv6_only = ip_version.contains("ipv6") || crate::util::get_str(m, "filter").contains("IPv6");

    let mut kept = Vec::new();
    for p in proxies.iter_mut() {
        let server = p.server();
        if server.is_empty() || crate::util::is_ip(&server) {
            kept.push(p.deep_clone());
            continue;
        }
        if p.get_bool("no-resolve") {
            kept.push(p.deep_clone());
            continue;
        }
        let cached = if no_cache { None } else { cache.lock().get(&server).cloned() };
        let resolved = cached.or_else(|| {
            use std::net::ToSocketAddrs;
            let addrs = (server.as_str(), 80u16).to_socket_addrs().ok();
            addrs.and_then(|mut it| {
                if ipv4_only {
                    it.find(|a| a.is_ipv4()).map(|a| a.ip().to_string())
                } else if ipv6_only {
                    it.find(|a| a.is_ipv6()).map(|a| a.ip().to_string())
                } else {
                    it.next().map(|a| a.ip().to_string())
                }
            })
        });
        match resolved {
            Some(ip) => {
                if !no_cache {
                    cache.lock().insert(server.clone(), ip.clone());
                }
                p.set("resolved", true);
                p.set("_resolved", true);
                p.set("server", ip);
                kept.push(p.deep_clone());
            }
            None => {
                if !remove_failed {
                    kept.push(p.deep_clone());
                }
            }
        }
    }
    *proxies = kept;
}
