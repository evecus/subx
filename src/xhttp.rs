//! xhttp / splithttp 完整支持。
//!
//! 对齐 Go 版 `internal/parser/xhttp_utils.go`（xhttp-utils.js / ech-utils.js）
//! 与 `internal/producer/uri.go`：range 整数归一化、extra 字段双向映射、
//! `downloadSettings` 的解析（Xray -> mihomo）与构建（mihomo -> Xray，**含继承**）。

use crate::ech;
use crate::model::Proxy;
use crate::util::{get_str, truthy, value_str, JMap};
use serde_json::{json, Value};

const JS_SAFE_INTEGER_MAX: i64 = 9_007_199_254_740_991;

fn is_plain(v: Option<&Value>) -> Option<JMap> {
    v.and_then(|x| x.as_object()).cloned()
}

fn not_blank(v: Option<&Value>) -> Option<String> {
    let s = v.and_then(|x| x.as_str())?.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn parse_uint_token(s: &str) -> Option<i64> {
    let t = s.trim();
    let digits = t.strip_prefix('+').unwrap_or(t);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: i64 = digits.parse().ok()?;
    (n <= JS_SAFE_INTEGER_MAX).then_some(n)
}

fn number_as_string(v: &Value) -> Option<String> {
    let f = v.as_f64()?;
    if f != f.trunc() || f.abs() > JS_SAFE_INTEGER_MAX as f64 {
        return None;
    }
    Some((f as i64).to_string())
}

/// 解析 "N" / "L-U" 形式的范围，并按 JS 语义校验上下界。
pub fn parse_range(
    v: Option<&Value>,
    allow_zero_lower: bool,
    allow_zero_upper: bool,
) -> Option<(i64, i64)> {
    let normalized = match v? {
        Value::String(s) => s.trim().to_string(),
        Value::Number(_) => number_as_string(v?)?,
        _ => return None,
    };
    let min_lower = if allow_zero_lower { 0 } else { 1 };
    let min_upper = if allow_zero_upper { 0 } else { 1 };
    let parts: Vec<&str> = normalized.split('-').collect();
    match parts.len() {
        1 => {
            let n = parse_uint_token(parts[0])?;
            let min_value = min_lower.max(min_upper);
            (n >= min_value).then_some((n, n))
        }
        2 => {
            let lower = parse_uint_token(parts[0])?;
            let upper = parse_uint_token(parts[1])?;
            (lower >= min_lower && upper >= min_upper && upper >= lower)
                .then_some((lower, upper))
        }
        _ => None,
    }
}

fn range_value(lower: i64, upper: i64, as_string: bool) -> Value {
    if lower == upper {
        if as_string {
            json!(upper.to_string())
        } else {
            json!(upper)
        }
    } else {
        json!(format!("{}-{}", lower, upper))
    }
}

pub fn positive_range(v: Option<&Value>) -> Option<Value> {
    parse_range(v, true, false).map(|(l, u)| range_value(l, u, false))
}

pub fn strict_range_string(v: Option<&Value>) -> Option<String> {
    parse_range(v, false, false)
        .map(|(l, u)| range_value(l, u, true))
        .and_then(|x| x.as_str().map(|s| s.to_string()))
}

pub fn strict_range_value(v: Option<&Value>) -> Option<Value> {
    parse_range(v, false, false).map(|(l, u)| range_value(l, u, false))
}

pub fn non_negative_range(v: Option<&Value>) -> Option<Value> {
    parse_range(v, true, true).map(|(l, u)| range_value(l, u, false))
}

pub fn integer_value(v: Option<&Value>, allow_negative: bool) -> Option<i64> {
    match v? {
        Value::Number(n) => {
            let f = n.as_f64()?;
            if f != f.trunc() || f.abs() > JS_SAFE_INTEGER_MAX as f64 {
                return None;
            }
            let i = f as i64;
            if !allow_negative && i < 0 {
                return None;
            }
            Some(i)
        }
        Value::String(s) => {
            let t = s.trim();
            let digits = if allow_negative {
                t.strip_prefix('+').or_else(|| t.strip_prefix('-')).unwrap_or(t)
            } else {
                t.strip_prefix('+').unwrap_or(t)
            };
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let n: i64 = t.parse().ok()?;
            if n.abs() > JS_SAFE_INTEGER_MAX || (!allow_negative && n < 0) {
                return None;
            }
            Some(n)
        }
        _ => None,
    }
}

/// 只有字符串值能进入 Xray headers；exclude 时忽略 Host 头。
pub fn string_header_map(v: Option<&Value>, exclude_host_header: bool) -> Option<JMap> {
    let m = is_plain(v)?;
    let mut out = JMap::new();
    for (k, val) in m {
        if exclude_host_header && k.eq_ignore_ascii_case("host") {
            continue;
        }
        if let Value::String(s) = val {
            out.insert(k, json!(s));
        }
    }
    (!out.is_empty()).then_some(out)
}

/// xmux（Xray） -> reuse-settings（mihomo）。
pub fn map_xmux_to_reuse_settings(v: Option<&Value>) -> Option<JMap> {
    let m = is_plain(v)?;
    let mut out = JMap::new();
    for (src, dst) in [
        ("maxConnections", "max-connections"),
        ("maxConcurrency", "max-concurrency"),
        ("cMaxReuseTimes", "c-max-reuse-times"),
        ("hMaxRequestTimes", "h-max-request-times"),
        ("hMaxReusableSecs", "h-max-reusable-secs"),
    ] {
        if let Some(n) = non_negative_range(m.get(src)) {
            let val = match n {
                Value::Number(i) => json!(i.as_i64().unwrap_or(0).to_string()),
                other => other,
            };
            out.insert(dst.into(), val);
        }
    }
    if let Some(n) = integer_value(m.get("hKeepAlivePeriod"), true) {
        out.insert("h-keep-alive-period".into(), json!(n));
    }
    (!out.is_empty()).then_some(out)
}

/// reuse-settings（mihomo） -> xmux（Xray）。
pub fn map_reuse_settings_to_xmux(v: Option<&Value>) -> Option<JMap> {
    let m = is_plain(v)?;
    let mut out = JMap::new();
    for (src, dst) in [
        ("max-connections", "maxConnections"),
        ("max-concurrency", "maxConcurrency"),
        ("c-max-reuse-times", "cMaxReuseTimes"),
        ("h-max-request-times", "hMaxRequestTimes"),
        ("h-max-reusable-secs", "hMaxReusableSecs"),
    ] {
        if let Some(n) = non_negative_range(m.get(src)) {
            let val = match n {
                Value::Number(i) => json!(i.as_i64().unwrap_or(0).to_string()),
                other => other,
            };
            out.insert(dst.into(), val);
        }
    }
    if let Some(n) = integer_value(m.get("h-keep-alive-period"), true) {
        out.insert("hKeepAlivePeriod".into(), json!(n));
    }
    (!out.is_empty()).then_some(out)
}

const EXTRA_STRING_FIELDS: &[(&str, &str)] = &[
    ("x-padding-key", "xPaddingKey"),
    ("x-padding-header", "xPaddingHeader"),
    ("x-padding-placement", "xPaddingPlacement"),
    ("x-padding-method", "xPaddingMethod"),
    ("uplink-http-method", "uplinkHTTPMethod"),
    ("session-placement", "sessionIDPlacement"),
    ("session-key", "sessionIDKey"),
    ("seq-placement", "seqPlacement"),
    ("seq-key", "seqKey"),
    ("uplink-data-placement", "uplinkDataPlacement"),
    ("uplink-data-key", "uplinkDataKey"),
];

/// mihomo xhttp-opts -> Xray extra/xhttpSettings 字段（产出器侧）。
pub fn apply_extra_fields(
    target: &mut JMap,
    opts: &JMap,
    exclude_host_header: bool,
    xmux_in_extra: bool,
) {
    if let Some(h) = string_header_map(opts.get("headers"), exclude_host_header) {
        target.insert("headers".into(), Value::Object(h));
    }
    if matches!(opts.get("no-grpc-header"), Some(Value::Bool(true))) {
        target.insert("noGRPCHeader".into(), json!(true));
    }
    for (src, dst) in EXTRA_STRING_FIELDS {
        if let Some(v) = opts.get(*src) {
            if !matches!(v, Value::Null) {
                target.insert((*dst).into(), v.clone());
            }
        }
    }
    if matches!(opts.get("x-padding-obfs-mode"), Some(Value::Bool(true))) {
        target.insert("xPaddingObfsMode".into(), json!(true));
    }
    if let Some(s) = opts.get("session-table").and_then(|v| v.as_str()) {
        target.insert("sessionIDTable".into(), json!(s));
    }
    if let Some(v) = strict_range_value(opts.get("session-length")) {
        target.insert("sessionIDLength".into(), v);
    }
    if let Some(v) = non_negative_range(opts.get("uplink-chunk-size")) {
        target.insert("uplinkChunkSize".into(), v);
    }
    if let Some(v) = strict_range_value(opts.get("sc-max-each-post-bytes")) {
        target.insert("scMaxEachPostBytes".into(), v);
    }
    if let Some(v) = positive_range(opts.get("sc-min-posts-interval-ms")) {
        target.insert("scMinPostsIntervalMs".into(), v);
    }
    if let Some(v) = strict_range_string(opts.get("x-padding-bytes")) {
        target.insert("xPaddingBytes".into(), json!(v));
    }
    if let Some(xmux) = map_reuse_settings_to_xmux(opts.get("reuse-settings")) {
        if xmux_in_extra {
            let mut extra = target
                .get("extra")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            extra.insert("xmux".into(), Value::Object(xmux));
            target.insert("extra".into(), Value::Object(extra));
        } else {
            target.insert("xmux".into(), Value::Object(xmux));
        }
    }
}

/// Xray extra/xhttpSettings -> mihomo xhttp-opts（解析器侧）。
pub fn absorb_extra_fields(target: &mut JMap, src: &JMap) {
    if let Some(h) = string_header_map(src.get("headers"), false) {
        target.insert("headers".into(), Value::Object(h));
    }
    if matches!(src.get("noGRPCHeader"), Some(Value::Bool(true))) {
        target.insert("no-grpc-header".into(), json!(true));
    }
    for (dst, src_key) in EXTRA_STRING_FIELDS {
        if let Some(v) = src.get(*src_key) {
            target.insert((*dst).into(), v.clone());
        }
    }
    if matches!(src.get("xPaddingObfsMode"), Some(Value::Bool(true))) {
        target.insert("x-padding-obfs-mode".into(), json!(true));
    }
    if let Some(v) = src.get("sessionIDTable") {
        target.insert("session-table".into(), v.clone());
    }
    if let Some(v) = src.get("sessionIDLength") {
        target.insert("session-length".into(), v.clone());
    }
    if let Some(v) = src.get("uplinkChunkSize") {
        target.insert("uplink-chunk-size".into(), v.clone());
    }
    if let Some(v) = src.get("scMaxEachPostBytes") {
        target.insert("sc-max-each-post-bytes".into(), v.clone());
    }
    if let Some(v) = src.get("scMinPostsIntervalMs") {
        target.insert("sc-min-posts-interval-ms".into(), v.clone());
    }
    if let Some(v) = src.get("xPaddingBytes") {
        target.insert("x-padding-bytes".into(), v.clone());
    }
    let nested = src.get("xmux").or_else(|| {
        src.get("extra")
            .and_then(|v| v.as_object())
            .and_then(|m| m.get("xmux"))
    });
    if let Some(rs) = map_xmux_to_reuse_settings(nested) {
        target.insert("reuse-settings".into(), Value::Object(rs));
    }
    // 其余未识别字段按「驼峰 -> 连字符」通用透传，不丢字段。
    for (k, v) in src {
        if matches!(
            k.as_str(),
            "headers" | "noGRPCHeader" | "xPaddingObfsMode" | "sessionIDTable"
                | "sessionIDLength" | "uplinkChunkSize" | "scMaxEachPostBytes"
                | "scMinPostsIntervalMs" | "xPaddingBytes" | "xmux" | "extra"
                | "downloadSettings" | "path" | "host" | "mode"
        ) || EXTRA_STRING_FIELDS.iter().any(|(_, d)| *d == k.as_str()) {
            continue;
        }
        target.insert(camel_to_hyphen(k), v.clone());
    }
}

fn camel_to_hyphen(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            out.push('-');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

pub fn transport_host(m: &JMap) -> String {
    if let Some(h) = m.get("headers").and_then(|v| v.as_object()) {
        if let Some(v) = h.get("Host").or_else(|| h.get("host")) {
            let s = value_str(v);
            if !s.is_empty() {
                return s;
            }
        }
    }
    get_str(m, "host")
}

/// Xray downloadSettings -> mihomo `xhttp-opts.download-settings`。
pub fn parse_download_settings(v: Option<&Value>) -> Option<JMap> {
    let m = is_plain(v)?;
    let mut parsed = JMap::new();
    let network = m
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    if network == "xhttp" || network == "splithttp" {
        parsed.insert("network".into(), json!("xhttp"));
    }
    if let Some(s) = not_blank(m.get("address")) {
        parsed.insert("server".into(), json!(s));
    }
    if let Some(n) = integer_value(m.get("port"), false) {
        parsed.insert("port".into(), json!(n));
    }
    let security = m
        .get("security")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    if security == "tls" || security == "reality" {
        parsed.insert("tls".into(), json!(true));
    }
    if let Some(tls) = is_plain(m.get("tlsSettings")) {
        if let Some(s) = not_blank(tls.get("serverName")) {
            parsed.insert("servername".into(), json!(s));
        }
        if let Some(s) = not_blank(tls.get("fingerprint")) {
            parsed.insert("client-fingerprint".into(), json!(s));
        }
        if let Some(arr) = tls.get("alpn").and_then(|v| v.as_array()) {
            if !arr.is_empty() && arr.iter().all(|x| x.as_str().map(|s| !s.is_empty()).unwrap_or(false)) {
                parsed.insert("alpn".into(), Value::Array(arr.clone()));
            }
        }
        if matches!(tls.get("allowInsecure"), Some(Value::Bool(true))) {
            parsed.insert("skip-cert-verify".into(), json!(true));
        }
        if let Some(opts) = ech::build_mihomo_ech_opts(
            tls.get("echConfigList"),
            tls.get("echForceQuery"),
            tls.get("echSockopt"),
        ) {
            parsed.insert("ech-opts".into(), Value::Object(opts));
        }
    }
    let mut reality_opts = JMap::new();
    if let Some(reality) = is_plain(m.get("realitySettings")) {
        if let Some(s) = not_blank(reality.get("publicKey")) {
            reality_opts.insert("public-key".into(), json!(s));
        }
        if let Some(s) = not_blank(reality.get("shortId")) {
            reality_opts.insert("short-id".into(), json!(s));
        }
        if let Some(s) = not_blank(reality.get("serverName")) {
            parsed.insert("servername".into(), json!(s));
        }
        if let Some(s) = not_blank(reality.get("fingerprint")) {
            parsed.insert("client-fingerprint".into(), json!(s));
        }
    }
    if security == "reality" || !reality_opts.is_empty() {
        parsed.insert("reality-opts".into(), Value::Object(reality_opts));
    }
    if let Some(xhttp) = is_plain(m.get("xhttpSettings")) {
        if let Some(s) = not_blank(xhttp.get("path")) {
            parsed.insert("path".into(), json!(s));
        }
        if let Some(s) = not_blank(xhttp.get("host")) {
            parsed.insert("host".into(), json!(s));
        }
        if let Some(s) = not_blank(xhttp.get("mode")) {
            parsed.insert("mode".into(), json!(s));
        }
        absorb_extra_fields(&mut parsed, &xhttp);
        if let Some(extra) = is_plain(xhttp.get("extra")) {
            absorb_extra_fields(&mut parsed, &extra);
        }
    }
    (!parsed.is_empty()).then_some(parsed)
}

/// mihomo download-settings -> Xray downloadSettings。
///
/// 继承规则（Go `buildXhttpDownloadSettings`）：`path` / `host` / `mode`
/// 在 download-settings 缺失时从外层 `xhttp-opts` 继承；ECH 走完整协商。
pub fn build_download_settings(ds: &JMap, outer: &JMap, _p: &Proxy) -> Option<JMap> {
    let explicit_network = get_str(ds, "network").to_lowercase();
    let normalized_network = if explicit_network == "xhttp" || explicit_network == "splithttp" {
        "xhttp".to_string()
    } else {
        String::new()
    };
    let mut result = JMap::new();
    if let Some(s) = not_blank(ds.get("server")) {
        result.insert("address".into(), json!(s));
    }
    if let Some(n) = integer_value(ds.get("port"), false) {
        result.insert("port".into(), json!(n));
    }
    let reality = is_plain(ds.get("reality-opts"));
    if reality.is_some() {
        result.insert("security".into(), json!("reality"));
    } else if matches!(ds.get("tls"), Some(Value::Bool(true))) {
        result.insert("security".into(), json!("tls"));
    }
    let mut tls_settings = JMap::new();
    if let Some(s) = not_blank(ds.get("servername")) {
        tls_settings.insert("serverName".into(), json!(s));
    }
    if let Some(s) = not_blank(ds.get("client-fingerprint")) {
        tls_settings.insert("fingerprint".into(), json!(s));
    }
    if matches!(ds.get("skip-cert-verify"), Some(Value::Bool(true))) {
        tls_settings.insert("allowInsecure".into(), json!(true));
    }
    if let Some(alpn) = ds.get("alpn") {
        let arr = match alpn {
            Value::Array(a) => a.clone(),
            other => vec![other.clone()],
        };
        tls_settings.insert("alpn".into(), Value::Array(arr));
    }
    let ech_fields = ech::build_xray_ech_fields(is_plain(ds.get("ech-opts")).as_ref(), "");
    for k in ["echConfigList", "echForceQuery", "echSockopt"] {
        if let Some(v) = ech_fields.get(k) {
            tls_settings.insert(k.into(), v.clone());
        }
    }
    if !tls_settings.is_empty() {
        result.insert("tlsSettings".into(), Value::Object(tls_settings));
    }
    if let Some(ro) = &reality {
        let mut reality_settings = JMap::new();
        if let Some(s) = not_blank(ds.get("servername")) {
            reality_settings.insert("serverName".into(), json!(s));
        }
        if let Some(s) = not_blank(ds.get("client-fingerprint")) {
            reality_settings.insert("fingerprint".into(), json!(s));
        }
        if let Some(s) = not_blank(ro.get("public-key")) {
            reality_settings.insert("publicKey".into(), json!(s));
        }
        if let Some(s) = not_blank(ro.get("short-id")) {
            reality_settings.insert("shortId".into(), json!(s));
        }
        if !reality_settings.is_empty() {
            result.insert("realitySettings".into(), Value::Object(reality_settings));
        }
    }
    let mut xhttp_settings = JMap::new();
    let ds_path = get_str(ds, "path");
    let path = if ds_path.is_empty() { get_str(outer, "path") } else { ds_path };
    if !path.is_empty() {
        xhttp_settings.insert("path".into(), json!(path));
    }
    let ds_host = transport_host(ds);
    let host = if ds_host.is_empty() { transport_host(outer) } else { ds_host };
    if !host.is_empty() {
        xhttp_settings.insert("host".into(), json!(host));
    }
    let ds_mode = get_str(ds, "mode");
    let mode = if ds_mode.is_empty() { get_str(outer, "mode") } else { ds_mode };
    if !mode.is_empty() {
        xhttp_settings.insert("mode".into(), json!(mode));
    }
    apply_extra_fields(&mut xhttp_settings, ds, true, true);
    if !xhttp_settings.is_empty() {
        result.insert("xhttpSettings".into(), Value::Object(xhttp_settings));
    }
    if result.is_empty() && normalized_network.is_empty() {
        return None;
    }
    let mut out = JMap::new();
    out.insert(
        "network".into(),
        json!(if normalized_network.is_empty() { "xhttp" } else { &normalized_network }),
    );
    for k in ["address", "port", "security", "tlsSettings", "realitySettings", "xhttpSettings"] {
        if let Some(v) = result.remove(k) {
            out.insert(k.into(), v);
        }
    }
    // Xray downloadSettings 省略 address/port 即复用出站地址，不做主节点继承。
    Some(out)
}

/// VLESS xhttp 节点的 `extra` 查询参数（产出器侧）。
pub fn build_structured_extra(p: &Proxy) -> Option<JMap> {
    let opts = p.get_map("xhttp-opts")?;
    let mut extra = JMap::new();
    apply_extra_fields(&mut extra, &opts, false, false);
    if let Some(ds) = is_plain(opts.get("download-settings")) {
        if let Some(built) = build_download_settings(&ds, &opts, p) {
            extra.insert("downloadSettings".into(), Value::Object(built));
        }
    }
    (!extra.is_empty()).then_some(extra)
}

/// VLESS URI 的 `extra` 参数 -> mihomo `xhttp-opts`。
pub fn absorb_xhttp_extra(p: &mut Proxy, v: Option<&Value>) {
    let Some(extra) = is_plain(v) else { return; };
    let mut opts = p.get_map("xhttp-opts").unwrap_or_default();
    absorb_extra_fields(&mut opts, &extra);
    if let Some(ds) = parse_download_settings(extra.get("downloadSettings")) {
        opts.insert("download-settings".into(), Value::Object(ds));
    }
    if !opts.is_empty() {
        p.set_value("xhttp-opts", Value::Object(opts));
    }
}

/// `prepare` 阶段：对齐 Go produce.go / clash.go 的 xhttp + Reality 继承规则。
/// 返回 false 表示该节点应被过滤掉。
pub fn filter_or_inherit(p: &mut Proxy, target_is_mihomo: bool) -> bool {
    if p.type_() != "vless" || p.get_str("network") != "xhttp" {
        return true;
    }
    let mut opts = match p.get_map("xhttp-opts") {
        Some(o) => o,
        None => return true,
    };
    let mode = get_str(&opts, "mode");
    let has_ds = opts.contains_key("download-settings");
    // Go produce.go: stream-one + downloadSettings 组合不支持。
    if mode == "stream-one" && has_ds {
        return false;
    }
    let mut ds = match is_plain(opts.get("download-settings")) {
        Some(d) => d,
        None => return true,
    };
    let main_pk = p
        .get_map("reality-opts")
        .map(|r| get_str(&r, "public-key"))
        .unwrap_or_default();
    if let Some(ro) = is_plain(ds.get("reality-opts")) {
        match ro.get("public-key") {
            Some(Value::String(s)) if s.is_empty() => {
                if main_pk.trim().is_empty() {
                    return false;
                }
            }
            Some(v) if value_str(v).trim().is_empty() => return false,
            None => {
                if get_str(&ro, "public-key").trim().is_empty() {
                    return false;
                }
            }
            _ => {}
        }
    }
    // Go clash.go: mihomo 平台下，主节点 Reality + 下载流 tls 且未显式 reality-opts
    // 时，注入空 public-key 以阻断 Reality 继承。
    let null = Value::Null;
    if target_is_mihomo
        && truthy(ds.get("tls").unwrap_or(&null))
        && p.get_bool("tls")
        && p.get_map("reality-opts").is_some()
        && ds.get("reality-opts").is_none()
    {
        let mut empty = JMap::new();
        empty.insert("public-key".into(), json!(""));
        ds.insert("reality-opts".into(), Value::Object(empty));
    }
    opts.insert("download-settings".into(), Value::Object(ds));
    p.set_value("xhttp-opts", Value::Object(opts));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_normalization() {
        assert_eq!(non_negative_range(Some(&json!("0-10"))), Some(json!("0-10")));
        assert_eq!(strict_range_string(Some(&json!(5))), Some("5".into()));
        assert_eq!(strict_range_string(Some(&json!("0"))), None);
        assert_eq!(integer_value(Some(&json!("-3")), false), None);
        assert_eq!(integer_value(Some(&json!("-3")), true), Some(-3));
    }

    #[test]
    fn download_settings_inherits_outer() {
        let mut outer = JMap::new();
        outer.insert("path".into(), json!("/outer"));
        outer.insert("mode".into(), json!("stream-up"));
        let mut headers = JMap::new();
        headers.insert("Host".into(), json!("cdn.example.com"));
        outer.insert("headers".into(), Value::Object(headers));
        let ds = JMap::new();
        let built = build_download_settings(&ds, &outer, &Proxy::new()).unwrap();
        let xs = built.get("xhttpSettings").unwrap().as_object().unwrap();
        assert_eq!(xs.get("path").unwrap(), "/outer");
        assert_eq!(xs.get("mode").unwrap(), "stream-up");
        assert_eq!(xs.get("host").unwrap(), "cdn.example.com");
    }
}
