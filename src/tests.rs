//! 单元/集成测试：解析、产出、cron、配置、存储、token。

use crate::config::normalize_path_prefix;
use crate::model::Proxy;
use crate::parser;
use crate::producer;
use crate::scheduler;
use crate::share;
use crate::store::Store;
use crate::util::{base64_encode, JMap};
use chrono::Timelike;
use serde_json::json;

#[test]
fn path_prefix_normalization() {
    assert_eq!(normalize_path_prefix(""), "");
    assert_eq!(normalize_path_prefix("/"), "");
    assert_eq!(normalize_path_prefix("mypanel/"), "/mypanel");
    assert_eq!(normalize_path_prefix("/a//b"), "/a/b");
    assert_eq!(normalize_path_prefix("  /x y/ "), "/x/y");
}

#[test]
fn cron_parse_and_next() {
    assert!(scheduler::valid("0 0 * * *"));
    assert!(scheduler::valid("*/5 9-18 * * 1-5"));
    assert!(!scheduler::valid("0 0 * *"));
    assert!(!scheduler::valid("60 0 * * *"));
    let s = scheduler::parse("0 0 * * *").unwrap();
    let now = chrono::Local::now();
    let next = s.next(now).expect("next midnight");
    assert!(next > now);
    assert_eq!(next.hour(), 0);
    assert_eq!(next.minute(), 0);
}

#[test]
fn parse_base64_subscription() {
    let plain = "ss://YWVzLTI1Ni1nY206cGFzcw==@example.com:8388#NodeA\ntrojan://pass@example.com:443?sni=x.com#NodeB";
    let encoded = base64_encode(plain);
    let proxies = parser::parse(&encoded);
    assert_eq!(proxies.len(), 2, "got {:?}", proxies.iter().map(|p| p.type_()).collect::<Vec<_>>());
    assert_eq!(proxies[0].type_(), "ss");
    assert_eq!(proxies[0].get_str("cipher"), "aes-256-gcm");
    assert_eq!(proxies[0].get_str("password"), "pass");
    assert_eq!(proxies[0].get_str("server"), "example.com");
    assert_eq!(proxies[0].port(), 8388);
    assert_eq!(proxies[0].name(), "NodeA");
    assert_eq!(proxies[1].type_(), "trojan");
    assert_eq!(proxies[1].get_bool("tls"), true);
}

#[test]
fn parse_vless_uri() {
    let line = "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&security=reality&type=ws&sni=example.com&pbk=PUBKEY&sid=abcd&path=%2Fws&host=cdn.example.com#VLESS%20Node";
    let proxies = parser::parse(line);
    assert_eq!(proxies.len(), 1);
    let p = &proxies[0];
    assert_eq!(p.type_(), "vless");
    assert_eq!(p.get_str("uuid"), "11111111-1111-1111-1111-111111111111");
    assert_eq!(p.get_str("network"), "ws");
    assert_eq!(p.get_str("sni"), "example.com");
    assert_eq!(p.get_str("name"), "VLESS Node");
    assert_eq!(p.get_map("reality-opts").unwrap().get("public-key").unwrap(), "PUBKEY");
    let ws = p.get_map("ws-opts").unwrap();
    assert_eq!(ws.get("path").unwrap(), "/ws");
}

#[test]
fn parse_clash_yaml() {
    let raw = "proxies:\n  - {name: N1, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-128-gcm, password: pw}\n  - {name: N2, type: vmess, server: x.com, port: 443, uuid: uuid1, alterId: 0, cipher: auto, tls: true}\n";
    let proxies = parser::parse(raw);
    assert_eq!(proxies.len(), 2);
    assert_eq!(proxies[0].type_(), "ss");
    assert_eq!(proxies[1].type_(), "vmess");
    assert_eq!(proxies[1].get_bool("tls"), true);
}

#[test]
fn produce_all_targets() {
    let proxies = parser::parse("ss://YWVzLTI1Ni1nY206cGFzcw==@example.com:8388#N1\nvmess://eyJ2IjoiMiIsInBzIjoiTjIiLCJhZGQiOiJ4LmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6InV1aWQiLCJhaWQiOiIwIiwic2N5IjoiYXV0byIsIm5ldCI6IndzIiwidGxzIjoidGxzIn0=");
    assert_eq!(proxies.len(), 2, "parse produced {:?}", proxies.iter().map(|p| p.display_name()).collect::<Vec<_>>());
    for target in [
        "json", "uri", "v2ray", "clash", "mihomo", "stash", "surge", "surge-mac",
        "surfboard", "loon", "shadowrocket", "qx", "sing-box", "egern",
    ] {
        let out = producer::produce(target, &proxies, None).unwrap_or_else(|e| panic!("{}: {}", target, e));
        assert!(!out.is_empty(), "{} produced empty output", target);
    }
    let json_out = producer::produce("json", &proxies, None).unwrap();
    assert_eq!(json_out.lines().count(), 2);
}

#[test]
fn uri_roundtrip() {
    let proxies = parser::parse("trojan://pass@example.com:443?sni=x.com&allowInsecure=1#T1");
    let uri = producer::produce("uri", &proxies, None).unwrap();
    assert!(uri.starts_with("trojan://"), "{}", uri);
    let reparsed = parser::parse(&uri);
    assert_eq!(reparsed.len(), 1);
    assert_eq!(reparsed[0].get_str("password"), "pass");
    assert_eq!(reparsed[0].get_str("sni"), "x.com");
}

#[test]
fn token_payload_modes() {
    let mut opts = JMap::new();
    opts.insert("mode".into(), json!("count"));
    opts.insert("count".into(), json!(5));
    let t = share::build_token_payload("sub", "s1", &opts);
    assert_eq!(t.get("token").unwrap().as_str().unwrap().len(), 32);
    assert_eq!(t.get("type").unwrap(), "sub");
    assert!(crate::model::token_usable(&t));

    let mut opts2 = JMap::new();
    opts2.insert("mode".into(), json!("duration"));
    opts2.insert("permanent".into(), json!(true));
    let t2 = share::build_token_payload("col", "c1", &opts2);
    assert_eq!(t2.get("expiresIn").unwrap(), "permanent");
    assert!(crate::model::token_usable(&t2));
}

#[test]
fn store_crud_and_positions() {
    let path = std::env::temp_dir().join(format!("subx-test-{}.db", std::process::id()));
    let path = path.to_string_lossy().to_string();
    let _ = std::fs::remove_file(&path);
    let st = Store::open(&path).unwrap();
    let mut rec = JMap::new();
    rec.insert("name".into(), json!("s1"));
    rec.insert("source".into(), json!("local"));
    rec.insert("content".into(), json!("ss://x"));
    st.upsert_sub("s1", &rec, "bottom").unwrap();
    assert_eq!(st.list_subs().unwrap().len(), 1);
    assert_eq!(st.get_sub("s1").unwrap().unwrap().get("content").unwrap(), "ss://x");
    assert!(st.rename_sub("s1", "s2", &rec).unwrap());
    assert!(st.get_sub("s1").unwrap().is_none());
    assert!(st.get_sub("s2").unwrap().is_some());
    st.delete_sub("s2").unwrap();
    assert!(st.list_subs().unwrap().is_empty());

    let mut t = JMap::new();
    t.insert("token".into(), json!("tok1"));
    t.insert("type".into(), json!("sub"));
    assert!(st.insert_token(&t).unwrap());
    assert!(!st.insert_token(&t).unwrap(), "duplicate token must be rejected");
    st.delete_token("tok1").unwrap();
    drop(st);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn operators_pipeline() {
    let raw = "ss://YWVzLTI1Ni1nY206cGFzcw==@1.1.1.1:8388#HK-01\nvmess://eyJ2IjoiMiIsInBzIjoiVVMtMDIiLCJhZGQiOiIyLjIuMi4yIiwicG9ydCI6IjQ0MyIsImlkIjoidXVpZCIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIn0=";
    let proxies = parser::parse(raw);
    assert_eq!(proxies.len(), 2);
    let ops = vec![crate::model::Operator {
        typ: "Type Filter".into(),
        args: json!({"keep": true, "value": ["ss"]}),
        disabled: false,
        custom_name: String::new(),
    }];
    let filtered = crate::processor::apply(proxies, &ops, &Default::default()).unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].type_(), "ss");
}

// ---------------- 移植的四项极边缘分支 ----------------

fn proxy(v: serde_json::Value) -> Proxy {
    Proxy::from_value(&v).unwrap()
}

#[test]
fn ech_full_negotiation() {
    // Xray echConfigList（DoH 形式）-> mihomo ech-opts -> URI / sing-box
    let line = "vless://11111111-1111-1111-1111-111111111111@e.com:443?encryption=none&security=tls&ech=ech.example.com%2Bhttps%3A%2F%2F1.1.1.1%2Fdns-query#ECH";
    let p = parser::parse(line);
    assert_eq!(p.len(), 1);
    let eo = p[0].get_map("ech-opts").expect("ech-opts");
    assert_eq!(eo.get("_dns").unwrap(), "https://1.1.1.1/dns-query");
    assert_eq!(eo.get("query-server-name").unwrap(), "ech.example.com");
    assert_eq!(eo.get("enable").unwrap(), true);

    // 完整协商字段：config + force-query + sockopt
    let full = proxy(json!({
        "name": "ECH2", "type": "vless", "server": "e.com", "port": 443,
        "uuid": "u", "tls": true, "network": "tcp",
        "ech-opts": {
            "enable": true, "config": "ECHCFG",
            "_force-query": "half", "_sockopt": {"dialer-proxy": "d1"}
        }
    }));
    let uri = producer::produce("uri", &[full.clone()], None).unwrap();
    let qpart = uri.split('?').nth(1).unwrap().split('#').next().unwrap();
    let params = crate::util::parse_query(qpart);
    assert_eq!(params.get("ech").map(|s| s.as_str()), Some("ECHCFG"));
    let sb: serde_json::Value = serde_json::from_str(&producer::produce("sing-box", &[full], None).unwrap()).unwrap();
    let ech = &sb["outbounds"][0]["tls"]["ech"];
    assert_eq!(ech["enabled"], true);
    assert_eq!(ech["query_server_name"], serde_json::Value::Null);
    // config 被归一成 PEM 行数组并自动包裹 BEGIN/END
    let cfg = ech["config"].as_array().unwrap();
    assert!(cfg.iter().any(|v| v == "-----BEGIN ECH CONFIGS-----"));
    assert!(cfg.iter().any(|v| v == "ECHCFG"));
}

#[test]
fn xhttp_download_settings_roundtrip() {
    let p = proxy(json!({
        "name": "XHTTP", "type": "vless", "server": "x.com", "port": 443,
        "uuid": "u", "tls": true, "network": "xhttp",
        "xhttp-opts": {
            "path": "/up", "mode": "stream-up",
            "headers": {"Host": "cdn.x.com"},
            "download-settings": {
                "server": "d.com", "port": 8443, "tls": true,
                "ech-opts": {"enable": true, "config": "ECHCFG"},
                "path": "/down"
            }
        }
    }));
    let uri = producer::produce("uri", &[p], None).unwrap();
    let qpart = uri.split('?').nth(1).unwrap().split('#').next().unwrap();
    let params = crate::util::parse_query(qpart);
    let extra: serde_json::Value = serde_json::from_str(params.get("extra").unwrap()).unwrap();
    let ds = &extra["downloadSettings"];
    assert_eq!(ds["network"], "xhttp");
    assert_eq!(ds["address"], "d.com");
    assert_eq!(ds["security"], "tls");
    assert_eq!(ds["tlsSettings"]["echConfigList"], "ECHCFG");
    let xs = &ds["xhttpSettings"];
    assert_eq!(xs["path"], "/down", "download-settings 自己的 path 优先");
    assert_eq!(xs["host"], "cdn.x.com", "host 从外层 xhttp-opts 继承");
    assert_eq!(xs["mode"], "stream-up", "mode 从外层 xhttp-opts 继承");

    // 反向：URI -> mihomo xhttp-opts.download-settings
    let reparsed = parser::parse(&uri);
    assert_eq!(reparsed.len(), 1);
    let opts = reparsed[0].get_map("xhttp-opts").unwrap();
    let ds2 = opts.get("download-settings").and_then(|v| v.as_object()).unwrap();
    assert_eq!(ds2.get("server").unwrap(), "d.com");
    assert_eq!(ds2.get("port").unwrap(), 8443);
    assert!(ds2.get("ech-opts").is_some());

    // mihomo 平台：主节点 Reality + 下载流 tls -> 注入空 public-key 阻断继承
    let reality = proxy(json!({
        "name": "R", "type": "vless", "server": "r.com", "port": 443,
        "uuid": "u", "tls": true, "network": "xhttp",
        "reality-opts": {"public-key": "PUBKEY"},
        "xhttp-opts": {
            "mode": "stream-up",
            "download-settings": {"tls": true}
        }
    }));
    let clash = producer::produce("mihomo", &[reality], None).unwrap();
    assert!(clash.contains("\"public-key\":\"\""), "{}", clash);
}

#[test]
fn singbox_full_chain() {
    let ss = proxy(json!({
        "name": "ST", "type": "ss", "server": "s.com", "port": 443,
        "cipher": "aes-128-gcm", "password": "pw", "plugin": "shadow-tls",
        "plugin-opts": {"version": 3, "password": "stpw", "host": "tls.com"},
        "tls": true, "sni": "tls.com"
    }));
    let wg = proxy(json!({
        "name": "WG", "type": "wireguard", "server": "w.com", "port": 51820,
        "private-key": "priv", "public-key": "pub", "ip": "10.0.0.2/32"
    }));
    let chain = proxy(json!({
        "name": "Chain", "type": "vless", "server": "v.com", "port": 443,
        "uuid": "u", "tls": true, "network": "ws", "skip-cert-verify": true,
        "ws-opts": {"path": "/ws", "headers": {"Host": "h.com"}},
        "ech-opts": {"enable": true, "config": "AAA"},
        "smux": {"enabled": true, "protocol": "smux", "max-streams": 4,
                 "brutal-opts": {"up": 10}},
        "ip-version": "ipv4", "_dns_server": "1.1.1.1", "tfo": true, "uot": true
    }));
    let unsupported = proxy(json!({
        "name": "Bad", "type": "vless", "server": "b.com", "port": 443,
        "uuid": "u", "network": "xhttp"
    }));
    let doc: serde_json::Value = serde_json::from_str(
        &producer::produce("sing-box", &[ss, wg, chain, unsupported], None).unwrap()
    ).unwrap();
    let outbounds = doc["outbounds"].as_array().unwrap();
    let endpoints = doc["endpoints"].as_array().unwrap();
    assert_eq!(endpoints.len(), 1, "wireguard 应归入 endpoints");
    assert_eq!(endpoints[0]["type"], "wireguard");
    assert!(outbounds.iter().any(|x| x["type"] == "shadowtls"));
    assert!(outbounds.iter().any(|x| x["detour"] == "ST_shadowtls"), "ss 走 shadowtls detour");
    assert!(!outbounds.iter().any(|x| x["tag"] == "Bad"), "xhttp 节点整组丢弃");
    let c = outbounds.iter().find(|x| x["tag"] == "Chain").unwrap();
    assert_eq!(c["domain_resolver"]["strategy"], "ipv4_only");
    assert_eq!(c["multiplex"]["brutal"]["up_mbps"], 10);
    assert_eq!(c["tcp_fast_open"], true);
    assert_eq!(c["udp_over_tcp"], true);
    assert_eq!(c["transport"]["type"], "ws");
    assert_eq!(c["transport"]["host"], "h.com");
    assert_eq!(c["tls"]["ech"]["enabled"], true);
    assert_eq!(c["tls"]["server_name"], "h.com", "insecure/Host 组合应生效");
}

#[test]
fn egern_surgemac_passthrough() {
    let eg = proxy(json!({
        "name": "E", "type": "ss", "server": "1.1.1.1", "port": 8388,
        "cipher": "aes-256-gcm", "password": "pw",
        "egern-opts": {"block-quic": true, "underlying-proxy": "P", "no-error-alert": true},
        "test-url": "http://www.gstatic.com/generate_204"
    }));
    let egern = producer::produce("egern", &[eg], None).unwrap();
    assert!(egern.contains("\"block-quic\":true"), "{}", egern);
    assert!(egern.contains("\"underlying-proxy\":\"P\""), "{}", egern);
    assert!(egern.contains("\"no-error-alert\":true"), "{}", egern);
    assert!(egern.contains("\"test-url\":\"http://www.gstatic.com/generate_204\""), "{}", egern);

    let ext = proxy(json!({
        "name": "Ext", "type": "external", "exec": "/usr/bin/mihomo", "local-port": 7890,
        "args": ["-config", "/tmp/c.yaml"], "addresses": ["1.1.1.1"], "udp": true,
        "test-url": "http://x", "block-quic": true,
        "surge-mac-opts": {"no-error-alert": true}
    }));
    let sm = producer::produce("surge-mac", &[ext], None).unwrap();
    assert!(sm.contains("= external,exec=\"/usr/bin/mihomo\",local-port=7890"), "{}", sm);
    assert!(sm.contains("args=\"/tmp/c.yaml\""), "{}", sm);
    assert!(sm.contains("no-error-alert=true"), "{}", sm);
    assert!(sm.contains("block-quic=true"), "{}", sm);

    // mihomoExternal 选项 -> external 行携带 base64 配置
    let mut opts = JMap::new();
    opts.insert("mihomoExternal".into(), json!(true));
    opts.insert("localPort".into(), json!(7891));
    let normal = proxy(json!({
        "name": "M", "type": "trojan", "server": "t.com", "port": 443,
        "password": "pw", "tls": true, "sni": "t.com"
    }));
    let m = producer::produce("surge-mac", &[normal], Some(&opts)).unwrap();
    assert!(m.contains("= external,"), "{}", m);
    assert!(m.contains("local-port=7891"), "{}", m);
    assert!(m.contains("args=\"-config\""), "{}", m);
}
