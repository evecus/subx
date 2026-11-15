//! 单元/集成测试：解析、产出、cron、配置、存储、token。

use crate::config::normalize_path_prefix;
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
