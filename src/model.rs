//! 统一数据模型。Proxy 采用动态 JSON 对象，与 Go 版 map[string]any 一致，
//! 保证协议特有字段在 parse -> process -> produce 全流程无损透传。

use crate::util::{get_array, get_bool, get_i64, get_map, get_str, value_i64, value_str, JMap};
use serde_json::{json, Value};

#[derive(Clone, Debug, Default)]
pub struct Proxy {
    pub fields: JMap,
}

impl Proxy {
    pub fn new() -> Self {
        Self { fields: JMap::new() }
    }

    pub fn from_map(m: JMap) -> Self {
        Self { fields: m }
    }

    pub fn from_value(v: &Value) -> Option<Self> {
        v.as_object().map(|m| Self::from_map(m.clone()))
    }

    pub fn fields(&self) -> &JMap {
        &self.fields
    }

    pub fn fields_mut(&mut self) -> &mut JMap {
        &mut self.fields
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.fields.get(key)
    }

    pub fn has(&self, key: &str) -> bool {
        self.fields.contains_key(key)
    }

    pub fn set<V: Into<Value>>(&mut self, key: &str, val: V) {
        self.fields.insert(key.to_string(), val.into());
    }

    pub fn set_value(&mut self, key: &str, val: Value) {
        self.fields.insert(key.to_string(), val);
    }

    pub fn delete(&mut self, key: &str) {
        self.fields.remove(key);
    }

    pub fn get_str(&self, key: &str) -> String {
        get_str(&self.fields, key)
    }

    pub fn get_i64(&self, key: &str) -> i64 {
        get_i64(&self.fields, key)
    }

    pub fn get_bool(&self, key: &str) -> bool {
        get_bool(&self.fields, key)
    }

    pub fn get_map(&self, key: &str) -> Option<JMap> {
        get_map(&self.fields, key)
    }

    pub fn get_array(&self, key: &str) -> Option<Vec<Value>> {
        get_array(&self.fields, key)
    }

    pub fn type_(&self) -> String {
        self.get_str("type")
    }

    pub fn name(&self) -> String {
        self.get_str("name")
    }

    pub fn server(&self) -> String {
        self.get_str("server")
    }

    pub fn port(&self) -> i64 {
        self.get_i64("port")
    }

    pub fn display_name(&self) -> String {
        let n = self.name();
        if !n.is_empty() {
            n
        } else {
            format!("{} {}:{}", self.type_(), self.server(), self.port())
        }
    }

    pub fn supported(&self) -> Option<JMap> {
        self.get_map("supported")
    }

    /// 对齐 Go Proxy.Clone：JSON 往返一次做深拷贝（字段顺序按 key 排序）。
    pub fn deep_clone(&self) -> Self {
        let sorted: serde_json::Map<String, Value> =
            self.fields.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        Self { fields: sorted }
    }

    pub fn into_value(self) -> Value {
        Value::Object(self.fields)
    }

    pub fn as_value(&self) -> Value {
        Value::Object(self.fields.clone())
    }

    /// 取嵌套路径，如 "ws-opts.headers.Host"。
    pub fn get_nested(&self, path: &str) -> Option<Value> {
        let mut cur = Value::Object(self.fields.clone());
        for part in path.split('.') {
            cur = cur.as_object()?.get(part)?.clone();
        }
        Some(cur)
    }

    pub fn is_ss_over_tls(&self) -> bool {
        if self.type_() != "ss" {
            return false;
        }
        matches!(self.get_str("plugin").as_str(), "shadow-tls" | "v2ray-plugin")
    }
}

/// 单条处理操作符。
#[derive(Clone, Debug)]
pub struct Operator {
    pub typ: String,
    pub args: Value,
    pub disabled: bool,
    pub custom_name: String,
}

impl Operator {
    pub fn from_value(v: &Value) -> Option<Self> {
        let m = v.as_object()?;
        Some(Self {
            typ: get_str(m, "type"),
            args: m.get("args").cloned().unwrap_or(Value::Null),
            disabled: get_bool(m, "disabled"),
            custom_name: get_str(m, "customName"),
        })
    }

    pub fn from_values(vals: Option<&Vec<Value>>) -> Vec<Self> {
        vals.map(|v| v.iter().filter_map(Self::from_value).collect())
            .unwrap_or_default()
    }
}

/// 从订阅/集合记录的 process 字段读取操作符。
pub fn operators_of(rec: &JMap) -> Vec<Operator> {
    Operator::from_values(get_array(rec, "process").as_ref())
}

pub fn prepend_lines_of(rec: &JMap) -> Vec<String> {
    string_lines(rec, "prependLines")
}

pub fn append_lines_of(rec: &JMap) -> Vec<String> {
    string_lines(rec, "appendLines")
}

pub fn string_lines(rec: &JMap, key: &str) -> Vec<String> {
    get_array(rec, key)
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect()
}

/// 目标格式定义（/api/targets）。
#[derive(Clone, Debug, serde::Serialize)]
pub struct Target {
    pub name: &'static str,
    pub label: &'static str,
}

pub fn canonical_targets() -> Vec<Target> {
    vec![
        Target { name: "mihomo", label: "Clash / Mihomo" },
        Target { name: "clash", label: "Clash" },
        Target { name: "stash", label: "Stash" },
        Target { name: "surge", label: "Surge" },
        Target { name: "surge-mac", label: "Surge Mac" },
        Target { name: "surfboard", label: "Surfboard" },
        Target { name: "loon", label: "Loon" },
        Target { name: "shadowrocket", label: "Shadowrocket" },
        Target { name: "qx", label: "Quantumult X" },
        Target { name: "sing-box", label: "sing-box" },
        Target { name: "v2ray", label: "V2Ray" },
        Target { name: "egern", label: "Egern" },
        Target { name: "json", label: "JSON" },
        Target { name: "uri", label: "通用链接 (URI)" },
    ]
}

/// token 是否仍可用（对齐 Go model.Token.Usable）。
pub fn token_usable(rec: &JMap) -> bool {
    let exp = get_i64(rec, "exp");
    if exp > 0 && exp <= crate::util::now_millis() {
        return false;
    }
    if get_str(rec, "mode") == "count" {
        let count = get_i64(rec, "count");
        let used = get_i64(rec, "usedCount");
        return count > 0 && used >= 0 && used < count;
    }
    true
}

/// 把字符串/数字/布尔值统一成 Value（构造 token 记录时用）。
pub fn v(s: impl Into<String>) -> Value {
    Value::String(s.into())
}

pub fn n(i: i64) -> Value {
    json!(i)
}

pub fn int_str(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Number(_) => value_i64(v).to_string(),
        other => value_str(other),
    }
}
