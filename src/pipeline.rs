//! 解析 -> 操作符 -> 产出 的完整流水线。

use crate::model::{Operator, Proxy};
use crate::processor::Context;
use crate::util::JMap;
use anyhow::{anyhow, Result};

#[derive(Default)]
pub struct Request {
    pub raw: String,
    pub target: String,
    pub options: Option<JMap>,
    pub operators: Vec<Operator>,
    pub prepend_lines: Vec<String>,
    pub append_lines: Vec<String>,
    pub useless: bool,
    pub sub_name: String,
    pub sub_display_name: String,
    pub url_base: String,
}

pub fn parse(raw: &str) -> Vec<Proxy> {
    crate::parser::parse(raw)
}

pub fn process(req: &Request) -> Result<String> {
    if req.target.trim().is_empty() {
        return Err(anyhow!("target format not specified"));
    }
    if !crate::producer::known(&req.target) {
        return Err(anyhow!("unsupported target: {}", req.target));
    }
    let mut proxies = parse(&req.raw);
    if !req.sub_name.is_empty() {
        for p in &mut proxies {
            p.set("_subName", req.sub_name.clone());
            p.set("_subDisplayName", req.sub_display_name.clone());
        }
    }
    if req.useless {
        proxies = crate::processor::useless_filter(proxies);
    }
    proxies = crate::processor::apply(proxies, &req.operators, &Context::default())?;
    let body = crate::producer::produce(&req.target, &proxies, req.options.as_ref())?;
    let mut lines = Vec::new();
    lines.extend(req.prepend_lines.iter().cloned());
    lines.push(body);
    lines.extend(req.append_lines.iter().cloned());
    if !req.url_base.is_empty() {
        for line in &mut lines {
            if line.trim_start().starts_with("url = ") {
                *line = format!("url = {}", req.url_base);
            }
        }
    }
    Ok(lines.join("\n"))
}

/// 集合流程：跳过 parse，直接在已合并的 Proxy 列表上应用操作符并产出。
pub fn process_proxies(
    proxies: Vec<Proxy>,
    target: &str,
    options: Option<&JMap>,
    operators: &[Operator],
    prepend_lines: &[String],
    append_lines: &[String],
) -> Result<String> {
    if target.trim().is_empty() {
        return Err(anyhow!("target format not specified"));
    }
    let proxies = crate::processor::apply(proxies, operators, &Context::default())?;
    let body = crate::producer::produce(target, &proxies, options)?;
    let mut lines = Vec::new();
    lines.extend(prepend_lines.iter().cloned());
    lines.push(body);
    lines.extend(append_lines.iter().cloned());
    Ok(lines.join("\n"))
}
