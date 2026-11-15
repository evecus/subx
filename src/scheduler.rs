//! 5 段 cron 解析与后台定时刷新（对齐 Go internal/scheduler）。

use crate::downloader::Downloader;
use crate::share::ShareResolver;
use crate::store::Store;
use crate::util::{get_str, JMap};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Datelike, Duration, Local, Timelike};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::time::MissedTickBehavior;

const BOUNDS: [(i64, i64); 5] = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)];

#[derive(Clone, Debug)]
pub struct Schedule {
    minutes: HashSet<i64>,
    hours: HashSet<i64>,
    days: HashSet<i64>,
    months: HashSet<i64>,
    weekdays: HashSet<i64>,
    day_unrestricted: bool,
    weekday_unrestricted: bool,
}

fn parse_field(f: &str, lo: i64, hi: i64) -> Result<HashSet<i64>> {
    let mut out = HashSet::new();
    for part in f.split(',') {
        if part.is_empty() {
            return Err(anyhow!("empty term"));
        }
        let mut step = 1i64;
        let base = if let Some((b, s)) = part.split_once('/') {
            step = s.parse::<i64>().map_err(|_| anyhow!("invalid step {}", s))?;
            if step <= 0 {
                return Err(anyhow!("invalid step {}", s));
            }
            b
        } else {
            part
        };
        let (start, end) = if base == "*" {
            (lo, hi)
        } else if let Some((a, b)) = base.split_once('-') {
            let a = a.parse::<i64>().map_err(|_| anyhow!("invalid range {}", base))?;
            let b = b.parse::<i64>().map_err(|_| anyhow!("invalid range {}", base))?;
            (a, b)
        } else {
            let v = base.parse::<i64>().map_err(|_| anyhow!("invalid value {}", base))?;
            (v, v)
        };
        if start < lo || end > hi || start > end {
            return Err(anyhow!("value out of range [{}-{}]", lo, hi));
        }
        let mut v = start;
        while v <= end {
            out.insert(v);
            v += step;
        }
    }
    Ok(out)
}

pub fn parse(expr: &str) -> Result<Schedule> {
    let fields: Vec<&str> = expr.trim().split_whitespace().collect();
    if fields.len() != 5 {
        return Err(anyhow!("cron expression must have exactly 5 fields (minute hour day month weekday), got {}", fields.len()));
    }
    let sets: Vec<HashSet<i64>> = fields
        .iter()
        .zip(BOUNDS.iter())
        .map(|(f, (lo, hi))| {
            parse_field(f, *lo, *hi).map_err(|e| anyhow!("field {:?}: {}", f, e))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Schedule {
        day_unrestricted: sets[2].len() == 31,
        weekday_unrestricted: sets[4].len() == 7,
        minutes: sets[0].clone(),
        hours: sets[1].clone(),
        days: sets[2].clone(),
        months: sets[3].clone(),
        weekdays: sets[4].clone(),
    })
}

pub fn valid(expr: &str) -> bool {
    parse(expr).is_ok()
}

impl Schedule {
    fn matches(&self, t: DateTime<Local>) -> bool {
        if !self.minutes.contains(&(t.minute() as i64)) {
            return false;
        }
        if !self.hours.contains(&(t.hour() as i64)) {
            return false;
        }
        if !self.months.contains(&(t.month() as i64)) {
            return false;
        }
        let day_ok = self.days.contains(&(t.day() as i64));
        let weekday_ok = self.weekdays.contains(&(t.weekday().num_days_from_sunday() as i64));
        match (self.day_unrestricted, self.weekday_unrestricted) {
            (true, true) => true,
            (true, false) => weekday_ok,
            (false, true) => day_ok,
            (false, false) => day_ok || weekday_ok,
        }
    }

    /// 返回 after 之后第一个匹配的分钟（最多向后搜索 4 年）。
    pub fn next(&self, after: DateTime<Local>) -> Option<DateTime<Local>> {
        let mut t = after.with_second(0)?.with_nanosecond(0)? + Duration::minutes(1);
        let limit = after + Duration::days(366 * 4);
        while t < limit {
            if self.matches(t) {
                return Some(t);
            }
            t += Duration::minutes(1);
        }
        None
    }
}

pub struct Runner {
    store: Arc<Store>,
    downloader: Downloader,
    resolver: Arc<ShareResolver>,
    last: HashMap<String, DateTime<Local>>,
}

impl Runner {
    pub fn start(store: Arc<Store>, resolver: Arc<ShareResolver>) {
        let runner = Arc::new(tokio::sync::Mutex::new(Runner {
            store,
            downloader: Downloader::new(),
            resolver,
            last: HashMap::new(),
        }));
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            // 启动后立即跑一次，避免恰好到点的任务等一分钟
            {
                let mut r = runner.lock().await;
                r.tick().await;
            }
            loop {
                ticker.tick().await;
                let mut r = runner.lock().await;
                r.tick().await;
            }
        });
    }

    async fn tick(&mut self) {
        let subs = match self.store.list_subs() {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("scheduler: list subs failed: {}", e);
                return;
            }
        };
        let now = Local::now();
        for rec in subs {
            if get_str(&rec, "source") != "remote" {
                continue;
            }
            let cron = get_str(&rec, "updateCron");
            let url = get_str(&rec, "url");
            if cron.is_empty() || url.is_empty() {
                continue;
            }
            let sched = match parse(&cron) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let name = get_str(&rec, "name");
            let from = self.last.get(&name).copied().unwrap_or_else(|| now - Duration::minutes(1));
            match sched.next(from) {
                Some(next) if next <= now => {}
                _ => continue,
            }
            self.refresh(&rec, &name, now).await;
        }
    }

    async fn refresh(&mut self, rec: &JMap, name: &str, now: DateTime<Local>) {
        let default_ua = self.resolver.store.get_settings().ok()
            .map(|s| get_str(&s, "defaultUserAgent")).unwrap_or_default();
        let content = self.downloader
            .fetch_url(&get_str(rec, "url"), &get_str(rec, "ua"), &default_ua)
            .await;
        match content {
            Ok(text) => {
                let mut updated = rec.clone();
                updated.insert("cachedContent".into(), json!(text));
                updated.insert("cachedAt".into(), json!(crate::util::now_millis()));
                if let Err(e) = self.store.upsert_sub(name, &updated, "bottom") {
                    tracing::warn!("scheduler: save {:?} failed: {}", name, e);
                    return;
                }
                tracing::info!("scheduler: refreshed {:?}", name);
            }
            Err(e) => tracing::warn!("scheduler: refresh {:?} failed: {}", name, e),
        }
        self.last.insert(name.to_string(), now);
    }
}
