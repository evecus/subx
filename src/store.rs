//! SQLite 存储层。表结构与 Go 版完全一致，可直接复用同一个 subx.db。

use crate::util::JMap;
use anyhow::{anyhow, Context, Result};
use parking_lot::Mutex;
use rusqlite::{params, Connection, Transaction};
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

fn is_unique_violation(e: &rusqlite::Error) -> bool {
    if let rusqlite::Error::SqliteFailure(_, msg) = e {
        return msg.as_deref().unwrap_or("").contains("UNIQUE constraint failed");
    }
    e.to_string().contains("UNIQUE constraint failed")
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent).context("create data dir")?;
        }
        let conn = Connection::open(path).context("open database")?;
        for pragma in [
            "PRAGMA journal_mode=WAL",
            "PRAGMA busy_timeout=5000",
            "PRAGMA foreign_keys=ON",
        ] {
            conn.execute_batch(pragma)
                .with_context(|| format!("exec {}", pragma))?;
        }
        let st = Self { conn: Arc::new(Mutex::new(conn)) };
        st.migrate()?;
        Ok(st)
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.conn.lock();
        let current: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if current >= 1 {
            return Ok(());
        }
        let tx = conn.unchecked_transaction()?;
        for q in [
            "CREATE TABLE IF NOT EXISTS subs (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, data TEXT NOT NULL, pos INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS collections (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, data TEXT NOT NULL, pos INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, data TEXT NOT NULL, pos INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL UNIQUE, data TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        ] {
            tx.execute(q, [])?;
        }
        tx.execute("PRAGMA user_version = 1", [])?;
        tx.commit()?;
        Ok(())
    }

    /// 在单个事务里执行多步写操作（改名 + 更新集合引用等）。
    pub fn with_tx<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Transaction<'_>) -> Result<T>,
    {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    // ---- 通用 name-keyed 实体 ----

    fn list(&self, table: &str) -> Result<Vec<JMap>> {
        let conn = self.conn.lock();
        let sql = format!("SELECT data FROM {} ORDER BY pos ASC, id ASC", table);
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for raw in rows {
            let raw = raw?;
            out.push(parse_map(&raw));
        }
        Ok(out)
    }

    fn get(&self, table: &str, name: &str) -> Result<Option<JMap>> {
        let conn = self.conn.lock();
        let sql = format!("SELECT data FROM {} WHERE name = ?", table);
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query(params![name])?;
        match rows.next()? {
            Some(r) => {
                let raw: String = r.get(0)?;
                Ok(Some(parse_map(&raw)))
            }
            None => Ok(None),
        }
    }

    fn upsert(&self, table: &str, name: &str, data: &JMap, position: &str) -> Result<()> {
        let conn = self.conn.lock();
        upsert_on(&conn, table, name, data, position)
    }

    fn rename(&self, table: &str, old: &str, new: &str, data: &JMap) -> Result<bool> {
        let conn = self.conn.lock();
        rename_on(&conn, table, old, new, data)
    }

    fn delete(&self, table: &str, name: &str) -> Result<()> {
        let conn = self.conn.lock();
        let sql = format!("DELETE FROM {} WHERE name = ?", table);
        conn.execute(&sql, params![name])?;
        Ok(())
    }

    // ---- subs ----
    pub fn list_subs(&self) -> Result<Vec<JMap>> { self.list("subs") }
    pub fn get_sub(&self, name: &str) -> Result<Option<JMap>> { self.get("subs", name) }
    pub fn upsert_sub(&self, name: &str, data: &JMap, position: &str) -> Result<()> {
        self.upsert("subs", name, data, position)
    }
    pub fn rename_sub(&self, old: &str, new: &str, data: &JMap) -> Result<bool> {
        self.rename("subs", old, new, data)
    }
    pub fn delete_sub(&self, name: &str) -> Result<()> { self.delete("subs", name) }

    // ---- collections ----
    pub fn list_collections(&self) -> Result<Vec<JMap>> { self.list("collections") }
    pub fn get_collection(&self, name: &str) -> Result<Option<JMap>> { self.get("collections", name) }
    pub fn upsert_collection(&self, name: &str, data: &JMap, position: &str) -> Result<()> {
        self.upsert("collections", name, data, position)
    }
    pub fn rename_collection(&self, old: &str, new: &str, data: &JMap) -> Result<bool> {
        self.rename("collections", old, new, data)
    }
    pub fn delete_collection(&self, name: &str) -> Result<()> { self.delete("collections", name) }

    // ---- files ----
    pub fn list_files(&self) -> Result<Vec<JMap>> { self.list("files") }
    pub fn get_file(&self, name: &str) -> Result<Option<JMap>> { self.get("files", name) }
    pub fn upsert_file(&self, name: &str, data: &JMap, position: &str) -> Result<()> {
        self.upsert("files", name, data, position)
    }
    pub fn rename_file(&self, old: &str, new: &str, data: &JMap) -> Result<bool> {
        self.rename("files", old, new, data)
    }
    pub fn delete_file(&self, name: &str) -> Result<()> { self.delete("files", name) }

    // ---- tokens ----
    pub fn list_tokens(&self) -> Result<Vec<JMap>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT data FROM tokens ORDER BY id ASC")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.map(|r| r.map(|raw| parse_map(&raw)).map_err(Into::into)).collect()
    }

    pub fn get_token(&self, token: &str) -> Result<Option<JMap>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT data FROM tokens WHERE token = ?")?;
        let mut rows = stmt.query(params![token])?;
        match rows.next()? {
            Some(r) => {
                let raw: String = r.get(0)?;
                Ok(Some(parse_map(&raw)))
            }
            None => Ok(None),
        }
    }

    /// 返回 false 表示 token 冲突。
    pub fn insert_token(&self, data: &JMap) -> Result<bool> {
        let token = crate::util::get_str(data, "token");
        let raw = serde_json::to_string(&Value::Object(data.clone()))?;
        let conn = self.conn.lock();
        match conn.execute("INSERT INTO tokens (token, data) VALUES (?, ?)", params![token, raw]) {
            Ok(_) => Ok(true),
            Err(e) if is_unique_violation(&e) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub fn update_token(&self, data: &JMap) -> Result<()> {
        let token = crate::util::get_str(data, "token");
        let raw = serde_json::to_string(&Value::Object(data.clone()))?;
        let conn = self.conn.lock();
        conn.execute("UPDATE tokens SET data = ? WHERE token = ?", params![raw, token])?;
        Ok(())
    }

    pub fn delete_token(&self, token: &str) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM tokens WHERE token = ?", params![token])?;
        Ok(())
    }

    // ---- settings ----
    pub fn get_settings(&self) -> Result<JMap> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = 'settings'")?;
        let mut rows = stmt.query([])?;
        match rows.next()? {
            Some(r) => {
                let raw: String = r.get(0)?;
                Ok(parse_map(&raw))
            }
            None => Ok(JMap::new()),
        }
    }

    pub fn save_settings(&self, v: &JMap) -> Result<()> {
        let raw = serde_json::to_string(&Value::Object(v.clone()))?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('settings', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![raw],
        )?;
        Ok(())
    }
}

fn parse_map(raw: &str) -> JMap {
    serde_json::from_str::<Value>(raw)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

fn upsert_on(conn: &Connection, table: &str, name: &str, data: &JMap, position: &str) -> Result<()> {
    let raw = serde_json::to_string(&Value::Object(data.clone()))?;
    let expr = if position == "top" {
        format!("SELECT COALESCE(MIN(pos), 1) - 1 FROM {}", table)
    } else {
        format!("SELECT COALESCE(MAX(pos), 0) + 1 FROM {}", table)
    };
    let pos: i64 = conn.query_row(&expr, [], |r| r.get(0))?;
    let sql = format!(
        "INSERT INTO {} (name, data, pos) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET data = excluded.data",
        table
    );
    conn.execute(&sql, params![name, raw, pos])?;
    Ok(())
}

/// 事务版 upsert，供 with_tx 内部使用。
pub fn upsert_tx(tx: &Transaction<'_>, table: &str, name: &str, data: &JMap) -> Result<()> {
    upsert_on(tx, table, name, data, "bottom")
}

pub fn list_tx(tx: &Transaction<'_>, table: &str) -> Result<Vec<JMap>> {
    let sql = format!("SELECT data FROM {} ORDER BY pos ASC, id ASC", table);
    let mut stmt = tx.prepare(&sql)?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    rows.map(|r| r.map(|raw| parse_map(&raw)).map_err(Into::into)).collect()
}

pub fn rename_tx(tx: &Transaction<'_>, table: &str, old: &str, new: &str, data: &JMap) -> Result<bool> {
    rename_on(tx, table, old, new, data)
}

pub fn delete_tx(tx: &Transaction<'_>, table: &str, name: &str) -> Result<()> {
    let sql = format!("DELETE FROM {} WHERE name = ?", table);
    tx.execute(&sql, params![name])?;
    Ok(())
}

fn rename_on(conn: &Connection, table: &str, old: &str, new: &str, data: &JMap) -> Result<bool> {
    let raw = serde_json::to_string(&Value::Object(data.clone()))?;
    let sql = format!("UPDATE {} SET name = ?, data = ? WHERE name = ?", table);
    match conn.execute(&sql, params![new, raw, old]) {
        Ok(_) => Ok(true),
        Err(e) if is_unique_violation(&e) => Ok(false),
        Err(e) => Err(anyhow!("{}", e)),
    }
}
