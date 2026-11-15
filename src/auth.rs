//! JWT 签发/校验与常量时间凭据比较。

use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub username: String,
    pub exp: i64,
    pub iat: i64,
}

pub fn sign_token(secret: &str, username: &str, ttl_hours: i64) -> Result<String> {
    let now = crate::util::now_secs();
    let claims = Claims {
        username: username.to_string(),
        exp: now + ttl_hours * 3600,
        iat: now,
    };
    Ok(encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?)
}

pub fn validate_token(secret: &str, raw: &str) -> Result<String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    let data = decode::<Claims>(
        raw,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_| anyhow!("invalid token"))?;
    Ok(data.claims.username)
}

/// 等长输入的常量时间字符串比较；长度不等直接返回 false。
pub fn constant_time_equal(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}
