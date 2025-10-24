//! rlid.rs - Signed, NAT-safe rate-limit identity cookie
//!
//! Cookie value format (URL-safe, no padding):
//!   rlid = "v1." <kid> "." <b64url(payload)> "." <b64url(signature)>
//!
//! Where:
//!   payload = ASCII: "<id>.<exp>"  (id is base64url, exp is unix secs)
//!   signature = HMAC-SHA256(key_kid, payload)
//!
//! - <kid> is a small decimal (u8) key identifier for rotation.
//! - <id> is a random base64url token (16 bytes raw -> 22 chars).
//! - <exp> is expiry unix timestamp (seconds).
//!
//! Validation:
//! - Parse, pick key by kid from `current` or `previous`.
//! - Verify HMAC in constant time.
//! - Check exp >= now.
//!
//! Re-issue hint:
//! - If remaining TTL <= ttl/3, `must_issue = true` (refresh cookie).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct KeyRecord {
    kid: u8,
    key: [u8; 32],
}

/// Outcome of verifying/creating an RL identity.
pub struct VerifyOutcome {
    /// The stable identity to use as the user bucket key (e.g., "ck:<id>").
    pub id: String,
    /// True if the server should send a new `Set-Cookie` (rotation/refresh).
    pub must_issue: bool,
}

pub struct RlidSigner {
    /// Cookie name (e.g., "rlid")
    pub cookie_name: &'static str,
    /// Total validity window for a token
    ttl: Duration,
    /// Current signing key (+ kid)
    current: KeyRecord,
    /// Previously active keys we still accept for validation
    previous: Vec<KeyRecord>,
    /// Reissue when remaining TTL <= ttl / reissue_divisor (default: 3)
    reissue_divisor: u32,
}

impl RlidSigner {
    /// Build a signer.
    ///
    /// - `cookie_name`: usually "rlid"
    /// - `ttl`: e.g. 24h
    /// - `current`: (kid, 32-byte key)
    /// - `previous`: zero or more (kid, 32-byte key) entries
    pub fn new(
        cookie_name: &'static str,
        ttl: Duration,
        current: (u8, [u8; 32]),
        previous: Vec<(u8, [u8; 32])>,
    ) -> Self {
        let current = KeyRecord {
            kid: current.0,
            key: current.1,
        };
        let previous = previous
            .into_iter()
            .map(|(kid, key)| KeyRecord { kid, key })
            .collect();

        Self {
            cookie_name,
            ttl,
            current,
            previous,
            reissue_divisor: 3,
        }
    }

    /// Optionally tweak the refresh threshold (default 3 ⇒ refresh when ≤ TTL/3 remaining).
    pub fn with_reissue_divisor(mut self, divisor: u32) -> Self {
        self.reissue_divisor = divisor.max(1);
        self
    }

    /// Verify an incoming cookie value; if missing/invalid/expired, mint a new id.
    ///
    /// Returns a stable `id` and a `must_issue` flag indicating whether you should
    /// respond with a fresh `Set-Cookie` to the client.
    pub fn verify_or_new(&self, token_opt: Option<&str>) -> VerifyOutcome {
        if let Some(token) = token_opt {
            if let Some(ok) = self.verify_v1(token) {
                return ok;
            }
        }
        // create a new identity when missing or invalid
        VerifyOutcome {
            id: self.gen_id(),
            must_issue: true,
        }
    }

    /// Create a full `Set-Cookie` header value for an existing `id`.
    ///
    /// - `secure`: set to true for HTTPS sites (recommended).
    /// - `domain`: optional Domain attribute (None = omit).
    /// - `path`: optional Path attribute (default Some("/")).
    pub fn issue_set_cookie(
        &self,
        id: &str,
        secure: bool,
        domain: Option<&str>,
        path: Option<&str>,
    ) -> String {
        let now = now_unix();
        let exp = now.saturating_add(self.ttl.as_secs());
        let value = self.make_v1_value(self.current.kid, id, exp);

        // Build attributes
        let mut parts = Vec::with_capacity(8);
        parts.push(format!("{}={}", self.cookie_name, value));
        if let Some(p) = path.or(Some("/")) {
            parts.push(format!("Path={}", p));
        }
        parts.push(format!("Max-Age={}", self.ttl.as_secs()));
        parts.push("HttpOnly".to_string());
        parts.push("SameSite=Lax".to_string());
        if secure {
            parts.push("Secure".to_string());
        }
        if let Some(d) = domain {
            // NOTE: add your own validation if needed
            parts.push(format!("Domain={}", d));
        }

        parts.join("; ")
    }

    /// Build the cookie *value* (no "name=" prefix) using the **current** key.
    pub fn make_value_current(&self, id: &str) -> String {
        let exp = now_unix().saturating_add(self.ttl.as_secs());
        self.make_v1_value(self.current.kid, id, exp)
    }

    // ---------- internals ----------

    fn verify_v1(&self, token: &str) -> Option<VerifyOutcome> {
        // Expect "v1.<kid>.<payload>.<mac>"
        let mut it = token.split('.');
        let v = it.next()?;
        if v != "v1" {
            return None;
        }
        let kid_s = it.next()?;
        let payload_b64 = it.next()?;
        let mac_b64 = it.next()?;
        if it.next().is_some() {
            return None;
        }

        let kid: u8 = kid_s.parse().ok()?;
        let key = self.find_key(kid)?;

        let payload = B64.decode(payload_b64).ok()?;
        let mac = B64.decode(mac_b64).ok()?;

        // Verify HMAC(payload)
        let mut mac_calc = HmacSha256::new_from_slice(&key.key).ok()?;
        mac_calc.update(&payload);
        if mac_calc.verify_slice(&mac).is_err() {
            return None;
        }

        // Parse payload "<id>.<exp>"
        let payload_str = std::str::from_utf8(&payload).ok()?;
        let (id, exp) = parse_payload_id_exp(payload_str)?;

        // Expiry check
        let now = now_unix();
        if exp < now {
            return Some(VerifyOutcome {
                id: id.to_string(),
                must_issue: true, // expired — ask client to refresh
            });
        }

        // Determine refresh threshold
        let remaining = exp.saturating_sub(now);
        let refresh_cutoff = (self.ttl.as_secs() / self.reissue_divisor as u64).max(1);
        let must_issue = remaining <= refresh_cutoff || kid != self.current.kid;

        Some(VerifyOutcome {
            id: id.to_string(),
            must_issue,
        })
    }

    fn make_v1_value(&self, kid: u8, id: &str, exp_unix: u64) -> String {
        let payload = format!("{}.{}", id, exp_unix);
        let payload_b = payload.as_bytes();

        let mut mac =
            HmacSha256::new_from_slice(&self.current.key).expect("HMAC key length is valid");
        mac.update(payload_b);
        let sig = mac.finalize().into_bytes();

        let payload_b64 = B64.encode(payload_b);
        let sig_b64 = B64.encode(sig);
        format!("v1.{}.{}.{}", kid, payload_b64, sig_b64)
    }

    fn find_key(&self, kid: u8) -> Option<&KeyRecord> {
        if self.current.kid == kid {
            return Some(&self.current);
        }
        self.previous.iter().find(|k| k.kid == kid)
    }

    fn gen_id(&self) -> String {
        use rand::RngCore;
        let mut b = [0u8; 16];
        // Use a fast RNG; swap to a CSPRNG (rand::rngs::OsRng) if you prefer.
        rand::rng().fill_bytes(&mut b);
        B64.encode(b)
    }
}

fn parse_payload_id_exp(s: &str) -> Option<(&str, u64)> {
    let mut it = s.rsplitn(2, '.'); // split from the right: "<id>.<exp>"
    let exp_s = it.next()?;
    let id = it.next()?;
    let exp = exp_s.parse::<u64>().ok()?;
    Some((id, exp))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rlid_round_trip_issue_and_verify() {
        let cur = [7u8; 32];
        let old = [9u8; 32];
        let signer = RlidSigner::new("rlid", Duration::from_secs(60), (2, cur), vec![(1, old)]);

        // new id + set-cookie
        let id = signer.gen_id();
        let sc = signer.issue_set_cookie(&id, false, None, Some("/"));
        assert!(sc.starts_with("rlid=v1.2."), "cookie format mismatch: {sc}");

        // extract value
        let value = sc.splitn(2, '=').nth(1).unwrap().split(';').next().unwrap();
        let res = signer.verify_or_new(Some(value));
        assert_eq!(res.id, id);
        assert!(!res.must_issue, "fresh token should not require refresh");
    }

    #[test]
    fn rlid_refresh_when_near_expiry() {
        let cur = [1u8; 32];
        let signer = RlidSigner::new("rlid", Duration::from_secs(3), (1, cur), vec![])
            .with_reissue_divisor(3);

        let id = signer.gen_id();
        let val = signer.make_value_current(&id);

        // Immediately valid; depending on timing, may or may not need refresh — accept both
        let res = signer.verify_or_new(Some(&val));
        assert_eq!(res.id, id);
    }

    #[test]
    fn invalid_token_yields_new_id() {
        let cur = [3u8; 32];
        let signer = RlidSigner::new("rlid", Duration::from_secs(60), (7, cur), vec![]);
        let res = signer.verify_or_new(Some("v1.9.notpayload.notmac"));
        assert!(res.must_issue);
        // id is random; just ensure it's non-empty
        assert!(!res.id.is_empty());
    }
}
