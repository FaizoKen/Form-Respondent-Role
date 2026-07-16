//! Short-lived session token for the DWEEB link-plugin picker.
//!
//! DWEEB (the Discord Webhook Embed Builder) embeds our `/dweeb/picker` page
//! in a sandboxed iframe so a server admin can point a Link button at one of
//! their forms without leaving the editor. Third-party cookies are unreliable
//! inside cross-site iframes (Safari ITP, Firefox ETP, Chrome partitioning),
//! so — exactly like the RoleLogic-dashboard iframe session in
//! [`crate::services::rl_token`] — the picker never depends on the `rl_session`
//! cookie. Instead the iframe opens a same-origin popup to `/dweeb/bridge`,
//! which *does* have first-party cookie context: the bridge verifies the
//! cookie, confirms the caller manages the target guild via the Auth Gateway,
//! mints this token, and hands it back to the iframe over `postMessage`.
//!
//! The token is bound to `(discord_id, guild_id)` and signed with
//! `session_secret`, so leaking one cannot be replayed against another guild.
//! It only ever grants **read** access to that guild's form list — the picker
//! writes nothing — and it is deliberately short-lived: the bridge re-mints
//! instantly for a signed-in manager.
//!
//! Format: `dws:{discord_id}:{guild_id}:{exp}:{hmac_hex}`. The `dws:` prefix
//! disambiguates from the cookie session token and the `ifs:` iframe-session
//! token so a shared handler can never confuse the credentials.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::rl_token::constant_time_eq;

type HmacSha256 = Hmac<Sha256>;

const DWEEB_PREFIX: &str = "dws:";
/// Read-only, guild-bound form-*name* listing is all this grants, so the TTL
/// optimizes for UX over rotation: the picker persists the token in its
/// (partitioned) storage so an admin signs in about once a day per server
/// rather than on every Configure open. Manager-permission revocation within
/// the window only exposes form titles/slugs — the same names any member sees
/// on the public form pages — never responses or config.
const DWEEB_TTL_SECS: i64 = 12 * 60 * 60;

pub struct DweebSession {
    pub discord_id: String,
    pub guild_id: String,
}

pub fn mint_dweeb_session(discord_id: &str, guild_id: &str, session_secret: &str) -> String {
    let exp = chrono::Utc::now().timestamp() + DWEEB_TTL_SECS;
    let payload = format!("{discord_id}:{guild_id}:{exp}");
    let mut mac =
        HmacSha256::new_from_slice(session_secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("{DWEEB_PREFIX}{payload}:{sig}")
}

pub fn verify_dweeb_session(token: &str, session_secret: &str) -> Option<DweebSession> {
    let rest = token.strip_prefix(DWEEB_PREFIX)?;
    let parts: Vec<&str> = rest.splitn(4, ':').collect();
    if parts.len() != 4 {
        return None;
    }
    let discord_id = parts[0];
    let guild_id = parts[1];
    let exp_str = parts[2];
    let sig = parts[3];

    let exp: i64 = exp_str.parse().ok()?;
    if chrono::Utc::now().timestamp() > exp {
        return None;
    }

    let payload = format!("{discord_id}:{guild_id}:{exp_str}");
    let mut mac =
        HmacSha256::new_from_slice(session_secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    if !constant_time_eq(sig.as_bytes(), expected.as_bytes()) {
        return None;
    }

    Some(DweebSession {
        discord_id: discord_id.to_string(),
        guild_id: guild_id.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION_SECRET: &str = "session-secret-not-for-prod";

    #[test]
    fn dweeb_session_round_trip() {
        let token = mint_dweeb_session("user1", "g1", SESSION_SECRET);
        let s = verify_dweeb_session(&token, SESSION_SECRET).expect("valid token");
        assert_eq!(s.discord_id, "user1");
        assert_eq!(s.guild_id, "g1");
    }

    #[test]
    fn dweeb_session_rejects_wrong_secret() {
        let token = mint_dweeb_session("u", "g", SESSION_SECRET);
        assert!(verify_dweeb_session(&token, "wrong-secret").is_none());
    }

    #[test]
    fn dweeb_session_rejects_guild_pivot() {
        // A token minted for (alice, g1) must not verify for g2 after editing
        // the guild portion — the HMAC binds the tuple.
        let token = mint_dweeb_session("alice", "g1", SESSION_SECRET);
        let rest = token.strip_prefix("dws:").unwrap();
        let parts: Vec<&str> = rest.splitn(4, ':').collect();
        let forged = format!("dws:{}:g2:{}:{}", parts[0], parts[2], parts[3]);
        assert!(verify_dweeb_session(&forged, SESSION_SECRET).is_none());
    }

    #[test]
    fn dweeb_session_rejects_expired() {
        // Hand-build an expired-but-correctly-signed token.
        let exp = chrono::Utc::now().timestamp() - 10;
        let payload = format!("u:g:{exp}");
        let mut mac = HmacSha256::new_from_slice(SESSION_SECRET.as_bytes()).unwrap();
        mac.update(payload.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        let token = format!("dws:{payload}:{sig}");
        assert!(verify_dweeb_session(&token, SESSION_SECRET).is_none());
    }

    #[test]
    fn dweeb_session_rejects_other_token_kinds() {
        // An `ifs:` iframe-session (or the bare cookie value) must never pass
        // for a DWEEB session — the prefix is the discriminator.
        assert!(verify_dweeb_session("ifs:u:g:r:0::123:aa", SESSION_SECRET).is_none());
        let no_prefix = mint_dweeb_session("u", "g", SESSION_SECRET);
        let no_prefix = no_prefix.strip_prefix("dws:").unwrap();
        assert!(verify_dweeb_session(no_prefix, SESSION_SECRET).is_none());
    }
}
