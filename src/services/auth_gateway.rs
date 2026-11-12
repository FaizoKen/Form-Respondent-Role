//! Server-to-server client for the centralized Auth Gateway's
//! `/auth/internal/*` endpoints.
//!
//! Background sync workers don't have a logged-in user cookie, so they call
//! these internal endpoints (header-authed via `X-Internal-Key`) instead of
//! the user-cookie-authed `/auth/guild_permission` and `/auth/guild_members`.
//!
//! All errors are bubbled up — callers (sync workers) should log and skip
//! the affected user/role-link this cycle (Convention 40), NEVER catch and
//! return an empty list, which would clear the role from every member on
//! every transient gateway hiccup.

use serde::Deserialize;

use crate::error::AppError;

/// Plugin slug sent to the Auth Gateway. Must match the URL prefix this
/// plugin is mounted under (`/form-respondent-role`) and the entry in the
/// gateway's plugin registry. The gateway uses this to scope the user's
/// per-(plugin × server) opt-outs when filtering guild lists.
const PLUGIN_SLUG: &str = "form-respondent-role";

#[derive(Debug, Deserialize)]
struct UserGuildIdsResponse {
    guild_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GuildOptoutIdsResponse {
    discord_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GuildNameResponse {
    guild_name: Option<String>,
}

/// Guilds the user is in where this plugin may give them roles: paused
/// guilds (by them or by the gateway's default) are left out. For deciding
/// where to sync, never for "is this user a member?" — see
/// [`fetch_member_guild_ids`].
pub async fn fetch_user_guild_ids(
    http: &reqwest::Client,
    base: &str,
    key: &str,
    discord_id: &str,
) -> Result<Vec<String>, AppError> {
    user_guild_ids(http, base, key, discord_id, false).await
}

/// Every guild the user is a member of, paused or not. For membership checks
/// (a form that requires being in the server): a pause decides whether roles
/// are given there, not whether the user belongs, and the gateway pauses every
/// server a user is first seen in or joins later unless they turned that off.
/// Asking the filtered list told those members "you must be a member of the
/// server" while they were in it, and the form page that would have
/// re-enabled the server never loaded.
pub async fn fetch_member_guild_ids(
    http: &reqwest::Client,
    base: &str,
    key: &str,
    discord_id: &str,
) -> Result<Vec<String>, AppError> {
    user_guild_ids(http, base, key, discord_id, true).await
}

async fn user_guild_ids(
    http: &reqwest::Client,
    base: &str,
    key: &str,
    discord_id: &str,
    include_paused: bool,
) -> Result<Vec<String>, AppError> {
    let url = format!("{base}/auth/internal/user_guild_ids");
    let include_paused = if include_paused { "true" } else { "false" };
    let resp = http
        .get(&url)
        .header("X-Internal-Key", key)
        // `plugin` scopes the response to this plugin's opt-out preferences
        // so guilds where the user disabled this plugin are excluded, unless
        // `include_paused` asks for plain membership.
        .query(&[
            ("discord_id", discord_id),
            ("plugin", PLUGIN_SLUG),
            ("include_paused", include_paused),
        ])
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway request failed: {e}")))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "auth_gateway user_guild_ids returned {status}: {body}"
        )));
    }

    let parsed: UserGuildIdsResponse = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway response not JSON: {e}")))?;
    Ok(parsed.guild_ids)
}

/// Discord IDs that have opted OUT of this plugin in `guild_id` — via the
/// guild-wide master toggle or a per-plugin override. The bulk sync builds its
/// candidate set from the plugin's OWN data (form respondents) rather than the
/// gateway's OAuth member cache, so it subtracts opt-outs here to honor the
/// centralized opt-out system even for respondents the gateway has never seen
/// sign in.
///
/// Only pauses the member made themselves (`explicit_only=true`). The gateway
/// also pauses, by default, every server a member is first seen in or joins
/// later unless they turned that off — a default nobody chose, which kept 43
/// respondents from their role on 2026-11-12. Submitting the form is a choice;
/// the default is not. A pause the member made still removes the role.
///
/// Convention 40: errors bubble up so the sync job retries — a gateway blip
/// must NEVER be read as "nobody opted out" (which would re-grant the role to
/// someone who explicitly opted out on the next atomic PUT).
pub async fn fetch_guild_optout_ids(
    http: &reqwest::Client,
    base: &str,
    key: &str,
    guild_id: &str,
) -> Result<Vec<String>, AppError> {
    let url = format!("{base}/auth/internal/guild_optout_ids");
    let resp = http
        .get(&url)
        .header("X-Internal-Key", key)
        .query(&[
            ("guild_id", guild_id),
            ("plugin", PLUGIN_SLUG),
            ("explicit_only", "true"),
        ])
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway request failed: {e}")))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "auth_gateway guild_optout_ids returned {status}: {body}"
        )));
    }

    let parsed: GuildOptoutIdsResponse = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway response not JSON: {e}")))?;
    Ok(parsed.discord_ids)
}

/// Resolve the guild's display name. Hits `/auth/internal/guild_member_ids`
/// and reads only the `guild_name` field. Returns `None` if the gateway has
/// no record of the guild yet (fresh install, user_guilds not seeded).
///
/// Failures are non-fatal: callers fall back to showing the guild_id, so
/// network blips never block the page render.
pub async fn fetch_guild_name(
    http: &reqwest::Client,
    base: &str,
    key: &str,
    guild_id: &str,
) -> Result<Option<String>, AppError> {
    let url = format!("{base}/auth/internal/guild_member_ids");
    let resp = http
        .get(&url)
        .header("X-Internal-Key", key)
        .query(&[("guild_id", guild_id)])
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway request failed: {e}")))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "auth_gateway guild_member_ids returned {status}: {body}"
        )));
    }

    let parsed: GuildNameResponse = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway response not JSON: {e}")))?;
    Ok(parsed.guild_name.filter(|s| !s.is_empty()))
}
