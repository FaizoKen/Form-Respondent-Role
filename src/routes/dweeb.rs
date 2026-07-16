//! DWEEB integration surface.
//!
//! DWEEB (the Discord Webhook Embed Builder, <https://dweeb.faizo.net>) lists
//! this plugin as a **link plugin**: a Link button whose URL points at our
//! member-facing form page (`/f/{slug}`). These routes deepen that integration
//! so the editor can do more than hold a URL template:
//!
//! - `GET /dweeb/status?guild=…` — public, CORS-open setup probe. DWEEB shows
//!   a "Ready / Needs setup" state on the attached-plugin chip instead of a
//!   permanent "set it up first" warning. Returns only whether the guild has
//!   any role link here — the same fact anyone could observe by probing the
//!   public verify/form pages — never config contents.
//! - `GET /dweeb/picker` — the config iframe DWEEB embeds so an admin picks
//!   one of their guild's forms instead of hand-pasting a `/f/{slug}` URL.
//! - `GET /dweeb/bridge?guild=…` — popup target that carries the first-party
//!   `rl_session` cookie context the sandboxed iframe can't have: it verifies
//!   the cookie, confirms guild-manager permission via the Auth Gateway, mints
//!   a short-lived [`dweeb_session`] token, and posts it to the opener.
//! - `GET /dweeb/forms?guild=…` — bearer-gated (that token), read-only list of
//!   the guild's forms for the picker.
//!
//! The picker/bridge/forms trio deliberately mirrors the RoleLogic-dashboard
//! iframe pattern (BLUEPRINT §1b): page-load auth is handed off out-of-band,
//! XHRs carry a purpose-bound bearer, and cookies are never relied on inside
//! the embedded frame.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::config::derive_origin;
use crate::error::AppError;
use crate::routes::admin::check_manager;
use crate::services::dweeb_session;
use crate::services::session;
use crate::AppState;

const SESSION_COOKIE: &str = "rl_session";
const PLUGIN_SLUG: &str = "form-respondent-role";
const PICKER_TEMPLATE: &str = include_str!("../../templates/dweeb_picker.html");

/// Shape check for a Discord snowflake id coming from an untrusted query.
fn is_snowflake(s: &str) -> bool {
    (15..=25).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

#[derive(Deserialize)]
pub struct GuildQuery {
    #[serde(default)]
    pub guild: Option<String>,
}

// ---------------------------------------------------------------------------
// GET /dweeb/status — public setup probe
// ---------------------------------------------------------------------------

/// JSON response with the CORS + cache headers the probe needs. The global
/// `CorsLayer` only mirrors the RoleLogic origins, so the wildcard is set
/// here: this endpoint is public, credential-less, and returns a boolean any
/// visitor could derive from the public pages anyway.
fn probe_json(status: StatusCode, cache_control: &'static str, body: Value) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (header::CACHE_CONTROL, cache_control),
        ],
        body.to_string(),
    )
        .into_response()
}

/// `GET /dweeb/status?guild=<id>` — is this guild set up on this plugin?
///
/// "Configured" means at least one role link exists (an admin created a role
/// link in the RoleLogic dashboard pointing here), i.e. the member-facing
/// URL a DWEEB Link button carries will actually do something.
pub async fn status(State(state): State<Arc<AppState>>, Query(q): Query<GuildQuery>) -> Response {
    let Some(guild) = q.guild.as_deref().filter(|g| is_snowflake(g)) else {
        return probe_json(
            StatusCode::BAD_REQUEST,
            "no-store",
            json!({ "error": "guild must be a Discord server id" }),
        );
    };

    let role_count: i64 =
        match sqlx::query_scalar("SELECT COUNT(*) FROM role_links WHERE guild_id = $1")
            .bind(guild)
            .fetch_one(&state.pool)
            .await
        {
            Ok(n) => n,
            Err(e) => {
                tracing::error!("dweeb status probe query failed: {e}");
                return probe_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "no-store",
                    json!({ "error": "temporarily unavailable" }),
                );
            }
        };

    probe_json(
        StatusCode::OK,
        // Short shared cache: the chip re-probes cheaply, and a just-finished
        // setup shows up within a minute.
        "public, max-age=60",
        json!({
            "schema_version": 1,
            "plugin": PLUGIN_SLUG,
            "guild_id": guild,
            "configured": role_count > 0,
            "role_count": role_count,
        }),
    )
}

// ---------------------------------------------------------------------------
// GET /dweeb/picker — the config iframe DWEEB embeds
// ---------------------------------------------------------------------------

pub async fn picker_page(State(state): State<Arc<AppState>>) -> Response {
    let body = PICKER_TEMPLATE.replace("__BASE_URL__", &state.config.base_url);
    // Only DWEEB may embed this page. The global security_headers baseline
    // would otherwise stamp `frame-ancestors 'none'` and block the iframe.
    let csp = format!(
        "frame-ancestors {}",
        state.config.dweeb_embed_origins.join(" ")
    );
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
            // No per-user content — the page bootstraps everything over
            // postMessage + bearer XHRs — so short-term caching is safe.
            (header::CACHE_CONTROL, "public, max-age=300".to_string()),
        ],
        body,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// GET /dweeb/bridge — first-party popup that mints the picker session
// ---------------------------------------------------------------------------

/// The plugin's path prefix (e.g. `/form-respondent-role`), derived from
/// `BASE_URL`. The Auth Gateway's `return_to` only accepts relative paths.
fn base_path(state: &AppState) -> String {
    let origin = derive_origin(&state.config.base_url);
    state
        .config
        .base_url
        .strip_prefix(&origin)
        .unwrap_or("")
        .to_string()
}

fn redirect_to_login(state: &AppState, guild: &str) -> Response {
    let origin = derive_origin(&state.config.base_url);
    let return_to = format!("{}/dweeb/bridge?guild={guild}", base_path(state));
    Redirect::temporary(&format!(
        "{origin}/auth/login?return_to={}",
        urlencoding::encode(&return_to)
    ))
    .into_response()
}

/// Small standalone HTML shell for the bridge popup (success and error
/// variants). Never embedded — the security-headers baseline stamps
/// `frame-ancestors 'none'` on it, which is exactly right for a popup.
fn bridge_html(status: StatusCode, title: &str, body_html: &str) -> Response {
    let body = format!(
        r##"<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: system-ui, sans-serif; max-width: 460px; margin: 0 auto; padding: 48px 20px; background: #0e1525; color: #d8dde6; }}
h1 {{ color: #a78bfa; font-size: 20px; margin-bottom: 12px; }}
p {{ color: #94a3b8; line-height: 1.55; margin: 10px 0; }}
.card {{ background: #161d2e; padding: 24px; border-radius: 12px; border: 1px solid #1e2a3d; margin: 16px 0; }}
.ok {{ color: #4ade80; }}
a {{ color: #a78bfa; }}
</style>
</head><body>
<h1>{title}</h1>
<div class="card">{body_html}</div>
</body></html>"##
    );
    (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "private, no-store"),
        ],
        body,
    )
        .into_response()
}

/// `GET /dweeb/bridge?guild=<id>` — popup flow:
/// no cookie → Auth Gateway login (which returns here) → manager check →
/// mint a guild-bound picker session → hand it to the opener via postMessage.
pub async fn bridge(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(q): Query<GuildQuery>,
) -> Response {
    let Some(guild) = q.guild.as_deref().filter(|g| is_snowflake(g)) else {
        return bridge_html(
            StatusCode::BAD_REQUEST,
            "Something's missing",
            "<p>This sign-in link is missing a server id. Close this window and reopen the picker from DWEEB.</p>",
        );
    };

    // First-party cookie context — the whole reason this popup exists.
    let session = jar
        .get(SESSION_COOKIE)
        .and_then(|c| session::verify_session(c.value(), &state.config.session_secret));
    let Some((discord_id, _display_name)) = session else {
        return redirect_to_login(&state, guild);
    };

    // Same manager gate as every admin surface: /auth/guild_permission with
    // the caller's own cookie forwarded.
    let cookie_value = jar
        .get(SESSION_COOKIE)
        .map(|c| c.value().to_string())
        .unwrap_or_default();
    if let Err(err) = check_manager(&state, &cookie_value, guild).await {
        let msg = match err {
            AppError::Forbidden(m) => m,
            _ => "Could not verify your permissions for this server. Try again.".to_string(),
        };
        let origin = derive_origin(&state.config.base_url);
        let return_to = format!("{}/dweeb/bridge?guild={guild}", base_path(&state));
        let switch = format!(
            "{origin}/auth/login?return_to={}",
            urlencoding::encode(&return_to)
        );
        let msg = msg
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        return bridge_html(
            StatusCode::FORBIDDEN,
            "Can't use this server",
            &format!(
                r##"<p>{msg}</p><p><a href="{switch}">Sign in with a different account</a></p>"##
            ),
        );
    }

    let token = dweeb_session::mint_dweeb_session(&discord_id, guild, &state.config.session_secret);
    tracing::info!(guild_id = guild, discord_id, "DWEEB picker session minted");

    // Token + guild are strictly [0-9a-z:] (validated snowflake, hex HMAC),
    // so embedding them in the script is safe for both HTML and JS contexts.
    let origin = derive_origin(&state.config.base_url);
    let body_html = format!(
        r##"<p id="auto" style="display:none" class="ok">Signed in. Returning you to DWEEB…</p>
<p id="manual" style="display:none">You're signed in. Close this window, then press <strong>I signed in — continue</strong> back in DWEEB.</p>
<script>
(function () {{
  var payload = {{ type: 'rl-dweeb:session', token: '{token}', guildId: '{guild}' }};
  var delivered = false;
  try {{
    if (window.opener && !window.opener.closed) {{
      window.opener.postMessage(payload, '{origin}');
      delivered = true;
    }}
  }} catch (e) {{}}
  document.getElementById(delivered ? 'auto' : 'manual').style.display = 'block';
  if (delivered) setTimeout(function () {{ window.close(); }}, 600);
}})();
</script>"##
    );
    bridge_html(StatusCode::OK, "Form picker", &body_html)
}

// ---------------------------------------------------------------------------
// GET /dweeb/forms — bearer-gated, read-only form list for the picker
// ---------------------------------------------------------------------------

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(|s| s.trim().to_string())
}

/// `GET /dweeb/forms?guild=<id>` with `Authorization: Bearer dws:…`.
///
/// Strictly read-only: the picker only needs names + slugs to build a
/// `/f/{slug}` URL. Mutations stay on the cookie-authenticated admin routes.
pub async fn forms(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<GuildQuery>,
) -> Result<Json<Value>, AppError> {
    let Some(guild) = q.guild.as_deref().filter(|g| is_snowflake(g)) else {
        return Err(AppError::BadRequest(
            "guild must be a Discord server id".into(),
        ));
    };

    let bearer = extract_bearer(&headers).ok_or_else(|| {
        AppError::UnauthorizedWith("Sign in with Discord to list this server's forms.".into())
    })?;
    let s = dweeb_session::verify_dweeb_session(&bearer, &state.config.session_secret).ok_or_else(
        || AppError::UnauthorizedWith("Your picker session expired. Sign in again.".into()),
    )?;
    if s.guild_id != guild {
        return Err(AppError::Forbidden(
            "This session doesn't grant access to that server.".into(),
        ));
    }
    tracing::debug!(
        guild_id = guild,
        discord_id = %s.discord_id,
        "DWEEB picker form list served"
    );

    let rows = sqlx::query_as::<_, (String, String, bool, chrono::DateTime<chrono::Utc>, Option<i64>)>(
        "SELECT f.slug, f.title, f.is_quiz, f.updated_at, \
                (SELECT COUNT(*) FROM form_responses fr WHERE fr.form_id = f.id::text) AS response_count \
         FROM forms f \
         WHERE f.guild_id = $1 AND f.archived = FALSE \
         ORDER BY f.updated_at DESC \
         LIMIT 200",
    )
    .bind(guild)
    .fetch_all(&state.pool)
    .await?;

    let items: Vec<Value> = rows
        .into_iter()
        .map(|(slug, title, is_quiz, updated_at, response_count)| {
            json!({
                "slug": slug,
                "title": title,
                "is_quiz": is_quiz,
                "updated_at": updated_at.to_rfc3339(),
                "response_count": response_count.unwrap_or(0),
            })
        })
        .collect();

    Ok(Json(json!({ "guild_id": guild, "forms": items })))
}
