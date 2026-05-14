//! Public respondent list page.
//!
//! Gated by `guild_settings.view_permission` ('members' = any guild member,
//! 'managers' = MANAGE_GUILD only). Defaults to 'managers' for privacy —
//! form responses can contain PII.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::services::{auth_gateway, session};
use crate::AppState;

const SESSION_COOKIE: &str = "rl_session";

pub fn render_respondents_page(base_url: &str) -> String {
    // Sign-in CTA points at /auth/login on the auth-gateway origin (cookie is
    // shared path=/, so navigating to it without the plugin prefix is correct).
    format!(
        r##"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Respondents</title>
    <link rel="icon" href="{base_url}/favicon.ico" type="image/x-icon">
    <meta name="theme-color" content="#7c3aed">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 920px; margin: 0 auto; padding: 32px 20px; background: #0e1525; color: #c8ccd4; min-height: 100vh; }}
        h1 {{ color: #a78bfa; font-size: 22px; }}
        .card {{ background: #161d2e; padding: 22px; border-radius: 10px; border: 1px solid #1e2a3d; margin: 14px 0; }}
        .msg {{ padding: 10px 14px; border-radius: 6px; margin: 12px 0; font-size: 13px; line-height: 1.5; }}
        .msg-error {{ background: #1c0a0a; color: #fca5a5; border: 1px solid #7f1d1d; }}
        .hidden {{ display: none !important; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th, td {{ padding: 8px 12px; text-align: left; }}
        th {{ color: #64748b; font-weight: 600; font-size: 11px; text-transform: uppercase; border-bottom: 2px solid #1e2a3d; }}
        td {{ border-bottom: 1px solid #111827; }}
        tr:hover td {{ background: #1a2236; }}
        .btn {{ padding: 6px 14px; border-radius: 6px; border: 1px solid #2a3548; background: #0e1525; color: #c8ccd4; cursor: pointer; font-family: inherit; font-size: 13px; text-decoration: none; display: inline-block; }}
        .btn:hover {{ background: #1e293b; }}
        .empty {{ text-align: center; padding: 32px; color: #64748b; }}
    </style>
</head>
<body>
    <h1 id="title">Respondents</h1>

    <div id="loading" class="card"><p style="color:#64748b;">Loading...</p></div>
    <div id="error" class="card hidden"></div>
    <div id="content" class="card hidden">
        <table>
            <thead><tr><th>Discord</th><th>Submitted</th><th>Last edited</th></tr></thead>
            <tbody id="rows"></tbody>
        </table>
    </div>

    <script>
    const API = '{base_url}';
    const ORIGIN = new URL(API).origin;
    const guild = location.pathname.split('/').pop();

    async function load() {{
        try {{
            const res = await fetch(API + '/respondents/' + guild + '/data', {{ credentials: 'include' }});
            const data = await res.json();
            if (!res.ok) {{
                showError(data.error || 'HTTP ' + res.status);
                return;
            }}
            document.getElementById('title').textContent = 'Respondents — ' + (data.guild_name || guild);
            const tbody = document.getElementById('rows');
            if (!data.respondents.length) {{
                document.getElementById('content').innerHTML = '<div class="empty">No respondents yet.</div>';
            }} else {{
                tbody.innerHTML = data.respondents.map(r =>
                    '<tr><td>' + escapeHtml(r.discord_id) + '</td><td>' + escapeHtml(r.submitted_at) + '</td><td>' + escapeHtml(r.last_edited_at) + '</td></tr>'
                ).join('');
            }}
            document.getElementById('loading').classList.add('hidden');
            document.getElementById('content').classList.remove('hidden');
        }} catch (e) {{
            showError(e.message);
        }}
    }}

    function showError(msg) {{
        const el = document.getElementById('error');
        const loginUrl = ORIGIN + '/auth/login?return_to=' + encodeURIComponent(location.pathname);
        el.innerHTML = '<div class="msg msg-error">' + escapeHtml(msg) + '</div><a class="btn" href="' + loginUrl + '">Sign in with Discord</a>';
        document.getElementById('loading').classList.add('hidden');
        el.classList.remove('hidden');
    }}

    function escapeHtml(s) {{
        return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({{
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        }})[c]);
    }}

    load();
    </script>
</body>
</html>"##
    )
}

pub async fn page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // The HTML shell is pre-rendered at startup (BASE_URL substituted once)
    // and is identical for every visitor. Dynamic data arrives via the
    // separate `/data` XHR, which is NOT cached. A 1-hour public cache on
    // the shell saves repeat fetches without leaking anything per-user.
    use axum::http::header;
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        state.respondents_html.clone(),
    )
}

#[derive(Deserialize)]
pub struct DataQuery {
    pub limit: Option<i64>,
}

/// `GET /respondents/:guild_id/data` — JSON for the page above.
pub async fn data(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(guild_id): Path<String>,
    Query(q): Query<DataQuery>,
) -> Result<Json<Value>, AppError> {
    let cookie = jar.get(SESSION_COOKIE).ok_or_else(|| {
        AppError::UnauthorizedWith("Sign in with Discord to view respondents.".into())
    })?;
    let (caller_id, _) = session::verify_session(cookie.value(), &state.config.session_secret)
        .ok_or_else(|| {
            AppError::UnauthorizedWith("Your session is invalid or expired. Sign in again.".into())
        })?;

    let view_permission: String =
        sqlx::query_scalar("SELECT view_permission FROM guild_settings WHERE guild_id = $1")
            .bind(&guild_id)
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or_else(|| "managers".to_string());

    // Forward to /auth/guild_permission with re-encoded cookie (Convention 31).
    let perm_url = format!(
        "{}/auth/guild_permission?guild_id={}",
        state.config.auth_gateway_url,
        urlencoding::encode(&guild_id),
    );
    let forwarded = Cookie::build(("rl_session", cookie.value()))
        .build()
        .encoded()
        .to_string();

    let perm_resp = state
        .http
        .get(&perm_url)
        .header("Cookie", forwarded)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway request failed: {e}")))?;

    if !perm_resp.status().is_success() {
        return Err(AppError::Forbidden(
            "Could not verify your permissions for this guild.".into(),
        ));
    }
    let perm: Value = perm_resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway response not JSON: {e}")))?;
    let is_member = perm
        .get("is_member")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_manager = perm
        .get("is_manager")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !is_member {
        return Err(AppError::Forbidden(
            "You're not a member of this server.".into(),
        ));
    }
    if view_permission == "managers" && !is_manager {
        return Err(AppError::Forbidden(
            "Only server managers can view the respondent list for this server.".into(),
        ));
    }

    let limit = q.limit.unwrap_or(500).min(2000);

    // Distinct respondents across every form bound to a role_link in this guild.
    let rows = sqlx::query_as::<
        _,
        (
            String,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        "SELECT DISTINCT ON (fr.discord_id) fr.discord_id, fr.submitted_at, fr.last_edited_at \
         FROM form_responses fr \
         JOIN role_links rl ON rl.form_id = fr.form_id \
         WHERE rl.guild_id = $1 AND fr.discord_id <> '' \
         ORDER BY fr.discord_id, fr.last_edited_at DESC \
         LIMIT $2",
    )
    .bind(&guild_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    let respondents: Vec<Value> = rows
        .into_iter()
        .map(|(discord_id, submitted_at, last_edited_at)| {
            json!({
                "discord_id": discord_id,
                "submitted_at": submitted_at.to_rfc3339(),
                "last_edited_at": last_edited_at.to_rfc3339(),
            })
        })
        .collect();

    // Resolve the guild's display name so the page title reads "Respondents —
    // <server name>" instead of leaking the raw snowflake. Best-effort: if the
    // gateway hiccups, fall back to the id on the front-end.
    let guild_name = auth_gateway::fetch_guild_name(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        &guild_id,
    )
    .await
    .unwrap_or(None);

    let _ = caller_id;
    Ok(Json(json!({
        "guild_id": guild_id,
        "guild_name": guild_name,
        "respondents": respondents,
    })))
}
