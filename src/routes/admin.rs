//! Admin form-builder API.
//!
//! All routes are gated on (1) a valid `rl_session` cookie, (2) `is_manager`
//! returned by `/auth/guild_permission` for the path's `guild_id`. This is
//! the same gating pattern as routes/respondents.rs.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::cookie::{Cookie, CookieJar};
use rand::Rng;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::models::condition::{ConditionOperator, ConditionTarget};
use crate::models::form::FormSchema;
use crate::schema::{self, RoleConfigBody};
use crate::services::csrf;
use crate::services::form_validator;
use crate::services::jobs;
use crate::services::rl_token;
use crate::services::security_headers;
use crate::services::session;
use crate::services::webhook;
use crate::AppState;

const SESSION_COOKIE: &str = "rl_session";

const STARTER_BLANK: &str = include_str!("../../templates/starter_blank.json");
const STARTER_APPLICATION: &str = include_str!("../../templates/starter_application.json");
const STARTER_SERVER_QUIZ: &str = include_str!("../../templates/starter_server_quiz.json");

const BUILDER_TEMPLATE: &str = include_str!("../../templates/builder.html");
const ADMIN_LIST_TEMPLATE: &str = include_str!("../../templates/admin_list.html");
const RESPONSES_TEMPLATE: &str = include_str!("../../templates/responses.html");
const ROLE_CONFIG_TEMPLATE: &str = include_str!("../../templates/role_config.html");

/// Verify the request's cookie session AND that the user is a manager of the
/// target guild. Returns the calling discord_id on success.
///
/// JSON variant: on failure returns AppError, which renders as a JSON body.
/// Use for XHR endpoints called by page JS.
async fn require_manager(
    state: &AppState,
    jar: &CookieJar,
    guild_id: &str,
) -> Result<String, AppError> {
    let cookie = jar
        .get(SESSION_COOKIE)
        .ok_or_else(|| AppError::UnauthorizedWith("Sign in with Discord first.".into()))?;
    let (caller_id, _) = session::verify_session(cookie.value(), &state.config.session_secret)
        .ok_or_else(|| {
            AppError::UnauthorizedWith("Your session is invalid or expired. Sign in again.".into())
        })?;
    check_manager(state, cookie.value(), guild_id).await?;
    Ok(caller_id)
}

async fn check_manager(
    state: &AppState,
    cookie_value: &str,
    guild_id: &str,
) -> Result<(), AppError> {
    let perm_url = format!(
        "{}/auth/guild_permission?guild_id={}",
        state.config.auth_gateway_url,
        urlencoding::encode(guild_id),
    );
    let forwarded = Cookie::build(("rl_session", cookie_value))
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
    let is_manager = perm
        .get("is_manager")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !is_manager {
        return Err(AppError::Forbidden(
            "Only server managers can edit forms for this server.".into(),
        ));
    }
    Ok(())
}

/// HTML variant: on failure returns a rendered HTML page (sign-in CTA or
/// access-denied page). Use for routes the user navigates to directly.
async fn require_manager_html(
    state: &AppState,
    jar: &CookieJar,
    guild_id: &str,
) -> Result<String, Response> {
    let cookie = match jar.get(SESSION_COOKIE) {
        Some(c) => c,
        None => return Err(render_signin_page(state)),
    };
    let session = session::verify_session(cookie.value(), &state.config.session_secret);
    let Some((caller_id, _)) = session else {
        return Err(render_signin_page(state));
    };
    match check_manager(state, cookie.value(), guild_id).await {
        Ok(()) => Ok(caller_id),
        Err(AppError::Forbidden(msg)) => Err(render_access_denied(state, &msg)),
        Err(_) => Err(render_access_denied(
            state,
            "Could not verify your permissions for this guild. Try reloading.",
        )),
    }
}

fn render_signin_page(state: &AppState) -> Response {
    let base_url = &state.config.base_url;
    let body = format!(
        r##"<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in — Form Builder</title>
<link rel="icon" href="{base_url}/favicon.ico" type="image/x-icon">
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: system-ui, sans-serif; max-width: 560px; margin: 0 auto; padding: 64px 20px; background: #0e1525; color: #d8dde6; min-height: 100vh; }}
h1 {{ color: #a78bfa; font-size: 26px; margin-bottom: 12px; }}
p {{ color: #94a3b8; line-height: 1.55; margin: 12px 0; }}
.card {{ background: #161d2e; padding: 28px; border-radius: 12px; border: 1px solid #1e2a3d; margin: 24px 0; }}
.btn {{ display: inline-block; padding: 12px 24px; background: #5865f2; color: white; text-decoration: none; border-radius: 8px; font-weight: 600; }}
.btn:hover {{ background: #4752c4; }}
</style>
</head><body>
<h1>Form Builder</h1>
<div class="card">
<p>Sign in with Discord to manage forms for this server. You'll need <strong>Manage Server</strong> permission.</p>
<p style="margin-top: 16px;"><a class="btn" id="signin">Sign in with Discord</a></p>
</div>
<script>
const ORIGIN = new URL('{base_url}').origin;
document.getElementById('signin').href = ORIGIN + '/auth/login?return_to=' + encodeURIComponent(location.pathname);
</script>
</body></html>"##
    );
    admin_html_response(state, StatusCode::OK, body)
}

fn render_access_denied(state: &AppState, message: &str) -> Response {
    let base_url = &state.config.base_url;
    let msg = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let body = format!(
        r##"<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access denied — Form Builder</title>
<link rel="icon" href="{base_url}/favicon.ico" type="image/x-icon">
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: system-ui, sans-serif; max-width: 560px; margin: 0 auto; padding: 64px 20px; background: #0e1525; color: #d8dde6; min-height: 100vh; }}
h1 {{ color: #fca5a5; font-size: 24px; margin-bottom: 12px; }}
p {{ color: #94a3b8; line-height: 1.55; margin: 12px 0; }}
.card {{ background: #161d2e; padding: 28px; border-radius: 12px; border: 1px solid #1e2a3d; margin: 24px 0; }}
.btn {{ display: inline-block; padding: 8px 16px; background: transparent; color: #cbd5e1; border: 1px solid #2a3548; text-decoration: none; border-radius: 6px; font-size: 13px; margin-top: 12px; }}
.btn:hover {{ background: #1e293b; }}
</style>
</head><body>
<h1>Can't access this form-builder</h1>
<div class="card"><p>{msg}</p>
<p><a class="btn" id="switch">Sign in with a different account</a></p></div>
<script>
const ORIGIN = new URL('{base_url}').origin;
document.getElementById('switch').href = ORIGIN + '/auth/login?return_to=' + encodeURIComponent(location.pathname);
</script>
</body></html>"##
    );
    admin_html_response(state, StatusCode::FORBIDDEN, body)
}

fn html_response(state: &AppState, body: String) -> Response {
    admin_html_response(state, StatusCode::OK, body)
}

/// Shared response builder for every admin HTML page. Sets the iframe CSP
/// (`frame-ancestors {rl_dashboard_origin}`) so the page can be embedded by
/// the RoleLogic dashboard, while the global `security_headers::baseline`
/// middleware fills in `nosniff` / `Referrer-Policy` / `HSTS`.
///
/// Defaults to `Cache-Control: private, no-store` — these are
/// cookie-authenticated pages, often with user-specific content, so they
/// must not be cached by shared proxies. Routes that can tolerate
/// short-term per-browser caching (e.g. the iframe role-config page,
/// re-fetched on every dashboard nav) should use
/// `admin_html_response_cached` instead.
fn admin_html_response(state: &AppState, status: StatusCode, body: String) -> Response {
    admin_html_response_with_cache(state, status, body, "private, no-store")
}

/// Like `admin_html_response` but lets the caller specify a richer
/// `Cache-Control` directive — used by responses that get hit repeatedly
/// during a single admin session (e.g. iframe nav).
fn admin_html_response_cached(
    state: &AppState,
    status: StatusCode,
    body: String,
    cache_control: &'static str,
) -> Response {
    admin_html_response_with_cache(state, status, body, cache_control)
}

fn admin_html_response_with_cache(
    state: &AppState,
    status: StatusCode,
    body: String,
    cache_control: &str,
) -> Response {
    let csp = security_headers::admin_iframe_csp(state.config.rl_dashboard_origin.as_deref());
    (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
            (header::CACHE_CONTROL, cache_control.to_string()),
        ],
        body,
    )
        .into_response()
}

fn random_slug() -> String {
    const CHARS: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

fn random_preview_token() -> String {
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill(&mut bytes);
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn template_schema(name: &str) -> Result<Value, AppError> {
    let raw = match name {
        "application" => STARTER_APPLICATION,
        "server_quiz" => STARTER_SERVER_QUIZ,
        "blank" | "" => STARTER_BLANK,
        other => {
            return Err(AppError::BadRequest(format!(
                "Unknown template '{other}'. Use blank, application, or server_quiz."
            )))
        }
    };
    serde_json::from_str(raw)
        .map_err(|e| AppError::Internal(format!("starter template invalid: {e}")))
}

// ---------------------------------------------------------------------------
// GET /admin/{guild_id} — forms list page
// ---------------------------------------------------------------------------

pub async fn list_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(guild_id): Path<String>,
) -> Response {
    if let Err(resp) = require_manager_html(&state, &jar, &guild_id).await {
        return resp;
    }
    let body = ADMIN_LIST_TEMPLATE
        .replace("__BASE_URL__", &state.config.base_url)
        .replace("__GUILD_ID__", &guild_id);
    html_response(&state, body)
}

pub async fn list_data(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(guild_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    require_manager(&state, &jar, &guild_id).await?;

    let rows = sqlx::query_as::<_, (uuid::Uuid, String, String, bool, bool, chrono::DateTime<chrono::Utc>, Option<i64>, Option<i64>)>(
        "SELECT f.id, f.slug, f.title, f.is_quiz, f.archived, f.updated_at, \
                (SELECT COUNT(*) FROM form_responses fr WHERE fr.form_id = f.id::text) AS response_count, \
                (SELECT COUNT(*) FROM role_links rl WHERE rl.form_id = f.id::text) AS bound_role_links_count \
         FROM forms f WHERE f.guild_id = $1 ORDER BY f.updated_at DESC",
    )
    .bind(&guild_id)
    .fetch_all(&state.pool)
    .await?;

    let items: Vec<Value> = rows
        .into_iter()
        .map(
            |(id, slug, title, is_quiz, archived, updated_at, response_count, role_links_count)| {
                json!({
                    "id": id.to_string(),
                    "slug": slug,
                    "title": title,
                    "is_quiz": is_quiz,
                    "archived": archived,
                    "updated_at": updated_at.to_rfc3339(),
                    "response_count": response_count.unwrap_or(0),
                    "bound_role_links_count": role_links_count.unwrap_or(0),
                })
            },
        )
        .collect();

    // Server-wide setting — surfaced here so admins manage it once for the
    // whole guild instead of having it duplicated on every role-config page.
    let view_permission: String =
        sqlx::query_scalar("SELECT view_permission FROM guild_settings WHERE guild_id = $1")
            .bind(&guild_id)
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or_else(|| "managers".to_string());

    Ok(Json(json!({
        "forms": items,
        "view_permission": view_permission,
    })))
}

/// `POST /admin/{guild_id}/view-permission` — set who can view the
/// respondent list page. Server-wide; not per-role.
#[derive(Deserialize)]
pub struct ViewPermissionBody {
    pub view_permission: String,
}

pub async fn set_view_permission(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
    Json(body): Json<ViewPermissionBody>,
) -> Result<Json<Value>, AppError> {
    csrf::verify_origin(&headers, &state.allowed_origins)?;
    require_manager(&state, &jar, &guild_id).await?;

    let vp = match body.view_permission.as_str() {
        "members" | "managers" => body.view_permission.clone(),
        other => {
            return Err(AppError::BadRequest(format!(
                "Unknown view_permission '{other}'. Use 'members' or 'managers'."
            )))
        }
    };

    sqlx::query(
        "INSERT INTO guild_settings (guild_id, view_permission, updated_at) \
         VALUES ($1, $2, now()) \
         ON CONFLICT (guild_id) DO UPDATE SET \
            view_permission = EXCLUDED.view_permission, \
            updated_at = now()",
    )
    .bind(&guild_id)
    .bind(&vp)
    .execute(&state.pool)
    .await?;

    Ok(Json(json!({ "success": true, "view_permission": vp })))
}

// ---------------------------------------------------------------------------
// POST /admin/{guild_id}/forms — create form from template
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateBody {
    #[serde(default)]
    pub template: String,
    #[serde(default)]
    pub title: Option<String>,
}

pub async fn create_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
    Json(body): Json<CreateBody>,
) -> Result<Json<Value>, AppError> {
    csrf::verify_origin(&headers, &state.allowed_origins)?;
    require_manager(&state, &jar, &guild_id).await?;

    let mut schema_value = template_schema(&body.template)?;
    if let Some(title) = body.title.as_ref() {
        if let Some(obj) = schema_value.as_object_mut() {
            obj.insert("title".into(), Value::String(title.clone()));
        }
    }
    let parsed: FormSchema = serde_json::from_value(schema_value.clone())
        .map_err(|e| AppError::Internal(format!("starter template invalid: {e}")))?;

    let title = if parsed.title.trim().is_empty() {
        "Untitled form".to_string()
    } else {
        parsed.title.clone()
    };
    let description = parsed.description.clone();
    // Templates carrying `correct`/`points` answers are quizzes — the column
    // controls auto-grading and quiz-mode UI, so it must match the schema.
    let is_quiz = parsed
        .iter_questions()
        .any(|q| q.correct.is_some() || q.points.is_some());

    // Insert with collision retry on slug.
    let preview_token = random_preview_token();
    let mut attempts = 0;
    loop {
        attempts += 1;
        if attempts > 5 {
            return Err(AppError::Internal("slug collision after 5 attempts".into()));
        }
        let slug = random_slug();
        let res = sqlx::query_as::<_, (uuid::Uuid,)>(
            "INSERT INTO forms (guild_id, slug, title, description, schema, is_quiz, preview_token) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        )
        .bind(&guild_id)
        .bind(&slug)
        .bind(&title)
        .bind(&description)
        .bind(&schema_value)
        .bind(is_quiz)
        .bind(&preview_token)
        .fetch_one(&state.pool)
        .await;
        match res {
            Ok((id,)) => {
                tracing::info!(guild_id, form_id = %id, slug, "Form created");
                return Ok(Json(json!({
                    "id": id.to_string(),
                    "slug": slug,
                    "preview_token": preview_token,
                })));
            }
            Err(sqlx::Error::Database(e)) if e.constraint() == Some("forms_slug_key") => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// GET /admin/{guild_id}/forms/{form_id} — builder UI shell
// ---------------------------------------------------------------------------

pub async fn builder_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path((guild_id, form_id)): Path<(String, String)>,
) -> Response {
    if let Err(resp) = require_manager_html(&state, &jar, &guild_id).await {
        return resp;
    }
    let body = BUILDER_TEMPLATE
        .replace("__BASE_URL__", &state.config.base_url)
        .replace("__GUILD_ID__", &guild_id)
        .replace("__FORM_ID__", &form_id);
    html_response(&state, body)
}

pub async fn builder_data(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path((guild_id, form_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    require_manager(&state, &jar, &guild_id).await?;
    let uuid = uuid::Uuid::parse_str(&form_id)
        .map_err(|_| AppError::BadRequest("Invalid form id.".into()))?;

    #[derive(sqlx::FromRow)]
    struct BuilderRow {
        id: uuid::Uuid,
        slug: String,
        title: String,
        description: String,
        version: i32,
        schema: Value,
        is_quiz: bool,
        open_at: Option<chrono::DateTime<chrono::Utc>>,
        close_at: Option<chrono::DateTime<chrono::Utc>>,
        allow_edits: bool,
        single_submission: bool,
        require_verified: bool,
        min_account_age_days: i32,
        success_message: String,
        preview_token: String,
        webhook_url: Option<String>,
        archived: bool,
    }
    let row = sqlx::query_as::<_, BuilderRow>(
        "SELECT id, slug, title, description, version, schema, is_quiz, \
                open_at, close_at, allow_edits, single_submission, require_verified, \
                min_account_age_days, success_message, preview_token, webhook_url, archived \
         FROM forms WHERE id = $1 AND guild_id = $2",
    )
    .bind(uuid)
    .bind(&guild_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Form not found.".into()))?;

    // The form's guild_id was already verified at the SELECT above, but we
    // re-assert it here as defense-in-depth so a future refactor can't
    // accidentally turn this into a cross-guild count oracle.
    let response_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM form_responses fr \
         JOIN forms f ON f.id::text = fr.form_id \
         WHERE fr.form_id = $1 AND f.guild_id = $2",
    )
    .bind(form_id.clone())
    .bind(&guild_id)
    .fetch_one(&state.pool)
    .await?;
    let bound_role_links_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_links rl \
         JOIN forms f ON f.id::text = rl.form_id \
         WHERE rl.form_id = $1 AND f.guild_id = $2",
    )
    .bind(form_id)
    .bind(&guild_id)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(json!({
        "id": row.id.to_string(),
        "slug": row.slug,
        "title": row.title,
        "description": row.description,
        "version": row.version,
        "schema": row.schema,
        "is_quiz": row.is_quiz,
        "open_at": row.open_at.map(|t| t.to_rfc3339()),
        "close_at": row.close_at.map(|t| t.to_rfc3339()),
        "allow_edits": row.allow_edits,
        "single_submission": row.single_submission,
        "require_verified": row.require_verified,
        "min_account_age_days": row.min_account_age_days,
        "success_message": row.success_message,
        "preview_token": row.preview_token,
        "webhook_url": row.webhook_url,
        "archived": row.archived,
        "response_count": response_count,
        "bound_role_links_count": bound_role_links_count,
    })))
}

// ---------------------------------------------------------------------------
// PUT /admin/{guild_id}/forms/{form_id} — save form
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UpdateBody {
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub schema: Value,
    #[serde(default)]
    pub is_quiz: bool,
    #[serde(default)]
    pub open_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub close_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub allow_edits: bool,
    #[serde(default = "default_true")]
    pub single_submission: bool,
    #[serde(default)]
    pub require_verified: bool,
    #[serde(default)]
    pub min_account_age_days: i32,
    #[serde(default = "default_success_message")]
    pub success_message: String,
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub archived: bool,
    pub version: i32,
}
fn default_true() -> bool {
    true
}
fn default_success_message() -> String {
    "Thanks for your response!".into()
}

pub async fn update_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, form_id)): Path<(String, String)>,
    Json(body): Json<UpdateBody>,
) -> Result<Json<Value>, AppError> {
    csrf::verify_origin(&headers, &state.allowed_origins)?;
    require_manager(&state, &jar, &guild_id).await?;
    let uuid = uuid::Uuid::parse_str(&form_id)
        .map_err(|_| AppError::BadRequest("Invalid form id.".into()))?;

    // Parse + sanity-check the schema.
    let mut schema_value = body.schema.clone();
    if let Some(obj) = schema_value.as_object_mut() {
        obj.insert("title".into(), Value::String(body.title.clone()));
        obj.insert(
            "description".into(),
            Value::String(body.description.clone()),
        );
    }
    let parsed: FormSchema = serde_json::from_value(schema_value.clone())
        .map_err(|e| AppError::BadRequest(format!("Schema is not a valid form definition: {e}")))?;
    form_validator::sanity_check(&parsed).map_err(|errs| AppError::BadRequest(errs.join(" ")))?;

    if body.min_account_age_days < 0 || body.min_account_age_days > 3650 {
        return Err(AppError::BadRequest(
            "min_account_age_days must be between 0 and 3650.".into(),
        ));
    }
    if let Some(url) = body.webhook_url.as_deref() {
        if !url.is_empty() && !webhook::is_safe_url(url) {
            return Err(AppError::BadRequest(
                "webhook_url must be an https:// URL on a public host.".into(),
            ));
        }
    }

    let result = sqlx::query(
        "UPDATE forms SET \
            title = $1, description = $2, schema = $3, is_quiz = $4, \
            open_at = $5, close_at = $6, allow_edits = $7, single_submission = $8, \
            require_verified = $9, min_account_age_days = $10, success_message = $11, \
            webhook_url = $12, archived = $13, version = version + 1, updated_at = now() \
         WHERE id = $14 AND guild_id = $15 AND version = $16",
    )
    .bind(&body.title)
    .bind(&body.description)
    .bind(&schema_value)
    .bind(body.is_quiz)
    .bind(body.open_at)
    .bind(body.close_at)
    .bind(body.allow_edits)
    .bind(body.single_submission)
    .bind(body.require_verified)
    .bind(body.min_account_age_days)
    .bind(&body.success_message)
    .bind(body.webhook_url.as_deref().filter(|s| !s.is_empty()))
    .bind(body.archived)
    .bind(uuid)
    .bind(&guild_id)
    .bind(body.version)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        // Either form doesn't exist or version drifted.
        let exists: Option<i32> =
            sqlx::query_scalar("SELECT version FROM forms WHERE id = $1 AND guild_id = $2")
                .bind(uuid)
                .bind(&guild_id)
                .fetch_optional(&state.pool)
                .await?;
        return match exists {
            Some(_) => Err(AppError::StaleVersion),
            None => Err(AppError::NotFound("Form not found.".into())),
        };
    }

    // Sync any role_links bound to this form (schema may have changed).
    let bound_role_links = sqlx::query_as::<_, (String, String)>(
        "SELECT guild_id, role_id FROM role_links WHERE form_id = $1",
    )
    .bind(form_id.clone())
    .fetch_all(&state.pool)
    .await?;
    let mut warnings: Vec<String> = Vec::new();
    let qids: std::collections::HashSet<&str> =
        parsed.iter_questions().map(|q| q.id.as_str()).collect();
    for (gid, rid) in &bound_role_links {
        let conditions: Value = sqlx::query_scalar(
            "SELECT conditions FROM role_links WHERE guild_id = $1 AND role_id = $2",
        )
        .bind(gid)
        .bind(rid)
        .fetch_one(&state.pool)
        .await?;
        for c in conditions.as_array().unwrap_or(&vec![]) {
            if let Some(target) = c.get("target") {
                if target.get("kind").and_then(|v| v.as_str()) == Some("question") {
                    if let Some(qid) = target.get("question_id").and_then(|v| v.as_str()) {
                        if !qids.contains(qid) {
                            warnings.push(format!(
                                "Role <{rid}> references question \"{qid}\" which no longer exists."
                            ));
                        }
                    }
                }
            }
        }
        if let Err(e) = jobs::enqueue_config_sync(&state.pool, gid, rid).await {
            tracing::warn!(guild_id = %gid, role_id = %rid, "enqueue config_sync after update failed: {e}");
        }
    }

    let new_version: i32 =
        sqlx::query_scalar("SELECT version FROM forms WHERE id = $1 AND guild_id = $2")
            .bind(uuid)
            .bind(&guild_id)
            .fetch_one(&state.pool)
            .await?;

    tracing::info!(
        guild_id,
        form_id,
        new_version,
        bound_role_links = bound_role_links.len(),
        "Form updated"
    );

    Ok(Json(json!({
        "version": new_version,
        "warnings": warnings,
    })))
}

// ---------------------------------------------------------------------------
// DELETE /admin/{guild_id}/forms/{form_id}
// ---------------------------------------------------------------------------

pub async fn delete_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, form_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    csrf::verify_origin(&headers, &state.allowed_origins)?;
    require_manager(&state, &jar, &guild_id).await?;
    let uuid = uuid::Uuid::parse_str(&form_id)
        .map_err(|_| AppError::BadRequest("Invalid form id.".into()))?;

    // Verify the form belongs to this guild BEFORE we read anything about it
    // or touch related rows. Without this, the bound SELECT below would leak
    // (guild_id, role_id) pairs for another tenant's form, and the cascading
    // UPDATE/DELETE would run against rows we'd rely on the final ownership
    // check (and tx rollback) to undo. Doing the check first removes the
    // window entirely.
    // `SELECT 1` returns INT4 in Postgres (not INT8), so decode as i32 — a
    // mismatched i64 here surfaces as "mismatched types; Rust type `i64` …
    // is not compatible with SQL type `INT4`" at runtime. We only care that
    // a row exists; the value is discarded.
    let owns: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM forms WHERE id = $1 AND guild_id = $2")
            .bind(uuid)
            .bind(&guild_id)
            .fetch_optional(&state.pool)
            .await?;
    if owns.is_none() {
        return Err(AppError::NotFound("Form not found.".into()));
    }

    // Find affected role_links BEFORE the cascade, so we can re-sync them.
    let bound = sqlx::query_as::<_, (String, String)>(
        "SELECT guild_id, role_id FROM role_links WHERE form_id = $1",
    )
    .bind(&form_id)
    .fetch_all(&state.pool)
    .await?;

    let mut tx = state.pool.begin().await?;
    sqlx::query("UPDATE role_links SET form_id = NULL, updated_at = now() WHERE form_id = $1")
        .bind(&form_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM form_responses WHERE form_id = $1")
        .bind(&form_id)
        .execute(&mut *tx)
        .await?;
    let res = sqlx::query("DELETE FROM forms WHERE id = $1 AND guild_id = $2")
        .bind(uuid)
        .bind(&guild_id)
        .execute(&mut *tx)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("Form not found.".into()));
    }
    tx.commit().await?;

    for (gid, rid) in &bound {
        if let Err(e) = jobs::enqueue_config_sync(&state.pool, gid, rid).await {
            tracing::warn!(guild_id = %gid, role_id = %rid, "enqueue config_sync after delete failed: {e}");
        }
    }

    tracing::info!(
        guild_id,
        form_id,
        unbound_role_links = bound.len(),
        "Form deleted"
    );

    Ok(Json(json!({"success": true})))
}

// ---------------------------------------------------------------------------
// POST /admin/{guild_id}/forms/{form_id}/duplicate
// ---------------------------------------------------------------------------

pub async fn duplicate_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, form_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    csrf::verify_origin(&headers, &state.allowed_origins)?;
    require_manager(&state, &jar, &guild_id).await?;
    let uuid = uuid::Uuid::parse_str(&form_id)
        .map_err(|_| AppError::BadRequest("Invalid form id.".into()))?;

    let src = sqlx::query_as::<
        _,
        (
            String,
            String,
            Value,
            bool,
            bool,
            bool,
            bool,
            i32,
            String,
            Option<String>,
        ),
    >(
        "SELECT title, description, schema, is_quiz, allow_edits, single_submission, \
                require_verified, min_account_age_days, success_message, webhook_url \
         FROM forms WHERE id = $1 AND guild_id = $2",
    )
    .bind(uuid)
    .bind(&guild_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Form not found.".into()))?;

    let new_title = format!("{} (copy)", src.0);
    let preview_token = random_preview_token();

    let mut attempts = 0;
    loop {
        attempts += 1;
        if attempts > 5 {
            return Err(AppError::Internal("slug collision after 5 attempts".into()));
        }
        let slug = random_slug();
        let res = sqlx::query_as::<_, (uuid::Uuid,)>(
            "INSERT INTO forms (guild_id, slug, title, description, schema, is_quiz, \
                                 allow_edits, single_submission, require_verified, \
                                 min_account_age_days, success_message, webhook_url, preview_token) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id",
        )
        .bind(&guild_id)
        .bind(&slug)
        .bind(&new_title)
        .bind(&src.1)
        .bind(&src.2)
        .bind(src.3)
        .bind(src.4)
        .bind(src.5)
        .bind(src.6)
        .bind(src.7)
        .bind(&src.8)
        .bind(&src.9)
        .bind(&preview_token)
        .fetch_one(&state.pool)
        .await;
        match res {
            Ok((id,)) => {
                return Ok(Json(json!({
                    "id": id.to_string(),
                    "slug": slug,
                    "preview_token": preview_token,
                })));
            }
            Err(sqlx::Error::Database(e)) if e.constraint() == Some("forms_slug_key") => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// GET /admin/{guild_id}/forms/{form_id}/responses — dashboard page
// ---------------------------------------------------------------------------

pub async fn responses_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path((guild_id, form_id)): Path<(String, String)>,
) -> Response {
    if let Err(resp) = require_manager_html(&state, &jar, &guild_id).await {
        return resp;
    }
    let body = RESPONSES_TEMPLATE
        .replace("__BASE_URL__", &state.config.base_url)
        .replace("__GUILD_ID__", &guild_id)
        .replace("__FORM_ID__", &form_id);
    html_response(&state, body)
}

pub async fn responses_data(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path((guild_id, form_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    require_manager(&state, &jar, &guild_id).await?;
    let uuid = uuid::Uuid::parse_str(&form_id)
        .map_err(|_| AppError::BadRequest("Invalid form id.".into()))?;

    let form_row = sqlx::query_as::<_, (String, Value, bool, String, String)>(
        "SELECT title, schema, is_quiz, slug, preview_token \
         FROM forms WHERE id = $1 AND guild_id = $2",
    )
    .bind(uuid)
    .bind(&guild_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Form not found.".into()))?;

    let rows = sqlx::query_as::<
        _,
        (
            uuid::Uuid,
            String,
            Value,
            Option<i32>,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        "SELECT id, discord_id, answers, total_score, submitted_at, last_edited_at \
         FROM form_responses WHERE form_id = $1 ORDER BY last_edited_at DESC LIMIT 1000",
    )
    .bind(&form_id)
    .fetch_all(&state.pool)
    .await?;

    let responses: Vec<Value> = rows
        .into_iter()
        .map(|(id, did, answers, score, submitted, edited)| {
            json!({
                "id": id.to_string(),
                "discord_id": did,
                "answers": answers,
                "total_score": score,
                "submitted_at": submitted.to_rfc3339(),
                "last_edited_at": edited.to_rfc3339(),
            })
        })
        .collect();

    Ok(Json(json!({
        "title": form_row.0,
        "schema": form_row.1,
        "is_quiz": form_row.2,
        "slug": form_row.3,
        "preview_token": form_row.4,
        "responses": responses,
    })))
}

// ---------------------------------------------------------------------------
// GET /admin/{guild_id}/forms/{form_id}/responses.csv — CSV export
// ---------------------------------------------------------------------------

pub async fn responses_csv(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path((guild_id, form_id)): Path<(String, String)>,
) -> Result<Response, AppError> {
    require_manager(&state, &jar, &guild_id).await?;
    let uuid = uuid::Uuid::parse_str(&form_id)
        .map_err(|_| AppError::BadRequest("Invalid form id.".into()))?;

    let form_row = sqlx::query_as::<_, (Value, bool, String)>(
        "SELECT schema, is_quiz, slug FROM forms WHERE id = $1 AND guild_id = $2",
    )
    .bind(uuid)
    .bind(&guild_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Form not found.".into()))?;

    let schema: FormSchema = serde_json::from_value(form_row.0)
        .map_err(|e| AppError::Internal(format!("schema invalid: {e}")))?;
    let is_quiz = form_row.1;
    let slug = form_row.2;

    let rows = sqlx::query_as::<
        _,
        (
            String,
            Value,
            Option<i32>,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        "SELECT discord_id, answers, total_score, submitted_at, last_edited_at \
         FROM form_responses WHERE form_id = $1 ORDER BY submitted_at",
    )
    .bind(&form_id)
    .fetch_all(&state.pool)
    .await?;

    let mut out = String::new();
    let answerable: Vec<_> = schema.iter_questions().collect();
    let mut header = vec![
        "discord_id".to_string(),
        "submitted_at".to_string(),
        "last_edited_at".to_string(),
    ];
    if is_quiz {
        header.push("total_score".to_string());
    }
    for q in &answerable {
        header.push(q.title.clone());
    }
    out.push_str(&csv_row(&header));

    for (did, answers, score, submitted, edited) in rows {
        let mut row = vec![did, submitted.to_rfc3339(), edited.to_rfc3339()];
        if is_quiz {
            row.push(score.map(|s| s.to_string()).unwrap_or_default());
        }
        for q in &answerable {
            let v = answers.get(&q.id);
            row.push(answer_to_csv(v));
        }
        out.push_str(&csv_row(&row));
    }

    let filename = format!("form-{slug}-responses.csv");
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        out,
    )
        .into_response())
}

fn csv_row(cells: &[String]) -> String {
    let mut s = String::new();
    for (i, c) in cells.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&csv_escape(c));
    }
    s.push('\n');
    s
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// GET /admin/{guild_id}/role/{role_id} — role-config page (rule builder)
// ---------------------------------------------------------------------------
//
// Entry point lives in two worlds:
//   1. Embedded in the RoleLogic dashboard iframe — request carries
//      `?rl_token=<jwt>` signed by RoleLogic with the role link's API token.
//      We verify it, mint a 1h iframe-session token bound to this
//      (guild_id, role_id, discord_id), and embed it in the page so XHRs
//      can authenticate without relying on third-party cookies.
//   2. Direct browser nav (e.g. an admin clicked a saved bookmark) — falls
//      back to the existing OAuth cookie + manager-permission check.

#[derive(Deserialize)]
pub struct RoleConfigPageQuery {
    #[serde(default)]
    rl_token: Option<String>,
}

pub async fn role_config_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path((guild_id, role_id)): Path<(String, String)>,
    Query(query): Query<RoleConfigPageQuery>,
) -> Response {
    // Path 1: iframe entry. If the rl_token verifies, we render with an
    // iframe-session token regardless of whether a cookie session exists.
    let iframe_session = match query.rl_token.as_deref() {
        Some(token) if !token.is_empty() => {
            match verify_iframe_entry(&state, &guild_id, &role_id, token).await {
                Ok(t) => Some(t),
                Err(resp) => return resp,
            }
        }
        _ => None,
    };

    // Path 2: direct nav — cookie + manager check.
    if iframe_session.is_none() {
        if let Err(resp) = require_manager_html(&state, &jar, &guild_id).await {
            return resp;
        }
    }

    let body = ROLE_CONFIG_TEMPLATE
        .replace("__BASE_URL__", &state.config.base_url)
        .replace("__GUILD_ID__", &guild_id)
        .replace("__ROLE_ID__", &role_id)
        .replace("__IFRAME_TOKEN__", iframe_session.as_deref().unwrap_or(""));

    // The RoleLogic dashboard re-iframes this page on every navigation to a
    // role tab — a 5-min private cache eliminates the repeat 44 KB download
    // without risking shared-cache staleness (the body contains a
    // freshly-minted iframe-session token; `private` keeps it browser-local
    // and `must-revalidate` ensures the cache obeys the max-age strictly).
    admin_html_response_cached(
        &state,
        StatusCode::OK,
        body,
        "private, max-age=300, must-revalidate",
    )
}

/// Verify `?rl_token=…` and return a freshly minted iframe-session token.
/// On failure, returns a rendered error page (so the iframe shows something
/// useful instead of an empty body).
async fn verify_iframe_entry(
    state: &AppState,
    guild_id: &str,
    role_id: &str,
    rl_token: &str,
) -> Result<String, Response> {
    let api_token: Option<String> =
        sqlx::query_scalar("SELECT api_token FROM role_links WHERE guild_id = $1 AND role_id = $2")
            .bind(guild_id)
            .bind(role_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| render_iframe_error(state, &format!("Database error: {e}")))?;

    let Some(api_token) = api_token else {
        return Err(render_iframe_error(
            state,
            "This role link isn't registered with this plugin yet.",
        ));
    };

    let verified = rl_token::verify(rl_token, &api_token, &state.config.base_url).map_err(|e| {
        let msg = match e {
            rl_token::RlTokenError::Expired => {
                "Your session expired. Reopen the plugin in the RoleLogic dashboard."
            }
            rl_token::RlTokenError::BadSignature | rl_token::RlTokenError::Malformed => {
                "Invalid auth token."
            }
            rl_token::RlTokenError::WrongAudience => "Token is for a different plugin.",
            rl_token::RlTokenError::WrongIssuer => "Token was not issued by RoleLogic.",
        };
        render_iframe_error(state, msg)
    })?;

    // Cross-check: the claims must match the path. RoleLogic signs each
    // token for a specific (guild_id, role_id), so a token signed for one
    // role link cannot be reused on a different page.
    if verified.guild_id != guild_id || verified.role_id != role_id {
        return Err(render_iframe_error(
            state,
            "Token does not match this role link.",
        ));
    }

    Ok(rl_token::mint_iframe_session(
        &verified.discord_id,
        guild_id,
        role_id,
        &state.config.session_secret,
    ))
}

fn render_iframe_error(state: &AppState, message: &str) -> Response {
    let base_url = &state.config.base_url;
    let msg = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let body = format!(
        r##"<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cannot load configuration</title>
<link rel="icon" href="{base_url}/favicon.ico" type="image/x-icon">
<style>
body {{ font-family: system-ui, sans-serif; background: #0e1525; color: #d8dde6; padding: 32px 24px; line-height: 1.5; }}
h1 {{ color: #fca5a5; font-size: 18px; margin-bottom: 10px; }}
p {{ color: #94a3b8; }}
</style>
</head><body>
<h1>Cannot load configuration</h1>
<p>{msg}</p>
</body></html>"##
    );
    admin_html_response(state, StatusCode::FORBIDDEN, body)
}

/// Allow either:
///   - Cookie session + manager check (direct nav), or
///   - `Authorization: Bearer ifs:…` iframe-session bound to this guild/role.
async fn require_role_config_access(
    state: &AppState,
    jar: &CookieJar,
    headers: &HeaderMap,
    guild_id: &str,
    role_id: &str,
) -> Result<String, AppError> {
    if let Some(bearer) = extract_bearer(headers) {
        let Some(s) = rl_token::verify_iframe_session(&bearer, &state.config.session_secret) else {
            return Err(AppError::UnauthorizedWith(
                "Your session expired. Reopen the plugin in the RoleLogic dashboard.".into(),
            ));
        };
        if s.guild_id != guild_id || s.role_id != role_id {
            return Err(AppError::Forbidden(
                "Token does not grant access to this role link.".into(),
            ));
        }
        return Ok(s.discord_id);
    }
    require_manager(state, jar, guild_id).await
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    v.strip_prefix("Bearer ").map(str::to_string)
}

pub async fn role_config_data(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;

    let link = sqlx::query_as::<_, (Option<String>, bool, Value)>(
        "SELECT form_id, grant_on_any_submission, conditions \
         FROM role_links WHERE guild_id = $1 AND role_id = $2",
    )
    .bind(&guild_id)
    .bind(&role_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| {
        AppError::NotFound("This role link doesn't exist. Has it been added in RoleLogic?".into())
    })?;
    let (form_id, grant_on_any_submission, conditions) = link;

    // All forms for this guild, with schema inline so the rule builder can
    // populate question / option pickers without an extra fetch when the
    // admin changes the form binding.
    let form_rows = sqlx::query_as::<_, (uuid::Uuid, String, bool, bool, Value)>(
        "SELECT id, title, is_quiz, archived, schema FROM forms WHERE guild_id = $1 \
         ORDER BY archived ASC, updated_at DESC",
    )
    .bind(&guild_id)
    .fetch_all(&state.pool)
    .await?;

    let forms: Vec<Value> = form_rows
        .into_iter()
        .map(|(id, title, is_quiz, archived, schema_json)| {
            let parsed: Option<FormSchema> = serde_json::from_value(schema_json).ok();
            let questions: Vec<Value> = parsed
                .as_ref()
                .map(|s| {
                    s.iter_questions()
                        .filter(|q| q.kind.is_conditionable())
                        .map(|q| {
                            let options: Vec<Value> = q
                                .options
                                .as_ref()
                                .map(|opts| {
                                    opts.iter()
                                        .map(|o| json!({ "id": o.id, "label": o.label }))
                                        .collect()
                                })
                                .unwrap_or_default();
                            json!({
                                "id": q.id,
                                "title": q.title,
                                "kind": q.kind.as_str(),
                                "is_array_valued": q.kind.is_array_valued(),
                                "options": options,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            json!({
                "id": id.to_string(),
                "title": title,
                "is_quiz": is_quiz,
                "archived": archived,
                "questions": questions,
            })
        })
        .collect();

    // Treat a brand-new role-link (grant_on_any_submission=false AND no
    // conditions yet — the conservative "grant nobody" default from
    // 001_initial_schema.sql) as "any_submission" in the UI. The radio still
    // commits to FALSE in the DB until the admin saves, so the "grant nobody"
    // safety property is preserved server-side; we just pre-select the more
    // common choice instead of dropping the admin into the empty-conditions
    // editor.
    let conditions_array = conditions.as_array().cloned().unwrap_or_default();
    let mode = if grant_on_any_submission || conditions_array.is_empty() {
        "any_submission"
    } else {
        "conditions"
    };

    // Flatten conditions for the front-end (target as a plain string).
    let conditions_out: Vec<Value> = conditions_array
        .into_iter()
        .map(|c| {
            let target = match c
                .get("target")
                .and_then(|t| t.get("kind"))
                .and_then(Value::as_str)
            {
                Some("quiz_total_score") => "__quiz_total_score__".to_string(),
                _ => c
                    .get("target")
                    .and_then(|t| t.get("question_id"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            };
            json!({
                "target": target,
                "operator": c.get("operator").cloned().unwrap_or(Value::Null),
                "value": c.get("value").cloned().unwrap_or(Value::Null),
                "value_end": c.get("value_end").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();

    Ok(Json(json!({
        "guild_id": guild_id,
        "role_id": role_id,
        "config": {
            "form_id": form_id.unwrap_or_default(),
            "mode": mode,
            "conditions": conditions_out,
        },
        "forms": forms,
        "operators": operator_catalog(),
        "max_conditions": schema::MAX_CONDITIONS,
    })))
}

pub async fn role_config_save(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
    Json(body): Json<RoleConfigBody>,
) -> Result<Json<Value>, AppError> {
    // Bearer-authenticated callers (iframe-session) are CSRF-safe by token
    // binding; only the cookie path needs an Origin allowlist check.
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;

    let link_exists: Option<i64> =
        sqlx::query_scalar("SELECT id FROM role_links WHERE guild_id = $1 AND role_id = $2")
            .bind(&guild_id)
            .bind(&role_id)
            .fetch_optional(&state.pool)
            .await?;
    if link_exists.is_none() {
        return Err(AppError::NotFound(
            "This role link doesn't exist. Has it been added in RoleLogic?".into(),
        ));
    }

    // Resolve the chosen form's schema so condition validation can match
    // operators against question kinds.
    let mut bound_form_schema: Option<FormSchema> = None;
    let mut bound_form_is_quiz = false;
    if let Some(fid) = body.form_id.as_deref() {
        let fid = fid.trim();
        if !fid.is_empty() {
            let uuid = uuid::Uuid::parse_str(fid).map_err(|_| {
                AppError::BadRequest("form_id must be a valid form UUID from the dropdown.".into())
            })?;
            let row = sqlx::query_as::<_, (Value, bool)>(
                "SELECT schema, is_quiz FROM forms WHERE id = $1 AND guild_id = $2",
            )
            .bind(uuid)
            .bind(&guild_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| {
                AppError::BadRequest("Selected form does not exist for this guild.".into())
            })?;
            bound_form_is_quiz = row.1;
            bound_form_schema = serde_json::from_value(row.0).ok();
        }
    }

    let parsed = schema::parse_role_config(body, bound_form_schema.as_ref(), bound_form_is_quiz)?;

    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "UPDATE role_links SET form_id = $1, grant_on_any_submission = $2, conditions = $3, \
                updated_at = now() \
         WHERE guild_id = $4 AND role_id = $5",
    )
    .bind(&parsed.form_id)
    .bind(parsed.grant_on_any_submission)
    .bind(serde_json::json!(&parsed.conditions))
    .bind(&guild_id)
    .bind(&role_id)
    .execute(&mut *tx)
    .await?;

    // view_permission is owned by the admin-list page now; only write through
    // if the (legacy) caller explicitly included it in the payload.
    if let Some(vp) = parsed.view_permission.as_deref() {
        sqlx::query(
            "INSERT INTO guild_settings (guild_id, view_permission, updated_at) \
             VALUES ($1, $2, now()) \
             ON CONFLICT (guild_id) DO UPDATE SET \
                view_permission = EXCLUDED.view_permission, \
                updated_at = now()",
        )
        .bind(&guild_id)
        .bind(vp)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    tracing::info!(
        guild_id,
        role_id,
        form_id = ?parsed.form_id,
        condition_count = parsed.conditions.len(),
        grant_on_any_submission = parsed.grant_on_any_submission,
        "Role config updated (plugin web)"
    );

    if let Err(e) = jobs::enqueue_config_sync(&state.pool, &guild_id, &role_id).await {
        tracing::warn!(
            guild_id,
            role_id,
            "enqueue config_sync after role-config save failed: {e}"
        );
    }

    Ok(Json(json!({"success": true})))
}

/// Operator metadata for the rule builder. One entry per operator with the
/// list of question kinds it's valid against. The front-end picks the value
/// widget from the operator key + the question's kind.
fn operator_catalog() -> Vec<Value> {
    use ConditionOperator::*;
    fn entry(op: ConditionOperator, label: &str, kinds: &[&str]) -> Value {
        json!({ "key": op.as_str(), "label": label, "kinds": kinds })
    }
    let text_kinds: &[&str] = &[
        "short_text",
        "long_text",
        "email",
        "single_choice",
        "dropdown",
        "agreement",
    ];
    let array_kinds: &[&str] = &["multi_choice"];
    let numeric_kinds: &[&str] = &["number", "scale", "__quiz_total_score__"];
    let date_kinds: &[&str] = &["date"];
    let free_text_kinds: &[&str] = &["short_text", "long_text", "email"];
    let eq_kinds: &[&str] = &[
        "short_text",
        "long_text",
        "email",
        "single_choice",
        "dropdown",
        "agreement",
        "multi_choice",
    ];

    vec![
        entry(Eq, "= equals", eq_kinds),
        entry(Neq, "≠ does not equal", text_kinds),
        entry(Contains, "contains (substring)", free_text_kinds),
        entry(Regex, "matches regex", free_text_kinds),
        entry(In, "is one of", text_kinds),
        entry(ContainsAll, "contains all of", array_kinds),
        entry(ContainsAny, "contains any of", array_kinds),
        entry(NotContains, "contains none of", array_kinds),
        entry(Gt, "> greater than", numeric_kinds),
        entry(Gte, "≥ at least", numeric_kinds),
        entry(Lt, "< less than", numeric_kinds),
        entry(Lte, "≤ at most", numeric_kinds),
        entry(Between, "between (inclusive)", numeric_kinds),
        entry(Before, "before (date)", date_kinds),
        entry(After, "after (date)", date_kinds),
    ]
}

// Silence unused-import warning for ConditionTarget — we only reference it
// indirectly through schema::parse_role_config but the import keeps it close
// to where the kinds-mapping logic lives.
#[allow(dead_code)]
fn _refer_to_condition_target(_t: ConditionTarget) {}

fn answer_to_csv(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect::<Vec<_>>()
            .join("; "),
        Some(other) => other.to_string(),
    }
}
