//! Member-facing form-fill flow.
//!
//! GET /f/{slug}        — render form (or sign-in CTA if no session)
//! POST /f/{slug}/submit — accept answers, write form_response, enqueue player_sync job
//! GET /f/{slug}/done   — confirmation page
//! GET /f/{slug}/preview?token=... — admin preview without login

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::models::form::FormSchema;
use crate::services::form_validator;
use crate::services::session;
use crate::services::webhook;
use crate::AppState;

const SESSION_COOKIE: &str = "rl_session";

#[derive(Debug, sqlx::FromRow)]
struct FormRow {
    #[allow(dead_code)]
    id: uuid::Uuid,
    guild_id: String,
    title: String,
    description: String,
    version: i32,
    schema: Value,
    is_quiz: bool,
    open_at: Option<chrono::DateTime<chrono::Utc>>,
    close_at: Option<chrono::DateTime<chrono::Utc>>,
    #[allow(dead_code)]
    allow_edits: bool,
    #[allow(dead_code)]
    single_submission: bool,
    require_verified: bool,
    min_account_age_days: i32,
    #[allow(dead_code)]
    success_message: String,
    preview_token: String,
    #[allow(dead_code)]
    webhook_url: Option<String>,
    archived: bool,
    #[allow(dead_code)]
    slug: String,
}

async fn load_form(state: &AppState, slug: &str) -> Result<FormRow, AppError> {
    sqlx::query_as::<_, FormRow>(
        "SELECT id, guild_id, title, description, version, schema, is_quiz, \
                open_at, close_at, allow_edits, single_submission, require_verified, \
                min_account_age_days, success_message, preview_token, webhook_url, archived, slug \
         FROM forms WHERE slug = $1",
    )
    .bind(slug)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::FormNotFound(slug.to_string()))
}

fn discord_account_age_days(discord_id: &str) -> Option<i64> {
    // Discord snowflake epoch: 2015-01-01T00:00:00Z, ms shift = 22.
    let snowflake: u64 = discord_id.parse().ok()?;
    let ms = (snowflake >> 22) + 1_420_070_400_000;
    let secs = (ms / 1000) as i64;
    let created = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)?;
    Some((chrono::Utc::now() - created).num_days())
}

pub async fn get_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(slug): Path<String>,
) -> Result<Response, AppError> {
    let form = load_form(&state, &slug).await?;
    if form.archived {
        return Err(AppError::FormNotFound(slug));
    }

    let now = chrono::Utc::now();
    if let Some(open_at) = form.open_at {
        if now < open_at {
            return Ok(render_status_page(
                &state.config.base_url,
                &form.title,
                &format!("This form opens at {}.", open_at.to_rfc3339()),
            ));
        }
    }
    if let Some(close_at) = form.close_at {
        if now > close_at {
            return Ok(render_status_page(
                &state.config.base_url,
                &form.title,
                "This form is no longer accepting submissions.",
            ));
        }
    }

    let session_data = jar
        .get(SESSION_COOKIE)
        .and_then(|c| session::verify_session(c.value(), &state.config.session_secret));

    let Some((discord_id, display_name)) = session_data else {
        return Ok(render_signin_page(&state.config.base_url, &form, &slug));
    };

    if form.min_account_age_days > 0 {
        let age = discord_account_age_days(&discord_id).unwrap_or(0);
        if age < form.min_account_age_days as i64 {
            return Ok(render_status_page(
                &state.config.base_url,
                &form.title,
                &format!(
                    "Your Discord account must be at least {} days old to submit this form (yours is {} days).",
                    form.min_account_age_days, age
                ),
            ));
        }
    }

    if form.require_verified {
        let guild_ids = match crate::services::auth_gateway::fetch_user_guild_ids(
            &state.http,
            &state.config.auth_gateway_url,
            &state.config.internal_api_key,
            &discord_id,
        )
        .await
        {
            Ok(ids) => ids,
            Err(e) => {
                // Surface a real error instead of silently denying access. A
                // gateway blip used to fall through `unwrap_or_default()` and
                // make every form look "members only" for the duration.
                tracing::error!(
                    discord_id = %discord_id,
                    form_id = %form.id,
                    "auth_gateway membership lookup failed: {e}"
                );
                return Ok(render_status_page(
                    &state.config.base_url,
                    &form.title,
                    "We couldn't verify your server membership right now. Please refresh in a moment.",
                ));
            }
        };
        if !guild_ids.iter().any(|g| g == &form.guild_id) {
            return Ok(render_status_page(
                &state.config.base_url,
                &form.title,
                "You must be a member of the server before you can submit this form.",
            ));
        }
    }

    Ok(render_form_page(
        &state.config.base_url,
        &form,
        &slug,
        &discord_id,
        &display_name,
        false,
    ))
}

#[derive(Deserialize)]
pub struct PreviewQuery {
    pub token: String,
}

pub async fn get_preview(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    Query(q): Query<PreviewQuery>,
) -> Result<Response, AppError> {
    let form = load_form(&state, &slug).await?;
    if !crate::services::rl_token::constant_time_eq(
        q.token.as_bytes(),
        form.preview_token.as_bytes(),
    ) {
        return Err(AppError::Forbidden("Invalid preview token.".into()));
    }
    Ok(render_form_page(
        &state.config.base_url,
        &form,
        &slug,
        "preview",
        "Preview",
        true,
    ))
}

#[derive(Deserialize)]
pub struct SubmitBody {
    pub answers: Value,
    pub version: i32,
}

pub async fn post_submit(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SubmitBody>,
) -> Result<Json<Value>, AppError> {
    // `X-RL-Preview` is a CLIENT OPT-OUT, never a security check: it lets
    // callers (curl, internal smoke tests) explicitly say "don't store this".
    // The actual preview protection is the UI in render.html which disables
    // the submit button and the JS click handler when `boot.preview` is true.
    // A real attacker would never set this header — they'd just POST without
    // it. So this branch only fires for legitimate opt-outs.
    if headers.get("x-rl-preview").and_then(|v| v.to_str().ok()) == Some("1") {
        return Err(AppError::Forbidden(
            "Preview mode does not accept submissions.".into(),
        ));
    }

    let cookie = jar
        .get(SESSION_COOKIE)
        .ok_or_else(|| AppError::UnauthorizedWith("Sign in with Discord to submit.".into()))?;
    let (discord_id, display_name) =
        session::verify_session(cookie.value(), &state.config.session_secret).ok_or_else(|| {
            AppError::UnauthorizedWith("Your session expired. Sign in again.".into())
        })?;

    let mut tx = state.pool.begin().await?;

    #[derive(sqlx::FromRow)]
    struct SubmitRow {
        id: uuid::Uuid,
        guild_id: String,
        title: String,
        version: i32,
        schema: Value,
        is_quiz: bool,
        single_submission: bool,
        allow_edits: bool,
        open_at: Option<chrono::DateTime<chrono::Utc>>,
        close_at: Option<chrono::DateTime<chrono::Utc>>,
        require_verified: bool,
        min_account_age_days: i32,
        success_message: String,
        webhook_url: Option<String>,
        archived: bool,
    }

    let row = sqlx::query_as::<_, SubmitRow>(
        "SELECT id, guild_id, title, version, schema, is_quiz, single_submission, allow_edits, \
                open_at, close_at, require_verified, min_account_age_days, success_message, \
                webhook_url, archived \
         FROM forms WHERE slug = $1 FOR SHARE",
    )
    .bind(&slug)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::FormNotFound(slug.clone()))?;

    let form_id = row.id;
    let guild_id = row.guild_id;
    let form_title = row.title;
    let version = row.version;
    let schema_json = row.schema;
    let is_quiz = row.is_quiz;
    let single_submission = row.single_submission;
    let allow_edits = row.allow_edits;
    let open_at = row.open_at;
    let close_at = row.close_at;
    let require_verified = row.require_verified;
    let min_account_age_days = row.min_account_age_days;
    let success_message = row.success_message;
    let webhook_url = row.webhook_url;
    let archived = row.archived;

    if archived {
        return Err(AppError::FormNotFound(slug));
    }
    if version != body.version {
        return Err(AppError::StaleVersion);
    }
    let now = chrono::Utc::now();
    if matches!(open_at, Some(t) if t > now) || matches!(close_at, Some(t) if t < now) {
        return Err(AppError::FormClosed);
    }
    if min_account_age_days > 0 {
        let age = discord_account_age_days(&discord_id).unwrap_or(0);
        if age < min_account_age_days as i64 {
            return Err(AppError::Forbidden(format!(
                "Account must be ≥{min_account_age_days} days old."
            )));
        }
    }
    if require_verified {
        let guild_ids = crate::services::auth_gateway::fetch_user_guild_ids(
            &state.http,
            &state.config.auth_gateway_url,
            &state.config.internal_api_key,
            &discord_id,
        )
        .await?;
        if !guild_ids.iter().any(|g| g == &guild_id) {
            return Err(AppError::Forbidden(
                "You must be a member of the server first.".into(),
            ));
        }
    }

    let schema: FormSchema = serde_json::from_value(schema_json)
        .map_err(|e| AppError::Internal(format!("form schema invalid: {e}")))?;

    let verified =
        form_validator::validate(&schema, &body.answers).map_err(AppError::ValidationFailed)?;

    let total_score = if is_quiz {
        Some(form_validator::compute_quiz_score(&schema, &verified))
    } else {
        None
    };

    let answers_json = Value::Object(verified);
    let form_id_text = form_id.to_string();

    // `version` is locked in via the surrounding `FOR SHARE` so persisting
    // it here freezes condition evaluation to the schema the user actually
    // answered against. See migration 007 for the column.
    let response_id: Option<uuid::Uuid> = if single_submission {
        if allow_edits {
            // Try INSERT; on conflict, UPDATE in place.
            let existing: Option<uuid::Uuid> = sqlx::query_scalar(
                "SELECT id FROM form_responses WHERE form_id = $1 AND discord_id = $2 LIMIT 1",
            )
            .bind(&form_id_text)
            .bind(&discord_id)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(id) = existing {
                sqlx::query(
                    "UPDATE form_responses SET answers = $1, total_score = $2, \
                                                schema_version = $3, last_edited_at = now() \
                     WHERE id = $4",
                )
                .bind(&answers_json)
                .bind(total_score)
                .bind(version)
                .bind(id)
                .execute(&mut *tx)
                .await?;
                Some(id)
            } else {
                let id = sqlx::query_scalar::<_, uuid::Uuid>(
                    "INSERT INTO form_responses (form_id, guild_id, discord_id, answers, total_score, schema_version) \
                     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
                )
                .bind(&form_id_text)
                .bind(&guild_id)
                .bind(&discord_id)
                .bind(&answers_json)
                .bind(total_score)
                .bind(version)
                .fetch_one(&mut *tx)
                .await?;
                Some(id)
            }
        } else {
            // Insert only if no row exists yet.
            let inserted = sqlx::query_scalar::<_, uuid::Uuid>(
                "INSERT INTO form_responses (form_id, guild_id, discord_id, answers, total_score, schema_version) \
                 SELECT $1, $2, $3, $4, $5, $6 \
                 WHERE NOT EXISTS ( \
                    SELECT 1 FROM form_responses WHERE form_id = $1 AND discord_id = $3 \
                 ) \
                 RETURNING id",
            )
            .bind(&form_id_text)
            .bind(&guild_id)
            .bind(&discord_id)
            .bind(&answers_json)
            .bind(total_score)
            .bind(version)
            .fetch_optional(&mut *tx)
            .await?;
            if inserted.is_none() {
                return Err(AppError::DuplicateSubmission);
            }
            inserted
        }
    } else {
        let id = sqlx::query_scalar::<_, uuid::Uuid>(
            "INSERT INTO form_responses (form_id, guild_id, discord_id, answers, total_score, schema_version) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
        )
        .bind(&form_id_text)
        .bind(&guild_id)
        .bind(&discord_id)
        .bind(&answers_json)
        .bind(total_score)
        .bind(version)
        .fetch_one(&mut *tx)
        .await?;
        Some(id)
    };

    // Enqueue background work INSIDE the transaction so the player_sync /
    // webhook jobs only exist if the response was actually persisted.
    crate::services::jobs::enqueue_player_sync(
        &mut *tx,
        crate::services::jobs::PlayerSyncPayload::Updated {
            discord_id: discord_id.clone(),
        },
    )
    .await?;

    if let Some(url) = webhook_url.as_ref() {
        if !url.trim().is_empty() {
            let payload = webhook::build_payload(
                &form_title,
                &slug,
                &display_name,
                &discord_id,
                &response_id.map(|i| i.to_string()).unwrap_or_default(),
                total_score,
                &state.config.base_url,
            );
            crate::services::jobs::enqueue_webhook(&mut *tx, url.clone(), payload).await?;
        }
    }

    tx.commit().await?;

    Ok(Json(json!({
        "success": true,
        "message": success_message,
        "total_score": total_score,
        "response_id": response_id.map(|i| i.to_string()),
    })))
}

pub async fn get_done() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        DONE_HTML,
    )
}

const DONE_HTML: &str = include_str!("../../templates/done.html");

// ---------------------------------------------------------------------------
// HTML rendering — inline page shells with `{base_url}` substitution.
// ---------------------------------------------------------------------------

fn html_response(body: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

fn html_response_status(body: String, status: StatusCode) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn render_signin_page(base_url: &str, form: &FormRow, slug: &str) -> Response {
    let title = escape_html(&form.title);
    let description = escape_html(&form.description);
    let return_to = format!("/form-respondent-role/f/{}", slug);
    let body = format!(
        r##"<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="icon" href="{base_url}/favicon.ico" type="image/x-icon">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{description}">
<meta property="og:url" content="{base_url}/f/{slug}">
<meta property="og:type" content="website">
<meta name="theme-color" content="#7c3aed">
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 640px; margin: 0 auto; padding: 48px 20px; background: #0e1525; color: #c8ccd4; min-height: 100vh; }}
h1 {{ color: #a78bfa; font-size: 28px; margin-bottom: 12px; }}
p {{ line-height: 1.55; margin: 12px 0; color: #94a3b8; }}
.card {{ background: #161d2e; padding: 28px; border-radius: 12px; border: 1px solid #1e2a3d; margin: 24px 0; }}
.btn {{ display: inline-block; padding: 12px 24px; background: #5865f2; color: white; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px; }}
.btn:hover {{ background: #4752c4; }}
</style>
</head><body>
<h1>{title}</h1>
{desc_block}
<div class="card">
<p>You need to sign in with Discord to fill out this form.</p>
<p style="margin-top: 16px;"><a class="btn" href="/auth/login?return_to={return_to}">Sign in with Discord</a></p>
</div>
</body></html>"##,
        title = title,
        description = description,
        base_url = base_url,
        slug = escape_html(slug),
        return_to = urlencoding::encode(&return_to),
        desc_block = if form.description.is_empty() {
            String::new()
        } else {
            format!("<p>{}</p>", description)
        }
    );
    html_response(body)
}

fn render_status_page(base_url: &str, form_title: &str, message: &str) -> Response {
    let title = escape_html(form_title);
    let msg = escape_html(message);
    let body = format!(
        r##"<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="icon" href="{base_url}/favicon.ico" type="image/x-icon">
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: system-ui, sans-serif; max-width: 640px; margin: 0 auto; padding: 48px 20px; background: #0e1525; color: #c8ccd4; min-height: 100vh; }}
h1 {{ color: #a78bfa; font-size: 26px; margin-bottom: 12px; }}
.card {{ background: #161d2e; padding: 28px; border-radius: 12px; border: 1px solid #1e2a3d; margin: 24px 0; }}
.card p {{ color: #cbd5e1; line-height: 1.55; }}
</style>
</head><body>
<h1>{title}</h1>
<div class="card"><p>{msg}</p></div>
</body></html>"##,
        title = title,
        msg = msg,
        base_url = base_url,
    );
    html_response_status(body, StatusCode::OK)
}

const RENDER_TEMPLATE: &str = include_str!("../../templates/render.html");

fn render_form_page(
    base_url: &str,
    form: &FormRow,
    slug: &str,
    discord_id: &str,
    display_name: &str,
    preview: bool,
) -> Response {
    // Embed the schema + form metadata as JSON for the JS to consume.
    let bootstrap = json!({
        "slug": slug,
        "title": form.title,
        "description": form.description,
        "version": form.version,
        "schema": form.schema,
        "is_quiz": form.is_quiz,
        "preview": preview,
        "discord_id": discord_id,
        "display_name": display_name,
        "base_url": base_url,
    })
    .to_string();

    let body = RENDER_TEMPLATE
        .replace("__BOOTSTRAP__", &bootstrap)
        .replace("__BASE_URL__", base_url)
        .replace("__TITLE__", &escape_html(&form.title))
        .replace("__DESCRIPTION__", &escape_html(&form.description))
        .replace("__SLUG__", &escape_html(slug));
    html_response(body)
}
