use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::json;

#[derive(Debug, Clone, Serialize)]
pub struct FieldError {
    pub question_id: String,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("RoleLogic API error: {0}")]
    RoleLogic(String),

    #[error("Role link not found on RoleLogic")]
    RoleLinkNotFound,

    #[error("Role link is disabled on RoleLogic")]
    RoleLinkDisabled,

    #[error("Role link user limit reached ({limit})")]
    UserLimitReached { limit: usize },

    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Unauthorized: {0}")]
    UnauthorizedWith(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Form not found: {0}")]
    FormNotFound(String),

    #[error("Form is not currently accepting submissions")]
    FormClosed,

    #[error("Submission rate limited")]
    SubmissionRateLimited,

    #[error("Validation failed")]
    ValidationFailed(Vec<FieldError>),

    #[error("Duplicate submission")]
    DuplicateSubmission,

    #[error("No attempts remaining")]
    AttemptsExhausted { max: i32 },

    #[error("Retry cooldown active")]
    RetryCooldown { retry_after_seconds: i64 },

    #[error("Already passed; no further attempts")]
    AlreadyPassed,

    #[error("Form was edited; reload and try again")]
    StaleVersion,

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Database(e) => classify_db_error(e),
            AppError::RoleLogic(e) => {
                tracing::error!("RoleLogic API error: {e}");
                (
                    StatusCode::BAD_GATEWAY,
                    axum::Json(json!({ "error": "Failed to sync roles" })),
                )
                    .into_response()
            }
            AppError::RoleLinkNotFound => (
                StatusCode::NOT_FOUND,
                axum::Json(json!({ "error": "Role link not found" })),
            )
                .into_response(),
            AppError::RoleLinkDisabled => (
                StatusCode::FORBIDDEN,
                axum::Json(json!({ "error": "Role link is disabled" })),
            )
                .into_response(),
            AppError::UserLimitReached { limit } => {
                tracing::warn!("Role link user limit reached: {limit}");
                (
                    StatusCode::FORBIDDEN,
                    axum::Json(json!({ "error": "Role link user limit reached" })),
                )
                    .into_response()
            }
            AppError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, axum::Json(json!({ "error": msg }))).into_response()
            }
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({ "error": "Invalid or missing authorization" })),
            )
                .into_response(),
            AppError::UnauthorizedWith(msg) => (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({ "error": msg })),
            )
                .into_response(),
            AppError::Forbidden(msg) => {
                (StatusCode::FORBIDDEN, axum::Json(json!({ "error": msg }))).into_response()
            }
            AppError::NotFound(msg) => {
                (StatusCode::NOT_FOUND, axum::Json(json!({ "error": msg }))).into_response()
            }
            AppError::FormNotFound(slug) => (
                StatusCode::NOT_FOUND,
                axum::Json(json!({ "error": format!("Form not found: {slug}") })),
            )
                .into_response(),
            AppError::FormClosed => (
                StatusCode::FORBIDDEN,
                axum::Json(json!({ "error": "This form is not currently accepting submissions." })),
            )
                .into_response(),
            AppError::SubmissionRateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(json!({ "error": "Too many submissions. Please slow down." })),
            )
                .into_response(),
            AppError::ValidationFailed(field_errors) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                axum::Json(json!({
                    "error": "Validation failed",
                    "field_errors": field_errors,
                })),
            )
                .into_response(),
            AppError::DuplicateSubmission => (
                StatusCode::CONFLICT,
                axum::Json(json!({
                    "error": "You've already submitted this form.",
                    "code": "DUPLICATE_SUBMISSION",
                })),
            )
                .into_response(),
            AppError::AttemptsExhausted { max } => (
                StatusCode::CONFLICT,
                axum::Json(json!({
                    "error": format!("You've used all {max} of your attempts for this form."),
                    "code": "ATTEMPTS_EXHAUSTED",
                    "max_attempts": max,
                })),
            )
                .into_response(),
            AppError::RetryCooldown {
                retry_after_seconds,
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, retry_after_seconds.to_string())],
                axum::Json(json!({
                    "error": "Please wait before trying again.",
                    "code": "RETRY_COOLDOWN",
                    "retry_after_seconds": retry_after_seconds,
                })),
            )
                .into_response(),
            AppError::AlreadyPassed => (
                StatusCode::CONFLICT,
                axum::Json(json!({
                    "error": "You've already passed — no further attempts are needed.",
                    "code": "ALREADY_PASSED",
                })),
            )
                .into_response(),
            AppError::StaleVersion => (
                StatusCode::CONFLICT,
                axum::Json(json!({
                    "error": "The form was edited while you were filling it out. Please reload.",
                    "code": "STALE_VERSION",
                })),
            )
                .into_response(),
            AppError::Internal(e) => {
                tracing::error!("Internal error: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(json!({ "error": "Internal server error" })),
                )
                    .into_response()
            }
        }
    }
}

/// Map a raw `sqlx::Error` to an HTTP response. Constraint violations are
/// client-causable so they get 4xx codes; everything else falls through to
/// 500 with a generic body (we log the real cause but never leak it).
fn classify_db_error(e: sqlx::Error) -> Response {
    if let sqlx::Error::Database(db_err) = &e {
        // PostgreSQL SQLSTATE codes, see
        // https://www.postgresql.org/docs/current/errcodes-appendix.html
        let code = db_err.code();
        let code_str = code.as_deref().unwrap_or("");
        let constraint = db_err.constraint().unwrap_or("");

        match code_str {
            // unique_violation
            "23505" => {
                tracing::warn!(constraint, "DB unique-violation: {db_err}");
                return (
                    StatusCode::CONFLICT,
                    axum::Json(json!({
                        "error": "A record with that value already exists.",
                        "code": "UNIQUE_VIOLATION",
                        "constraint": constraint,
                    })),
                )
                    .into_response();
            }
            // foreign_key_violation
            "23503" => {
                tracing::warn!(constraint, "DB foreign-key-violation: {db_err}");
                return (
                    StatusCode::CONFLICT,
                    axum::Json(json!({
                        "error": "Operation would violate a referential constraint.",
                        "code": "FOREIGN_KEY_VIOLATION",
                        "constraint": constraint,
                    })),
                )
                    .into_response();
            }
            // check_violation
            "23514" => {
                tracing::warn!(constraint, "DB check-violation: {db_err}");
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({
                        "error": "One or more fields failed a database check.",
                        "code": "CHECK_VIOLATION",
                        "constraint": constraint,
                    })),
                )
                    .into_response();
            }
            // not_null_violation
            "23502" => {
                tracing::warn!(constraint, "DB not-null-violation: {db_err}");
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({
                        "error": "A required field was missing.",
                        "code": "NOT_NULL_VIOLATION",
                    })),
                )
                    .into_response();
            }
            _ => {}
        }
    }

    tracing::error!("Database error: {e}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(json!({ "error": "Internal server error" })),
    )
        .into_response()
}
