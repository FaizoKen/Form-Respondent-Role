//! RoleLogic GET/POST /config helpers + structured role-config validator.
//!
//! The RoleLogic dashboard renders this plugin's UI inline via `ui_mode:
//! "iframe"` — `GET /config` returns an embed URL that points at the
//! plugin's own role-config page where all form-binding / eligibility /
//! condition editing happens (see [routes::admin::role_config_*]).
//!
//! `parse_role_config` is called from that page's POST handler to validate
//! and normalize the structured payload before writing it to `role_links` +
//! `guild_settings`.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::models::condition::{Condition, ConditionOperator, ConditionTarget};
use crate::models::form::FormSchema;

/// Hard cap on conditions per role. Was 7 because of the RoleLogic dashboard's
/// 30-field-per-section limit; now arbitrary but kept low so admins don't try
/// to express rule trees in a flat AND-list.
pub const MAX_CONDITIONS: usize = 12;

pub struct ParsedConfig {
    pub form_id: Option<String>,
    pub grant_on_any_submission: bool,
    pub conditions: Vec<Condition>,
    /// `Some(_)` when the request explicitly set view_permission, `None`
    /// when the field was omitted. The admin-list page now owns this
    /// setting, so role-config saves pass `None` and the existing value
    /// in `guild_settings` is preserved.
    pub view_permission: Option<String>,
}

/// Build the iframe-mode response returned by GET /config. RoleLogic appends
/// `?rl_token=<jwt>` to `embed_url` before rendering the iframe; we verify
/// that token on `role_config_page` to authenticate the admin.
pub fn build_iframe_config(base_url: &str, guild_id: &str, role_id: &str) -> Value {
    let embed_url = format!("{base_url}/admin/{guild_id}/role/{role_id}");
    json!({
        "version": 1,
        "ui_mode": "iframe",
        "name": "Form Respondent Role",
        "description": "Build a form, gate Discord roles on submissions or answer-conditions.",
        "embed_url": embed_url,
    })
}

/// POST /config is unreachable in iframe mode — the RoleLogic backend rejects
/// it before forwarding — but the contract still expects 200 on the off
/// chance an older backend forwards a call. Token has already been verified
/// in the handler.
pub fn accept_empty_config() -> Value {
    json!({ "success": true })
}

// ---------------------------------------------------------------------------
// Plugin-web payload: structured role config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RoleConfigBody {
    #[serde(default)]
    pub form_id: Option<String>,
    pub mode: String,
    #[serde(default)]
    pub conditions: Vec<ConditionInput>,
    #[serde(default)]
    pub view_permission: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConditionInput {
    pub target: String,
    pub operator: String,
    #[serde(default)]
    pub value: Value,
    #[serde(default)]
    pub value_end: Option<Value>,
}

/// Validate a structured role-config payload from the plugin web. `bound_form`
/// is the chosen form's parsed schema (None if `form_id` is empty or unknown;
/// we let partial config save so admins can come back later).
pub fn parse_role_config(
    body: RoleConfigBody,
    bound_form: Option<&FormSchema>,
    form_is_quiz: bool,
) -> Result<ParsedConfig, AppError> {
    let form_id = body
        .form_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let grant_on_any_submission = match body.mode.as_str() {
        "any_submission" => true,
        "conditions" => false,
        other => {
            return Err(AppError::BadRequest(format!(
                "Unknown eligibility mode '{other}'."
            )))
        }
    };

    let view_permission = match body.view_permission.as_deref() {
        None | Some("") => None,
        Some("members") | Some("managers") => body.view_permission.clone(),
        Some(other) => {
            return Err(AppError::BadRequest(format!(
                "Unknown view_permission '{other}'."
            )))
        }
    };

    let mut conditions: Vec<Condition> = Vec::new();
    if !grant_on_any_submission {
        if body.conditions.is_empty() {
            return Err(AppError::BadRequest(
                "Eligibility is set to \"match conditions\" but no conditions were added.".into(),
            ));
        }
        if body.conditions.len() > MAX_CONDITIONS {
            return Err(AppError::BadRequest(format!(
                "At most {MAX_CONDITIONS} conditions per role."
            )));
        }
        for (i, raw) in body.conditions.into_iter().enumerate() {
            conditions.push(validate_condition(i, raw, bound_form, form_is_quiz)?);
        }
    }

    Ok(ParsedConfig {
        form_id,
        grant_on_any_submission,
        conditions,
        view_permission,
    })
}

fn validate_condition(
    index: usize,
    raw: ConditionInput,
    bound_form: Option<&FormSchema>,
    form_is_quiz: bool,
) -> Result<Condition, AppError> {
    let n = index + 1;
    let target_raw = raw.target.trim();
    if target_raw.is_empty() {
        return Err(AppError::BadRequest(format!(
            "Condition #{n}: pick a question (or quiz total score)."
        )));
    }

    let operator = ConditionOperator::from_key(raw.operator.trim()).ok_or_else(|| {
        AppError::BadRequest(format!(
            "Condition #{n}: unknown operator '{}'.",
            raw.operator
        ))
    })?;

    let target = if target_raw == "__quiz_total_score__" {
        if !form_is_quiz {
            return Err(AppError::BadRequest(format!(
                "Condition #{n}: \"Quiz total score\" only works on quiz forms."
            )));
        }
        if !matches!(
            operator,
            ConditionOperator::Eq
                | ConditionOperator::Neq
                | ConditionOperator::Gt
                | ConditionOperator::Gte
                | ConditionOperator::Lt
                | ConditionOperator::Lte
                | ConditionOperator::Between
        ) {
            return Err(AppError::BadRequest(format!(
                "Condition #{n}: quiz total score only supports numeric comparisons."
            )));
        }
        ConditionTarget::QuizTotalScore
    } else if let Some(form) = bound_form {
        let q = form.find_question(target_raw).ok_or_else(|| {
            AppError::BadRequest(format!(
                "Condition #{n}: question \"{target_raw}\" doesn't exist on the chosen form."
            ))
        })?;
        if q.kind.is_array_valued()
            && !matches!(
                operator,
                ConditionOperator::ContainsAll
                    | ConditionOperator::ContainsAny
                    | ConditionOperator::NotContains
                    | ConditionOperator::Eq
                    | ConditionOperator::Neq
            )
        {
            return Err(AppError::BadRequest(format!(
                "Condition #{n}: checkbox questions need a list operator (contains all / any / none)."
            )));
        }
        ConditionTarget::Question {
            question_id: target_raw.to_string(),
        }
    } else {
        // No bound form (form_id empty) — accept and trust round-trip, validator
        // will re-run once a form is picked.
        ConditionTarget::Question {
            question_id: target_raw.to_string(),
        }
    };

    let value = normalize_condition_value(operator, raw.value, n)?;
    let value_end = match (operator, raw.value_end) {
        (ConditionOperator::Between, Some(end)) => {
            Some(normalize_condition_value(operator, end, n)?)
        }
        (ConditionOperator::Between, None) => {
            return Err(AppError::BadRequest(format!(
                "Condition #{n}: \"between\" needs both a min and a max value."
            )));
        }
        _ => None,
    };

    if matches!(operator, ConditionOperator::Regex) {
        let pattern = value.as_str().unwrap_or("");
        // Mirror the runtime caps used in `condition_eval.rs` so a pattern
        // that compiles at save time also compiles at eval time.
        if regex::RegexBuilder::new(pattern)
            .size_limit(1 << 20)
            .dfa_size_limit(1 << 20)
            .build()
            .is_err()
        {
            return Err(AppError::BadRequest(format!(
                "Condition #{n}: regex pattern is invalid."
            )));
        }
    }

    Ok(Condition {
        target,
        operator,
        value,
        value_end,
    })
}

fn normalize_condition_value(
    op: ConditionOperator,
    raw: Value,
    n: usize,
) -> Result<Value, AppError> {
    match op {
        ConditionOperator::Gt
        | ConditionOperator::Gte
        | ConditionOperator::Lt
        | ConditionOperator::Lte
        | ConditionOperator::Between => {
            let parsed = match &raw {
                Value::Number(num) => num.as_i64().or_else(|| num.as_f64().map(|f| f as i64)),
                Value::String(s) => s.trim().parse::<i64>().ok(),
                _ => None,
            };
            parsed.map(Value::from).ok_or_else(|| {
                AppError::BadRequest(format!(
                    "Condition #{n}: numeric value required (got {raw})."
                ))
            })
        }
        ConditionOperator::In
        | ConditionOperator::ContainsAll
        | ConditionOperator::ContainsAny
        | ConditionOperator::NotContains => {
            let arr: Vec<Value> = match raw {
                Value::Array(a) => a
                    .into_iter()
                    .filter(|v| !matches!(v, Value::Null) && !v.as_str().is_some_and(str::is_empty))
                    .collect(),
                Value::String(s) => s
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| Value::String(s.to_string()))
                    .collect(),
                Value::Null => vec![],
                other => vec![other],
            };
            if arr.is_empty() {
                return Err(AppError::BadRequest(format!(
                    "Condition #{n}: list operator needs at least one value."
                )));
            }
            Ok(Value::Array(arr))
        }
        ConditionOperator::Before | ConditionOperator::After => {
            let s = raw.as_str().unwrap_or("").trim().to_string();
            if s.is_empty() {
                return Err(AppError::BadRequest(format!(
                    "Condition #{n}: date value required."
                )));
            }
            Ok(Value::String(s))
        }
        _ => match raw {
            Value::String(s) => {
                if s.trim().is_empty() {
                    Err(AppError::BadRequest(format!(
                        "Condition #{n}: value required."
                    )))
                } else {
                    Ok(Value::String(s))
                }
            }
            Value::Number(num) => Ok(Value::String(num.to_string())),
            Value::Null => Err(AppError::BadRequest(format!(
                "Condition #{n}: value required."
            ))),
            other => Ok(other),
        },
    }
}
