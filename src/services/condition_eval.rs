//! Condition evaluation — both per-user (Rust, in-memory) and per-role-link
//! (dynamic SQL WHERE).
//!
//! Convention 42 invariant: an unconfigured role link grants the role to
//! nobody. Empty `conditions` AND `grant_on_any_submission = false` means
//! "match nobody". Both the Rust path AND the SQL path enforce this BEFORE
//! inspecting the conditions slice.

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::models::condition::{Condition, ConditionOperator, ConditionTarget};

/// A response record's data needed to evaluate conditions.
pub struct ResponseEvalData<'a> {
    /// `{questionId: answerValue}` JSON object from form_responses.answers.
    pub answers: &'a Value,
    /// Total quiz score (only for graded quiz responses).
    pub total_score: Option<i64>,
}

/// Evaluate the role-link's eligibility for a given response.
///
/// - If `grant_on_any_submission` is true, returns true regardless of conditions.
/// - Otherwise, an empty `conditions` slice returns false (Convention 42).
/// - Otherwise, all conditions must pass (AND).
pub fn evaluate(
    grant_on_any_submission: bool,
    conditions: &[Condition],
    data: &ResponseEvalData,
) -> bool {
    if grant_on_any_submission {
        return true;
    }
    if conditions.is_empty() {
        return false;
    }
    conditions.iter().all(|c| evaluate_single(c, data))
}

fn evaluate_single(condition: &Condition, data: &ResponseEvalData) -> bool {
    let actual: Value = match &condition.target {
        ConditionTarget::Question { question_id } => data
            .answers
            .get(question_id)
            .cloned()
            .unwrap_or(Value::Null),
        ConditionTarget::QuizTotalScore => match data.total_score {
            Some(n) => Value::from(n),
            None => Value::Null,
        },
    };

    if matches!(actual, Value::Null) && !matches!(condition.operator, ConditionOperator::Neq) {
        // No answer to test against — fail (except for `neq`, which can be
        // satisfied by absence; admins rely on this for "anyone who DIDN'T
        // pick option X qualifies").
        return false;
    }

    match condition.operator {
        ConditionOperator::Eq => string_compare(&actual, &condition.value, |a, b| a == b),
        ConditionOperator::Neq => {
            // Null on actual + neq → satisfied iff expected is non-empty.
            if matches!(actual, Value::Null) {
                return !condition.value.as_str().unwrap_or("").is_empty();
            }
            string_compare(&actual, &condition.value, |a, b| a != b)
        }
        ConditionOperator::Contains => {
            string_compare(&actual, &condition.value, |a, b| a.contains(b))
        }
        ConditionOperator::Regex => {
            let Some(pattern) = condition.value.as_str() else {
                return false;
            };
            // The `regex` crate uses linear-time matching (no catastrophic
            // backtracking), so a malicious pattern can't burn CPU like in
            // PCRE engines. Memory is the remaining vector: bound the compiled
            // size and the runtime DFA cache.
            let regex = regex::RegexBuilder::new(pattern)
                .size_limit(1 << 20)
                .dfa_size_limit(1 << 20)
                .build();
            let Ok(regex) = regex else {
                return false;
            };
            let actual_str = string_value(&actual).unwrap_or_default();
            regex.is_match(&actual_str)
        }
        ConditionOperator::In => {
            let actual_str = string_value(&actual).unwrap_or_default();
            condition
                .value
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .any(|s| s == actual_str)
                })
                .unwrap_or(false)
        }
        ConditionOperator::ContainsAll => {
            let actual_set = array_values(&actual);
            condition
                .value
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .all(|need| actual_set.iter().any(|a| a == need))
                })
                .unwrap_or(false)
        }
        ConditionOperator::ContainsAny => {
            let actual_set = array_values(&actual);
            condition
                .value
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .any(|need| actual_set.iter().any(|a| a == need))
                })
                .unwrap_or(false)
        }
        ConditionOperator::NotContains => {
            let actual_set = array_values(&actual);
            condition
                .value
                .as_array()
                .map(|arr| {
                    !arr.iter()
                        .filter_map(|v| v.as_str())
                        .any(|need| actual_set.iter().any(|a| a == need))
                })
                .unwrap_or(true)
        }
        ConditionOperator::Gt
        | ConditionOperator::Gte
        | ConditionOperator::Lt
        | ConditionOperator::Lte
        | ConditionOperator::Between => {
            let Some(actual_n) = numeric_value(&actual) else {
                return false;
            };
            let Some(expected_n) = numeric_value(&condition.value) else {
                return false;
            };
            match condition.operator {
                ConditionOperator::Gt => actual_n > expected_n,
                ConditionOperator::Gte => actual_n >= expected_n,
                ConditionOperator::Lt => actual_n < expected_n,
                ConditionOperator::Lte => actual_n <= expected_n,
                ConditionOperator::Between => {
                    let end_n = condition
                        .value_end
                        .as_ref()
                        .and_then(numeric_value)
                        .unwrap_or(expected_n);
                    actual_n >= expected_n && actual_n <= end_n
                }
                _ => unreachable!(),
            }
        }
        ConditionOperator::Before | ConditionOperator::After => {
            let Some(actual_dt) = parse_datetime(&actual) else {
                return false;
            };
            let Some(expected_dt) = condition.value.as_str().and_then(parse_datetime_str) else {
                return false;
            };
            match condition.operator {
                ConditionOperator::Before => actual_dt < expected_dt,
                ConditionOperator::After => actual_dt > expected_dt,
                _ => unreachable!(),
            }
        }
    }
}

fn string_value(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn array_values(v: &Value) -> Vec<String> {
    match v {
        Value::Array(arr) => arr
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        Value::String(s) => vec![s.clone()],
        _ => vec![],
    }
}

fn numeric_value(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse::<f64>().ok(),
        _ => None,
    }
}

fn parse_datetime(v: &Value) -> Option<DateTime<Utc>> {
    v.as_str().and_then(parse_datetime_str)
}

fn parse_datetime_str(s: &str) -> Option<DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
        // Forms date answers come back as "YYYY-MM-DD"; promote to start-of-day UTC.
        .or_else(|| {
            chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
                .ok()
                .map(|d| d.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc())
        })
}

fn string_compare<F: Fn(&str, &str) -> bool>(actual: &Value, expected: &Value, f: F) -> bool {
    let Some(a) = string_value(actual) else {
        return false;
    };
    let Some(b) = string_value(expected) else {
        return false;
    };
    f(&a, &b)
}

// ---------------------------------------------------------------------------
// SQL WHERE-clause builder for bulk per-role-link sync.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ConditionBind {
    Text(String),
    Int(i64),
}

/// Build a SQL WHERE clause that filters `form_responses` rows.
///
/// Returns ("clause", binds). The clause references the `fr` alias for the
/// form_responses table and uses parameter indices starting at `bind_offset + 1`.
///
/// Convention 42: callers MUST early-return BEFORE invoking this function
/// when (`!grant_on_any_submission` AND conditions is empty). This builder
/// returns "TRUE" for empty input so the SQL stays valid in the
/// `grant_on_any_submission = true` case where the caller intentionally
/// wants to match every submission.
pub fn build_condition_where(
    conditions: &[Condition],
    bind_offset: usize,
) -> (String, Vec<ConditionBind>) {
    if conditions.is_empty() {
        return ("TRUE".to_string(), vec![]);
    }

    let mut clauses: Vec<String> = Vec::new();
    let mut binds: Vec<ConditionBind> = Vec::new();

    for c in conditions {
        let (target_text_expr, target_num_expr) = match &c.target {
            ConditionTarget::Question { question_id } => {
                let qid_idx = bind_offset + binds.len() + 1;
                binds.push(ConditionBind::Text(question_id.clone()));
                (
                    format!("(fr.answers ->> ${qid_idx})"),
                    format!("NULLIF(fr.answers ->> ${qid_idx}, '')::numeric"),
                )
            }
            ConditionTarget::QuizTotalScore => (
                "fr.total_score::text".to_string(),
                "fr.total_score::numeric".to_string(),
            ),
        };

        let clause = match c.operator {
            ConditionOperator::Eq => {
                let v = c.value.as_str().unwrap_or("").to_string();
                let idx = bind_offset + binds.len() + 1;
                binds.push(ConditionBind::Text(v));
                format!("{target_text_expr} = ${idx}")
            }
            ConditionOperator::Neq => {
                let v = c.value.as_str().unwrap_or("").to_string();
                let idx = bind_offset + binds.len() + 1;
                binds.push(ConditionBind::Text(v));
                format!("({target_text_expr} IS DISTINCT FROM ${idx})")
            }
            ConditionOperator::Contains => {
                let v = c.value.as_str().unwrap_or("").to_string();
                let idx = bind_offset + binds.len() + 1;
                binds.push(ConditionBind::Text(format!("%{}%", escape_like(&v))));
                format!("{target_text_expr} LIKE ${idx}")
            }
            ConditionOperator::Regex => {
                let v = c.value.as_str().unwrap_or("").to_string();
                let idx = bind_offset + binds.len() + 1;
                binds.push(ConditionBind::Text(v));
                format!("{target_text_expr} ~ ${idx}")
            }
            ConditionOperator::In => {
                let arr: Vec<String> = c
                    .value
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                if arr.is_empty() {
                    "FALSE".to_string()
                } else {
                    let placeholders: Vec<String> = arr
                        .iter()
                        .enumerate()
                        .map(|(i, _)| format!("${}", bind_offset + binds.len() + 1 + i))
                        .collect();
                    for s in arr {
                        binds.push(ConditionBind::Text(s));
                    }
                    format!("{target_text_expr} IN ({})", placeholders.join(","))
                }
            }
            ConditionOperator::ContainsAll
            | ConditionOperator::ContainsAny
            | ConditionOperator::NotContains => {
                // Only meaningful for question targets (checkbox arrays).
                let qid = match &c.target {
                    ConditionTarget::Question { question_id } => question_id.clone(),
                    ConditionTarget::QuizTotalScore => return ("FALSE".to_string(), vec![]),
                };
                let qid_idx = bind_offset + binds.len() + 1;
                binds.push(ConditionBind::Text(qid));
                let needs: Vec<String> = c
                    .value
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                if needs.is_empty() {
                    match c.operator {
                        ConditionOperator::NotContains => "TRUE".to_string(),
                        _ => "FALSE".to_string(),
                    }
                } else {
                    let placeholders: Vec<String> = needs
                        .iter()
                        .enumerate()
                        .map(|(i, _)| format!("${}", bind_offset + binds.len() + 1 + i))
                        .collect();
                    for s in needs {
                        binds.push(ConditionBind::Text(s));
                    }
                    let arr_expr = format!(
                        "ARRAY(SELECT jsonb_array_elements_text(COALESCE(fr.answers -> ${qid_idx}, '[]'::jsonb)))"
                    );
                    let needs_arr = format!("ARRAY[{}]::text[]", placeholders.join(","));
                    match c.operator {
                        ConditionOperator::ContainsAll => format!("{arr_expr} @> {needs_arr}"),
                        ConditionOperator::ContainsAny => format!("{arr_expr} && {needs_arr}"),
                        ConditionOperator::NotContains => {
                            format!("NOT ({arr_expr} && {needs_arr})")
                        }
                        _ => unreachable!(),
                    }
                }
            }
            ConditionOperator::Gt
            | ConditionOperator::Gte
            | ConditionOperator::Lt
            | ConditionOperator::Lte => {
                let n = c
                    .value
                    .as_i64()
                    .or_else(|| c.value.as_f64().map(|f| f as i64))
                    .unwrap_or(0);
                let idx = bind_offset + binds.len() + 1;
                binds.push(ConditionBind::Int(n));
                let op = match c.operator {
                    ConditionOperator::Gt => ">",
                    ConditionOperator::Gte => ">=",
                    ConditionOperator::Lt => "<",
                    ConditionOperator::Lte => "<=",
                    _ => unreachable!(),
                };
                format!("({target_num_expr}) {op} ${idx}")
            }
            ConditionOperator::Between => {
                let n = c
                    .value
                    .as_i64()
                    .or_else(|| c.value.as_f64().map(|f| f as i64))
                    .unwrap_or(0);
                let end = c
                    .value_end
                    .as_ref()
                    .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
                    .unwrap_or(n);
                let idx_a = bind_offset + binds.len() + 1;
                let idx_b = bind_offset + binds.len() + 2;
                binds.push(ConditionBind::Int(n));
                binds.push(ConditionBind::Int(end));
                format!("({target_num_expr}) >= ${idx_a} AND ({target_num_expr}) <= ${idx_b}")
            }
            ConditionOperator::Before | ConditionOperator::After => {
                let v = c.value.as_str().unwrap_or("").to_string();
                let idx = bind_offset + binds.len() + 1;
                binds.push(ConditionBind::Text(v));
                let op = if matches!(c.operator, ConditionOperator::Before) {
                    "<"
                } else {
                    ">"
                };
                format!("(NULLIF({target_text_expr}, '')::timestamptz) {op} ${idx}::timestamptz")
            }
        };

        clauses.push(clause);
    }

    (clauses.join(" AND "), binds)
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn q(qid: &str, op: ConditionOperator, value: Value) -> Condition {
        Condition {
            target: ConditionTarget::Question {
                question_id: qid.into(),
            },
            operator: op,
            value,
            value_end: None,
        }
    }

    fn answers(pairs: &[(&str, Value)]) -> Value {
        let mut obj = serde_json::Map::new();
        for (k, v) in pairs {
            obj.insert((*k).into(), v.clone());
        }
        Value::Object(obj)
    }

    fn data<'a>(answers: &'a Value, score: Option<i64>) -> ResponseEvalData<'a> {
        ResponseEvalData {
            answers,
            total_score: score,
        }
    }

    // ---------- Convention 42 ----------

    #[test]
    fn convention_42_no_conditions_no_grant_means_nobody() {
        let a = answers(&[]);
        // grant_on_any_submission=false AND no conditions → reject.
        assert!(!evaluate(false, &[], &data(&a, None)));
    }

    #[test]
    fn grant_on_any_short_circuits_true() {
        let a = answers(&[]);
        // grant_on_any_submission=true should return true even with
        // an empty conditions slice — the conditions aren't even consulted.
        assert!(evaluate(true, &[], &data(&a, None)));
    }

    #[test]
    fn all_conditions_must_match_and() {
        let a = answers(&[("q1", json!("yes")), ("q2", json!("30"))]);
        let conds = vec![
            q("q1", ConditionOperator::Eq, json!("yes")),
            q("q2", ConditionOperator::Gte, json!(18)),
        ];
        assert!(evaluate(false, &conds, &data(&a, None)));

        // Flip one — overall must become false.
        let conds = vec![
            q("q1", ConditionOperator::Eq, json!("no")),
            q("q2", ConditionOperator::Gte, json!(18)),
        ];
        assert!(!evaluate(false, &conds, &data(&a, None)));
    }

    // ---------- numeric ----------

    #[test]
    fn gte_compares_numeric() {
        let a = answers(&[("age", json!("21"))]);
        assert!(evaluate(
            false,
            &[q("age", ConditionOperator::Gte, json!(18))],
            &data(&a, None),
        ));
        assert!(!evaluate(
            false,
            &[q("age", ConditionOperator::Gte, json!(25))],
            &data(&a, None),
        ));
    }

    #[test]
    fn between_inclusive_bounds() {
        let a = answers(&[("score", json!("50"))]);
        let mut c = q("score", ConditionOperator::Between, json!(40));
        c.value_end = Some(json!(60));
        assert!(evaluate(false, &[c], &data(&a, None)));

        let a = answers(&[("score", json!("39"))]);
        let mut c = q("score", ConditionOperator::Between, json!(40));
        c.value_end = Some(json!(60));
        assert!(!evaluate(false, &[c], &data(&a, None)));
    }

    // ---------- string ----------

    #[test]
    fn eq_string_exact_match() {
        let a = answers(&[("region", json!("EU"))]);
        assert!(evaluate(
            false,
            &[q("region", ConditionOperator::Eq, json!("EU"))],
            &data(&a, None),
        ));
        // Case-sensitive — "eu" ≠ "EU".
        assert!(!evaluate(
            false,
            &[q("region", ConditionOperator::Eq, json!("eu"))],
            &data(&a, None),
        ));
    }

    #[test]
    fn contains_substring() {
        let a = answers(&[("bio", json!("I love Rust and Discord"))]);
        assert!(evaluate(
            false,
            &[q("bio", ConditionOperator::Contains, json!("Rust"))],
            &data(&a, None),
        ));
    }

    #[test]
    fn regex_basic_match() {
        let a = answers(&[("zip", json!("90210"))]);
        assert!(evaluate(
            false,
            &[q("zip", ConditionOperator::Regex, json!(r"^\d{5}$"))],
            &data(&a, None),
        ));
        // Bad pattern → rejected (returns false), never panics.
        assert!(!evaluate(
            false,
            &[q("zip", ConditionOperator::Regex, json!("(("))],
            &data(&a, None),
        ));
    }

    // ---------- multi_choice ----------

    #[test]
    fn contains_any_for_multi_choice() {
        let a = answers(&[("hobbies", json!(["coding", "music"]))]);
        assert!(evaluate(
            false,
            &[q(
                "hobbies",
                ConditionOperator::ContainsAny,
                json!(["music", "art"]),
            )],
            &data(&a, None),
        ));
        assert!(!evaluate(
            false,
            &[q(
                "hobbies",
                ConditionOperator::ContainsAny,
                json!(["art", "writing"]),
            )],
            &data(&a, None),
        ));
    }

    #[test]
    fn contains_all_requires_full_set() {
        let a = answers(&[("hobbies", json!(["coding", "music"]))]);
        assert!(evaluate(
            false,
            &[q(
                "hobbies",
                ConditionOperator::ContainsAll,
                json!(["coding", "music"]),
            )],
            &data(&a, None),
        ));
        // Missing one of the required → false.
        assert!(!evaluate(
            false,
            &[q(
                "hobbies",
                ConditionOperator::ContainsAll,
                json!(["coding", "music", "art"]),
            )],
            &data(&a, None),
        ));
    }

    // ---------- quiz total score target ----------

    #[test]
    fn quiz_total_score_gte() {
        let a = answers(&[]);
        let c = Condition {
            target: ConditionTarget::QuizTotalScore,
            operator: ConditionOperator::Gte,
            value: json!(8),
            value_end: None,
        };
        assert!(evaluate(
            false,
            std::slice::from_ref(&c),
            &data(&a, Some(8))
        ));
        assert!(evaluate(
            false,
            std::slice::from_ref(&c),
            &data(&a, Some(10))
        ));
        assert!(!evaluate(
            false,
            std::slice::from_ref(&c),
            &data(&a, Some(7))
        ));
        // No total score at all (non-quiz response) → false.
        assert!(!evaluate(false, &[c], &data(&a, None)));
    }

    // ---------- missing answer ----------

    #[test]
    fn missing_answer_fails_eq_but_neq_can_pass() {
        let a = answers(&[]); // q1 not answered
                              // eq against an unanswered question is always false.
        assert!(!evaluate(
            false,
            &[q("q1", ConditionOperator::Eq, json!("yes"))],
            &data(&a, None),
        ));
        // neq against an unanswered question is true when expected is non-empty
        // — admins rely on this for "anyone who didn't pick option X".
        assert!(evaluate(
            false,
            &[q("q1", ConditionOperator::Neq, json!("forbidden_value"))],
            &data(&a, None),
        ));
    }
}
