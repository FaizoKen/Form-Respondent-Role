//! Condition evaluation.
//!
//! [`evaluate`] is the single authority on whether a response qualifies for a
//! role link, used by BOTH sync paths: per-player
//! ([`crate::services::sync::sync_for_player`]) and bulk per-role-link
//! (`query_qualifying`). It must stay that way. This module previously also
//! carried a `build_condition_where` that re-expressed the same rules as SQL
//! for the bulk path, and the two drifted — `not_contains` on an unanswered
//! question, `neq` on a checkbox answer, and numeric comparisons against
//! non-numeric answers all disagreed. Because the two paths write the same
//! user list, every disagreement became a grant/revoke loop that took a
//! member's role away and gave it back on a timer. A second implementation of
//! these semantics, in any language, reintroduces that bug.
//!
//! Convention 42 invariant: an unconfigured role link grants the role to
//! nobody. Empty `conditions` AND `grant_on_any_submission = false` means
//! "match nobody", enforced BEFORE the conditions slice is inspected.

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

    // No answer to test against — fail, except for the two negative operators,
    // which absence satisfies: admins rely on `neq` for "anyone who DIDN'T pick
    // option X qualifies", and `not_contains` is exactly that for a checkbox
    // question. Leaving `not_contains` in the blanket fail was the sharpest of
    // the Rust/SQL disagreements this module used to carry — SQL coalesced a
    // missing answer to `[]` and matched, Rust bailed here and didn't, so every
    // member who skipped the question flipped between the two sync paths.
    let unanswered_ok = matches!(
        condition.operator,
        ConditionOperator::Neq | ConditionOperator::NotContains
    );
    if matches!(actual, Value::Null) && !unanswered_ok {
        return false;
    }

    match condition.operator {
        ConditionOperator::Eq => eq_matches(&actual, &condition.value).unwrap_or(false),
        ConditionOperator::Neq => {
            // Null on actual + neq → satisfied iff expected is non-empty.
            if matches!(actual, Value::Null) {
                return !condition.value.as_str().unwrap_or("").is_empty();
            }
            // Strictly the negation of `eq` — except that an *incomparable*
            // expected value (an array, say, from a hand-edited row) stays
            // false in both directions. Negating it instead would turn a
            // nonsense condition into "matches everyone", which grants the
            // role to the whole server rather than to nobody.
            eq_matches(&actual, &condition.value)
                .map(|matched| !matched)
                .unwrap_or(false)
        }
        ConditionOperator::Contains => {
            let Some(needle) = string_value(&condition.value) else {
                return false;
            };
            selections(&actual).iter().any(|s| s.contains(&needle))
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
            selections(&actual).iter().any(|s| regex.is_match(s))
        }
        ConditionOperator::In => {
            // "eq any of these", so it holds to the same single-selection rule
            // as `eq`.
            let chosen = selections(&actual);
            let [only] = chosen.as_slice() else {
                return false;
            };
            condition
                .value
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).any(|s| s == only))
                .unwrap_or(false)
        }
        ConditionOperator::ContainsAll => {
            let actual_set = selections(&actual);
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
            let actual_set = selections(&actual);
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
            let actual_set = selections(&actual);
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

/// An answer viewed as the set of values it holds — the single projection every
/// value-comparing operator works from.
///
/// `form_validator` stores a `multi_choice` answer as an array of option ids
/// and every other kind as a lone string, so this is "the selected options" for
/// a checkbox and "the answer" for anything else. Treating a scalar as a
/// one-element set is what lets the scalar operators keep working unchanged
/// while gaining a sensible meaning on checkbox answers, and it degrades
/// gracefully when a question's kind changes underneath a saved condition
/// (array answers left behind by a checkbox that is now single-choice, and
/// vice versa).
fn selections(v: &Value) -> Vec<String> {
    match v {
        Value::Array(arr) => arr
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        // Covers strings and, defensively, the numbers/bools that older or
        // imported rows may hold even though the validator no longer writes
        // them. Objects and null project to the empty set.
        other => string_value(other).into_iter().collect(),
    }
}

/// Whether the answer equals `expected`, or `None` when `expected` has no
/// string form and the comparison is therefore meaningless.
///
/// Equality is over the whole answer, so a checkbox matches only when it is a
/// single selection equal to the value — `["red"]` is `eq "red"`, but
/// `["red","blue"]` is not. Both used to be unconditionally false (a checkbox
/// answer has no string projection), which made `eq` on a checkbox grant nobody
/// and `neq` on a checkbox — offered in the same dropdown — grant nobody
/// either, when it should have been the exact complement.
fn eq_matches(actual: &Value, expected: &Value) -> Option<bool> {
    let expected = string_value(expected)?;
    let chosen = selections(actual);
    Some(matches!(chosen.as_slice(), [only] if *only == expected))
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

    #[test]
    fn not_contains_is_satisfied_by_an_unanswered_question() {
        // The checkbox form of "didn't pick option X": a member who skipped the
        // question picked none of the listed options, so they qualify. The bulk
        // sync's old SQL agreed; this evaluator did not, and the two took the
        // role off each other in a loop.
        let a = answers(&[]);
        assert!(evaluate(
            false,
            &[q(
                "hobbies",
                ConditionOperator::NotContains,
                json!(["forbidden"]),
            )],
            &data(&a, None),
        ));
    }

    #[test]
    fn not_contains_still_rejects_a_listed_answer() {
        let a = answers(&[("hobbies", json!(["coding", "forbidden"]))]);
        assert!(!evaluate(
            false,
            &[q(
                "hobbies",
                ConditionOperator::NotContains,
                json!(["forbidden"]),
            )],
            &data(&a, None),
        ));
    }

    #[test]
    fn positive_list_operators_still_fail_an_unanswered_question() {
        // Only the negative operators are exempt from the unanswered guard.
        let a = answers(&[]);
        for op in [
            ConditionOperator::ContainsAll,
            ConditionOperator::ContainsAny,
        ] {
            assert!(
                !evaluate(false, &[q("hobbies", op, json!(["music"]))], &data(&a, None)),
                "{op:?} should not match an unanswered question"
            );
        }
    }

    // The bulk sync used to translate these into SQL, where a non-numeric
    // answer aborted the whole query with a cast error (`'abc'::numeric`) and a
    // scalar answer aborted the list operators
    // (`jsonb_array_elements_text('"yes"')`). Both now run through this
    // evaluator, which reports "doesn't match" and keeps going.
    #[test]
    fn non_numeric_answer_fails_numeric_comparison_without_erroring() {
        let a = answers(&[("age", json!("not a number"))]);
        assert!(!evaluate(
            false,
            &[q("age", ConditionOperator::Gte, json!(18))],
            &data(&a, None),
        ));
    }

    // ---------- checkbox answers under the scalar operators ----------
    //
    // `schema::validate_condition` offers eq/neq on multi_choice questions
    // alongside the list operators, but a checkbox answer is a JSON array and
    // had no string form, so both were unconditionally false: `eq` granted
    // nobody and `neq` — its exact complement — granted nobody too.

    #[test]
    fn eq_matches_a_single_selection_checkbox() {
        let a = answers(&[("hobbies", json!(["music"]))]);
        assert!(evaluate(
            false,
            &[q("hobbies", ConditionOperator::Eq, json!("music"))],
            &data(&a, None),
        ));
        assert!(!evaluate(
            false,
            &[q("hobbies", ConditionOperator::Eq, json!("art"))],
            &data(&a, None),
        ));
    }

    #[test]
    fn eq_rejects_a_multi_selection_checkbox() {
        // Equality is over the whole answer: picking two options is not
        // "the answer is music".
        let a = answers(&[("hobbies", json!(["music", "coding"]))]);
        assert!(!evaluate(
            false,
            &[q("hobbies", ConditionOperator::Eq, json!("music"))],
            &data(&a, None),
        ));
    }

    #[test]
    fn neq_is_the_exact_complement_of_eq_on_checkboxes() {
        let single = answers(&[("hobbies", json!(["music"]))]);
        let multi = answers(&[("hobbies", json!(["music", "coding"]))]);
        for (a, label) in [(&single, "single"), (&multi, "multi")] {
            let eq = evaluate(
                false,
                &[q("hobbies", ConditionOperator::Eq, json!("music"))],
                &data(a, None),
            );
            let neq = evaluate(
                false,
                &[q("hobbies", ConditionOperator::Neq, json!("music"))],
                &data(a, None),
            );
            assert_ne!(eq, neq, "eq and neq must disagree on the {label} answer");
        }
    }

    #[test]
    fn incomparable_value_matches_nobody_in_either_direction() {
        // A hand-edited row can hold a list where a string belongs. Negating
        // "unsatisfiable" would turn nonsense into "grant the whole server".
        let a = answers(&[("region", json!("EU"))]);
        for op in [ConditionOperator::Eq, ConditionOperator::Neq] {
            assert!(
                !evaluate(false, &[q("region", op, json!(["EU"]))], &data(&a, None)),
                "{op:?} against a non-string value should match nobody"
            );
        }
    }

    #[test]
    fn contains_and_regex_search_within_each_selection() {
        let a = answers(&[("hobbies", json!(["classical music", "coding"]))]);
        assert!(evaluate(
            false,
            &[q("hobbies", ConditionOperator::Contains, json!("music"))],
            &data(&a, None),
        ));
        assert!(evaluate(
            false,
            &[q("hobbies", ConditionOperator::Regex, json!(r"^cod"))],
            &data(&a, None),
        ));
        assert!(!evaluate(
            false,
            &[q("hobbies", ConditionOperator::Regex, json!(r"^art"))],
            &data(&a, None),
        ));
    }

    #[test]
    fn scalar_answers_are_unaffected_by_the_set_projection() {
        // The whole point of projecting a scalar to a one-element set: every
        // non-checkbox question must behave exactly as it did before.
        let a = answers(&[("region", json!("EU")), ("bio", json!("I love Rust"))]);
        let d = || data(&a, None);
        assert!(evaluate(
            false,
            &[q("region", ConditionOperator::Eq, json!("EU"))],
            &d()
        ));
        assert!(!evaluate(
            false,
            &[q("region", ConditionOperator::Eq, json!("US"))],
            &d()
        ));
        assert!(evaluate(
            false,
            &[q("region", ConditionOperator::Neq, json!("US"))],
            &d()
        ));
        assert!(!evaluate(
            false,
            &[q("region", ConditionOperator::Neq, json!("EU"))],
            &d()
        ));
        assert!(evaluate(
            false,
            &[q("region", ConditionOperator::In, json!(["EU", "UK"]))],
            &d()
        ));
        assert!(!evaluate(
            false,
            &[q("region", ConditionOperator::In, json!(["US", "UK"]))],
            &d()
        ));
        assert!(evaluate(
            false,
            &[q("bio", ConditionOperator::Contains, json!("Rust"))],
            &d()
        ));
        assert!(evaluate(
            false,
            &[q("bio", ConditionOperator::Regex, json!("^I love"))],
            &d()
        ));
    }

    #[test]
    fn in_holds_to_the_same_single_selection_rule_as_eq() {
        // `in` is "eq any of these", so a two-option pick is no more "in" the
        // list than it is equal to a member of it.
        let a = answers(&[("hobbies", json!(["music"]))]);
        assert!(evaluate(
            false,
            &[q("hobbies", ConditionOperator::In, json!(["music", "art"]))],
            &data(&a, None),
        ));
        let a = answers(&[("hobbies", json!(["music", "coding"]))]);
        assert!(!evaluate(
            false,
            &[q("hobbies", ConditionOperator::In, json!(["music", "art"]))],
            &data(&a, None),
        ));
    }

    #[test]
    fn scalar_answer_is_handled_by_list_operators() {
        // A question that used to be a checkbox and is now single-choice leaves
        // scalar answers behind for conditions still using list operators.
        let a = answers(&[("hobbies", json!("music"))]);
        assert!(evaluate(
            false,
            &[q("hobbies", ConditionOperator::ContainsAny, json!(["music"]))],
            &data(&a, None),
        ));
        assert!(!evaluate(
            false,
            &[q("hobbies", ConditionOperator::ContainsAny, json!(["art"]))],
            &data(&a, None),
        ));
    }
}
