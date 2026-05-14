use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Operators applicable to a single condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    /// String equality (case-sensitive).
    Eq,
    /// String inequality.
    Neq,
    /// String contains (substring).
    Contains,
    /// String matches a regex.
    Regex,
    /// Value is one of a list of strings.
    In,
    /// All listed strings appear (for checkbox arrays).
    ContainsAll,
    /// Any listed string appears (for checkbox arrays).
    ContainsAny,
    /// None of the listed strings appear.
    NotContains,
    /// Numeric `>`.
    Gt,
    /// Numeric `>=`.
    Gte,
    /// Numeric `<`.
    Lt,
    /// Numeric `<=`.
    Lte,
    /// Numeric range, inclusive (uses value + value_end).
    Between,
    /// Date/time before (RFC3339).
    Before,
    /// Date/time after (RFC3339).
    After,
}

impl ConditionOperator {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Neq => "neq",
            Self::Contains => "contains",
            Self::Regex => "regex",
            Self::In => "in",
            Self::ContainsAll => "contains_all",
            Self::ContainsAny => "contains_any",
            Self::NotContains => "not_contains",
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Lt => "lt",
            Self::Lte => "lte",
            Self::Between => "between",
            Self::Before => "before",
            Self::After => "after",
        }
    }

    pub fn from_key(k: &str) -> Option<Self> {
        Some(match k {
            "eq" => Self::Eq,
            "neq" => Self::Neq,
            "contains" => Self::Contains,
            "regex" => Self::Regex,
            "in" => Self::In,
            "contains_all" => Self::ContainsAll,
            "contains_any" => Self::ContainsAny,
            "not_contains" => Self::NotContains,
            "gt" => Self::Gt,
            "gte" => Self::Gte,
            "lt" => Self::Lt,
            "lte" => Self::Lte,
            "between" => Self::Between,
            "before" => Self::Before,
            "after" => Self::After,
            _ => return None,
        })
    }
}

/// A single condition row in `role_links.conditions`.
///
/// `target` selects what data on the response to test — either a specific
/// question's answer or the response-wide quiz total score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub target: ConditionTarget,
    pub operator: ConditionOperator,
    pub value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_end: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConditionTarget {
    /// Test the answer to a specific question.
    Question { question_id: String },
    /// Test the response's total quiz score (only valid if form is a quiz).
    QuizTotalScore,
}
