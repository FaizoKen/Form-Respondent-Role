//! Strongly-typed view of `forms.schema` JSONB.
//!
//! The form-builder writes free-form JSON; we parse it through these types
//! both for ergonomic access (renderer, validator, schema-builder) and to
//! enforce structural sanity at PUT time.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FormSchema {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub settings: FormSettings,
    #[serde(default)]
    pub pages: Vec<Page>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FormSettings {
    #[serde(default = "default_submit_label")]
    pub submit_label: String,
    #[serde(default = "default_true")]
    pub show_progress_bar: bool,
    #[serde(default)]
    pub shuffle_questions: bool,
}

impl Default for FormSettings {
    fn default() -> Self {
        Self {
            submit_label: default_submit_label(),
            show_progress_bar: true,
            shuffle_questions: false,
        }
    }
}

fn default_submit_label() -> String {
    "Submit".to_string()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Page {
    pub id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub questions: Vec<Question>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Question {
    pub id: String,
    pub kind: QuestionKind,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub required: bool,

    // Kind-specific optional fields. We carry all of them on a single struct
    // for serde-simplicity; sanity_check() rejects forms where a field is set
    // on a kind that doesn't use it (or required-fields are missing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<QuestionOption>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correct: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub points: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionKind {
    ShortText,
    LongText,
    Number,
    SingleChoice,
    MultiChoice,
    Dropdown,
    Scale,
    Date,
    Email,
    Agreement,
    Info,
    Image,
    Video,
}

impl QuestionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ShortText => "short_text",
            Self::LongText => "long_text",
            Self::Number => "number",
            Self::SingleChoice => "single_choice",
            Self::MultiChoice => "multi_choice",
            Self::Dropdown => "dropdown",
            Self::Scale => "scale",
            Self::Date => "date",
            Self::Email => "email",
            Self::Agreement => "agreement",
            Self::Info => "info",
            Self::Image => "image",
            Self::Video => "video",
        }
    }

    /// Whether this kind produces an answer (info/image questions are display-only).
    pub fn is_answerable(&self) -> bool {
        !matches!(self, Self::Info | Self::Image | Self::Video)
    }

    /// Whether this kind can take part in a condition (i.e. used in the
    /// dashboard's question dropdown).
    pub fn is_conditionable(&self) -> bool {
        self.is_answerable()
    }

    /// Whether this kind expects a list-of-strings answer (multi_choice).
    pub fn is_array_valued(&self) -> bool {
        matches!(self, Self::MultiChoice)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QuestionOption {
    pub id: String,
    pub label: String,
}

impl FormSchema {
    /// Walk all answerable questions in declaration order.
    pub fn iter_questions(&self) -> impl Iterator<Item = &Question> {
        self.pages
            .iter()
            .flat_map(|p| p.questions.iter())
            .filter(|q| q.kind.is_answerable())
    }

    /// Look up a question by id.
    pub fn find_question(&self, id: &str) -> Option<&Question> {
        self.iter_questions().find(|q| q.id == id)
    }
}
