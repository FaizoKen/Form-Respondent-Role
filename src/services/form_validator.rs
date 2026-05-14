//! Server-side validation for form submissions and form-builder PUT bodies.
//!
//! `validate()` runs at submit time: type-checks the answer payload against
//! the form's question schema and produces a normalized `VerifiedAnswers`
//! ready to insert into `form_responses.answers`. The normalized shape is
//! what `condition_eval.rs` expects (see [condition_eval.rs:42-52]).
//!
//! `sanity_check()` runs at form-builder PUT time: structural invariants on
//! the schema itself (unique ids, ≤50 questions, regexes compile, etc.).

use std::collections::HashSet;

use serde_json::{Map, Value};

use crate::error::FieldError;
use crate::models::form::{FormSchema, Question, QuestionKind};

const MAX_QUESTIONS: usize = 50;
const MAX_PAGES: usize = 10;
const MAX_OPTIONS_PER_QUESTION: usize = 50;
const DEFAULT_MAX_TEXT_LEN: usize = 100;
const DEFAULT_MAX_LONG_TEXT_LEN: usize = 4000;

/// Normalized answer payload, ready for `form_responses.answers` JSONB column.
/// Keys are question ids; values are normalized per-kind shapes:
/// - text/email/single_choice/dropdown/scale/number/date → JSON string
/// - multi_choice → JSON array of option-id strings
/// - agreement → JSON string "true"
pub type VerifiedAnswers = Map<String, Value>;

/// Validate an answer payload against the form schema.
///
/// `raw_answers` is the user-submitted JSON object (whatever shape the
/// browser sent). We project it down to the questions defined on the form
/// and reject anything that doesn't match.
pub fn validate(
    schema: &FormSchema,
    raw_answers: &Value,
) -> Result<VerifiedAnswers, Vec<FieldError>> {
    let mut out: VerifiedAnswers = Map::new();
    let mut errors: Vec<FieldError> = Vec::new();

    let answers_obj = match raw_answers.as_object() {
        Some(m) => m,
        None => {
            errors.push(FieldError {
                question_id: String::new(),
                message: "Answers must be a JSON object.".into(),
            });
            return Err(errors);
        }
    };

    for q in schema.iter_questions() {
        let raw = answers_obj.get(&q.id);

        let result = match q.kind {
            QuestionKind::ShortText | QuestionKind::LongText => validate_text(q, raw),
            QuestionKind::Number | QuestionKind::Scale => validate_number(q, raw),
            QuestionKind::SingleChoice | QuestionKind::Dropdown => validate_single_choice(q, raw),
            QuestionKind::MultiChoice => validate_multi_choice(q, raw),
            QuestionKind::Date => validate_date(q, raw),
            QuestionKind::Email => validate_email(q, raw),
            QuestionKind::Agreement => validate_agreement(q, raw),
            QuestionKind::Info | QuestionKind::Image | QuestionKind::Video => continue,
        };

        match result {
            Ok(Some(v)) => {
                out.insert(q.id.clone(), v);
            }
            Ok(None) => {
                // Unanswered + not required → skip silently.
            }
            Err(msg) => errors.push(FieldError {
                question_id: q.id.clone(),
                message: msg,
            }),
        }
    }

    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

fn is_blank(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.trim().is_empty(),
        Some(Value::Array(a)) => a.is_empty(),
        _ => false,
    }
}

fn validate_text(q: &Question, raw: Option<&Value>) -> Result<Option<Value>, String> {
    if is_blank(raw) {
        return require(q);
    }
    let s = raw
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Answer must be text.".to_string())?
        .trim();
    let max_len = q.max_length.map(|n| n as usize).unwrap_or_else(|| {
        if matches!(q.kind, QuestionKind::LongText) {
            DEFAULT_MAX_LONG_TEXT_LEN
        } else {
            DEFAULT_MAX_TEXT_LEN
        }
    });
    if s.chars().count() > max_len {
        return Err(format!("Answer is too long (max {max_len} characters)."));
    }
    Ok(Some(Value::String(s.to_string())))
}

fn validate_number(q: &Question, raw: Option<&Value>) -> Result<Option<Value>, String> {
    if is_blank(raw) {
        return require(q);
    }
    let n = match raw.unwrap() {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
    .ok_or_else(|| "Answer must be a number.".to_string())?;

    if let Some(min) = q.min {
        if n < min {
            return Err(format!("Answer must be at least {min}."));
        }
    }
    if let Some(max) = q.max {
        if n > max {
            return Err(format!("Answer must be at most {max}."));
        }
    }
    // Store as string so SQL `(fr.answers ->> 'qid')::numeric` works (the
    // condition SQL builder casts text→numeric explicitly).
    if n.fract() == 0.0 && n.is_finite() {
        Ok(Some(Value::String((n as i64).to_string())))
    } else {
        Ok(Some(Value::String(n.to_string())))
    }
}

fn validate_single_choice(q: &Question, raw: Option<&Value>) -> Result<Option<Value>, String> {
    if is_blank(raw) {
        return require(q);
    }
    let s = raw
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Answer must be a single option id.".to_string())?;
    let options = q
        .options
        .as_ref()
        .ok_or_else(|| "Question is misconfigured (no options).".to_string())?;
    if !options.iter().any(|o| o.id == s) {
        return Err("Selected option is not valid for this question.".into());
    }
    Ok(Some(Value::String(s.to_string())))
}

fn validate_multi_choice(q: &Question, raw: Option<&Value>) -> Result<Option<Value>, String> {
    if is_blank(raw) {
        return require(q);
    }
    let arr = raw
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Answer must be a list of option ids.".to_string())?;
    let options = q
        .options
        .as_ref()
        .ok_or_else(|| "Question is misconfigured (no options).".to_string())?;
    let mut chosen: Vec<Value> = Vec::with_capacity(arr.len());
    for v in arr {
        let s = v
            .as_str()
            .ok_or_else(|| "Each selection must be an option id string.".to_string())?;
        if !options.iter().any(|o| o.id == s) {
            return Err(format!("Option \"{s}\" is not valid for this question."));
        }
        chosen.push(Value::String(s.to_string()));
    }
    Ok(Some(Value::Array(chosen)))
}

fn validate_date(q: &Question, raw: Option<&Value>) -> Result<Option<Value>, String> {
    if is_blank(raw) {
        return require(q);
    }
    let s = raw
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Answer must be a date string.".to_string())?
        .trim();
    // Accept either YYYY-MM-DD or full RFC3339; condition_eval handles both.
    if chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_err()
        && chrono::DateTime::parse_from_rfc3339(s).is_err()
    {
        return Err("Date must be in YYYY-MM-DD format.".into());
    }
    Ok(Some(Value::String(s.to_string())))
}

fn validate_email(q: &Question, raw: Option<&Value>) -> Result<Option<Value>, String> {
    if is_blank(raw) {
        return require(q);
    }
    let s = raw
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Email must be text.".to_string())?
        .trim();
    if !looks_like_email(s) {
        return Err("That doesn't look like a valid email address.".into());
    }
    if s.len() > 320 {
        return Err("Email is too long.".into());
    }
    Ok(Some(Value::String(s.to_string())))
}

fn validate_agreement(q: &Question, raw: Option<&Value>) -> Result<Option<Value>, String> {
    let truthy = match raw {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => matches!(s.as_str(), "true" | "yes" | "on" | "1"),
        Some(Value::Number(n)) => n.as_i64().map(|i| i != 0).unwrap_or(false),
        _ => false,
    };
    if !truthy {
        if q.required {
            return Err("You must agree to continue.".into());
        }
        return Ok(None);
    }
    Ok(Some(Value::String("true".to_string())))
}

fn require(q: &Question) -> Result<Option<Value>, String> {
    if q.required {
        Err("This question is required.".into())
    } else {
        Ok(None)
    }
}

fn looks_like_email(s: &str) -> bool {
    let mut parts = s.split('@');
    let (Some(local), Some(domain)) = (parts.next(), parts.next()) else {
        return false;
    };
    if parts.next().is_some() || local.is_empty() || domain.len() < 3 {
        return false;
    }
    domain.contains('.')
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Compute the quiz total score for a verified answer set against the schema.
/// Awards `points` for an exact match against `correct`; absent/wrong → 0.
pub fn compute_quiz_score(schema: &FormSchema, verified: &VerifiedAnswers) -> i32 {
    let mut total = 0i32;
    for q in schema.iter_questions() {
        let Some(points) = q.points else {
            continue;
        };
        let Some(correct) = q.correct.as_ref() else {
            continue;
        };
        let Some(actual) = verified.get(&q.id) else {
            continue;
        };
        let matched = match q.kind {
            QuestionKind::MultiChoice => {
                // For multi-choice, correct is a JSON array; require set equality.
                let want = correct
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect::<HashSet<_>>()
                    })
                    .unwrap_or_default();
                let got = actual
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect::<HashSet<_>>()
                    })
                    .unwrap_or_default();
                want == got
            }
            _ => {
                let want = correct.as_str().unwrap_or_default();
                let got = actual.as_str().unwrap_or_default();
                !want.is_empty() && want == got
            }
        };
        if matched {
            total = total.saturating_add(points);
        }
    }
    total
}

/// Structural sanity check on a form schema (PUT-time validator).
pub fn sanity_check(schema: &FormSchema) -> Result<(), Vec<String>> {
    let mut errors: Vec<String> = Vec::new();
    let mut seen_qids: HashSet<&str> = HashSet::new();
    let mut seen_pids: HashSet<&str> = HashSet::new();
    let mut total_qs = 0usize;

    if schema.title.trim().is_empty() {
        errors.push("Form title is required.".into());
    }
    if schema.title.chars().count() > 200 {
        errors.push("Form title must be ≤200 characters.".into());
    }
    if schema.description.chars().count() > 2000 {
        errors.push("Form description must be ≤2000 characters.".into());
    }
    if schema.pages.is_empty() {
        errors.push("Form must have at least one page.".into());
    }
    if schema.pages.len() > MAX_PAGES {
        errors.push(format!("Form has too many pages (max {MAX_PAGES})."));
    }

    for (pi, page) in schema.pages.iter().enumerate() {
        if page.id.trim().is_empty() {
            errors.push(format!("Page #{} has no id.", pi + 1));
        } else if !seen_pids.insert(page.id.as_str()) {
            errors.push(format!(
                "Page #{} has duplicate id \"{}\".",
                pi + 1,
                page.id
            ));
        }

        for (qi, q) in page.questions.iter().enumerate() {
            total_qs += 1;
            if q.id.trim().is_empty() {
                errors.push(format!(
                    "Question #{} on page {} has no id.",
                    qi + 1,
                    pi + 1
                ));
            } else if !seen_qids.insert(q.id.as_str()) {
                errors.push(format!("Duplicate question id \"{}\".", q.id));
            }
            if q.title.trim().is_empty()
                && !matches!(
                    q.kind,
                    QuestionKind::Info | QuestionKind::Image | QuestionKind::Video
                )
            {
                errors.push(format!("Question \"{}\" needs a title.", q.id));
            }
            check_question_kind(q, &mut errors);
        }
    }

    if total_qs > MAX_QUESTIONS {
        errors.push(format!(
            "Form has {total_qs} questions; max is {MAX_QUESTIONS}."
        ));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn check_question_kind(q: &Question, errors: &mut Vec<String>) {
    match q.kind {
        QuestionKind::SingleChoice | QuestionKind::MultiChoice | QuestionKind::Dropdown => {
            let opts = q.options.as_deref().unwrap_or(&[]);
            if opts.is_empty() {
                errors.push(format!("Question \"{}\" needs at least one option.", q.id));
            }
            if opts.len() > MAX_OPTIONS_PER_QUESTION {
                errors.push(format!(
                    "Question \"{}\" has too many options (max {MAX_OPTIONS_PER_QUESTION}).",
                    q.id
                ));
            }
            let mut seen = HashSet::new();
            for o in opts {
                if o.id.trim().is_empty() {
                    errors.push(format!("Question \"{}\" has an option with no id.", q.id));
                } else if !seen.insert(o.id.as_str()) {
                    errors.push(format!(
                        "Question \"{}\" has duplicate option id \"{}\".",
                        q.id, o.id
                    ));
                }
                if o.label.chars().count() > 200 {
                    errors.push(format!(
                        "Question \"{}\" option \"{}\" label is too long.",
                        q.id, o.id
                    ));
                }
            }
        }
        QuestionKind::Scale | QuestionKind::Number => {
            if let (Some(min), Some(max)) = (q.min, q.max) {
                if min > max {
                    errors.push(format!("Question \"{}\" has min > max.", q.id));
                }
            }
        }
        QuestionKind::Agreement => {
            if !q.required {
                errors.push(format!(
                    "Agreement question \"{}\" must be marked required.",
                    q.id
                ));
            }
        }
        QuestionKind::Image => {
            let url = q.image_url.as_deref().unwrap_or("").trim();
            if url.is_empty() {
                errors.push(format!("Image element \"{}\" needs an image URL.", q.id));
            } else if !is_safe_image_url(url) {
                errors.push(format!(
                    "Image element \"{}\" URL must start with http:// or https:// (data: and javascript: URLs are not allowed).",
                    q.id
                ));
            } else if url.chars().count() > 2048 {
                errors.push(format!(
                    "Image element \"{}\" URL is too long (max 2048 characters).",
                    q.id
                ));
            }
            if let Some(alt) = q.alt_text.as_deref() {
                if alt.chars().count() > 200 {
                    errors.push(format!(
                        "Image element \"{}\" alt text is too long (max 200 characters).",
                        q.id
                    ));
                }
            }
        }
        QuestionKind::Video => {
            let url = q.image_url.as_deref().unwrap_or("").trim();
            if url.is_empty() {
                errors.push(format!("Video element \"{}\" needs a video URL.", q.id));
            } else if !is_safe_image_url(url) {
                errors.push(format!(
                    "Video element \"{}\" URL must start with http:// or https:// (data: and javascript: URLs are not allowed).",
                    q.id
                ));
            } else if url.chars().count() > 2048 {
                errors.push(format!(
                    "Video element \"{}\" URL is too long (max 2048 characters).",
                    q.id
                ));
            }
        }
        _ => {}
    }
}

/// Looser sibling of `webhook::is_safe_url` for image references: HTTPS is
/// preferred but HTTP is allowed (many community CDNs still serve HTTP),
/// while `javascript:`/`data:` and other smuggling schemes are refused.
fn is_safe_image_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    if lower.starts_with("javascript:")
        || lower.starts_with("data:")
        || lower.starts_with("vbscript:")
        || lower.starts_with("file:")
    {
        return false;
    }
    lower.starts_with("http://") || lower.starts_with("https://")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::form::{
        FormSchema, FormSettings, Page, Question, QuestionKind, QuestionOption,
    };

    fn q(id: &str, kind: QuestionKind, title: &str) -> Question {
        Question {
            id: id.into(),
            kind,
            title: title.into(),
            description: String::new(),
            required: false,
            max_length: None,
            min: None,
            max: None,
            options: None,
            correct: None,
            points: None,
            placeholder: None,
            help_text: None,
            image_url: None,
            alt_text: None,
        }
    }

    fn page(id: &str, questions: Vec<Question>) -> Page {
        Page {
            id: id.into(),
            title: String::new(),
            description: String::new(),
            questions,
        }
    }

    fn schema(pages: Vec<Page>) -> FormSchema {
        FormSchema {
            title: "Test form".into(),
            description: String::new(),
            settings: FormSettings::default(),
            pages,
        }
    }

    fn opts(ids: &[&str]) -> Vec<QuestionOption> {
        ids.iter()
            .map(|id| QuestionOption {
                id: (*id).into(),
                label: format!("Label for {id}"),
            })
            .collect()
    }

    #[test]
    fn minimal_valid_schema_passes() {
        let s = schema(vec![page(
            "p1",
            vec![q("q1", QuestionKind::ShortText, "First")],
        )]);
        sanity_check(&s).expect("minimal form should validate");
    }

    #[test]
    fn empty_title_rejected() {
        let mut s = schema(vec![page(
            "p1",
            vec![q("q1", QuestionKind::ShortText, "First")],
        )]);
        s.title = "   ".into();
        assert!(sanity_check(&s).is_err());
    }

    #[test]
    fn no_pages_rejected() {
        let s = schema(vec![]);
        assert!(sanity_check(&s).is_err());
    }

    #[test]
    fn duplicate_question_ids_rejected() {
        let s = schema(vec![page(
            "p1",
            vec![
                q("dup", QuestionKind::ShortText, "First"),
                q("dup", QuestionKind::ShortText, "Second"),
            ],
        )]);
        let errs = sanity_check(&s).expect_err("duplicate qid should fail");
        assert!(errs
            .iter()
            .any(|e| e.to_ascii_lowercase().contains("duplicate")));
    }

    #[test]
    fn duplicate_page_ids_rejected() {
        let s = schema(vec![
            page("same", vec![q("q1", QuestionKind::ShortText, "x")]),
            page("same", vec![q("q2", QuestionKind::ShortText, "y")]),
        ]);
        assert!(sanity_check(&s).is_err());
    }

    #[test]
    fn missing_question_title_rejected_for_answerables() {
        let s = schema(vec![page(
            "p1",
            vec![q("q1", QuestionKind::ShortText, "  ")],
        )]);
        assert!(sanity_check(&s).is_err());
    }

    #[test]
    fn info_question_can_have_blank_title() {
        // Info/image/video are display-only — no answer collected, so a blank
        // title is intentional (often used as a section heading).
        let s = schema(vec![page(
            "p1",
            vec![
                q("info1", QuestionKind::Info, ""),
                q("real", QuestionKind::ShortText, "Real question"),
            ],
        )]);
        sanity_check(&s).expect("info element without title is allowed");
    }

    #[test]
    fn single_choice_needs_options() {
        let mut s = schema(vec![page(
            "p1",
            vec![q("q1", QuestionKind::SingleChoice, "Pick one")],
        )]);
        // No options set.
        assert!(sanity_check(&s).is_err());

        // With options it should pass.
        s.pages[0].questions[0].options = Some(opts(&["a", "b"]));
        sanity_check(&s).expect("single_choice with options is valid");
    }

    #[test]
    fn duplicate_option_ids_rejected() {
        let mut s = schema(vec![page(
            "p1",
            vec![q("q1", QuestionKind::SingleChoice, "Pick one")],
        )]);
        s.pages[0].questions[0].options = Some(opts(&["a", "a"]));
        assert!(sanity_check(&s).is_err());
    }

    #[test]
    fn agreement_must_be_required() {
        let mut s = schema(vec![page(
            "p1",
            vec![q("agree", QuestionKind::Agreement, "Agree to rules")],
        )]);
        // required=false (the default) — should fail.
        assert!(sanity_check(&s).is_err());

        s.pages[0].questions[0].required = true;
        sanity_check(&s).expect("required agreement is valid");
    }

    #[test]
    fn scale_min_greater_than_max_rejected() {
        let mut sq = q("s1", QuestionKind::Scale, "Rate");
        sq.min = Some(10.0);
        sq.max = Some(5.0);
        let s = schema(vec![page("p1", vec![sq])]);
        assert!(sanity_check(&s).is_err());
    }

    #[test]
    fn image_url_must_be_http_scheme() {
        let mut qi = q("i1", QuestionKind::Image, "");
        qi.image_url = Some("javascript:alert(1)".into());
        let s = schema(vec![page("p1", vec![qi])]);
        assert!(sanity_check(&s).is_err());

        let mut qi = q("i2", QuestionKind::Image, "");
        qi.image_url = Some("https://cdn.example.com/x.png".into());
        let s = schema(vec![page("p1", vec![qi])]);
        sanity_check(&s).expect("https image url is valid");
    }

    #[test]
    fn too_many_pages_rejected() {
        let pages = (0..MAX_PAGES + 1)
            .map(|i| {
                page(
                    &format!("p{i}"),
                    vec![q(&format!("q{i}"), QuestionKind::ShortText, "x")],
                )
            })
            .collect();
        assert!(sanity_check(&schema(pages)).is_err());
    }

    #[test]
    fn too_many_questions_rejected() {
        let qs: Vec<Question> = (0..MAX_QUESTIONS + 1)
            .map(|i| q(&format!("q{i}"), QuestionKind::ShortText, "x"))
            .collect();
        let s = schema(vec![page("p1", qs)]);
        assert!(sanity_check(&s).is_err());
    }
}
