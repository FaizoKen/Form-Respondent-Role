-- Passing-score threshold for quiz forms.
--
-- When a form is a quiz (`is_quiz = true`), the submit handler computes
-- `total_score` server-side and compares it against `passing_score` to decide
-- the boolean `passed` shown to the respondent. The raw score is no longer
-- echoed to the client (it would leak an oracle that lets users edit-loop
-- towards a correct answer set). Admins still see the raw score in the
-- responses dashboard.
--
-- NULL means "no threshold configured" — any successful submission is
-- treated as `passed = true`. Conditions on `QuizTotalScore` continue to use
-- the persisted `form_responses.total_score` and are unaffected by this
-- column.
ALTER TABLE forms
    ADD COLUMN IF NOT EXISTS passing_score INTEGER;
