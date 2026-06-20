-- Configurable retry / cooldown system for forms and quizzes.
--
-- Until now a form was either "unlimited submissions" (single_submission =
-- false, one row per submit) or "exactly one submission, ever"
-- (single_submission = true; quizzes are always forced into this mode to
-- avoid the submit -> see-outcome -> tweak -> resubmit answer-key oracle).
--
-- This migration generalises the single-submission mode into a *bounded
-- retry* mode: admins may allow up to N graded attempts with a cooldown
-- between them, and choose whether the best or the latest attempt is the one
-- that counts towards role eligibility.
--
-- Why this is safe to relax the one-shot quiz rule:
--   * We still never echo the raw score or per-question correctness — only a
--     single pass/fail bit per attempt (see routes/form_render.rs).
--   * Question + option order is still shuffled on every page load.
--   * `max_attempts` caps the total information a brute-forcer can extract and
--     `retry_cooldown_seconds` rate-limits it over wall-clock time.
-- The admin opts in explicitly; the defaults below reproduce today's exact
-- one-shot behaviour, so existing forms are unaffected.
--
-- These knobs only have meaning when the form keeps a single canonical
-- response per (form, member) — i.e. single_submission = true (quizzes always
-- are). Keeping one canonical row is also what makes the two sync paths agree:
-- per-player sync reads the member's latest row and per-role-link bulk sync
-- matches any row, so with exactly one row "best/latest attempt counts" is
-- evaluated identically by both. Unlimited forms (single_submission = false)
-- ignore these columns.

-- ---- forms: per-form retry policy ----------------------------------------

-- Maximum number of attempts a member may make. 1 = today's one-shot
-- behaviour (the default, so existing rows are unchanged); a value >= 2 allows
-- bounded retries; 0 means unlimited attempts (still cooldown-gated).
ALTER TABLE forms
    ADD COLUMN IF NOT EXISTS max_attempts INTEGER NOT NULL DEFAULT 1;

-- Minimum number of seconds a member must wait between two attempts. 0
-- disables the cooldown. Capped in the application layer (<= 90 days).
ALTER TABLE forms
    ADD COLUMN IF NOT EXISTS retry_cooldown_seconds INTEGER NOT NULL DEFAULT 0;

-- Which attempt becomes the canonical response used for role evaluation:
--   'keep_best'   -> the highest-scoring attempt wins; passing is sticky
--                    (once a member passes they cannot drop below it). The
--                    standard exam behaviour. Falls back to keep_latest when
--                    the form is not graded (no scores to compare).
--   'keep_latest' -> the most recent attempt always replaces the previous one.
-- The inline CHECK is created together with the column; because the whole
-- ADD COLUMN is guarded by IF NOT EXISTS, re-running this migration is a no-op
-- and never tries to add a duplicate constraint.
ALTER TABLE forms
    ADD COLUMN IF NOT EXISTS retry_policy TEXT NOT NULL DEFAULT 'keep_best'
        CHECK (retry_policy IN ('keep_best', 'keep_latest'));

-- When true, a member who has already passed (met the form's passing_score)
-- gets no further attempts — their winning attempt is locked in. Only
-- meaningful for graded quizzes that set a passing_score; ignored otherwise.
ALTER TABLE forms
    ADD COLUMN IF NOT EXISTS lock_on_pass BOOLEAN NOT NULL DEFAULT TRUE;

-- ---- form_responses: per-member attempt tracking -------------------------

-- How many attempts this canonical response represents. Combined with
-- last_edited_at (the time of the most recent attempt) and submitted_at (the
-- first attempt) it drives the cooldown + attempt-limit enforcement in the
-- submit handler. Unlimited (multi-row) forms leave this at 1 per row.
ALTER TABLE form_responses
    ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 1;

-- Whether the canonical attempt met the form's passing_score. NULL when the
-- form is not a graded quiz or sets no threshold (every submission "passes").
-- Used only for retry gating (lock_on_pass) and member-facing messaging;
-- role eligibility is still decided live by the role-link conditions, never
-- by this column.
ALTER TABLE form_responses
    ADD COLUMN IF NOT EXISTS passed BOOLEAN;
