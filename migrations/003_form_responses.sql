-- Form responses. Column names match what services/sync.rs and
-- services/condition_eval.rs expect (form_id TEXT, last_edited_at, etc.) so
-- those files transplant verbatim from Google-Forms-Respondent-Role.
--
-- form_id is TEXT (storing UUID-as-text), NOT a UUID-typed column or an FK.
-- Cascade behavior on form delete is handled at the application layer in the
-- admin DELETE handler (NULL out role_links.form_id, then DELETE responses).
CREATE TABLE IF NOT EXISTS form_responses (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    form_id         TEXT NOT NULL,
    guild_id        TEXT NOT NULL,
    discord_id      TEXT NOT NULL,
    answers         JSONB NOT NULL,
    total_score     INTEGER,
    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_edited_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_form_responses_form_user ON form_responses (form_id, discord_id);
CREATE INDEX IF NOT EXISTS idx_form_responses_discord ON form_responses (discord_id);
CREATE INDEX IF NOT EXISTS idx_form_responses_guild ON form_responses (guild_id);
CREATE INDEX IF NOT EXISTS idx_form_responses_answers_gin ON form_responses USING GIN (answers);
