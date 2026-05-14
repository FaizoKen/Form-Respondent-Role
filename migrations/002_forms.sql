-- Admin-defined forms. Each form belongs to one guild; multiple role_links
-- can reference the same form with different conditions.
--
-- The `schema` JSONB is the canonical form definition (pages → questions → options).
-- Atomically replaced via PUT /admin/{guild_id}/forms/{id}; `version` is
-- incremented on every save and used as an optimistic-concurrency token.
CREATE TABLE IF NOT EXISTS forms (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    guild_id                TEXT NOT NULL,
    slug                    TEXT NOT NULL UNIQUE,
    title                   TEXT NOT NULL,
    description             TEXT NOT NULL DEFAULT '',
    version                 INTEGER NOT NULL DEFAULT 1,
    schema                  JSONB NOT NULL,
    is_quiz                 BOOLEAN NOT NULL DEFAULT FALSE,
    open_at                 TIMESTAMPTZ,
    close_at                TIMESTAMPTZ,
    allow_edits             BOOLEAN NOT NULL DEFAULT FALSE,
    single_submission       BOOLEAN NOT NULL DEFAULT TRUE,
    require_verified        BOOLEAN NOT NULL DEFAULT FALSE,
    min_account_age_days    INTEGER NOT NULL DEFAULT 0,
    success_message         TEXT NOT NULL DEFAULT 'Thanks for your response!',
    preview_token           TEXT NOT NULL,
    webhook_url             TEXT,
    archived                BOOLEAN NOT NULL DEFAULT FALSE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_forms_guild ON forms (guild_id);
