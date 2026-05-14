-- Role links: one per guild+role pair registered via POST /register.
-- Until the admin picks a form and sets eligibility, conditions = '[]' AND
-- grant_on_any_submission = FALSE means "grant to nobody" (Convention 42).
CREATE TABLE IF NOT EXISTS role_links (
    id                          BIGSERIAL PRIMARY KEY,
    guild_id                    TEXT NOT NULL,
    role_id                     TEXT NOT NULL,
    api_token                   TEXT NOT NULL,
    form_id                     TEXT,
    grant_on_any_submission     BOOLEAN NOT NULL DEFAULT FALSE,
    conditions                  JSONB NOT NULL DEFAULT '[]',
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (guild_id, role_id)
);
CREATE INDEX IF NOT EXISTS idx_role_links_form_id ON role_links (form_id) WHERE form_id IS NOT NULL;

-- Role assignments: tracks which users currently have which roles (local mirror).
CREATE TABLE IF NOT EXISTS role_assignments (
    guild_id        TEXT NOT NULL,
    role_id         TEXT NOT NULL,
    discord_id      TEXT NOT NULL,
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (guild_id, role_id, discord_id),
    FOREIGN KEY (guild_id, role_id) REFERENCES role_links (guild_id, role_id) ON DELETE CASCADE
);
