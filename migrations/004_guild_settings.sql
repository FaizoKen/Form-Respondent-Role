-- Per-guild settings (Convention 33). Currently controls who can view the
-- public respondent list page. Add more guild-scoped knobs here without
-- touching role_links.
CREATE TABLE IF NOT EXISTS guild_settings (
    guild_id        TEXT PRIMARY KEY,
    view_permission TEXT NOT NULL DEFAULT 'managers',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
