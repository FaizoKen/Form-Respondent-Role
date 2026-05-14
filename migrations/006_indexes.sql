-- Performance indexes for hot read paths discovered during scale review.
-- All `IF NOT EXISTS` so re-running is safe; can be rolled forward in any
-- order relative to other 006-and-later migrations.

-- Admin "list forms in guild" sorts by updated_at DESC.
CREATE INDEX IF NOT EXISTS idx_forms_guild_updated
    ON forms (guild_id, updated_at DESC);

-- Builder/responses pages count and stream form_responses by form, newest
-- first. The (form_id, submitted_at DESC) composite supports both.
CREATE INDEX IF NOT EXISTS idx_form_responses_form_submitted
    ON form_responses (form_id, submitted_at DESC);

-- Slug lookup hits this on every form-fill and every submit. UNIQUE on slug
-- is enforced elsewhere (migration 002); this is an explicit b-tree to
-- guarantee the planner uses it.
CREATE INDEX IF NOT EXISTS idx_forms_slug
    ON forms (slug);

-- Sync workers fan out by (guild_id, role_id) when a config changes;
-- they then need every role_link bound to a form within a guild.
CREATE INDEX IF NOT EXISTS idx_role_links_guild_role
    ON role_links (guild_id, role_id);
CREATE INDEX IF NOT EXISTS idx_role_links_form
    ON role_links (form_id)
    WHERE form_id IS NOT NULL;
