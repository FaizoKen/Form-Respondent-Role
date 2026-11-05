-- The respondent's Discord display name, as their sign-in session carried it
-- when they submitted (refreshed on every later attempt or edit).
--
-- The Responses page, its CSV export and the public respondent list used to
-- show only the raw Discord ID, which tells an admin reviewing applications
-- nothing about who applied. Nullable and additive (expand-only): rows from
-- before this column keep showing the ID, and an older replica that never
-- writes it is harmless during a rolling deploy.
ALTER TABLE form_responses ADD COLUMN IF NOT EXISTS display_name TEXT;
