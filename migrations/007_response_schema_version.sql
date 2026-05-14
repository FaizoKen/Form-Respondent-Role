-- Persist the form's `version` *at submit time* alongside the response.
--
-- Condition evaluation in sync workers used to re-read the LIVE schema; if
-- the admin edited the form after the user submitted, conditions that
-- referenced a now-deleted question silently evaluated to false and quietly
-- denied the role. Storing the version freezes the evaluation to the schema
-- the user actually answered against.
--
-- Backfilled with each form's current version so existing responses keep
-- working. New rows get the value explicitly from the submit handler.
ALTER TABLE form_responses
    ADD COLUMN IF NOT EXISTS schema_version INTEGER;

-- Backfill: assume existing responses were against whatever version is live.
-- This is imperfect for very old data but is the only honest estimate we
-- can make without a separate audit log.
UPDATE form_responses fr
SET schema_version = COALESCE(
        (SELECT version FROM forms f WHERE f.id::text = fr.form_id),
        1
    )
WHERE schema_version IS NULL;

ALTER TABLE form_responses
    ALTER COLUMN schema_version SET NOT NULL;

ALTER TABLE form_responses
    ALTER COLUMN schema_version SET DEFAULT 1;
