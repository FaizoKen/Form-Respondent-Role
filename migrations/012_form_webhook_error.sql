-- Why the form's webhook last refused a submission, for the builder to show.
--
-- A webhook that Discord deleted answered 404 to every submission, and each
-- one went to the dead-letter queue where only the operator saw it (prod: one
-- form, 31 dead deliveries from 2026-10-11 to 11-19). The owner never learned
-- their notifications had stopped. Set when the destination refuses a
-- delivery in a way the owner can fix, cleared by the next delivery that
-- succeeds or by saving a different URL. Nullable and additive (expand-only):
-- an older replica that never writes it is harmless during a rolling deploy.
ALTER TABLE forms ADD COLUMN IF NOT EXISTS webhook_error TEXT;
ALTER TABLE forms ADD COLUMN IF NOT EXISTS webhook_error_at TIMESTAMPTZ;
