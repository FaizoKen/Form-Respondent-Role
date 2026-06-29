-- One-time startup-backfill bookkeeping.
--
-- Some maintenance tasks must run exactly once after a deploy — e.g. re-syncing
-- every existing role link after a change to who-qualifies logic — without an
-- admin manually pressing Save on each server (most admins can't: they only
-- control their own guild). A named row here marks such a backfill as already
-- run, so it never repeats on later boots or across replicas.
--
-- The application claims a backfill by INSERTing its name inside the same
-- transaction that enqueues the work; the marker and the enqueued jobs commit
-- together, giving exactly-once semantics even with multiple replicas racing
-- on startup. To force a fresh one-time pass after a future change, use a new
-- name (e.g. bump a version suffix) rather than deleting rows.
CREATE TABLE IF NOT EXISTS startup_backfills (
    name         TEXT PRIMARY KEY,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
