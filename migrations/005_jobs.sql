-- Durable background-job queue.
--
-- Replaces the per-process `tokio::sync::mpsc::channel` so events survive
-- replica crashes, can be picked up by any replica, and never silently drop
-- on SIGTERM. Workers claim rows with `FOR UPDATE SKIP LOCKED` so N replicas
-- drain in parallel without double-processing.
--
-- `kind` discriminates the payload shape:
--   * 'player_sync'  → {"discord_id": "...", "event": "updated"|"unlinked"}
--   * 'config_sync'  → {"guild_id": "...", "role_id": "..."}
--   * 'webhook'      → {"url": "...", "payload": {...}}
--
-- Lifecycle: pending → in_progress → (completed|failed→pending|dead).
-- 'completed' rows are kept briefly for observability then GC'd.

CREATE TABLE IF NOT EXISTS jobs (
    id              BIGSERIAL PRIMARY KEY,
    kind            TEXT NOT NULL,
    payload         JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 8,
    next_run_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT,
    locked_by       TEXT,
    locked_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    CONSTRAINT jobs_status_check
        CHECK (status IN ('pending','in_progress','completed','dead'))
);

-- Hot path: workers poll for pending rows ordered by next_run_at. Partial
-- index keeps the working set tiny even when there are many completed rows.
CREATE INDEX IF NOT EXISTS idx_jobs_pending_next_run
    ON jobs (next_run_at)
    WHERE status = 'pending';

-- For operator dashboards / DLQ replay tooling.
CREATE INDEX IF NOT EXISTS idx_jobs_dead_recent
    ON jobs (completed_at DESC)
    WHERE status = 'dead';

-- Detect stuck-in-progress rows (worker crashed after claiming but before
-- finishing). A reaper task can flip these back to pending.
CREATE INDEX IF NOT EXISTS idx_jobs_locked
    ON jobs (locked_at)
    WHERE status = 'in_progress';
