//! Durable background-job queue backed by the `jobs` table.
//!
//! Replaces the per-process `tokio::sync::mpsc::channel`s for role sync and
//! webhook delivery so that:
//!   * events survive replica crashes / SIGTERM (durable, transactional);
//!   * any replica can pick up a job (`FOR UPDATE SKIP LOCKED`);
//!   * transient upstream failures retry with exponential backoff + jitter;
//!   * permanently-failing jobs land in a DLQ (`status = 'dead'`) instead of
//!     silently disappearing.
//!
//! See migration `005_jobs.sql` for the schema. Enqueue with `enqueue()`
//! inside the calling transaction; the job worker (`tasks::job_worker`)
//! claims and dispatches.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgExecutor, PgPool};

use crate::error::AppError;

/// Postgres NOTIFY channel that `enqueue` fires when an immediately-runnable
/// job has been inserted. `tasks::job_listener` LISTENs on this channel and
/// wakes the per-replica `Notify` that every worker selects on.
pub const JOBS_CHANNEL: &str = "jobs_pending";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    PlayerSync,
    ConfigSync,
    Webhook,
}

impl JobKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PlayerSync => "player_sync",
            Self::ConfigSync => "config_sync",
            Self::Webhook => "webhook",
        }
    }
    pub fn from_db(s: &str) -> Option<Self> {
        match s {
            "player_sync" => Some(Self::PlayerSync),
            "config_sync" => Some(Self::ConfigSync),
            "webhook" => Some(Self::Webhook),
            _ => None,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct Job {
    pub id: i64,
    pub kind: String,
    pub payload: Value,
    pub attempts: i32,
    pub max_attempts: i32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum PlayerSyncPayload {
    /// A user submitted/edited a form — re-evaluate role assignments for them.
    Updated { discord_id: String },
    /// The user unlinked their Discord — remove all assignments for them.
    Unlinked { discord_id: String },
}

// `config_sync` and `webhook` payloads are read field-by-field at dispatch
// time (see `tasks::job_worker::dispatch`); the JSON shape is documented in
// migration `005_jobs.sql`. Typed payload structs are intentionally not
// declared so adding a new field doesn't require coordinating struct +
// dispatch + caller in lockstep.

/// Enqueue a job. Pass a transaction reference when you need atomicity with
/// the surrounding write (the usual case for `post_submit`).
///
/// `delay_secs` is rolled into `next_run_at` — used by `config_sync` to
/// debounce rapid-fire saves into one delayed run.
pub async fn enqueue<'e, E>(
    executor: E,
    kind: JobKind,
    payload: Value,
    delay_secs: u64,
) -> Result<(), AppError>
where
    E: PgExecutor<'e>,
{
    // INSERT and (conditionally) NOTIFY in a single round-trip. The
    // `WHERE next_run_at <= now()` on the outer SELECT filters out delayed
    // jobs so workers aren't woken up only to find no claimable rows —
    // polling will pick those up at their scheduled time.
    sqlx::query(
        "WITH inserted AS ( \
             INSERT INTO jobs (kind, payload, next_run_at) \
             VALUES ($1, $2, now() + make_interval(secs => $3)) \
             RETURNING next_run_at \
         ) \
         SELECT pg_notify('jobs_pending', '') \
         FROM inserted WHERE next_run_at <= now()",
    )
    .bind(kind.as_str())
    .bind(payload)
    .bind(delay_secs as f64)
    .execute(executor)
    .await?;
    Ok(())
}

/// Claim up to `batch_size` pending jobs whose `next_run_at` has passed.
/// `FOR UPDATE SKIP LOCKED` keeps N workers (in the same or different
/// replicas) from contending on the same rows.
pub async fn claim_batch(
    pool: &PgPool,
    worker_id: &str,
    batch_size: i64,
) -> Result<Vec<Job>, AppError> {
    let rows = sqlx::query_as::<_, Job>(
        "UPDATE jobs SET status = 'in_progress', \
                          locked_by = $1, \
                          locked_at = now(), \
                          attempts = attempts + 1 \
         WHERE id IN ( \
             SELECT id FROM jobs \
             WHERE status = 'pending' AND next_run_at <= now() \
             ORDER BY id \
             LIMIT $2 \
             FOR UPDATE SKIP LOCKED \
         ) \
         RETURNING id, kind, payload, attempts, max_attempts",
    )
    .bind(worker_id)
    .bind(batch_size)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn complete(pool: &PgPool, id: i64) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE jobs SET status = 'completed', \
                         completed_at = now(), \
                         locked_by = NULL, \
                         locked_at = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Soft-fail: push the job back to `pending` with an exponential-backoff
/// `next_run_at`. Will be retried by whichever worker claims it next.
pub async fn fail_retry(pool: &PgPool, job: &Job, err: &str) -> Result<(), AppError> {
    let delay = backoff_delay(job.attempts);
    sqlx::query(
        "UPDATE jobs SET status = 'pending', \
                         next_run_at = now() + make_interval(secs => $1), \
                         last_error = $2, \
                         locked_by = NULL, \
                         locked_at = NULL \
         WHERE id = $3",
    )
    .bind(delay.as_secs_f64())
    .bind(err)
    .bind(job.id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Hard-fail: send to DLQ. Operator can replay manually via SQL or a future
/// admin UI.
pub async fn fail_dead(pool: &PgPool, id: i64, err: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE jobs SET status = 'dead', \
                         completed_at = now(), \
                         last_error = $1, \
                         locked_by = NULL, \
                         locked_at = NULL \
         WHERE id = $2",
    )
    .bind(err)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Reaper: revive `in_progress` rows whose locker died mid-flight (no
/// completion or retry after the lock timeout). Called periodically by the
/// job worker so a crashed replica doesn't strand work.
pub async fn reap_stuck(pool: &PgPool, max_lock_secs: i64) -> Result<u64, AppError> {
    let res = sqlx::query(
        "UPDATE jobs SET status = 'pending', \
                         next_run_at = now(), \
                         locked_by = NULL, \
                         locked_at = NULL \
         WHERE status = 'in_progress' \
           AND locked_at < now() - make_interval(secs => $1)",
    )
    .bind(max_lock_secs as f64)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Exponential backoff with up-to-1s jitter. Attempts 1..=7 sleep 2s..128s;
/// attempt 8 is capped at 256s. After 8 failures the worker dispatches to
/// `fail_dead` instead of calling this.
pub fn backoff_delay(attempt: i32) -> std::time::Duration {
    use rand::Rng;
    let capped = attempt.clamp(1, 8);
    let base_secs = 2_u64.pow(capped as u32);
    let jitter_ms = rand::thread_rng().gen_range(0..1000);
    std::time::Duration::from_millis(base_secs * 1000 + jitter_ms)
}

// ---------------------------------------------------------------------------
// Typed enqueue helpers — keeps callers from hand-rolling JSON.
// ---------------------------------------------------------------------------

pub async fn enqueue_player_sync<'e, E>(
    executor: E,
    payload: PlayerSyncPayload,
) -> Result<(), AppError>
where
    E: PgExecutor<'e>,
{
    let payload = serde_json::to_value(&payload).expect("PlayerSyncPayload serializes");
    enqueue(executor, JobKind::PlayerSync, payload, 0).await
}

/// Config-sync is debounced to absorb autosave bursts: rapid edits coalesce
/// into one re-evaluation `debounce_secs` after the last edit.
pub async fn enqueue_config_sync<'e, E>(
    executor: E,
    guild_id: &str,
    role_id: &str,
) -> Result<(), AppError>
where
    E: PgExecutor<'e>,
{
    let payload = json!({
        "guild_id": guild_id,
        "role_id": role_id,
    });
    enqueue(executor, JobKind::ConfigSync, payload, 5).await
}

pub async fn enqueue_webhook<'e, E>(executor: E, url: String, body: Value) -> Result<(), AppError>
where
    E: PgExecutor<'e>,
{
    let payload = json!({ "url": url, "body": body });
    enqueue(executor, JobKind::Webhook, payload, 0).await
}
