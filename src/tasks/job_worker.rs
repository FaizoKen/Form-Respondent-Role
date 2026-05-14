//! Job-polling worker. Replaces the legacy mpsc-based player_sync_worker
//! and config_sync_worker. N worker tasks (set by `WORKER_CONCURRENCY`) run
//! in parallel; each claims a batch via `FOR UPDATE SKIP LOCKED` and
//! dispatches by job kind. Workers stop accepting new work on shutdown but
//! finish whatever's in-flight.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::error::AppError;
use crate::services::jobs::{self, Job, JobKind, PlayerSyncPayload};
use crate::services::sync;
use crate::tasks::shutdown::ShutdownGuard;
use crate::AppState;

/// Fallback poll interval. With LISTEN/NOTIFY wired in (see
/// `tasks::job_listener`) the worker wakes within milliseconds of a job
/// being enqueued, so polling only needs to catch the rare missed
/// notification (reconnect window, pgBouncer transaction-mode quirks) and
/// delayed jobs whose `next_run_at` is in the future. 2 s is a balance
/// between idle DB load and worst-case pickup latency for delayed jobs.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const BATCH_SIZE: i64 = 8;
/// Reap any in_progress job whose lock has been held longer than this.
/// Slightly larger than the longest legitimate sync (heavy role_link can
/// take ~30 min on extreme tenants per `rolelogic::COMMIT_TIMEOUT`).
const STUCK_LOCK_SECS: i64 = 60 * 45;

pub async fn run(state: Arc<AppState>, mut shutdown: ShutdownGuard, worker_id: String) {
    tracing::info!(worker_id, "Job worker started");

    let mut last_reap = std::time::Instant::now();
    let reap_every = Duration::from_secs(120);

    loop {
        // Cheap, non-async check before each pull.
        if shutdown.is_triggered() {
            break;
        }

        // Periodically un-stick jobs whose worker crashed mid-claim.
        if last_reap.elapsed() >= reap_every {
            if let Ok(n) = jobs::reap_stuck(&state.pool, STUCK_LOCK_SECS).await {
                if n > 0 {
                    tracing::warn!(reaped = n, "Reaped stuck-in-progress jobs");
                }
            }
            last_reap = std::time::Instant::now();
        }

        let claimed = match jobs::claim_batch(&state.pool, &worker_id, BATCH_SIZE).await {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(worker_id, "claim_batch failed: {e}");
                tokio::select! {
                    _ = tokio::time::sleep(POLL_INTERVAL) => {}
                    _ = shutdown.wait() => break,
                }
                continue;
            }
        };

        if claimed.is_empty() {
            // Wake on either: a NOTIFY relayed by `tasks::job_listener`, the
            // fallback poll timer, or shutdown. The notification path is the
            // common case in production (sub-ms latency); the timer is a
            // safety net for missed notifications and delayed-runtime jobs.
            tokio::select! {
                _ = state.jobs_notify.notified() => continue,
                _ = tokio::time::sleep(POLL_INTERVAL) => continue,
                _ = shutdown.wait() => break,
            }
        }

        for job in claimed {
            if shutdown.is_triggered() {
                // Release lock so another replica can pick this up after the
                // reaper interval; we just bumped `attempts` so backoff still
                // protects against a hot loop on shutdown-restart cycles.
                if let Err(e) = jobs::fail_retry(&state.pool, &job, "worker shutting down").await {
                    tracing::error!(job.id, "failed to release job during shutdown: {e}");
                }
                continue;
            }

            let kind_for_log = job.kind.clone();
            let job_id = job.id;
            match dispatch(&job, &state).await {
                Ok(()) => {
                    if let Err(e) = jobs::complete(&state.pool, job_id).await {
                        tracing::error!(job_id, "complete failed: {e}");
                    }
                }
                Err(outcome) => match outcome {
                    JobError::Terminal(msg) => {
                        tracing::error!(job_id, kind = %kind_for_log, "Job dead (terminal): {msg}");
                        let _ = jobs::fail_dead(&state.pool, job_id, &msg).await;
                    }
                    JobError::Retry(msg) => {
                        if job.attempts >= job.max_attempts {
                            tracing::error!(
                                job_id,
                                kind = %kind_for_log,
                                attempts = job.attempts,
                                "Job dead (max attempts exceeded): {msg}"
                            );
                            let _ = jobs::fail_dead(&state.pool, job_id, &msg).await;
                        } else {
                            tracing::warn!(
                                job_id,
                                kind = %kind_for_log,
                                attempts = job.attempts,
                                "Job failed, will retry: {msg}"
                            );
                            let _ = jobs::fail_retry(&state.pool, &job, &msg).await;
                        }
                    }
                },
            }
        }
    }

    tracing::info!(worker_id, "Job worker drained and stopping");
}

/// Distinguish "give up forever" from "try again later". Lets the worker
/// short-circuit DLQ promotion when the cause clearly won't change (e.g. the
/// role link was deleted upstream).
enum JobError {
    Terminal(String),
    Retry(String),
}

impl From<AppError> for JobError {
    fn from(e: AppError) -> Self {
        match e {
            AppError::RoleLinkNotFound => {
                JobError::Terminal("role link no longer exists upstream".into())
            }
            AppError::UserLimitReached { limit } => JobError::Terminal(format!(
                "role link user limit reached ({limit}); retry won't help"
            )),
            other => JobError::Retry(other.to_string()),
        }
    }
}

async fn dispatch(job: &Job, state: &AppState) -> Result<(), JobError> {
    let kind = JobKind::from_db(&job.kind)
        .ok_or_else(|| JobError::Terminal(format!("unknown job kind '{}'", job.kind)))?;

    match kind {
        JobKind::PlayerSync => {
            let payload: PlayerSyncPayload = serde_json::from_value(job.payload.clone())
                .map_err(|e| JobError::Terminal(format!("invalid player_sync payload: {e}")))?;
            match payload {
                PlayerSyncPayload::Updated { discord_id } => {
                    sync::sync_for_player(&discord_id, state).await?;
                }
                PlayerSyncPayload::Unlinked { discord_id } => {
                    sync::remove_all_assignments(&discord_id, state).await?;
                }
            }
        }
        JobKind::ConfigSync => {
            let guild_id = job
                .payload
                .get("guild_id")
                .and_then(Value::as_str)
                .ok_or_else(|| JobError::Terminal("config_sync payload missing guild_id".into()))?;
            let role_id = job
                .payload
                .get("role_id")
                .and_then(Value::as_str)
                .ok_or_else(|| JobError::Terminal("config_sync payload missing role_id".into()))?;
            sync::sync_for_role_link(guild_id, role_id, state).await?;
        }
        JobKind::Webhook => {
            let url = job
                .payload
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| JobError::Terminal("webhook payload missing url".into()))?;
            let body = job
                .payload
                .get("body")
                .cloned()
                .ok_or_else(|| JobError::Terminal("webhook payload missing body".into()))?;
            crate::services::webhook::deliver_once(&state.http, url, &body)
                .await
                .map_err(|reason| {
                    // The webhook delivery layer classifies its own errors.
                    if reason.terminal {
                        JobError::Terminal(reason.message)
                    } else {
                        JobError::Retry(reason.message)
                    }
                })?;
        }
    }
    Ok(())
}
