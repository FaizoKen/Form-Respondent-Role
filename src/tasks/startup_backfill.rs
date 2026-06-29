//! One-time startup backfills.
//!
//! Each named backfill runs exactly once across all boots and replicas: the
//! marker INSERT and the work it enqueues commit in a single transaction
//! (`ON CONFLICT DO NOTHING` makes every later caller a no-op). See migration
//! `010_startup_backfill.sql`.

use crate::AppState;

/// Marker for the membership-model resync. When the bulk sync switched from
/// gating respondents on the gateway's OAuth member cache to "all respondents
/// minus opt-outs" (so members who never opened the RoleLogic dashboard still
/// get their role), every existing role link needed one full re-evaluation —
/// but only that link's own admin can press Save, and most can't reach the
/// others. This backfill enqueues that resync for every form-bound link once.
///
/// Bump the version suffix to force a fresh one-time pass after a future change
/// that again needs every link re-evaluated.
const MEMBERSHIP_RESYNC: &str = "membership_model_resync_v1";

/// Run all pending one-time backfills. Best-effort: failures are logged, never
/// fatal — the server still starts, and an un-run backfill is retried on the
/// next boot (the marker is only written when the work is durably enqueued).
pub async fn run(state: &AppState) {
    resync_all_form_links(state).await;
}

/// Claim [`MEMBERSHIP_RESYNC`] and, if this is the first run, enqueue a debounced
/// `config_sync` for every role link bound to a form. The marker and the jobs
/// are written in one transaction, so we either enqueue the whole set exactly
/// once or not at all.
async fn resync_all_form_links(state: &AppState) {
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!("startup backfill: begin tx failed: {e}");
            return;
        }
    };

    // Claim atomically. rows_affected() == 0 means a previous boot (or another
    // replica, just now) already ran it — nothing to do.
    let claimed = match sqlx::query(
        "INSERT INTO startup_backfills (name) VALUES ($1) ON CONFLICT DO NOTHING",
    )
    .bind(MEMBERSHIP_RESYNC)
    .execute(&mut *tx)
    .await
    {
        Ok(r) => r.rows_affected() == 1,
        Err(e) => {
            tracing::error!("startup backfill: marker insert failed: {e}");
            let _ = tx.rollback().await;
            return;
        }
    };

    if !claimed {
        let _ = tx.rollback().await;
        return;
    }

    // Enqueue one config_sync per form-bound link, in the same transaction as
    // the marker. Payload + 5s debounce delay mirror `jobs::enqueue_config_sync`
    // so the worker dispatches these identically to a manual Save.
    let enqueued = match sqlx::query(
        "INSERT INTO jobs (kind, payload, next_run_at) \
         SELECT 'config_sync', \
                jsonb_build_object('guild_id', guild_id, 'role_id', role_id), \
                now() + make_interval(secs => 5) \
         FROM role_links \
         WHERE form_id IS NOT NULL",
    )
    .execute(&mut *tx)
    .await
    {
        Ok(r) => r.rows_affected(),
        Err(e) => {
            tracing::error!("startup backfill: enqueue resync failed: {e}");
            let _ = tx.rollback().await;
            return;
        }
    };

    match tx.commit().await {
        Ok(_) => tracing::info!(
            backfill = MEMBERSHIP_RESYNC,
            links = enqueued,
            "startup backfill: enqueued full resync for all form-bound role links"
        ),
        // Commit failed → marker not written → the backfill re-runs next boot.
        Err(e) => tracing::error!("startup backfill: commit failed: {e}"),
    }
}
