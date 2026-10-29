use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;

use crate::config::DbPoolConfig;

/// How long an individual pooled connection may live before being recycled.
/// Caps how long pgBouncer's server-side mapping persists and limits the
/// blast radius of a leaked-but-still-pooled connection.
const POOL_MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);

/// Prepared statements each pooled connection keeps. When the cache is full
/// sqlx closes the least recently used one, so a backend never holds more
/// plans than this.
///
/// Never set it to 0. With the cache off, sqlx 0.8 still prepares every
/// query as a new named statement (`sqlx_s_N`) and never closes it, so each
/// backend keeps one plan per query it has run until `POOL_MAX_LIFETIME`
/// recycles the connection. That OOM-killed Kick-Channel-Role's 256 MB DB
/// container on 2026-10-29. Disabling the cache never made pgBouncer
/// transaction mode safe either: a named statement is still parsed in one
/// sync and executed in the next. Behind pgBouncer, run 1.21+ with
/// `max_prepared_statements` at least this high.
const STATEMENT_CACHE_CAPACITY: usize = 100;

pub async fn create_pool(database_url: &str, cfg: &DbPoolConfig) -> PgPool {
    let connect_options = PgConnectOptions::from_str(database_url)
        .expect("invalid DATABASE_URL")
        .statement_cache_capacity(STATEMENT_CACHE_CAPACITY);

    PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .min_connections(cfg.min_connections)
        .acquire_timeout(Duration::from_secs(cfg.acquire_timeout_secs))
        .idle_timeout(Duration::from_secs(cfg.idle_timeout_secs))
        .max_lifetime(POOL_MAX_LIFETIME)
        // Skip the per-acquire `SELECT 1` liveness probe — under pgBouncer
        // the backend is short-lived anyway, and a dead-connection failure
        // surfaces at the next real query just as well. Saves one DB
        // round-trip per request.
        .test_before_acquire(false)
        .connect_with(connect_options)
        .await
        .expect("Failed to connect to PostgreSQL")
}

/// Migrations are applied in order on startup. They are idempotent
/// (`CREATE … IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`, etc.) so a replica
/// that finds them already applied is a no-op. New migrations MUST follow
/// the expand→contract pattern (additive first; breaking column drops in a
/// follow-up) so blue/green deploys never run two app versions against an
/// incompatible schema.
pub async fn run_migrations(pool: &PgPool) {
    let migrations: &[(&str, &str)] = &[
        ("001", include_str!("../migrations/001_initial_schema.sql")),
        ("002", include_str!("../migrations/002_forms.sql")),
        ("003", include_str!("../migrations/003_form_responses.sql")),
        ("004", include_str!("../migrations/004_guild_settings.sql")),
        ("005", include_str!("../migrations/005_jobs.sql")),
        ("006", include_str!("../migrations/006_indexes.sql")),
        (
            "007",
            include_str!("../migrations/007_response_schema_version.sql"),
        ),
        (
            "008",
            include_str!("../migrations/008_form_passing_score.sql"),
        ),
        ("009", include_str!("../migrations/009_form_retries.sql")),
        (
            "010",
            include_str!("../migrations/010_startup_backfill.sql"),
        ),
    ];
    for (id, sql) in migrations {
        sqlx::raw_sql(sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration {id} failed: {e}"));
    }
    tracing::info!("Applied {} migrations", migrations.len());
}
