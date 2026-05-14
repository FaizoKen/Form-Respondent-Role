# CONTRIBUTING

## Stack

- **Rust** (edition 2021, latest stable).
- **axum 0.8** for HTTP, **sqlx 0.8** for Postgres, **tokio** runtime.
- Hand-rolled HTML templates in `templates/` — no framework. Vanilla JS.
- Docker for local Postgres; `compose.yml` brings up both services.

## Local dev

```bash
# 1. Copy and fill .env
cp .env.example .env
# Generate secrets:
#   openssl rand -base64 24    # POSTGRES_PASSWORD
#   openssl rand -base64 48    # SESSION_SECRET
#   openssl rand -hex 32       # INTERNAL_API_KEY
# Set BASE_URL=http://localhost:8089/form-respondent-role for local

# 2. Bring up Postgres + plugin
docker compose up --build

# Or, run the plugin on the host against a containerized DB:
docker compose up db
cargo run
```

Iterating without a full rebuild:

```bash
cargo run                         # debug build, runs migrations on start
cargo run -- migrate              # migrate only, exit cleanly
cargo watch -x run                # if you have cargo-watch installed
```

## What to run before opening a PR

```bash
cargo fmt --all --check
cargo clippy --no-deps --all-targets -- -D warnings
cargo test
```

CI runs all three plus `cargo audit` and a Docker build on every push/PR
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)). Don't merge red.

## Repository conventions

Several conventions are enforced by reviewers; the high-leverage ones:

- **Layered architecture**: routes are HTTP-thin (parse, dispatch, render).
  Logic lives in `services/`. Data shapes live in `models/`. Don't merge
  layers — a route handler shouldn't talk to the DB directly except for
  trivial reads.
- **Every read of a multi-tenant table must filter by `guild_id`** (or by a
  parent column whose ownership is provably scoped). Adding a SELECT
  without that filter to `forms` / `form_responses` / `role_links` /
  `role_assignments` will trip review.
- **HMAC and token comparisons MUST be constant-time** —
  `crate::services::rl_token::constant_time_eq`. Never `==` on a signature.
- **State-changing routes**: cookie-authenticated POST/PUT/DELETE handlers
  must call `csrf::verify_origin(&headers, &state.allowed_origins)?` after
  `require_manager`. The Bearer-token (iframe-session) flow is exempt.
- **Outbound HTTP to admin-supplied URLs**: always go through
  `services::webhook::deliver_once` (which does the SSRF check). Never
  invoke `reqwest::Client::post` directly on a URL the admin pasted.
- **Don't reintroduce `tokio::spawn` for "fire-and-forget" side effects**
  that have to survive a SIGTERM. Enqueue a job via `services::jobs`
  inside the caller's transaction instead. Workers in `tasks::job_worker`
  pick it up.

## Adding a migration

1. Create `migrations/NNN_short_name.sql` with the next number. **All SQL
   must be idempotent**: `CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT
   EXISTS`, `CREATE INDEX IF NOT EXISTS`, `UPDATE … WHERE col IS NULL`.
2. Wire it into `db::run_migrations` (the `migrations` slice).
3. Follow **expand → contract**: ship additive changes first (new column
   added as NULL or with a default; backfill; only mark NOT NULL once
   all replicas of the old version are gone). See
   `migrations/007_response_schema_version.sql` for the pattern.
4. Document the migration intent in a block comment at the top of the
   `.sql` file — what the column is for, why it was added.

Never write a destructive migration (`DROP TABLE`, `DROP COLUMN`, narrowing
column types) without an explicit rollout plan documented in the PR
description. Blue-green and canary deploys run both versions side by side
during the rollout; a breaking schema change must wait until the old
version is gone.

## Adding a job kind

1. Add a variant to `JobKind` in `services/jobs.rs` and update the
   `as_str` / `from_db` mappings.
2. Document the payload shape in the comment block in
   `migrations/005_jobs.sql`.
3. Add a typed `enqueue_<kind>` helper alongside the existing ones so
   callers don't hand-roll the payload JSON.
4. Add a `JobKind::Foo => …` arm in `tasks::job_worker::dispatch` that
   parses the payload and dispatches. Map errors via the `JobError::Terminal`
   vs `Retry` discriminator: terminal failures go straight to DLQ; only
   genuinely-recoverable errors should retry.

## Adding an admin endpoint

The pattern (state-changing):

```rust
pub async fn my_endpoint(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
    Json(body): Json<MyBody>,
) -> Result<Json<Value>, AppError> {
    csrf::verify_origin(&headers, &state.allowed_origins)?;
    require_manager(&state, &jar, &guild_id).await?;
    // … your work, scoped to guild_id …
    Ok(Json(json!({"success": true})))
}
```

Wire it in `main.rs`'s router with the right HTTP verb. Don't forget to
add `headers: HeaderMap` to the function signature — that's how the
Origin check sees the incoming request.

## Testing strategy

Unit tests live next to the code in `#[cfg(test)] mod tests { … }`. The
security-critical modules have coverage; if you change them, run
`cargo test` and add cases for the behavior change.

Adding a test:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_of_invariant() {
        // arrange
        // act
        // assert
    }
}
```

Integration tests (full HTTP flow against a real DB) are not yet wired up
— see Phase 4 in `.claude/plans/ultrathink-inspect-the-crystalline-canyon.md`
for the planned shape.

## Code style

- `cargo fmt` is authoritative. Don't manually format around it.
- `clippy --all-targets -- -D warnings` must pass. If a lint is genuinely
  wrong for a case, `#[allow(clippy::name_of_lint)]` on the smallest
  possible scope with a comment explaining why.
- Comments document **why**, not **what**. Identifiers do the "what".
- Don't introduce new dependencies without a justification line in the
  PR. The dep set is intentionally tight.
- Don't add `unsafe` blocks. There's exactly zero in this codebase and
  any new ones need a strong case in review.

## PR checklist

Before requesting review:

- [ ] `cargo fmt --all --check` passes.
- [ ] `cargo clippy --no-deps --all-targets -- -D warnings` passes.
- [ ] `cargo test` passes.
- [ ] If you added a migration, it follows expand→contract and is
      idempotent.
- [ ] If you added an admin endpoint, it filters by `guild_id` and
      enforces CSRF where appropriate.
- [ ] If you added an outbound HTTP call to a user-supplied URL, it goes
      through `webhook::deliver_once` (or has an equivalent SSRF check).
- [ ] If you persisted secrets or PII, the trace layer redacts them and
      the log lines don't carry them.
- [ ] PR description names the threat-model / scaling / UX dimension the
      change moves on. "Refactor for cleanliness" is fine, but say so.

## What we explicitly don't do

(These come up in PRs more often than you'd expect. They're settled
decisions; reopen them only with new evidence.)

- No PCRE-style regex engine — we use the `regex` crate specifically
  because it's linear-time. Adding `fancy-regex` or anything similar
  reintroduces ReDoS risk.
- No async DB pool except sqlx. No diesel, no sea-orm.
- No template engine — `replace("__MARKER__", …)` is ugly but tractable
  and keeps the build dep-light. If you propose a template engine, also
  propose how it handles the CSP nonce work (Phase 4.4).
- No new outbound HTTP client. Everything goes through the shared
  `reqwest::Client` on `AppState` so timeout/connection-pool tuning lives
  in one place.
- No fire-and-forget `tokio::spawn` for work that has to survive a
  deploy. See the jobs-queue rule above.
