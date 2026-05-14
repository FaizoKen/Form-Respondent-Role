# OPERATIONS

Runbook for operating Form-Respondent-Role in production. Pair with the
high-level README.

## Probes & health

| Endpoint | Behavior | Use for |
| --- | --- | --- |
| `GET /form-respondent-role/health` | 200 if DB ping succeeds; **503** if DB unreachable | Container liveness — orchestrator restarts truly stuck pods. |
| `GET /form-respondent-role/ready` | 200 normally; **503** the instant `AppState.draining` flips (SIGTERM received) | LB traffic gating — drains replicas before HTTP actually stops. |

Both endpoints are unauthenticated and exempt from rate limiting; do NOT
expose them to the public internet from the LB if possible.

## Graceful shutdown

On SIGTERM (Unix) or Ctrl-C (Windows):

1. Signal listener sets `AppState.draining = true` → `/ready` starts
   returning 503.
2. `Shutdown::trigger()` broadcasts to:
   - axum (`with_graceful_shutdown`) — finishes in-flight HTTP, refuses new
     connections.
   - Each `tasks::job_worker::run` — finishes the current job batch, then
     for any job not yet processed, sends a `fail_retry("worker shutting
     down")` so the lock is released and another replica/cycle picks it up.
3. `main` joins all worker handles before returning.

Tune your orchestrator's `terminationGracePeriodSeconds` to at least the
longest expected job duration. Heavy `sync_for_role_link` calls can take up
to `rolelogic::COMMIT_TIMEOUT` = 30 min on very large tenants; production
deploys with such tenants should bump the grace period and/or break those
syncs into smaller chunks before scheduling node drains.

## Job queue lifecycle

```
                     enqueue (transactional with caller)
                              │
                              ▼
                        ┌──────────┐
                        │ pending  │
                        └─────┬────┘
        claim_batch (FOR UPDATE SKIP LOCKED, attempts++)
                              │
                              ▼
                        ┌──────────────┐
                        │ in_progress  │── worker crash mid-flight ──►  reap_stuck
                        └──────┬───────┘     (every 2 min)
              dispatch  ┌──────┴──────┐
                 ok ────►  completed  │
              retry  ───►  pending    │  (with next_run_at = now + backoff)
              terminal ►  dead        │
                        └─────────────┘
```

Tunables (see `services/jobs.rs`):

- `MAX_ATTEMPTS` per job = 8 (column default; can be overridden by INSERT).
- Backoff = `2^attempt` seconds + 0–1s jitter, capped at attempt 8 → 256s.
- `BATCH_SIZE` per claim = 8.
- `POLL_INTERVAL` between empty claims = 500 ms.
- `STUCK_LOCK_SECS` = 45 min — longer than the worst-case `sync_for_role_link`
  to avoid false-positive reaping.

### DLQ replay (operator SQL)

A job in `status = 'dead'` did not exceed time alive — it exceeded attempts
or hit a terminal classification (RoleLinkNotFound, UserLimitReached, 4xx
webhook). To replay manually:

```sql
-- Inspect dead jobs.
SELECT id, kind, payload, attempts, last_error, completed_at
FROM jobs
WHERE status = 'dead'
ORDER BY completed_at DESC
LIMIT 50;

-- Replay one by id.
UPDATE jobs
SET status = 'pending',
    attempts = 0,
    next_run_at = now(),
    last_error = NULL,
    completed_at = NULL
WHERE id = 12345 AND status = 'dead';

-- Replay all dead jobs of a kind (use with care — usually one at a time).
UPDATE jobs
SET status = 'pending',
    attempts = 0,
    next_run_at = now(),
    last_error = NULL,
    completed_at = NULL
WHERE status = 'dead' AND kind = 'webhook';
```

Before mass replay, check the `last_error` patterns — replaying a
genuinely-broken webhook URL will just refill the DLQ.

### Stuck-job reaper

Runs inside every job worker every 2 minutes. Reverts any `in_progress`
row whose `locked_at < now() - 45 min` back to `pending` and clears
`locked_by`. Logs the count via `tracing::warn!`.

If you see this reap count spiking, a worker is crashing mid-claim. Check
worker process logs around the `locked_by` value to find which replica.

## Rate limiting

Per-IP via `tower_governor` (`SmartIpKeyExtractor`):

- 5 requests/sec sustained, burst 20.
- The reverse proxy in front MUST overwrite `X-Forwarded-For` / `Forwarded` with
  the real client IP. Cloudflare Tunnel and most managed LBs do this by
  default. **Verify with `curl -H "X-Forwarded-For: 1.2.3.4" …` against a
  staging deploy — the limiter should bucket by `1.2.3.4`, not by the
  proxy's IP.**
- A periodic background task calls `governor_limiter.retain_recent()` every
  60 seconds to GC dead IPs from the limiter's in-memory store.

To tighten `/submit` or loosen `/admin` paths, split the router (see plan's
Phase 0.1 follow-up; currently a single global limiter).

## DB pool tuning

Knobs (env, defaults in parens):

- `DB_MAX_CONNECTIONS` (16)
- `DB_MIN_CONNECTIONS` (2)
- `DB_ACQUIRE_TIMEOUT_SECS` (5)
- `DB_IDLE_TIMEOUT_SECS` (600)
- `WORKER_CONCURRENCY` (4)

Budget guidance:

- Behind pgBouncer in transaction-pool mode: replicas × `DB_MAX_CONNECTIONS`
  ≤ pgBouncer pool size. Each replica's `WORKER_CONCURRENCY` shares the
  pool with the HTTP tier; cap workers to ~half the pool so admin pages
  don't starve under sync load.
- No pgBouncer: budget conservatively against raw Postgres `max_connections`.
  The default Postgres ships with `max_connections = 100`, and Form-Respondent-Role's
  `compose.yml` sets `max_connections = 15` for the local dev container —
  *that local cap is intentional and must be raised in prod*.

## Observability

- All HTTP requests get an `x-request-id` (UUIDv4 if upstream didn't send
  one). Logs include this; correlate across layers by grepping.
- `tracing` is structured. Suggested fields when raising issues from logs:
  `worker_id`, `job_id`, `guild_id`, `role_id`, `discord_id`, `form_id`.
- `Authorization`, `Cookie`, and `X-Internal-Key` are marked sensitive —
  they're redacted to `<sensitive>` in `TraceLayer` output even at DEBUG.
- Metrics endpoint (`/metrics`) and OpenTelemetry exporter are NOT yet
  wired up. Use structured logs as the primary signal until that phase
  lands.

## Common incidents

### Auth Gateway is down or slow

Symptoms: `/f/{slug}` GET returns "We couldn't verify your server membership
right now, please refresh in a moment"; admin pages get
"Could not verify your permissions for this guild."

Caused by `/auth/guild_permission` or `/auth/internal/*` failing. Plugin
surfaces the error rather than silently denying access (Phase 0.9 fix).

Mitigations:
- Auto-recovers when gateway returns. No manual replay needed.
- If gateway will be down >5 min, consider showing a maintenance banner.

### RoleLogic API is down

Symptoms: `player_sync` and `config_sync` jobs accumulate in `status =
'in_progress'` and then bounce to `pending` with `last_error` containing
"RoleLogic API error". `attempts` climbs on each retry.

Mitigations:
- Backoff curve maxes around 4–5 minutes; transient outages auto-resolve.
- If the outage is >40 min, jobs will start going to `dead` (attempts ≥ 8).
  After RoleLogic recovers, replay the DLQ with the SQL above.

### Postgres failover

Symptoms: `/health` flips to 503; HTTP traffic 502s; workers log
connection errors.

Mitigations:
- Replicas eventually re-establish pool connections.
- `/ready` does NOT flip on Postgres outage (it tracks shutdown, not DB).
  If you want LB draining on DB outage too, point the LB's health probe at
  `/health` instead of `/ready`.
- After failover, in-progress jobs whose connection was killed get reaped
  after 45 min. To speed recovery, manually:
  ```sql
  UPDATE jobs SET status='pending', locked_by=NULL, locked_at=NULL, next_run_at=now()
  WHERE status='in_progress' AND locked_at < now() - interval '5 minutes';
  ```

### Webhook target keeps returning 5xx

Symptoms: a guild's `webhook` jobs cycle through retry → fail; admins
complain about missing notifications.

The job worker treats 5xx as retry-able; after 8 attempts the job is dead.
`last_error` will say `webhook returned 5XX`.

Mitigations:
- Confirm the URL is reachable from the deploy: `curl -X POST -H 'content-type:
  application/json' -d '{}' <url>`. Often the admin pasted a Discord webhook
  that was later deleted.
- If the URL is bad, the admin should fix it in the form builder; future
  submissions will use the new URL. Old DLQ rows are deliverable to the
  *original* URL only — discard them rather than replaying.

### Queue depth growing

```sql
SELECT kind, count(*), min(created_at) AS oldest
FROM jobs
WHERE status = 'pending'
GROUP BY kind;
```

If `pending` is growing faster than workers can drain:

- Scale `WORKER_CONCURRENCY` up. Beware DB pool budget (above).
- Add replicas (each runs its own worker pool — they share work via
  `SKIP LOCKED`).
- Inspect for a single slow `sync_for_role_link` call hogging a worker —
  large tenants can take minutes. Worker logs will show the locking job.

### Rate limiter blocking real users

The default 5/sec burst 20 is generous for individuals but tight for shared
IPs (NAT gateways, ISPs in countries with single-IP egress). If you see
many `429 Too Many Requests` for legit member submissions, raise
`burst_size` and/or `per_second` in `main.rs` and redeploy. Per-route
tightening of `/submit` vs looser `/admin` is the follow-up direction.

## Migrations

- Applied automatically on every startup, in numeric order, idempotent
  (`CREATE … IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`).
- For blue-green / canary rollouts, run `form-respondent-role migrate`
  once as a pre-deploy step. The binary applies migrations and exits with
  status 0.
- New migrations MUST follow the **expand → contract** pattern: additive
  in the version that ships first; only break old shapes in a later
  version once all replicas of the old version are gone. See
  `migrations/007_response_schema_version.sql` for the canonical example
  (add column, backfill, mark NOT NULL).

## Secrets

- `SESSION_SECRET` rotation: invalidates all live `rl_session` and
  iframe-session tokens. Members re-log via the Auth Gateway. Admins
  reload the iframe. Plan rotation outside peak hours.
- `INTERNAL_API_KEY` rotation: must be done atomically across Auth Gateway
  and every plugin replica or `/auth/internal/*` calls will 401. Use a
  two-key window (gateway accepts both old and new for a transition) if
  the gateway supports it.
- `DATABASE_URL` password rotation: standard Postgres password change +
  rolling restart of replicas with the new value.

`.env` is in `.gitignore` and `.dockerignore`. Production secrets should
live in the orchestrator's secret store, not on the deploy host's disk.
