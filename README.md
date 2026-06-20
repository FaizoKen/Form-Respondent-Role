# Form-Respondent-Role

A RoleLogic plugin that gates Discord roles behind a member-fillable form.
Server admins build a form (single-choice, multi-choice, scale, text, quiz, …);
members fill it on web; matching answers grant the bound Discord role through
the RoleLogic API.

Written in Rust (axum, sqlx, tokio). Stateless HTTP tier + N durable
job-polling workers backed by Postgres. Designed for multi-region public
deploy (1000+ guilds).

---

## Quick start (local)

You need Docker. Postgres + the plugin start together in `compose.yml`.

```bash
cp .env.example .env
# Fill in: POSTGRES_PASSWORD, SESSION_SECRET, INTERNAL_API_KEY, BASE_URL.
# Suggested generators:
#   openssl rand -base64 24    # POSTGRES_PASSWORD
#   openssl rand -base64 48    # SESSION_SECRET
#   openssl rand -hex 32       # INTERNAL_API_KEY
docker compose up --build
```

Then visit `http://localhost:8089/form-respondent-role/health` — should
return `{"status":"healthy"}`. Member-facing forms live at
`/form-respondent-role/f/{slug}`; admin builder is at
`/form-respondent-role/admin/{guild_id}`.

The Auth Gateway it talks to (cookie minting, guild-membership lookup) is a
separate service. Point `AUTH_GATEWAY_URL` at it and share `INTERNAL_API_KEY`.

## How it fits together

```
                                ┌─────────────────────────┐
                                │  RoleLogic dashboard    │
                                │  (iframes the plugin    │
                                │   on the role-config    │
                                │   page; mints rl_token  │
                                │   JWTs)                 │
                                └────────────┬────────────┘
                                             │  iframe + ?rl_token=…
                  cookie session             │
   ┌────────────┐  ──────────────►   ┌───────▼─────────────┐
   │ Discord    │                    │ Form-Respondent-    │
   │ member     │  fills form @      │ Role  (this repo)   │
   │            │  /f/{slug}  ────►  │                     │
   └────────────┘                    │  axum + sqlx        │
                                     │   ├ HTTP tier       │
                                     │   ├ job workers     │
                                     │   └ Postgres pool   │
                                     └─┬─────────────┬─────┘
                          enqueues job │             │ /auth/guild_permission,
                          on submit    │             │ /auth/internal/* via
                                       │             │ X-Internal-Key
                                       │             │
                                ┌──────▼─────┐  ┌────▼─────────┐
                                │ Postgres   │  │ Auth Gateway │
                                │ (jobs +    │  │              │
                                │  responses)│  └──────────────┘
                                └──────┬─────┘
                                       │
                                       │ workers claim FOR UPDATE
                                       │ SKIP LOCKED, dispatch by kind:
                                       │   player_sync, config_sync, webhook
                                       │
                                ┌──────▼──────────────┐
                                │ RoleLogic API       │
                                │ (PUT /users, etc.)  │
                                └─────────────────────┘
```

### Key contracts

- **Member-fill flow** — `GET /f/{slug}` renders the form; `POST /f/{slug}/submit`
  validates against the schema *as of submit time*, inserts the response,
  enqueues `player_sync` + (optional) `webhook` jobs in the same transaction,
  commits. Worker re-evaluates role conditions and calls RoleLogic to
  add/remove the user.
- **Retries & cooldown** — forms that keep a single canonical response
  (`single_submission`, which quizzes always are) can allow bounded retries:
  `max_attempts` (1 = one-shot, the default; 0 = unlimited),
  `retry_cooldown_seconds` between attempts, and `retry_policy`
  (`keep_best` — highest score wins, passing is sticky — or `keep_latest`),
  plus `lock_on_pass`. Each member keeps exactly one canonical row, so the
  per-player and per-role-link sync paths evaluate the *same* attempt; the
  submit handler takes a per-`(form, member)` `pg_advisory_xact_lock` so the
  cooldown/limit check and write are atomic against concurrent submits. The
  anti-cheat posture is unchanged — only a pass/fail bit (never the score or
  per-question correctness) is returned, and question/option order is
  shuffled per load, so retries leak at most one bit per attempt, rate-limited
  by the cooldown and capped by `max_attempts`. See
  [`migrations/009_form_retries.sql`](migrations/009_form_retries.sql) and
  [`src/services/retry.rs`](src/services/retry.rs).
- **Admin builder** — `GET /admin/{guild_id}` is the form list, `GET /admin/{guild_id}/forms/{form_id}`
  is the builder UI. CSRF: cookie-authenticated state-changing routes
  enforce an `Origin` allowlist atop the CORS allowlist. Optimistic locking
  on `forms.version` prevents two tabs from clobbering each other.
- **RoleLogic iframe** — `GET /admin/{guild_id}/role/{role_id}?rl_token=…`
  is the embeddable role-config page. The dashboard mints an HS256 JWT
  signed with the role link's API token; we verify locally (no callback),
  then mint a `ifs:`-prefixed iframe-session token bound to `(discord_id,
  guild_id, role_id)` for subsequent XHR.
- **Job queue** — `services/jobs.rs` + `tasks/job_worker.rs`. Backoff with
  jitter, terminal-vs-retry classification, DLQ (`status = 'dead'`), reaper
  that revives jobs whose worker crashed mid-claim.

## Configuration

All config lives in env vars. See [`.env.example`](.env.example) for the
full list with comments. Required:

| Var | What |
| --- | --- |
| `DATABASE_URL` | `postgres://…` |
| `SESSION_SECRET` | HMAC key for `rl_session` + iframe-session + CSRF cookies |
| `BASE_URL` | Public-facing plugin URL (https in prod, no trailing slash) |
| `INTERNAL_API_KEY` | Shared secret for plugin → Auth Gateway calls |
| `POSTGRES_PASSWORD` | Used by both the DB container and `DATABASE_URL` |

Optional but commonly set: `AUTH_GATEWAY_URL`, `ROLELOGIC_API_URL`,
`RL_DASHBOARD_ORIGIN`, `DB_MAX_CONNECTIONS`, `WORKER_CONCURRENCY`.

## Deploying

Production target is **multi-region public service, 1000+ guilds**.

1. Provision Postgres. Run migrations once via `form-respondent-role migrate`
   (the binary accepts a `migrate` subcommand that exits cleanly).
2. Deploy stateless replicas behind a load balancer.
   - LB **must** rewrite `X-Forwarded-For` / `Forwarded` to the real client IP
     (Cloudflare Tunnel and most managed LBs do this by default). The per-IP
     rate limiter uses `SmartIpKeyExtractor` and is spoofable otherwise.
   - LB should hit `/form-respondent-role/ready` for traffic gating
     (drains to 503 on SIGTERM) and `/form-respondent-role/health` for
     liveness (503 when DB is unreachable).
3. Run pgBouncer in transaction-pool mode in front of Postgres.
   Budget `replicas * DB_MAX_CONNECTIONS` ≤ pgBouncer pool size.
4. Set `RL_DASHBOARD_ORIGIN` to the dashboard's public origin so admin
   pages can be iframed.

See [OPERATIONS.md](OPERATIONS.md) for the runbook (DLQ replay, common
incidents, rate-limit tuning).

## Repo layout

```
src/
  main.rs              # Router wiring, middleware stack, signal handler
  config.rs            # AppConfig from env
  db.rs                # Pool + migrations
  error.rs             # AppError + sqlx-error → HTTP-status classifier
  schema.rs            # role-config payload parsing
  routes/
    plugin.rs          # RoleLogic /register, /config
    form_render.rs     # Member-facing GET/POST /f/{slug}
    admin.rs           # Admin builder, role-config, responses, CSV export
    respondents.rs     # Optional public respondent list
    health.rs          # /health, /ready, /favicon.ico
  services/
    jobs.rs            # Durable queue (enqueue, claim, retry, dead-letter)
    sync.rs            # Per-player + per-role-link sync engine
    rolelogic.rs       # RoleLogic API client
    auth_gateway.rs    # Auth Gateway client (/auth/internal/*)
    session.rs         # rl_session cookie verify
    rl_token.rs        # rl_token JWT + iframe-session token
    csrf.rs            # Origin allowlist check
    security_headers.rs# CSP/HSTS/nosniff/Referrer-Policy middleware
    webhook.rs         # SSRF-checked outbound delivery
    condition_eval.rs  # Rust + SQL condition evaluators
    form_validator.rs  # PUT-time and submit-time validators
  tasks/
    job_worker.rs      # Polling worker (FOR UPDATE SKIP LOCKED)
    shutdown.rs        # tokio broadcast-based shutdown
migrations/            # SQL, applied in numeric order on startup
templates/             # Hand-rolled HTML (Discord-styled dark UI)
```

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for local dev setup, migration policy
(expand→contract), code style, and the PR checklist.

Quick commands:

```bash
cargo build               # debug build
cargo test                # all unit tests
cargo clippy --no-deps --all-targets -- -D warnings
cargo fmt --all --check
docker compose up --build # full local stack
```

CI on every push/PR via [`.github/workflows/ci.yml`](.github/workflows/ci.yml):
fmt, clippy, tests, `cargo audit`, Docker build.

## Security posture

- HMAC verifications are constant-time (both `rl_session` and iframe-session).
- Rate-limited per-IP via `tower_governor` (`SmartIpKeyExtractor`).
- CSP `frame-ancestors` set on every HTML response — default-deny with admin
  pages explicitly opting into the RoleLogic dashboard origin.
- CSRF: server-side `Origin` allowlist atop the CORS allowlist; iframe-session
  Bearer flow is exempt (the token's HMAC binding IS the CSRF defense).
- Webhook SSRF: HTTPS-only, IPv4 + IPv6 private/loopback/link-local/multicast
  blocked at URL-parse time AND after DNS resolution. AWS/GCP metadata IP
  (`169.254.169.254`) explicitly blocked.
- Schema-drift protection: every response persists the `forms.version` it
  was answered against (foundation; full as-of replay is a follow-up).
- Container runs as unprivileged `app:app` UID 10001.

The original audit + roadmap that motivated the above is in
`.claude/plans/ultrathink-inspect-the-crystalline-canyon.md`.

## License

TBD.
