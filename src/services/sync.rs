//! Sync engine — both per-player (lightweight) and per-role-link (bulk).
//!
//! The functions in this module are the dispatch targets for jobs claimed
//! by [`crate::tasks::job_worker`]. Job payloads (`PlayerSyncPayload`,
//! `ConfigSyncPayload`) live in [`crate::services::jobs`].

use std::collections::{BTreeSet, HashSet};

use futures_util::stream::{self, StreamExt};
use futures_util::TryStreamExt;
use serde_json::Value;

use crate::error::AppError;
use crate::models::condition::Condition;
use crate::services::auth_gateway;
use crate::services::condition_eval::{self, ResponseEvalData};
use crate::AppState;

// ---------------------------------------------------------------------------
// Per-player sync
// ---------------------------------------------------------------------------

pub async fn sync_for_player(discord_id: &str, state: &AppState) -> Result<(), AppError> {
    let pool = &state.pool;
    let rl_client = &state.rl_client;

    let gateway_guilds = auth_gateway::fetch_user_guild_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        discord_id,
    )
    .await?;

    // The gateway list only covers guilds this user is in *and that RoleLogic
    // has cached via OAuth*. A respondent who completed a form but never opened
    // the RoleLogic dashboard is absent from it, so per-player sync would never
    // grant their role until a full per-role-link rebuild ran. Union in every
    // guild where the user has a form_response; opt-outs are vetted below, for
    // all of them alike.
    let respondent_guilds: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT guild_id FROM form_responses WHERE discord_id = $1")
            .bind(discord_id)
            .fetch_all(pool)
            .await?;

    let existing: HashSet<(String, String)> = sqlx::query_as::<_, (String, String)>(
        "SELECT guild_id, role_id FROM role_assignments WHERE discord_id = $1",
    )
    .bind(discord_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();

    let mut candidate_guilds: BTreeSet<String> = gateway_guilds.into_iter().collect();
    candidate_guilds.extend(respondent_guilds);
    // Every guild we've already granted in, too — otherwise we can grant a role
    // we can never take back. Deleting a member's response drops that guild
    // from `respondent_guilds`, and the admin delete handler enqueues a
    // player_sync precisely to revoke the role; without the assignment's own
    // guild in scope the link is never examined and the revoke silently no-ops,
    // leaving it to the next config save. Anything we assigned stays reachable.
    candidate_guilds.extend(existing.iter().map(|(g, _)| g.clone()));

    if candidate_guilds.is_empty() {
        return Ok(());
    }
    let candidate_guilds: Vec<String> = candidate_guilds.into_iter().collect();

    // role_links bound to a form, in any guild this user qualifies for.
    let role_links = sqlx::query_as::<_, (String, String, String, String, bool, Value)>(
        "SELECT rl.guild_id, rl.role_id, rl.api_token, rl.form_id, rl.grant_on_any_submission, rl.conditions \
         FROM role_links rl \
         WHERE rl.guild_id = ANY($1) AND rl.form_id IS NOT NULL",
    )
    .bind(&candidate_guilds[..])
    .fetch_all(pool)
    .await?;

    if role_links.is_empty() {
        return Ok(());
    }

    // Vet EVERY guild that has a link for an opt-out, not just the ones the
    // gateway didn't return.
    //
    // `fetch_user_guild_ids` is passed this plugin's slug and is documented to
    // drop guilds the user opted out of, which is why gateway-returned guilds
    // used to be trusted unvetted. But `sync_for_role_link` doesn't take that
    // on faith — it subtracts `fetch_guild_optout_ids` itself. Two paths
    // deciding the same question from different sources is the exact shape of
    // the bug that made these two hand a role back and forth: if the gateway
    // ever stops honouring the `plugin` scope, the bulk sync drops the
    // opted-out member and this one puts them straight back, forever. Asking
    // the same authority the bulk path asks costs one round-trip per
    // *configured* guild and removes the assumption entirely.
    //
    // Narrowed to guilds with a form-bound link first: a user in 50 servers,
    // one of which runs this plugin, pays for one lookup rather than 50.
    //
    // Convention 40: an opt-out lookup error bubbles up and the job retries —
    // a gateway blip must never read as "nobody opted out".
    let link_guilds: BTreeSet<String> = role_links.iter().map(|(g, ..)| g.clone()).collect();
    let mut opted_out: HashSet<String> = HashSet::new();
    for guild_id in &link_guilds {
        let optouts = auth_gateway::fetch_guild_optout_ids(
            &state.http,
            &state.config.auth_gateway_url,
            &state.config.internal_api_key,
            guild_id,
        )
        .await?;
        if optouts.iter().any(|o| o == discord_id) {
            opted_out.insert(guild_id.clone());
        }
    }

    enum Action {
        Add {
            guild_id: String,
            role_id: String,
            api_token: String,
        },
        Remove {
            guild_id: String,
            role_id: String,
            api_token: String,
        },
    }

    let mut actions: Vec<Action> = Vec::new();
    for (guild_id, role_id, api_token, form_id, grant_any, raw_conditions) in &role_links {
        // Opted out of this plugin in this guild → qualifies for nothing here.
        // `sync_for_role_link` subtracts the same people from the set it
        // uploads, so matching it means the opt-out sticks instead of the two
        // paths reversing each other. It also lands on the member's next form
        // interaction rather than waiting for someone to re-save the config.
        let qualifies = if opted_out.contains(guild_id) {
            false
        } else {
            // Evaluate ALL of this user's responses to the form and qualify on
            // any match — the same semantics as the bulk sync, which collects
            // every respondent with a qualifying row. Retry-governed and
            // editable forms keep one canonical row per member, so this only
            // changes behaviour on unlimited multi-row forms, where the old
            // latest-row-only check would revoke a role the bulk sync had
            // granted from an earlier qualifying submission (grant/revoke
            // flapping).
            let resp_rows = sqlx::query_as::<_, (Value, Option<i32>)>(
                "SELECT answers, total_score FROM form_responses \
                 WHERE form_id = $1 AND discord_id = $2",
            )
            .bind(form_id)
            .bind(discord_id)
            .fetch_all(pool)
            .await?;

            let conditions: Vec<Condition> = raw_conditions
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| serde_json::from_value::<Condition>(v.clone()).ok())
                .collect();

            resp_rows.iter().any(|(answers, total_score)| {
                let data = ResponseEvalData {
                    answers,
                    total_score: total_score.map(i64::from),
                };
                condition_eval::evaluate(*grant_any, &conditions, &data)
            })
        };

        let currently_assigned = existing.contains(&(guild_id.clone(), role_id.clone()));
        match (qualifies, currently_assigned) {
            (true, false) => actions.push(Action::Add {
                guild_id: guild_id.clone(),
                role_id: role_id.clone(),
                api_token: api_token.clone(),
            }),
            (false, true) => actions.push(Action::Remove {
                guild_id: guild_id.clone(),
                role_id: role_id.clone(),
                api_token: api_token.clone(),
            }),
            _ => {}
        }
    }

    if actions.is_empty() {
        return Ok(());
    }

    let discord_id_owned = discord_id.to_string();
    stream::iter(actions)
        .for_each_concurrent(10, |action| {
            let pool = pool.clone();
            let rl_client = rl_client.clone();
            let discord_id = discord_id_owned.clone();
            async move {
                match action {
                    Action::Add {
                        guild_id,
                        role_id,
                        api_token,
                    } => {
                        match rl_client
                            .add_user(&guild_id, &role_id, &discord_id, &api_token)
                            .await
                        {
                            Err(AppError::RoleLinkNotFound) => {
                                delete_orphan_role_link(&guild_id, &role_id, &pool).await;
                                return;
                            }
                            // Disabled link: skip silently, leave config intact.
                            Err(AppError::RoleLinkDisabled) => return,
                            Err(AppError::UserLimitReached { limit }) => {
                                tracing::warn!(
                                    guild_id,
                                    role_id,
                                    discord_id,
                                    limit,
                                    "Cannot add user: role link user limit reached"
                                );
                                return;
                            }
                            Err(e) => {
                                tracing::error!(
                                    guild_id,
                                    role_id,
                                    discord_id,
                                    "Failed to add user to role: {e}"
                                );
                                return;
                            }
                            Ok(_) => {}
                        }
                        if let Err(e) = sqlx::query(
                            "INSERT INTO role_assignments (guild_id, role_id, discord_id) \
                             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                        )
                        .bind(&guild_id)
                        .bind(&role_id)
                        .bind(&discord_id)
                        .execute(&pool)
                        .await
                        {
                            tracing::error!(
                                guild_id,
                                role_id,
                                discord_id,
                                "Failed to insert role_assignment: {e}"
                            );
                        }
                    }
                    Action::Remove {
                        guild_id,
                        role_id,
                        api_token,
                    } => {
                        match rl_client
                            .remove_user(&guild_id, &role_id, &discord_id, &api_token)
                            .await
                        {
                            Err(AppError::RoleLinkNotFound) => {
                                delete_orphan_role_link(&guild_id, &role_id, &pool).await;
                                return;
                            }
                            // Disabled link: skip silently, leave config intact.
                            Err(AppError::RoleLinkDisabled) => return,
                            Err(e) => {
                                tracing::error!(
                                    guild_id,
                                    role_id,
                                    discord_id,
                                    "Failed to remove user from role: {e}"
                                );
                                return;
                            }
                            Ok(_) => {}
                        }
                        if let Err(e) = sqlx::query(
                            "DELETE FROM role_assignments \
                             WHERE guild_id = $1 AND role_id = $2 AND discord_id = $3",
                        )
                        .bind(&guild_id)
                        .bind(&role_id)
                        .bind(&discord_id)
                        .execute(&pool)
                        .await
                        {
                            tracing::error!(
                                guild_id,
                                role_id,
                                discord_id,
                                "Failed to delete role_assignment: {e}"
                            );
                        }
                    }
                }
            }
        })
        .await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Per-role-link sync (bulk)
// ---------------------------------------------------------------------------

pub async fn sync_for_role_link(
    guild_id: &str,
    role_id: &str,
    state: &AppState,
) -> Result<(), AppError> {
    let pool = &state.pool;
    let rl_client = &state.rl_client;

    let link = sqlx::query_as::<_, (String, Option<String>, bool, Value)>(
        "SELECT api_token, form_id, grant_on_any_submission, conditions \
         FROM role_links WHERE guild_id = $1 AND role_id = $2",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_optional(pool)
    .await?;

    let Some((api_token, Some(form_id), grant_any, raw_conditions)) = link else {
        return Ok(());
    };

    let conditions: Vec<Condition> = raw_conditions
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| serde_json::from_value::<Condition>(v.clone()).ok())
        .collect();

    // Convention 42: empty conditions AND not grant_any → match nobody.
    // Drain to empty atomically and exit.
    if !grant_any && conditions.is_empty() {
        match rl_client
            .upload_users(guild_id, role_id, &[], &api_token)
            .await
        {
            Ok(_) => {}
            Err(AppError::RoleLinkNotFound) => {
                delete_orphan_role_link(guild_id, role_id, pool).await;
                return Ok(());
            }
            // Disabled link: leave config + assignments intact, just skip.
            Err(AppError::RoleLinkDisabled) => return Ok(()),
            Err(e) => return Err(e),
        }
        sqlx::query("DELETE FROM role_assignments WHERE guild_id = $1 AND role_id = $2")
            .bind(guild_id)
            .bind(role_id)
            .execute(pool)
            .await?;
        return Ok(());
    }

    // Candidate universe = everyone who submitted this form (a `form_responses`
    // row), minus anyone who opted this guild/plugin out. We deliberately do
    // NOT intersect with the gateway's guild member list: that list is only the
    // OAuth-derived cache of users who have signed into RoleLogic and whose
    // 7-day-refreshed guild list still names this server. A respondent who
    // completed the quiz but never opened the RoleLogic dashboard — or whose
    // cache has since gone stale — is absent from it, which is exactly why this
    // link under-granted (e.g. 359 respondents collapsing to ~100). RoleLogic's
    // bot is the real authority on who is actually in the guild when it applies
    // the role, so pushing a non-member is harmless; opt-outs are still honored
    // centrally below. Convention 40: an opt-out lookup error bubbles up and the
    // job retries — we never treat a hiccup as "nobody opted out".
    let optout_ids = auth_gateway::fetch_guild_optout_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        guild_id,
    )
    .await?;

    // Push the FULL qualifying set. We do NOT pre-cap by a limit read from the
    // RoleLogic API: that read depends on the central API echoing `user_limit`,
    // which it does not on older builds — it silently fell back to 100 and
    // capped premium links at 100. Instead the RoleLogic server, the real
    // authority on the per-tier cap, enforces it on the PUT; if (and only if)
    // it rejects the set as over-limit we re-query capped to the real limit it
    // reports and push that. For premium links (cap in the millions) the first
    // push always succeeds, so the cap no longer depends on any API deploy.
    let qualifying_ids =
        query_qualifying(pool, &form_id, &optout_ids, grant_any, &conditions, None).await?;

    // Skip the PUT entirely when the desired set already equals what's assigned
    // (both ordered + de-duped, so `==` is an exact set comparison). Keeps the
    // startup backfill and repeated config_syncs from re-uploading unchanged
    // links. Sorted in Rust, not by `ORDER BY`: `qualifying_ids` comes out of a
    // BTreeSet, and Postgres' collation order on TEXT need not match Rust's —
    // mismatched orderings would fail this check on equal sets and re-upload
    // every time.
    let mut current: Vec<String> = sqlx::query_scalar(
        "SELECT discord_id FROM role_assignments WHERE guild_id = $1 AND role_id = $2",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_all(pool)
    .await?;
    current.sort();
    if current == qualifying_ids {
        return Ok(());
    }

    // The set we actually uploaded — equals `qualifying_ids` unless the server
    // reports an over-limit rejection, in which case we cap to its real limit.
    let final_ids = match rl_client
        .upload_users(guild_id, role_id, &qualifying_ids, &api_token)
        .await
    {
        Ok(_) => qualifying_ids,
        Err(AppError::RoleLinkNotFound) => {
            delete_orphan_role_link(guild_id, role_id, pool).await;
            return Ok(());
        }
        Err(AppError::RoleLinkDisabled) => return Ok(()),
        Err(AppError::UserLimitReached { limit }) => {
            tracing::warn!(
                guild_id,
                role_id,
                limit,
                qualifying = qualifying_ids.len(),
                "Qualifying set exceeds role-link cap; capping to the server limit"
            );
            let capped = query_qualifying(
                pool,
                &form_id,
                &optout_ids,
                grant_any,
                &conditions,
                Some(limit),
            )
            .await?;
            match rl_client
                .upload_users(guild_id, role_id, &capped, &api_token)
                .await
            {
                Ok(_) => {}
                Err(AppError::RoleLinkNotFound) => {
                    delete_orphan_role_link(guild_id, role_id, pool).await;
                    return Ok(());
                }
                Err(AppError::RoleLinkDisabled) => return Ok(()),
                Err(e) => return Err(e),
            }
            capped
        }
        Err(e) => return Err(e),
    };

    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM role_assignments WHERE guild_id = $1 AND role_id = $2")
        .bind(guild_id)
        .bind(role_id)
        .execute(&mut *tx)
        .await?;

    if !final_ids.is_empty() {
        sqlx::query(
            "INSERT INTO role_assignments (guild_id, role_id, discord_id) \
             SELECT $1, $2, UNNEST($3::text[])",
        )
        .bind(guild_id)
        .bind(role_id)
        .bind(&final_ids)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

/// Discord IDs that qualify for a form-bound role link: distinct respondents to
/// `form_id` whose responses satisfy the link's eligibility, minus `optout_ids`.
///
/// Eligibility is decided by [`condition_eval::evaluate`] — the *same* function
/// [`sync_for_player`] uses. This path used to translate the conditions into a
/// SQL `WHERE` clause instead, which had to reproduce the Rust semantics
/// exactly and didn't: `not_contains` against an unanswered question matched in
/// SQL but not in Rust, `neq` against a checkbox answer matched in SQL but not
/// in Rust, and a numeric comparison against a non-numeric answer aborted the
/// entire query with a cast error rather than simply not matching. Every such
/// disagreement is a grant/revoke loop — the bulk sync drops a member the
/// per-player sync just added, RoleLogic strips the role, the per-player sync
/// adds them back. Sharing one evaluator makes that class of bug
/// unrepresentable rather than merely fixed.
///
/// Rows stream, so peak memory is the qualifying set rather than the response
/// table. Filtering moved out of SQL but the access path did not: the old
/// `answers ->> $q` predicates were not indexable either, so both versions scan
/// this form's rows via `idx_form_responses_form_user`.
///
/// `limit = None` returns everyone; `Some(n)` keeps the `n` lowest-sorted IDs
/// (used only to retry after the server reports an over-cap rejection). The cut
/// is deterministic, so a capped link doesn't churn a different subset of
/// members on every sync.
async fn query_qualifying(
    pool: &sqlx::PgPool,
    form_id: &str,
    optout_ids: &[String],
    grant_on_any_submission: bool,
    conditions: &[Condition],
    limit: Option<usize>,
) -> Result<Vec<String>, AppError> {
    // `<> ALL($2)` keeps everyone when the opt-out list is empty.
    let mut rows = sqlx::query_as::<_, (String, Value, Option<i32>)>(
        "SELECT fr.discord_id, fr.answers, fr.total_score \
         FROM form_responses fr \
         WHERE fr.form_id = $1 \
           AND fr.discord_id <> '' \
           AND fr.discord_id <> ALL($2::text[])",
    )
    .bind(form_id)
    .bind(optout_ids)
    .fetch(pool);

    // BTreeSet, not Vec + sort: it dedupes and orders in one structure, and the
    // ordering is Rust's, matching how the caller sorts `role_assignments`.
    // Postgres' `ORDER BY` on a TEXT column is collation-dependent and would
    // not necessarily agree.
    let mut qualifying: BTreeSet<String> = BTreeSet::new();
    while let Some((discord_id, answers, total_score)) = rows.try_next().await? {
        // A member qualifies on ANY of their responses (unlimited forms keep a
        // row per submission), so once they're in there's nothing left to test.
        if qualifying.contains(&discord_id) {
            continue;
        }
        let data = ResponseEvalData {
            answers: &answers,
            total_score: total_score.map(i64::from),
        };
        if condition_eval::evaluate(grant_on_any_submission, conditions, &data) {
            qualifying.insert(discord_id);
        }
    }

    let mut ids: Vec<String> = qualifying.into_iter().collect();
    if let Some(n) = limit {
        ids.truncate(n);
    }
    Ok(ids)
}

// ---------------------------------------------------------------------------
// Account unlink — drop all role_assignments for a user.
// ---------------------------------------------------------------------------

pub async fn remove_all_assignments(discord_id: &str, state: &AppState) -> Result<(), AppError> {
    let pool = &state.pool;
    let rl_client = &state.rl_client;

    let assignments = sqlx::query_as::<_, (String, String, String)>(
        "SELECT ra.guild_id, ra.role_id, rl.api_token \
         FROM role_assignments ra \
         JOIN role_links rl ON rl.guild_id = ra.guild_id AND rl.role_id = ra.role_id \
         WHERE ra.discord_id = $1",
    )
    .bind(discord_id)
    .fetch_all(pool)
    .await?;

    for (guild_id, role_id, api_token) in &assignments {
        match rl_client
            .remove_user(guild_id, role_id, discord_id, api_token)
            .await
        {
            Ok(_) => {}
            Err(AppError::RoleLinkNotFound) => {
                delete_orphan_role_link(guild_id, role_id, pool).await;
            }
            Err(e) => {
                tracing::error!(
                    guild_id,
                    role_id,
                    discord_id,
                    "Failed to remove user during unlink: {e}"
                );
            }
        }
    }

    sqlx::query("DELETE FROM role_assignments WHERE discord_id = $1")
        .bind(discord_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Delete a role_link the RoleLogic API reports as 404 (deleted upstream).
/// CASCADE clears role_assignments. Best-effort: logs DB failures, never
/// propagates them — sync workers must not stop syncing other links over
/// a cleanup hiccup.
async fn delete_orphan_role_link(guild_id: &str, role_id: &str, pool: &sqlx::PgPool) {
    tracing::warn!(
        guild_id,
        role_id,
        "Role link not found on RoleLogic; removing orphaned local row"
    );
    if let Err(e) = sqlx::query("DELETE FROM role_links WHERE guild_id = $1 AND role_id = $2")
        .bind(guild_id)
        .bind(role_id)
        .execute(pool)
        .await
    {
        tracing::error!(guild_id, role_id, "Failed to delete orphan role_link: {e}");
    }
}
