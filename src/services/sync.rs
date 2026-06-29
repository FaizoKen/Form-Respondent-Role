//! Sync engine — both per-player (lightweight) and per-role-link (bulk).
//!
//! The functions in this module are the dispatch targets for jobs claimed
//! by [`crate::tasks::job_worker`]. Job payloads (`PlayerSyncPayload`,
//! `ConfigSyncPayload`) live in [`crate::services::jobs`].

use std::collections::HashSet;

use futures_util::stream::{self, StreamExt};
use serde_json::Value;

use crate::error::AppError;
use crate::models::condition::Condition;
use crate::services::auth_gateway;
use crate::services::condition_eval::{self, ConditionBind, ResponseEvalData};
use crate::AppState;

// ---------------------------------------------------------------------------
// Per-player sync
// ---------------------------------------------------------------------------

pub async fn sync_for_player(discord_id: &str, state: &AppState) -> Result<(), AppError> {
    let pool = &state.pool;
    let rl_client = &state.rl_client;

    let mut guild_ids = auth_gateway::fetch_user_guild_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        discord_id,
    )
    .await?;

    // The gateway list only covers guilds this user is in *and that RoleLogic
    // has cached via OAuth*. A respondent who completed a form but never opened
    // the RoleLogic dashboard is absent from it, so per-player sync would never
    // grant their role until a full per-role-link rebuild ran. Add every guild
    // where the user has a form_response that the gateway didn't already
    // return — vetting each for an opt-out (a user who logged in and opted this
    // guild/plugin out is missing from the gateway list *for that reason*, so
    // we must not re-add it; a never-logged-in user cannot have opted out).
    // Convention 40: an opt-out lookup error bubbles up and the job retries.
    let respondent_guilds: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT guild_id FROM form_responses WHERE discord_id = $1")
            .bind(discord_id)
            .fetch_all(pool)
            .await?;
    let known: HashSet<&str> = guild_ids.iter().map(String::as_str).collect();
    let extra: Vec<String> = respondent_guilds
        .into_iter()
        .filter(|g| !known.contains(g.as_str()))
        .collect();
    for g in extra {
        let optouts = auth_gateway::fetch_guild_optout_ids(
            &state.http,
            &state.config.auth_gateway_url,
            &state.config.internal_api_key,
            &g,
        )
        .await?;
        if !optouts.iter().any(|o| o == discord_id) {
            guild_ids.push(g);
        }
    }

    if guild_ids.is_empty() {
        return Ok(());
    }

    // role_links bound to a form, in any guild this user qualifies for.
    let role_links = sqlx::query_as::<_, (String, String, String, String, bool, Value)>(
        "SELECT rl.guild_id, rl.role_id, rl.api_token, rl.form_id, rl.grant_on_any_submission, rl.conditions \
         FROM role_links rl \
         WHERE rl.guild_id = ANY($1) AND rl.form_id IS NOT NULL",
    )
    .bind(&guild_ids[..])
    .fetch_all(pool)
    .await?;

    if role_links.is_empty() {
        return Ok(());
    }

    let existing: HashSet<(String, String)> = sqlx::query_as::<_, (String, String)>(
        "SELECT guild_id, role_id FROM role_assignments WHERE discord_id = $1",
    )
    .bind(discord_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();

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
        // Look up this user's most recent response to this form.
        let resp_row = sqlx::query_as::<_, (Value, Option<i32>)>(
            "SELECT answers, total_score FROM form_responses \
             WHERE form_id = $1 AND discord_id = $2 \
             ORDER BY last_edited_at DESC LIMIT 1",
        )
        .bind(form_id)
        .bind(discord_id)
        .fetch_optional(pool)
        .await?;

        let qualifies = if let Some((answers, total_score)) = resp_row {
            let conditions: Vec<Condition> = raw_conditions
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| serde_json::from_value::<Condition>(v.clone()).ok())
                .collect();

            let data = ResponseEvalData {
                answers: &answers,
                total_score: total_score.map(|t| t as i64),
            };
            condition_eval::evaluate(*grant_any, &conditions, &data)
        } else {
            false
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
    let qualifying_ids = query_qualifying(pool, &form_id, &optout_ids, &conditions, None).await?;

    // Skip the PUT entirely when the desired set already equals what's assigned
    // (both ordered + de-duped, so `==` is an exact set comparison). Keeps the
    // startup backfill and repeated config_syncs from re-uploading unchanged
    // links.
    let current: Vec<String> = sqlx::query_scalar(
        "SELECT discord_id FROM role_assignments \
         WHERE guild_id = $1 AND role_id = $2 ORDER BY discord_id",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_all(pool)
    .await?;
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
            let capped =
                query_qualifying(pool, &form_id, &optout_ids, &conditions, Some(limit)).await?;
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
/// `form_id` who pass `conditions`, minus `optout_ids`. `limit = None` returns
/// the full set; `Some(n)` caps it (used only to retry after the server reports
/// an over-cap rejection). Binds: `$1 = form_id`, `$2 = optout_ids`, condition
/// binds from `$3`, optional `LIMIT` last. `<> ALL($2)` keeps everyone when the
/// opt-out list is empty.
async fn query_qualifying(
    pool: &sqlx::PgPool,
    form_id: &str,
    optout_ids: &[String],
    conditions: &[Condition],
    limit: Option<usize>,
) -> Result<Vec<String>, AppError> {
    let (cond_where, cond_binds) = condition_eval::build_condition_where(conditions, 2);

    let mut sql = format!(
        "SELECT DISTINCT fr.discord_id \
         FROM form_responses fr \
         WHERE fr.form_id = $1 \
           AND fr.discord_id <> '' \
           AND fr.discord_id <> ALL($2::text[]) \
           AND ({cond_where}) \
         ORDER BY fr.discord_id"
    );
    if limit.is_some() {
        let limit_idx = 2 + cond_binds.len() + 1;
        sql.push_str(&format!(" LIMIT ${limit_idx}"));
    }

    let mut q = sqlx::query_scalar::<_, String>(&sql);
    q = q.bind(form_id);
    q = q.bind(optout_ids);
    for bind in &cond_binds {
        match bind {
            ConditionBind::Int(v) => {
                q = q.bind(*v);
            }
            ConditionBind::Text(v) => {
                q = q.bind(v.as_str());
            }
        }
    }
    if let Some(l) = limit {
        q = q.bind(l as i64);
    }
    Ok(q.fetch_all(pool).await?)
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
