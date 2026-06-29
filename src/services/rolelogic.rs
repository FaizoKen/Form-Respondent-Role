use std::time::Duration;

use crate::error::AppError;

/// Hard cap for a single `PUT /users` request (server-side limit).
const PUT_MAX_USERS: usize = 100_000;
/// Per-chunk cap for the chunked upload flow (server-side limit).
const CHUNK_SIZE: usize = 100_000;
/// Per-request timeout for a single chunk POST. Chunks are short
/// transactions but the payload can be ~2 MB of JSON, so allow headroom.
const CHUNK_TIMEOUT: Duration = Duration::from_secs(120);
/// Per-request timeout for the commit POST. The server may take up to
/// 30 minutes to perform the atomic swap on very large staging sets.
const COMMIT_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Body substring RoleLogic returns when our token isn't found server-side.
/// Because `RoleLinkToken` rows cascade on `RoleLink` delete, getting this
/// reliably signals the role link has been deleted upstream — not a token
/// rotation (the API has no rotate endpoint) and not "disabled" (that
/// returns a different 403 message). Source: `role-link-token.guard.ts`.
const RL_LINK_GONE_ERROR_MSG: &str = "Invalid or revoked token";
/// Body substring RoleLogic returns when the role link exists but its owner has
/// toggled it off. Unlike [`RL_LINK_GONE_ERROR_MSG`] this is NOT a deletion —
/// the link (and its config) must be left intact; we simply skip syncing it
/// this cycle instead of erroring and retrying to the dead-letter queue.
/// Source: `role-link-token.guard.ts` ("This role link is disabled").
const RL_LINK_DISABLED_ERROR_MSG: &str = "This role link is disabled";

/// Extract the per-tier user cap from a RoleLogic limit-rejection body.
///
/// The server raises `HttpException("Maximum <N> users per role link …")`,
/// which reaches us as `{"errors":"Maximum <N> users per role link …", …}`
/// — the number is in the message, there is no structured field. Older builds
/// returned `{"data":{"user_limit":<N>}}`; we accept both. Returns `None` when
/// the body is some other error (so the caller treats it as a generic failure).
fn parse_user_limit(body: &str) -> Option<usize> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(n) = v["data"]["user_limit"].as_u64() {
            return Some(n as usize);
        }
    }
    let after = body.split("Maximum ").nth(1)?;
    if !after.contains("users per role link") {
        return None;
    }
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

#[derive(Clone)]
pub struct RoleLogicClient {
    http: reqwest::Client,
    base_url: String,
}

impl RoleLogicClient {
    pub fn new(base_url: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    pub async fn add_user(
        &self,
        guild_id: &str,
        role_id: &str,
        user_id: &str,
        token: &str,
    ) -> Result<bool, AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/{}",
            self.base_url, guild_id, role_id, user_id
        );

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();

            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_GONE_ERROR_MSG) {
                return Err(AppError::RoleLinkNotFound);
            }
            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_DISABLED_ERROR_MSG)
            {
                return Err(AppError::RoleLinkDisabled);
            }

            if matches!(
                status,
                reqwest::StatusCode::BAD_REQUEST | reqwest::StatusCode::FORBIDDEN
            ) {
                if let Some(limit) = parse_user_limit(&body) {
                    return Err(AppError::UserLimitReached { limit });
                }
            }

            return Err(AppError::RoleLogic(format!(
                "Add user failed: {status} - {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        Ok(body["data"]["added"].as_bool().unwrap_or(false))
    }

    pub async fn remove_user(
        &self,
        guild_id: &str,
        role_id: &str,
        user_id: &str,
        token: &str,
    ) -> Result<bool, AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/{}",
            self.base_url, guild_id, role_id, user_id
        );

        let resp = self
            .http
            .delete(&url)
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_GONE_ERROR_MSG) {
                return Err(AppError::RoleLinkNotFound);
            }
            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_DISABLED_ERROR_MSG)
            {
                return Err(AppError::RoleLinkDisabled);
            }
            return Err(AppError::RoleLogic(format!(
                "Remove user failed: {status} - {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        Ok(body["data"]["removed"].as_bool().unwrap_or(false))
    }

    /// Replace the full user set in a single atomic `PUT /users` request.
    /// Server rejects anything over `PUT_MAX_USERS`. For larger sets,
    /// callers should use [`upload_users`] which routes to the chunked flow.
    pub async fn replace_users(
        &self,
        guild_id: &str,
        role_id: &str,
        user_ids: &[String],
        token: &str,
    ) -> Result<usize, AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users",
            self.base_url, guild_id, role_id
        );

        let resp = self
            .http
            .put(&url)
            .header("Authorization", format!("Token {token}"))
            .json(user_ids)
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_GONE_ERROR_MSG) {
                return Err(AppError::RoleLinkNotFound);
            }
            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_DISABLED_ERROR_MSG)
            {
                return Err(AppError::RoleLinkDisabled);
            }
            // Over the per-tier cap: the server rejects the whole PUT with the
            // real limit in the message. Surface it so the caller can re-push a
            // set capped to that limit instead of failing the sync outright.
            if matches!(
                status,
                reqwest::StatusCode::BAD_REQUEST | reqwest::StatusCode::FORBIDDEN
            ) {
                if let Some(limit) = parse_user_limit(&body) {
                    return Err(AppError::UserLimitReached { limit });
                }
            }
            return Err(AppError::RoleLogic(format!(
                "Replace users failed: {status} - {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        Ok(body["data"]["user_count"].as_u64().unwrap_or(0) as usize)
    }

    /// High-level user-set upload. Picks the right transport for the size:
    /// - `len <= 100_000`: single atomic `PUT /users`.
    /// - `len > 100_000`: chunked flow (init → chunks → commit).
    ///
    /// Returns the deduped `user_count` reported by the server.
    pub async fn upload_users(
        &self,
        guild_id: &str,
        role_id: &str,
        user_ids: &[String],
        token: &str,
    ) -> Result<usize, AppError> {
        if user_ids.len() <= PUT_MAX_USERS {
            return self.replace_users(guild_id, role_id, user_ids, token).await;
        }

        let total = user_ids.len();
        tracing::info!(
            guild_id,
            role_id,
            total,
            "Bulk user set exceeds PUT cap; using chunked upload"
        );

        let upload_id = self.start_upload(guild_id, role_id, token).await?;
        let chunk_count = user_ids.chunks(CHUNK_SIZE).count();

        for (i, chunk) in user_ids.chunks(CHUNK_SIZE).enumerate() {
            if let Err(e) = self
                .upload_chunk(guild_id, role_id, &upload_id, chunk, token)
                .await
            {
                tracing::error!(
                    guild_id,
                    role_id,
                    upload_id,
                    chunk_idx = i,
                    chunk_count,
                    "Chunk upload failed; cancelling session: {e}"
                );
                if let Err(cancel_err) = self
                    .cancel_upload(guild_id, role_id, &upload_id, token)
                    .await
                {
                    tracing::warn!(
                        guild_id,
                        role_id,
                        upload_id,
                        "Cancel after chunk failure also failed: {cancel_err}"
                    );
                }
                return Err(e);
            }
        }

        let final_count = self
            .commit_upload(guild_id, role_id, &upload_id, token)
            .await?;
        tracing::info!(
            guild_id,
            role_id,
            upload_id,
            chunks = chunk_count,
            final_count,
            "Chunked upload committed"
        );
        Ok(final_count)
    }

    /// Step 1: open a chunked-upload session. Returns the `upload_id`.
    pub async fn start_upload(
        &self,
        guild_id: &str,
        role_id: &str,
        token: &str,
    ) -> Result<String, AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/upload",
            self.base_url, guild_id, role_id
        );

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_GONE_ERROR_MSG) {
                return Err(AppError::RoleLinkNotFound);
            }
            if status == reqwest::StatusCode::FORBIDDEN && body.contains(RL_LINK_DISABLED_ERROR_MSG)
            {
                return Err(AppError::RoleLinkDisabled);
            }
            return Err(AppError::RoleLogic(format!(
                "Start upload failed: {status} - {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        body["data"]["upload_id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| AppError::RoleLogic("Start upload response missing upload_id".into()))
    }

    /// Step 2: append a chunk (≤ `CHUNK_SIZE` user IDs) to an open session.
    pub async fn upload_chunk(
        &self,
        guild_id: &str,
        role_id: &str,
        upload_id: &str,
        user_ids: &[String],
        token: &str,
    ) -> Result<(), AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/upload/{}/chunk",
            self.base_url, guild_id, role_id, upload_id
        );

        let resp = self
            .http
            .post(&url)
            .timeout(CHUNK_TIMEOUT)
            .header("Authorization", format!("Token {token}"))
            .json(user_ids)
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::RoleLogic(format!(
                "Upload chunk failed: {status} - {body}"
            )));
        }

        Ok(())
    }

    /// Step 3: commit a chunked upload. Server dedupes across chunks and
    /// atomically swaps in the new user set. Returns the final user_count.
    pub async fn commit_upload(
        &self,
        guild_id: &str,
        role_id: &str,
        upload_id: &str,
        token: &str,
    ) -> Result<usize, AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/upload/{}/commit",
            self.base_url, guild_id, role_id, upload_id
        );

        let resp = self
            .http
            .post(&url)
            .timeout(COMMIT_TIMEOUT)
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::RoleLogic(format!(
                "Commit upload failed: {status} - {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        Ok(body["data"]["user_count"].as_u64().unwrap_or(0) as usize)
    }

    /// Cancel an open upload session (best-effort cleanup on failure).
    pub async fn cancel_upload(
        &self,
        guild_id: &str,
        role_id: &str,
        upload_id: &str,
        token: &str,
    ) -> Result<(), AppError> {
        let url = format!(
            "{}/api/role-link/{}/{}/users/upload/{}",
            self.base_url, guild_id, role_id, upload_id
        );

        let resp = self
            .http
            .delete(&url)
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
            .map_err(|e| AppError::RoleLogic(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::RoleLogic(format!(
                "Cancel upload failed: {status} - {body}"
            )));
        }

        Ok(())
    }
}
