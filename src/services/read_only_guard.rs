//! Method-based backstop for the read-only impersonation contract
//! (BLUEPRINT §1b.10).
//!
//! A request that authenticates with a READ-ONLY iframe-session (a developer
//! impersonating a user) may never mutate state. The mutating handlers are
//! individually protected too — they only accept cookie sessions or check
//! `read_only` themselves — but this layer catches every current *and future*
//! write path in one place: any non-GET request carrying a read-only session
//! (bearer header or `ifs` query param) is rejected before routing.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::services::rl_token::{self, IframeSession};
use crate::AppState;

pub async fn block_read_only_writes(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method();
    if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
        return next.run(req).await;
    }
    if let Some(session) = read_only_session_on(&req, &state.config.session_secret) {
        // The read-only UI disables every write affordance, so a request
        // landing here means someone drove the API directly — worth an audit
        // line with the real (developer) actor.
        tracing::warn!(
            method = %method,
            path = req.uri().path(),
            target = %session.discord_id,
            actor = session.actor_id.as_deref().unwrap_or("?"),
            "Blocked write request carrying a read-only impersonation session"
        );
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "error": "This view is read-only while impersonating a user."
            })),
        )
            .into_response();
    }
    next.run(req).await
}

/// Extract and verify an iframe-session from `Authorization: Bearer …` or the
/// `ifs` query param. `Some` only when the token verifies AND is read-only —
/// unverifiable tokens fall through so the handler's own auth produces its
/// usual 401.
fn read_only_session_on(req: &Request, session_secret: &str) -> Option<IframeSession> {
    let bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string);
    // Query-param sessions are meant for page-entry GETs only, but check them
    // here too so a mutating request can't smuggle one past the guard.
    let token = bearer.or_else(|| query_param(req.uri().query()?, "ifs"))?;
    let session = rl_token::verify_iframe_session(&token, session_secret)?;
    session.read_only.then_some(session)
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name)
            .then(|| urlencoding::decode(v).ok().map(|s| s.into_owned()))
            .flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::query_param;

    #[test]
    fn query_param_extracts_and_decodes() {
        assert_eq!(
            query_param("a=1&ifs=ifs%3Au%3Ag", "ifs").as_deref(),
            Some("ifs:u:g")
        );
        assert_eq!(query_param("a=1&b=2", "ifs"), None);
        assert_eq!(query_param("ifs", "ifs"), None); // no '='
    }
}
