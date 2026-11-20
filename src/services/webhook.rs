//! Per-form webhook delivery.
//!
//! The submit handler enqueues a `JobKind::Webhook` job inside the same
//! transaction as the response. The job worker calls `deliver_once` here,
//! which classifies failures as retry-able (5xx / network) vs terminal
//! (4xx, bad URL, DNS to a private range). Backoff and DLQ live in
//! `services::jobs`.

use std::net::IpAddr;
use std::time::Duration;

use serde_json::Value;

const TIMEOUT_SECS: u64 = 5;
/// Time-budget for the pre-flight DNS resolution. Webhook delivery already
/// has a 5s overall budget, so we keep this short.
const DNS_TIMEOUT_SECS: u64 = 2;

/// Reason a single webhook attempt failed, classified for the job worker.
#[derive(Debug, Clone)]
pub struct WebhookFailure {
    pub message: String,
    /// `true` → drop into DLQ immediately. `false` → backoff + retry.
    pub terminal: bool,
    /// What the form's owner should be told, when the destination refused
    /// the delivery for a reason only they can fix (the webhook was deleted,
    /// the URL is not a webhook). The builder shows it under the URL field.
    pub owner_notice: Option<String>,
}

/// Shown for a Discord URL that is not a webhook.
const NOT_A_WEBHOOK: &str = "This is a Discord link, but not a webhook URL, so nothing \
     would be posted. In Discord, open the channel's settings, go to Integrations → \
     Webhooks, create a webhook and paste its URL here (it starts with \
     https://discord.com/api/webhooks/).";

fn is_discord_host(host: &str) -> bool {
    let host = host.strip_prefix("www.").unwrap_or(host);
    matches!(
        host,
        "discord.com"
            | "discordapp.com"
            | "ptb.discord.com"
            | "canary.discord.com"
            | "ptb.discordapp.com"
            | "canary.discordapp.com"
            | "discord.gg"
    )
}

/// Why a Discord URL cannot take a webhook post; `None` for a webhook URL and
/// for any URL that is not Discord's.
///
/// Discord answers a POST to a channel link or an invite with its web app and
/// a 200, so a pasted channel link looked delivered while nothing was posted
/// (prod, Nov 2026: 6 forms, 36 submissions "delivered" to nowhere).
pub fn discord_url_problem(url: &str) -> Option<&'static str> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    if !is_discord_host(&host) {
        return None;
    }
    let segments: Vec<&str> = parsed
        .path_segments()
        .map(|s| s.filter(|p| !p.is_empty()).collect())
        .unwrap_or_default();
    let rest = match segments.as_slice() {
        ["api", "webhooks", rest @ ..] => rest,
        ["api", version, "webhooks", rest @ ..]
            if version
                .strip_prefix('v')
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())) =>
        {
            rest
        }
        _ => return Some(NOT_A_WEBHOOK),
    };
    match rest {
        [id, _token, ..] if id.bytes().all(|b| b.is_ascii_digit()) => None,
        _ => Some(NOT_A_WEBHOOK),
    }
}

/// What to tell the owner about a refusal they can fix; `None` when the
/// failure may be ours (a 400 on our payload) or may pass.
fn refusal_notice(url: &str, status: reqwest::StatusCode) -> Option<String> {
    let discord = reqwest::Url::parse(url)
        .ok()
        .and_then(|u| {
            u.host_str()
                .map(|h| is_discord_host(&h.to_ascii_lowercase()))
        })
        .unwrap_or(false);
    match status.as_u16() {
        404 | 410 if discord => Some(
            "Discord says this webhook no longer exists, so submissions are not being \
             posted. Create a new webhook in the channel's settings (Integrations → \
             Webhooks) and paste its URL here."
                .into(),
        ),
        401 | 403 if discord => Some(
            "Discord refused this webhook's token, so submissions are not being posted. \
             Copy the webhook URL from Discord again and paste it here."
                .into(),
        ),
        401 | 403 | 404 | 410 => Some(format!(
            "The webhook URL answered {status}, so submissions are not reaching it. \
             Check the URL."
        )),
        _ => None,
    }
}

/// Note on every form using `url` that its webhook refused a delivery.
pub async fn record_refusal(pool: &sqlx::PgPool, url: &str, notice: &str) {
    if let Err(e) = sqlx::query(
        "UPDATE forms SET webhook_error = $2, webhook_error_at = now() WHERE webhook_url = $1",
    )
    .bind(url)
    .bind(notice)
    .execute(pool)
    .await
    {
        tracing::warn!("Could not record a webhook refusal: {e}");
    }
}

/// Clear an earlier refusal once a delivery to `url` goes through. Matches
/// no row in the common case, so it writes nothing.
pub async fn record_delivery(pool: &sqlx::PgPool, url: &str) {
    if let Err(e) = sqlx::query(
        "UPDATE forms SET webhook_error = NULL, webhook_error_at = NULL \
         WHERE webhook_url = $1 AND webhook_error IS NOT NULL",
    )
    .bind(url)
    .execute(pool)
    .await
    {
        tracing::warn!("Could not clear a webhook refusal: {e}");
    }
}

/// One delivery attempt. Used by the job worker; callers MUST NOT call this
/// from a request handler — enqueue a `JobKind::Webhook` job instead so
/// retries and DLQ go through the durable queue.
pub async fn deliver_once(
    http: &reqwest::Client,
    url: &str,
    body: &Value,
) -> Result<(), WebhookFailure> {
    if !is_safe_url(url) {
        return Err(WebhookFailure {
            message: "URL rejected: must be https with a public host".into(),
            terminal: true,
            owner_notice: None,
        });
    }
    if let Some(problem) = discord_url_problem(url) {
        return Err(WebhookFailure {
            message: "not a Discord webhook URL".into(),
            terminal: true,
            owner_notice: Some(problem.into()),
        });
    }
    // Pre-flight: resolve the host ourselves and check each resolved IP.
    // `is_safe_url` already rejects IP-literal hosts on private ranges,
    // but a hostname like `evil.example.com` resolving to `127.0.0.1` is
    // a classic SSRF vector that only this check stops.
    if let Err(reason) = resolve_and_check(url).await {
        return Err(WebhookFailure {
            // DNS resolution failures aren't terminal — the target may be
            // momentarily unresolvable — but a resolved-to-private result
            // is, because that means the URL itself is unsafe and won't
            // become safe on retry.
            terminal: reason == "resolved to a private or loopback address",
            message: format!("DNS check: {reason}"),
            owner_notice: None,
        });
    }

    let resp = match http
        .post(url)
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .json(body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return Err(WebhookFailure {
                message: format!("request failed: {e}"),
                terminal: false,
                owner_notice: None,
            });
        }
    };

    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    // 4xx (other than 408/429) → terminal: the URL or payload is wrong;
    // hammering won't help.
    let terminal = status.is_client_error()
        && status != reqwest::StatusCode::REQUEST_TIMEOUT
        && status != reqwest::StatusCode::TOO_MANY_REQUESTS;
    Err(WebhookFailure {
        message: format!("webhook returned {status}"),
        terminal,
        owner_notice: refusal_notice(url, status),
    })
}

async fn resolve_and_check(url: &str) -> Result<(), &'static str> {
    let parsed = reqwest::Url::parse(url).map_err(|_| "invalid URL")?;
    let host = parsed.host_str().ok_or("missing host")?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    let target = format!("{host}:{port}");

    let lookup = tokio::time::timeout(
        Duration::from_secs(DNS_TIMEOUT_SECS),
        tokio::net::lookup_host(target),
    )
    .await
    .map_err(|_| "DNS resolution timed out")?
    .map_err(|_| "DNS resolution failed")?;

    let mut any_resolved = false;
    for addr in lookup {
        any_resolved = true;
        if !is_safe_ip(addr.ip()) {
            return Err("resolved to a private or loopback address");
        }
    }
    if !any_resolved {
        return Err("hostname did not resolve to any address");
    }
    Ok(())
}

/// Predicate used by both the URL-time check and the post-resolution check.
fn is_safe_ip(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !(v4.is_private() || v4.is_link_local() || v4.is_multicast()),
        IpAddr::V6(v6) => {
            if v6.is_unique_local() || v6.is_unicast_link_local() || v6.is_multicast() {
                return false;
            }
            if let Some(v4) = v6.to_ipv4() {
                !(v4.is_loopback()
                    || v4.is_unspecified()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_multicast())
            } else {
                true
            }
        }
    }
}

/// Reject `http://`, private/loopback hosts, and obviously-bogus inputs to
/// reduce SSRF surface area. The admin set this URL, so the bar is "no
/// accidents," not "Fort Knox."
pub fn is_safe_url(url: &str) -> bool {
    let u = match reqwest::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    if u.scheme() != "https" {
        return false;
    }
    let host = match u.host_str() {
        Some(h) => h.to_ascii_lowercase(),
        None => return false,
    };
    if host == "localhost" || host.ends_with(".localhost") {
        return false;
    }
    // `Url::host_str()` keeps the brackets on IPv6 literals (`[::1]`) — strip
    // them before parsing so the IP check actually fires.
    let host_for_parse = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(&host);
    if let Ok(ip) = host_for_parse.parse::<IpAddr>() {
        return is_safe_ip(ip);
    }
    true
}

#[cfg(test)]
// `build_payload` lives after this module in source order; that's intentional
// (tests grouped near the predicates they exercise) but it would otherwise
// trip `clippy::items_after_test_module`.
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    // ---------- is_safe_url (URL-time check) ----------

    #[test]
    fn safe_url_accepts_public_https() {
        assert!(is_safe_url("https://example.com/webhook"));
        assert!(is_safe_url(
            "https://hooks.discord.com/api/webhooks/123/abc"
        ));
    }

    #[test]
    fn safe_url_rejects_http() {
        assert!(!is_safe_url("http://example.com"));
    }

    #[test]
    fn safe_url_rejects_localhost() {
        assert!(!is_safe_url("https://localhost/x"));
        assert!(!is_safe_url("https://api.localhost/x"));
    }

    #[test]
    fn safe_url_rejects_ipv4_loopback_and_private() {
        assert!(!is_safe_url("https://127.0.0.1/"));
        assert!(!is_safe_url("https://10.0.0.5/"));
        assert!(!is_safe_url("https://192.168.1.1/"));
        assert!(!is_safe_url("https://172.16.0.1/"));
        // 169.254.169.254 is the AWS / GCP metadata endpoint — must stay blocked
        // since most cloud creds bypass live there.
        assert!(!is_safe_url("https://169.254.169.254/latest/meta-data/"));
    }

    #[test]
    fn safe_url_rejects_ipv6_loopback_and_private() {
        assert!(!is_safe_url("https://[::1]/"));
        assert!(!is_safe_url("https://[::]/"));
        assert!(!is_safe_url("https://[fc00::1]/")); // ULA
        assert!(!is_safe_url("https://[fd00::1]/")); // ULA
        assert!(!is_safe_url("https://[fe80::1]/")); // link-local
                                                     // IPv4-mapped IPv6 should be treated as the underlying IPv4 — `::ffff:127.0.0.1`
                                                     // is one of the most overlooked SSRF bypasses.
        assert!(!is_safe_url("https://[::ffff:127.0.0.1]/"));
        assert!(!is_safe_url("https://[::ffff:10.0.0.1]/"));
    }

    #[test]
    fn safe_url_accepts_public_ipv6() {
        // 2001:db8::/32 is reserved-for-docs but isn't loopback/ULA/link-local
        // and `is_safe_ip` doesn't currently block reserved ranges. Real
        // public IPv6 like `[2606:4700::]` also passes.
        assert!(is_safe_url("https://[2606:4700::1]/x"));
    }

    #[test]
    fn safe_url_rejects_invalid_inputs() {
        assert!(!is_safe_url(""));
        assert!(!is_safe_url("not a url"));
        assert!(!is_safe_url("javascript:alert(1)"));
        assert!(!is_safe_url("file:///etc/passwd"));
        assert!(!is_safe_url("ftp://example.com"));
    }

    // ---------- discord_url_problem (pasted links that are not webhooks) ----------

    #[test]
    fn discord_webhook_urls_are_accepted() {
        for url in [
            "https://discord.com/api/webhooks/123456789012345678/abc-DEF_123",
            "https://discordapp.com/api/webhooks/1/x",
            "https://ptb.discord.com/api/v10/webhooks/1/x",
            "https://canary.discord.com/api/webhooks/1/x/",
            "https://discord.com/api/webhooks/1/x?wait=true",
        ] {
            assert_eq!(discord_url_problem(url), None, "{url}");
        }
    }

    #[test]
    fn discord_links_that_are_not_webhooks_are_refused() {
        // The shapes found in prod: a channel link and an invite.
        for url in [
            "https://discord.com/channels/111111111111111111/222222222222222222",
            "https://discord.gg/AbCdEf",
            "https://www.discord.com/invite/abc",
            "https://discord.com/api/webhooks/123456789012345678",
            "https://discord.com/api/webhooks/not-an-id/token",
            "https://discord.com/api/vX/webhooks/1/x",
            "https://discord.com/",
        ] {
            assert!(discord_url_problem(url).is_some(), "{url}");
        }
    }

    #[test]
    fn other_hosts_are_left_alone() {
        assert_eq!(
            discord_url_problem("https://hooks.zapier.com/hooks/catch/1/x"),
            None
        );
        assert_eq!(
            discord_url_problem("https://notdiscord.com/channels/1"),
            None
        );
        assert_eq!(discord_url_problem("not a url"), None);
    }

    // ---------- refusal_notice (what the form's owner is told) ----------

    #[test]
    fn a_deleted_or_rejected_discord_webhook_is_explained() {
        let url = "https://discord.com/api/webhooks/1/x";
        let gone = refusal_notice(url, reqwest::StatusCode::NOT_FOUND).unwrap();
        assert!(gone.contains("no longer exists"), "{gone}");
        let token = refusal_notice(url, reqwest::StatusCode::UNAUTHORIZED).unwrap();
        assert!(token.contains("token"), "{token}");
    }

    #[test]
    fn a_refusal_that_may_be_ours_or_may_pass_is_not_blamed_on_the_owner() {
        let url = "https://discord.com/api/webhooks/1/x";
        for status in [400, 408, 429, 500, 502] {
            let status = reqwest::StatusCode::from_u16(status).unwrap();
            assert_eq!(refusal_notice(url, status), None, "{status}");
        }
        // Another host gets the plain version.
        let other = refusal_notice("https://example.com/hook", reqwest::StatusCode::GONE).unwrap();
        assert!(other.contains("410"), "{other}");
    }

    // ---------- is_safe_ip (post-resolution check) ----------

    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn safe_ip_v4() {
        assert!(is_safe_ip(Ipv4Addr::new(1, 1, 1, 1).into()));
        assert!(is_safe_ip(Ipv4Addr::new(8, 8, 8, 8).into()));

        assert!(!is_safe_ip(Ipv4Addr::new(127, 0, 0, 1).into()));
        assert!(!is_safe_ip(Ipv4Addr::new(10, 0, 0, 5).into()));
        assert!(!is_safe_ip(Ipv4Addr::new(192, 168, 1, 1).into()));
        assert!(!is_safe_ip(Ipv4Addr::new(169, 254, 169, 254).into()));
        assert!(!is_safe_ip(Ipv4Addr::new(224, 0, 0, 1).into())); // multicast
        assert!(!is_safe_ip(Ipv4Addr::new(0, 0, 0, 0).into())); // unspecified
    }

    #[test]
    fn safe_ip_v6() {
        // Public IPv6 — Cloudflare's recursor, just an example public address.
        assert!(is_safe_ip(
            Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111).into()
        ));

        assert!(!is_safe_ip(Ipv6Addr::LOCALHOST.into()));
        assert!(!is_safe_ip(Ipv6Addr::UNSPECIFIED.into()));
        // ULA fc00::/7
        assert!(!is_safe_ip(
            Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1).into()
        ));
        assert!(!is_safe_ip(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).into()
        ));
        // Link-local fe80::/10
        assert!(!is_safe_ip(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into()
        ));
        // IPv4-mapped — `::ffff:127.0.0.1`
        assert!(!is_safe_ip(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001).into()
        ));
    }
}

/// Build the JSON payload posted on each submission. Discord webhooks
/// honor the `content` field to render a message; other endpoints can
/// still consume the structured fields.
pub fn build_payload(
    form_title: &str,
    form_slug: &str,
    member_name: &str,
    discord_id: &str,
    response_id: &str,
    total_score: Option<i32>,
    base_url: &str,
) -> Value {
    let response_url = format!("{base_url}/f/{form_slug}");
    let score_line = total_score
        .map(|s| format!("\nScore: {s}"))
        .unwrap_or_default();
    let content = format!(
        "**New submission to \"{form_title}\"**\nFrom: <@{discord_id}> ({member_name}){score_line}\n{response_url}"
    );
    serde_json::json!({
        "content": content,
        "form_title": form_title,
        "form_slug": form_slug,
        "member_name": member_name,
        "discord_id": discord_id,
        "response_id": response_id,
        "total_score": total_score,
        "submitted_at": chrono::Utc::now().to_rfc3339(),
    })
}
