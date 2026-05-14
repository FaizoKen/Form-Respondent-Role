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
