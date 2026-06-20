//! Retry / cooldown decision logic for form & quiz submissions.
//!
//! This module is deliberately pure: it takes the form's retry policy, the
//! member's existing canonical attempt (if any), and the freshly-graded new
//! submission, and decides whether the new attempt is allowed and, if so,
//! what the canonical response row should now hold. No I/O, so the rules are
//! unit-tested in isolation; the submit handler in `routes::form_render`
//! wraps it in an advisory-locked transaction to make the read-decide-write
//! atomic against concurrent submits from the same member.
//!
//! Invariant kept by the caller: this only governs forms that keep a single
//! canonical response per (form, member). That is what makes the two sync
//! paths agree on "which attempt counts" — see migration 009.

use chrono::{DateTime, Duration, Utc};

/// Which attempt becomes the canonical response used for role evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryPolicy {
    /// Highest-scoring attempt wins; passing is sticky. Falls back to
    /// `KeepLatest` when there are no scores to compare (ungraded form).
    KeepBest,
    /// The most recent attempt always replaces the previous one.
    KeepLatest,
}

impl RetryPolicy {
    /// Parse from the stored/posted string, defaulting to `KeepBest` for any
    /// unknown value (the DB CHECK + admin validation keep it to the two
    /// known values, so this is just a total function for robustness).
    pub fn from_str_or_default(s: &str) -> Self {
        match s {
            "keep_latest" => RetryPolicy::KeepLatest,
            _ => RetryPolicy::KeepBest,
        }
    }
}

/// Per-form retry configuration (mirrors the `forms` columns added in 009).
#[derive(Debug, Clone, Copy)]
pub struct RetryConfig {
    /// Maximum attempts. `<= 0` means unlimited.
    pub max_attempts: i32,
    /// Minimum seconds between consecutive attempts. `0` disables cooldown.
    pub cooldown_seconds: i64,
    pub policy: RetryPolicy,
    /// Once the member has passed, deny further attempts (graded quizzes only).
    pub lock_on_pass: bool,
}

impl RetryConfig {
    /// Whether retries are actually in play (more than one attempt possible,
    /// or a cooldown is configured). Used to decide which member-facing copy
    /// and error code to surface; a plain `max_attempts == 1` form behaves
    /// exactly like the historical one-shot form.
    pub fn retries_enabled(&self) -> bool {
        self.max_attempts != 1 || self.cooldown_seconds > 0
    }
}

/// The member's existing canonical attempt for this form.
#[derive(Debug, Clone, Copy)]
pub struct ExistingAttempt {
    pub attempt_count: i32,
    pub last_attempt_at: DateTime<Utc>,
    pub total_score: Option<i32>,
    pub passed: Option<bool>,
}

/// The freshly-validated, freshly-graded new submission.
#[derive(Debug, Clone, Copy)]
pub struct NewSubmission {
    pub total_score: Option<i32>,
    pub passed: Option<bool>,
}

/// Why a new attempt was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// Member already passed and `lock_on_pass` is set.
    AlreadyPassed,
    /// All attempts have been used.
    AttemptsExhausted { max: i32 },
    /// Still inside the cooldown window.
    Cooldown {
        retry_after_seconds: i64,
        next_attempt_at: DateTime<Utc>,
    },
}

/// What the canonical response row should become after an accepted attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedAttempt {
    /// `true` -> persist the new submission's answers; `false` -> keep the
    /// previously stored answers (a `keep_best` attempt that didn't improve).
    pub overwrite_answers: bool,
    pub total_score: Option<i32>,
    pub passed: Option<bool>,
    pub attempt_count: i32,
}

/// Decide whether `new` is allowed given the form `config` and the member's
/// `existing` canonical attempt (None = first ever attempt).
pub fn decide(
    now: DateTime<Utc>,
    config: &RetryConfig,
    existing: Option<&ExistingAttempt>,
    new: &NewSubmission,
) -> Result<AcceptedAttempt, DenyReason> {
    let Some(e) = existing else {
        // First attempt — always allowed.
        return Ok(AcceptedAttempt {
            overwrite_answers: true,
            total_score: new.total_score,
            passed: new.passed,
            attempt_count: 1,
        });
    };

    // Order matters: surface the most "permanent" reason first so the member
    // sees the right call to action (you're done > out of tries > wait a bit).
    if config.lock_on_pass && e.passed == Some(true) {
        return Err(DenyReason::AlreadyPassed);
    }
    if config.max_attempts > 0 && e.attempt_count >= config.max_attempts {
        return Err(DenyReason::AttemptsExhausted {
            max: config.max_attempts,
        });
    }
    if config.cooldown_seconds > 0 {
        let next = e.last_attempt_at + Duration::seconds(config.cooldown_seconds);
        if now < next {
            let ms = (next - now).num_milliseconds().max(0);
            // Ceil to whole seconds so a sub-second remainder never rounds to
            // "0 seconds left" while still inside the window.
            let retry_after_seconds = (ms + 999) / 1000;
            return Err(DenyReason::Cooldown {
                retry_after_seconds: retry_after_seconds.max(1),
                next_attempt_at: next,
            });
        }
    }

    let attempt_count = e.attempt_count.saturating_add(1);
    let combined_passed = match (e.passed, new.passed) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(false) || b.unwrap_or(false)),
    };

    // keep_best only has meaning when both attempts are graded; otherwise we
    // have nothing to compare, so behave like keep_latest.
    let score_aware_best = matches!(config.policy, RetryPolicy::KeepBest)
        && e.total_score.is_some()
        && new.total_score.is_some();

    if score_aware_best {
        let improved = new.total_score > e.total_score; // strictly greater keeps the first best on ties
        Ok(AcceptedAttempt {
            overwrite_answers: improved,
            total_score: e.total_score.max(new.total_score),
            passed: combined_passed,
            attempt_count,
        })
    } else {
        Ok(AcceptedAttempt {
            overwrite_answers: true,
            total_score: new.total_score,
            passed: new.passed,
            attempt_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(max: i32, cooldown: i64, policy: RetryPolicy, lock: bool) -> RetryConfig {
        RetryConfig {
            max_attempts: max,
            cooldown_seconds: cooldown,
            policy,
            lock_on_pass: lock,
        }
    }

    fn t(secs_ago: i64) -> DateTime<Utc> {
        Utc::now() - Duration::seconds(secs_ago)
    }

    #[test]
    fn first_attempt_always_allowed() {
        let c = cfg(1, 0, RetryPolicy::KeepBest, true);
        let got = decide(
            Utc::now(),
            &c,
            None,
            &NewSubmission {
                total_score: Some(5),
                passed: Some(false),
            },
        )
        .expect("first attempt allowed");
        assert!(got.overwrite_answers);
        assert_eq!(got.attempt_count, 1);
        assert_eq!(got.total_score, Some(5));
    }

    #[test]
    fn one_shot_form_blocks_second_attempt() {
        let c = cfg(1, 0, RetryPolicy::KeepBest, true);
        let existing = ExistingAttempt {
            attempt_count: 1,
            last_attempt_at: t(10),
            total_score: Some(3),
            passed: Some(false),
        };
        let err = decide(
            Utc::now(),
            &c,
            Some(&existing),
            &NewSubmission {
                total_score: Some(9),
                passed: Some(true),
            },
        )
        .expect_err("one-shot blocks resubmit");
        assert_eq!(err, DenyReason::AttemptsExhausted { max: 1 });
    }

    #[test]
    fn exhausted_after_max_attempts() {
        let c = cfg(3, 0, RetryPolicy::KeepLatest, false);
        let existing = ExistingAttempt {
            attempt_count: 3,
            last_attempt_at: t(10_000),
            total_score: None,
            passed: None,
        };
        let err = decide(
            Utc::now(),
            &c,
            Some(&existing),
            &NewSubmission {
                total_score: None,
                passed: None,
            },
        )
        .expect_err("exhausted");
        assert_eq!(err, DenyReason::AttemptsExhausted { max: 3 });
    }

    #[test]
    fn unlimited_never_exhausts() {
        let c = cfg(0, 0, RetryPolicy::KeepLatest, false);
        let existing = ExistingAttempt {
            attempt_count: 999,
            last_attempt_at: t(10),
            total_score: None,
            passed: None,
        };
        let got = decide(
            Utc::now(),
            &c,
            Some(&existing),
            &NewSubmission {
                total_score: None,
                passed: None,
            },
        )
        .expect("unlimited allows");
        assert_eq!(got.attempt_count, 1000);
    }

    #[test]
    fn cooldown_blocks_then_allows() {
        let c = cfg(5, 3600, RetryPolicy::KeepLatest, false);
        let existing = ExistingAttempt {
            attempt_count: 1,
            last_attempt_at: t(60), // 1 minute ago, cooldown is 1 hour
            total_score: None,
            passed: None,
        };
        let new = NewSubmission {
            total_score: None,
            passed: None,
        };
        match decide(Utc::now(), &c, Some(&existing), &new) {
            Err(DenyReason::Cooldown {
                retry_after_seconds,
                ..
            }) => {
                assert!(retry_after_seconds > 3500 && retry_after_seconds <= 3540);
            }
            other => panic!("expected cooldown, got {other:?}"),
        }

        // Past the cooldown window -> allowed.
        let existing_old = ExistingAttempt {
            last_attempt_at: t(7200),
            ..existing
        };
        decide(Utc::now(), &c, Some(&existing_old), &new).expect("past cooldown allows");
    }

    #[test]
    fn lock_on_pass_blocks_passed_member() {
        let c = cfg(5, 0, RetryPolicy::KeepBest, true);
        let existing = ExistingAttempt {
            attempt_count: 1,
            last_attempt_at: t(10),
            total_score: Some(10),
            passed: Some(true),
        };
        let err = decide(
            Utc::now(),
            &c,
            Some(&existing),
            &NewSubmission {
                total_score: Some(10),
                passed: Some(true),
            },
        )
        .expect_err("locked after pass");
        assert_eq!(err, DenyReason::AlreadyPassed);
    }

    #[test]
    fn lock_on_pass_off_lets_passed_member_retry() {
        let c = cfg(5, 0, RetryPolicy::KeepBest, false);
        let existing = ExistingAttempt {
            attempt_count: 1,
            last_attempt_at: t(10),
            total_score: Some(8),
            passed: Some(true),
        };
        // A worse retry keeps the best and stays passed.
        let got = decide(
            Utc::now(),
            &c,
            Some(&existing),
            &NewSubmission {
                total_score: Some(2),
                passed: Some(false),
            },
        )
        .expect("retry allowed");
        assert!(!got.overwrite_answers, "worse score keeps old answers");
        assert_eq!(got.total_score, Some(8));
        assert_eq!(got.passed, Some(true), "passing is sticky under keep_best");
    }

    #[test]
    fn keep_best_overwrites_on_improvement() {
        let c = cfg(5, 0, RetryPolicy::KeepBest, false);
        let existing = ExistingAttempt {
            attempt_count: 1,
            last_attempt_at: t(10),
            total_score: Some(4),
            passed: Some(false),
        };
        let got = decide(
            Utc::now(),
            &c,
            Some(&existing),
            &NewSubmission {
                total_score: Some(9),
                passed: Some(true),
            },
        )
        .expect("improvement allowed");
        assert!(got.overwrite_answers, "better score overwrites answers");
        assert_eq!(got.total_score, Some(9));
        assert_eq!(got.passed, Some(true));
        assert_eq!(got.attempt_count, 2);
    }

    #[test]
    fn keep_latest_always_overwrites() {
        let c = cfg(5, 0, RetryPolicy::KeepLatest, false);
        let existing = ExistingAttempt {
            attempt_count: 1,
            last_attempt_at: t(10),
            total_score: Some(9),
            passed: Some(true),
        };
        let got = decide(
            Utc::now(),
            &c,
            Some(&existing),
            &NewSubmission {
                total_score: Some(1),
                passed: Some(false),
            },
        )
        .expect("latest allowed");
        assert!(got.overwrite_answers);
        assert_eq!(got.total_score, Some(1));
        assert_eq!(got.passed, Some(false), "latest is not sticky");
    }

    #[test]
    fn ungraded_keep_best_behaves_like_latest() {
        let c = cfg(5, 0, RetryPolicy::KeepBest, false);
        let existing = ExistingAttempt {
            attempt_count: 1,
            last_attempt_at: t(10),
            total_score: None,
            passed: None,
        };
        let got = decide(
            Utc::now(),
            &c,
            Some(&existing),
            &NewSubmission {
                total_score: None,
                passed: None,
            },
        )
        .expect("ungraded retry allowed");
        assert!(got.overwrite_answers, "no scores -> overwrite with latest");
    }

    #[test]
    fn retries_enabled_reflects_config() {
        assert!(!cfg(1, 0, RetryPolicy::KeepBest, true).retries_enabled());
        assert!(cfg(3, 0, RetryPolicy::KeepBest, true).retries_enabled());
        assert!(cfg(1, 600, RetryPolicy::KeepBest, true).retries_enabled());
        assert!(cfg(0, 0, RetryPolicy::KeepBest, true).retries_enabled());
    }
}
