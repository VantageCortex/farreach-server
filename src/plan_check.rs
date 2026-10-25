use hbb_common::{log, tokio};
use serde_derive::Deserialize;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

const DENY_MESSAGE: &str = "This computer isn't on an active FarReach plan.";
const OUTAGE_MESSAGE: &str =
    "FarReach couldn't confirm this computer's plan. Try again in a minute.";

#[derive(Clone)]
struct Cached {
    allow: bool,
    message: String,
    until: Instant,
}

static CACHE: Mutex<Option<HashMap<String, Cached>>> = Mutex::new(None);

pub fn plan_check_enabled(value: Option<&str>) -> bool {
    value
        .map(|item| item.trim().eq_ignore_ascii_case("on"))
        .unwrap_or(false)
}

#[derive(Deserialize)]
struct CheckBody {
    allow: bool,
    #[serde(default)]
    message: String,
    #[serde(default)]
    cache_seconds: Option<u64>,
}

pub fn decision_from_body(body: &str, allow_default: u64, deny_default: u64) -> Result<(bool, String, u64), ()> {
    let parsed: CheckBody = serde_json::from_str(body).map_err(|_| ())?;
    let seconds = match parsed.cache_seconds {
        Some(0) => 0,
        Some(seconds) => seconds,
        None => {
            if parsed.allow {
                allow_default
            } else {
                deny_default
            }
        }
    };
    let message = if parsed.allow {
        String::new()
    } else if parsed.message.is_empty() {
        DENY_MESSAGE.to_owned()
    } else {
        parsed.message
    };
    Ok((parsed.allow, message, seconds))
}

fn cache() -> std::sync::MutexGuard<'static, Option<HashMap<String, Cached>>> {
    CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn cached(id: &str, now: Instant) -> Option<Cached> {
    cache()
        .get_or_insert_with(HashMap::new)
        .get(id)
        .filter(|item| item.until > now)
        .cloned()
}

fn remember(id: &str, allow: bool, message: String, seconds: u64, now: Instant) {
    if seconds == 0 {
        return;
    }
    cache().get_or_insert_with(HashMap::new).insert(
        id.to_owned(),
        Cached {
            allow,
            message,
            until: now + Duration::from_secs(seconds),
        },
    );
}

fn enabled() -> bool {
    plan_check_enabled(std::env::var("FARREACH_PLAN_CHECK").ok().as_deref())
}

pub async fn refuse_reach(id: &str) -> Option<String> {
    if !enabled() {
        return None;
    }
    match ask(id, "reach").await {
        Ask::Allow => None,
        Ask::Deny(message) => {
            log_deny();
            Some(message)
        }
    }
}

pub fn note_connected(id: &str) {
    if !enabled() {
        return;
    }
    let id = id.to_owned();
    tokio::spawn(async move {
        let _ = ask(&id, "connected").await;
    });
}

enum Ask {
    Allow,
    Deny(String),
}

async fn ask(id: &str, action: &str) -> Ask {
    let now = Instant::now();
    if let Some(hit) = cached(id, now) {
        return if hit.allow {
            Ask::Allow
        } else {
            Ask::Deny(hit.message)
        };
    }
    let url = std::env::var("FARREACH_PLAN_CHECK_URL").unwrap_or_default();
    let token = std::env::var("FARREACH_CHECK_TOKEN").unwrap_or_default();
    if url.trim().is_empty() || token.trim().is_empty() {
        return Ask::Deny(OUTAGE_MESSAGE.to_owned());
    }
    let owned = id.to_owned();
    let action = action.to_owned();
    let fetched = tokio::task::spawn_blocking(move || post_check(&url, &token, &owned, &action)).await;
    match fetched {
        Ok(Ok((allow, message, seconds))) => {
            remember(id, allow, message.clone(), seconds, Instant::now());
            if allow {
                Ask::Allow
            } else {
                Ask::Deny(message)
            }
        }
        _ => {
            if let Some(hit) = cached(&id, Instant::now()) {
                if hit.allow {
                    return Ask::Allow;
                }
            }
            Ask::Deny(OUTAGE_MESSAGE.to_owned())
        }
    }
}

fn post_check(url: &str, token: &str, id: &str, action: &str) -> Result<(bool, String, u64), ()> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(800))
        .build()
        .map_err(|_| ())?;
    let response = client
        .post(url)
        .header("Authorization", format!("Bearer {}", token))
        .json(&serde_json::json!({ "id": id, "action": action }))
        .send()
        .map_err(|_| ())?;
    if !response.status().is_success() {
        return Err(());
    }
    let text = response.text().map_err(|_| ())?;
    decision_from_body(&text, 300, 30)
}

fn log_deny() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    static EXTRA: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|item| item.as_secs())
        .unwrap_or(0);
    let previous = LAST.load(Ordering::Relaxed);
    if previous != 0 && now.saturating_sub(previous) < 60 {
        EXTRA.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let extra = EXTRA.swap(0, Ordering::Relaxed);
    LAST.store(now, Ordering::Relaxed);
    log::warn!("FarReach plan check denied a reach ({} more in the last minute)", extra);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stays_off_unless_the_switch_says_on() {
        assert!(!plan_check_enabled(None));
        assert!(!plan_check_enabled(Some("off")));
        assert!(!plan_check_enabled(Some("")));
        assert!(plan_check_enabled(Some("on")));
        assert!(plan_check_enabled(Some(" ON ")));
    }

    #[test]
    fn reads_an_allow_and_a_deny() {
        let (allow, _, seconds) = decision_from_body(r#"{"allow":true,"message":"","cache_seconds":12}"#, 300, 30).unwrap();
        assert!(allow);
        assert_eq!(seconds, 12);
        let (allow, message, seconds) = decision_from_body(r#"{"allow":false}"#, 300, 30).unwrap();
        assert!(!allow);
        assert_eq!(message, DENY_MESSAGE);
        assert_eq!(seconds, 30);
        let (_, _, none) = decision_from_body(r#"{"allow":true,"cache_seconds":0}"#, 300, 30).unwrap();
        assert_eq!(none, 0);
        assert!(decision_from_body("nope", 300, 30).is_err());
    }

    #[test]
    fn an_outage_keeps_a_remembered_yes_only() {
        let id = "cache-yes";
        remember(id, true, String::new(), 300, Instant::now());
        let hit = cached(id, Instant::now()).unwrap();
        assert!(hit.allow);
        remember("cache-old", true, String::new(), 1, Instant::now() - Duration::from_secs(5));
        assert!(cached("cache-old", Instant::now()).is_none());
    }
}
