use hbb_common::{log, tokio};
use serde_derive::Deserialize;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, OnceLock,
    },
    time::{Duration, Instant, SystemTime},
};

const DENY_MESSAGE: &str = "This computer isn't on an active FarReach plan.";
const OUTAGE_MESSAGE: &str =
    "FarReach couldn't confirm this computer's plan. Try again in a minute.";
const DAY_SECS: u64 = 24 * 60 * 60;
const CONNECTED_SECS: u64 = 60;
const MAP_LIMIT: usize = 10_000;
const BACKGROUND_LIMIT: usize = 8;

#[derive(Clone)]
struct Cached {
    allow: bool,
    message: String,
    until: Instant,
}

static CACHE: Mutex<Option<HashMap<String, Cached>>> = Mutex::new(None);
static ALLOWED: Mutex<Option<HashMap<String, SystemTime>>> = Mutex::new(None);
static CONNECTED: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);
static HTTP: OnceLock<reqwest::Client> = OnceLock::new();
static BACKGROUND: AtomicUsize = AtomicUsize::new(0);

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

fn allowed() -> std::sync::MutexGuard<'static, Option<HashMap<String, SystemTime>>> {
    ALLOWED.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn connected() -> std::sync::MutexGuard<'static, Option<HashMap<String, Instant>>> {
    CONNECTED.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn cached(id: &str, now: Instant) -> Option<Cached> {
    cache()
        .get_or_insert_with(HashMap::new)
        .get(id)
        .filter(|item| item.until > now)
        .cloned()
}

fn store_answer(id: &str, allow: bool, message: String, until: Instant) {
    let mut guard = cache();
    let map = guard.get_or_insert_with(HashMap::new);
    map.insert(
        id.to_owned(),
        Cached {
            allow,
            message,
            until,
        },
    );
    prune_expired(map, |item| item.until <= Instant::now());
}

fn remember(id: &str, allow: bool, message: String, seconds: u64, at: Instant) {
    if allow {
        note_allowed(id, SystemTime::now());
    }
    if seconds == 0 {
        return;
    }
    let Some(until) = at.checked_add(Duration::from_secs(seconds)) else {
        return;
    };
    store_answer(id, allow, message, until);
}

fn note_allowed(id: &str, at: SystemTime) {
    let Some(until) = at.checked_add(Duration::from_secs(DAY_SECS)) else {
        return;
    };
    store_allowed(id, until);
}

fn store_allowed(id: &str, until: SystemTime) {
    let mut guard = allowed();
    let map = guard.get_or_insert_with(HashMap::new);
    map.insert(id.to_owned(), until);
    prune_expired(map, |until| *until <= SystemTime::now());
}

fn allowed_recently(id: &str, now: SystemTime) -> bool {
    allowed()
        .get_or_insert_with(HashMap::new)
        .get(id)
        .map(|until| *until > now)
        .unwrap_or(false)
}

fn claim_connected(id: &str, now: Instant) -> bool {
    let mut guard = connected();
    let map = guard.get_or_insert_with(HashMap::new);
    if let Some(until) = map.get(id) {
        if *until > now {
            return false;
        }
    }
    let Some(until) = now.checked_add(Duration::from_secs(CONNECTED_SECS)) else {
        return false;
    };
    map.insert(id.to_owned(), until);
    prune_expired(map, |until| *until <= Instant::now());
    true
}

fn prune_expired<T>(map: &mut HashMap<String, T>, mut expired: impl FnMut(&T) -> bool) {
    if map.len() <= MAP_LIMIT {
        return;
    }
    map.retain(|_, value| !expired(value));
    if map.len() <= MAP_LIMIT {
        return;
    }
    let extra = map.len() - MAP_LIMIT;
    let keys: Vec<String> = map.keys().take(extra).cloned().collect();
    for key in keys {
        map.remove(&key);
    }
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

pub fn refuse_udp(id: &str) -> Option<String> {
    if !enabled() {
        return None;
    }
    let (refusal, background) = decide(id, Instant::now());
    if background {
        start_background_reach(id);
    }
    if refusal.is_some() {
        log_deny();
    }
    refusal
}

pub fn note_connected(id: &str) {
    if !enabled() {
        return;
    }
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    if !claim_connected(id, Instant::now()) {
        return;
    }
    let id = id.to_owned();
    tokio::spawn(async move {
        let _ = post_check(&id, "connected").await;
    });
}

enum Ask {
    Allow,
    Deny(String),
}

enum Memory {
    Allow,
    Deny(String),
    Unknown,
}

fn memory(id: &str, now: Instant) -> Memory {
    if let Some(hit) = cached(id, now) {
        return if hit.allow {
            Memory::Allow
        } else {
            Memory::Deny(hit.message)
        };
    }
    if allowed_recently(id, SystemTime::now()) {
        Memory::Allow
    } else {
        Memory::Unknown
    }
}

fn decide(id: &str, now: Instant) -> (Option<String>, bool) {
    match memory(id, now) {
        Memory::Allow => (None, false),
        Memory::Deny(message) => (Some(message), false),
        Memory::Unknown => (Some(OUTAGE_MESSAGE.to_owned()), true),
    }
}

fn outage_answer(id: &str, now: Instant) -> Ask {
    match decide(id, now).0 {
        None => Ask::Allow,
        Some(message) => Ask::Deny(message),
    }
}

async fn ask(id: &str, action: &str) -> Ask {
    if let Some(hit) = cached(id, Instant::now()) {
        return if hit.allow {
            Ask::Allow
        } else {
            Ask::Deny(hit.message)
        };
    }
    match post_check(id, action).await {
        Ok((allow, message, seconds)) => {
            remember(id, allow, message.clone(), seconds, Instant::now());
            if allow {
                Ask::Allow
            } else {
                Ask::Deny(message)
            }
        }
        Err(()) => outage_answer(id, Instant::now()),
    }
}

struct BackgroundPermit;

impl Drop for BackgroundPermit {
    fn drop(&mut self) {
        BACKGROUND.fetch_sub(1, Ordering::Relaxed);
    }
}

fn reserve_background() -> Option<BackgroundPermit> {
    loop {
        let current = BACKGROUND.load(Ordering::Relaxed);
        if current >= BACKGROUND_LIMIT {
            return None;
        }
        if BACKGROUND
            .compare_exchange(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Some(BackgroundPermit);
        }
    }
}

fn start_background_reach(id: &str) {
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    let Some(permit) = reserve_background() else {
        return;
    };
    let id = id.to_owned();
    tokio::spawn(async move {
        let _permit = permit;
        let _ = ask(&id, "reach").await;
    });
}

fn http_client() -> Result<&'static reqwest::Client, ()> {
    if let Some(client) = HTTP.get() {
        return Ok(client);
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(800))
        .build()
        .map_err(|_| ())?;
    Ok(HTTP.get_or_init(|| client))
}

async fn post_check(id: &str, action: &str) -> Result<(bool, String, u64), ()> {
    let url = std::env::var("FARREACH_PLAN_CHECK_URL").unwrap_or_default();
    let token = std::env::var("FARREACH_CHECK_TOKEN").unwrap_or_default();
    if url.trim().is_empty() || token.trim().is_empty() {
        return Err(());
    }
    let response = http_client()?
        .post(&url)
        .header("Authorization", format!("Bearer {}", token))
        .json(&serde_json::json!({ "id": id, "action": action }))
        .send()
        .await
        .map_err(|_| ())?;
    if !response.status().is_success() {
        return Err(());
    }
    let text = response.text().await.map_err(|_| ())?;
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

    #[test]
    fn connected_skips_the_cache_and_is_rate_limited() {
        let id = "connected-skips-cache";
        let now = Instant::now();
        remember(id, true, String::new(), 300, now);
        assert!(cached(id, now).unwrap().allow);
        assert!(claim_connected(id, now));
        assert!(!claim_connected(id, now + Duration::from_secs(59)));
        assert!(claim_connected(id, now + Duration::from_secs(60)));
    }

    #[test]
    fn an_outage_allows_an_id_allowed_23_hours_ago_and_refuses_older_and_unknown() {
        let now = SystemTime::now();
        note_allowed(
            "outage-23h",
            now.checked_sub(Duration::from_secs(23 * 60 * 60)).unwrap(),
        );
        note_allowed(
            "outage-25h",
            now.checked_sub(Duration::from_secs(25 * 60 * 60)).unwrap(),
        );
        let at = Instant::now();
        assert!(matches!(outage_answer("outage-23h", at), Ask::Allow));
        assert!(matches!(
            outage_answer("outage-25h", at),
            Ask::Deny(message) if message == OUTAGE_MESSAGE
        ));
        assert!(matches!(
            outage_answer("outage-unknown", at),
            Ask::Deny(message) if message == OUTAGE_MESSAGE
        ));
    }

    #[test]
    fn udp_decision_never_waits_and_refuses_an_unknown_id() {
        let (refusal, background) = decide("udp-unknown-id", Instant::now());
        assert_eq!(refusal.as_deref(), Some(OUTAGE_MESSAGE));
        assert!(background);
    }

    #[test]
    fn pruning_keeps_the_maps_bounded() {
        let mut live = HashMap::new();
        let later = Instant::now() + Duration::from_secs(30);
        for i in 0..10_050 {
            live.insert(format!("live-{i}"), later);
            prune_expired(&mut live, |_| false);
        }
        assert!(live.len() <= MAP_LIMIT);

        let expired_at = Instant::now();
        let expired_allow = SystemTime::now();
        for i in 0..10_001 {
            store_answer(&format!("prune-c-{i}"), false, String::new(), expired_at);
            store_allowed(&format!("prune-a-{i}"), expired_allow);
            let mut guard = connected();
            let map = guard.get_or_insert_with(HashMap::new);
            map.insert(format!("prune-n-{i}"), expired_at);
            prune_expired(map, |until| *until <= Instant::now());
        }
        assert!(cache().as_ref().map(|map| map.len()).unwrap_or(0) <= MAP_LIMIT);
        assert!(allowed().as_ref().map(|map| map.len()).unwrap_or(0) <= MAP_LIMIT);
        assert!(connected().as_ref().map(|map| map.len()).unwrap_or(0) <= MAP_LIMIT);
        assert!(cached("prune-c-0", Instant::now()).is_none());
        assert!(!allowed_recently("prune-a-0", SystemTime::now()));
        assert!(connected().as_ref().map(|map| !map.contains_key("prune-n-0")).unwrap_or(true));
    }
}
