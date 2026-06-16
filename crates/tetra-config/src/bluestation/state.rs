use std::collections::{HashMap, HashSet, VecDeque};
use tetra_core::TimeslotAllocator;

/// A one-shot or repeating SDS broadcast message injected at runtime via the dashboard.
///
/// Each message is broadcast to all MSs on the cell (GSSI 0xFFFFFF) using the same
/// SDS-TL TRANSFER mechanism as Home Mode Display. Messages are transmitted at the
/// `home_mode_display` interval (or `sds_broadcast` interval if that is configured),
/// round-robining with the static PID-220 callsign text so neither displaces the other.
///
/// - `repeat_count = 0` → repeats indefinitely until explicitly deleted.
/// - `repeat_count > 0` → auto-removed after that many transmissions.
#[derive(Debug, Clone)]
pub struct LiveSdsMessage {
    /// Unique ID (monotonically incrementing, assigned by the stack).
    pub id: u32,
    /// Text to broadcast (UTF-8; encoded as ISO-8859-1 on TX, unknown chars → '?').
    pub text: String,
    /// SDS protocol ID. Defaults to 220 so it appears on the radio home screen.
    pub protocol_id: u8,
    /// Source ISSI shown on the radio. Defaults to 16777215 (0xFFFFFF, "network").
    pub source_issi: u32,
    /// 0 = repeat forever; >0 = auto-remove after this many transmissions.
    pub repeat_count: u32,
    /// Number of times this message has been transmitted so far.
    pub sent_count: u32,
}

#[derive(Debug, Clone)]
pub struct Subscriber {
    pub issi: u32,
    // Set of attached GSSIs
    pub attached_groups: HashSet<u32>,
}

/// Centralized subscriber registry tracking locally registered ISSIs and their group affiliations.
#[derive(Debug, Clone)]
pub struct SubscriberRegistry {
    /// Registered ISSIs → Subscriber information
    subscribers: HashMap<u32, Subscriber>,
    /// Set of all GSSIs with at least one local affiliate
    all_attached_groups: HashSet<u32>,
}

impl Default for SubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: HashMap::new(),
            all_attached_groups: HashSet::new(),
        }
    }

    pub fn is_registered(&self, issi: u32) -> bool {
        self.subscribers.contains_key(&issi)
    }

    /// Tolerant registration; if ISSI already registered, we overwrite it with a fresh Subscriber struct
    pub fn register(&mut self, issi: u32) {
        self.deregister(issi); // Clean up any existing registration to prevent stale affiliations
        self.subscribers.insert(
            issi,
            Subscriber {
                issi,
                attached_groups: HashSet::new(),
            },
        );
    }

    /// Gets mutable ref to subscriber. If not registered, a default Subscriber is inserted.
    pub fn get_subscriber_mut(&mut self, issi: u32) -> &mut Subscriber {
        self.subscribers.entry(issi).or_insert_with(|| Subscriber {
            issi,
            attached_groups: HashSet::new(),
        })
    }

    /// Deregister an ISSI, removing it from the registry and cleaning up any group affiliations
    pub fn deregister(&mut self, issi: u32) {
        if let Some(subscriber) = self.subscribers.remove(&issi) {
            // Clean up global group affiliations for this subscriber
            for gssi in &subscriber.attached_groups {
                // Check if any other subscriber is still affiliated with this group
                let still_has_members = self.subscribers.values().any(|s| s.attached_groups.contains(gssi));
                if !still_has_members {
                    self.all_attached_groups.remove(gssi);
                }
            }
        }
    }

    /// Add GSSI to subscriber's attached groups and global set
    pub fn affiliate(&mut self, issi: u32, gssi: u32) {
        let subscriber = self.get_subscriber_mut(issi);
        subscriber.attached_groups.insert(gssi);
        self.all_attached_groups.insert(gssi);
    }

    /// Remove GSSI from subscriber's attached groups. Update global set if no more subscribers are affiliated with this GSSI.
    pub fn deaffiliate(&mut self, issi: u32, gssi: u32) {
        let subscriber = self.get_subscriber_mut(issi);
        if subscriber.attached_groups.remove(&gssi) {
            // Check if any other subscriber is still affiliated with this group
            let still_has_members = self.subscribers.values().any(|s| s.attached_groups.contains(&gssi));
            if !still_has_members {
                self.all_attached_groups.remove(&gssi);
            }
        }
    }

    /// Check if any subscriber is affiliated with the given GSSI
    pub fn has_group_members(&self, gssi: u32) -> bool {
        self.all_attached_groups.contains(&gssi)
    }

    /// Returns all currently registered ISSIs.
    ///
    /// Used by BrewEntity after Brew reconnection to issue D-LOCATION-UPDATE-COMMAND
    /// to all locally registered MS, forcing them to re-affiliate with the BS.
    /// Without this, MS units that were registered before a Brew disconnect believe
    /// they are still affiliated and do not re-register, causing PTT denial until
    /// they are manually power-cycled or the BS service is restarted.
    pub fn all_registered_issis(&self) -> impl Iterator<Item = u32> + '_ {
        self.subscribers.keys().copied()
    }

    /// Groups the given ISSI is currently affiliated to (empty if not registered).
    /// Used by the SDS path to reach a member of an active group call on the group's
    /// traffic timeslot.
    pub fn attached_groups_of(&self, issi: u32) -> Vec<u32> {
        self.subscribers
            .get(&issi)
            .map(|s| s.attached_groups.iter().copied().collect())
            .unwrap_or_default()
    }
}

/// Runtime override for the built-in WX/METAR service, edited from the dashboard.
///
/// Mirrors the editable subset of `[wx_service]` config. When `Some`, it takes precedence
/// over the config so toggles/edits apply immediately without a restart; the dashboard
/// also writes the new values back to the TOML so they persist. `None` means "no override
/// — use the config value".
#[derive(Debug, Clone, Default)]
pub struct WxRuntimeOverride {
    pub enabled: bool,
    pub service_issi: u32,
    pub periodic_enabled: bool,
    pub periodic_issi: u32,
    pub periodic_is_group: bool,
    pub periodic_icao: String,
    pub periodic_interval_secs: u64,
}

/// Runtime override for Telegram alerts, edited from the dashboard.
///
/// Mirrors the editable `[telegram_alerts]` config. When `Some`, it takes precedence over the
/// config so toggles/edits (and the detected chat IDs / pasted token) apply immediately without
/// a restart; the dashboard also writes the values back to the TOML so they persist. `None`
/// means "no override — use the config value". The token is kept as a plain `String` here (the
/// state is in-memory only); the config-side `CfgTelegram` wraps it in `SecretField`.
#[derive(Debug, Clone, Default)]
pub struct TelegramRuntimeOverride {
    pub enabled: bool,
    pub bot_token: String,
    pub chat_ids: Vec<i64>,
    pub alert_connect: bool,
    pub alert_disconnect: bool,
    pub alert_t351: bool,
    pub alert_lip: bool,
    pub alert_backhaul: bool,
    pub alert_critical_logs: bool,
}

/// Mutable, stack-editable state (mutex-protected).
#[derive(Debug, Clone)]
pub struct StackState {
    pub timeslot_alloc: TimeslotAllocator,
    /// Backhaul/network connection to SwMI (e.g., Brew/TetraPack). False -> fallback mode.
    pub network_connected: bool,
    /// Centralized subscriber registry for local-first routing decisions.
    pub subscribers: SubscriberRegistry,
    /// Queue of live SDS messages injected at runtime via the dashboard.
    /// Transmitted round-robin alongside the static Home Mode Display text.
    pub live_sds_queue: VecDeque<LiveSdsMessage>,
    /// Monotonically incrementing ID counter for live SDS messages.
    pub next_live_sds_id: u32,
    /// Runtime ISSI whitelist override edited from the dashboard. When `Some`, it takes
    /// precedence over the config file's `[security] issi_whitelist` so changes apply
    /// immediately without a restart. An empty Vec here means "open network" (all ISSIs
    /// allowed), exactly like an empty whitelist in config. `None` means "no override —
    /// fall back to the config value". The dashboard also writes the new list back to the
    /// TOML so it survives a restart.
    pub issi_whitelist_override: Option<Vec<u32>>,
    /// Runtime override for the WX/METAR service (dashboard toggle). See WxRuntimeOverride.
    pub wx_override: Option<WxRuntimeOverride>,
    /// Runtime override for Telegram alerts (dashboard editing). See TelegramRuntimeOverride.
    pub telegram_override: Option<TelegramRuntimeOverride>,
    /// Live map "identity currently reachable on a traffic channel" → (DL timeslot, usage_marker),
    /// republished every tick by CMCE call control from the live call tables (so it is never
    /// stale). Keyed by GSSI for active group calls and by each participant ISSI for connected
    /// individual calls. The SDS path uses it to steal a FACCH half-slot on the right timeslot
    /// so it can reach an MS engaged in a call, which is NOT listening to the MCCH
    /// (ETSI EN 300 392-2 §23.5). Empty when no calls are active, so idle delivery stays on
    /// the MCCH exactly as before.
    pub active_call_ts: std::collections::HashMap<u32, (u8, u8)>,

    /// Per-MS energy-economy downlink monitoring window, republished every tick by MM from the
    /// live client registry (so it is never stale). Keyed by ISSI; value = (monitoring_frame
    /// 1..=18, monitoring_multiframe, cycle_len). Only MSs granted an actual energy-saving mode
    /// (Eg1..Eg7, cycle_len >= 2) appear here — a StayAlive / unknown MS is ABSENT, which the
    /// scheduler treats as "always reachable" (never gated). Used to defer unsolicited individual
    /// downlink (incoming-call D-SETUP, SDS) until the MS is awake on its window
    /// (ETSI EN 300 392-2 §16.7). Empty when no MS is in energy economy.
    pub ee_monitoring_windows: std::collections::HashMap<u32, (u8, u8, u8)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_deregister() {
        let mut reg = SubscriberRegistry::new();
        assert!(!reg.is_registered(1001));
        reg.register(1001);
        assert!(reg.is_registered(1001));
        reg.deregister(1001);
        assert!(!reg.is_registered(1001));
    }

    #[test]
    fn test_affiliate_deaffiliate() {
        let mut reg = SubscriberRegistry::new();
        reg.register(1001);
        reg.affiliate(1001, 91);
        assert!(reg.has_group_members(91));
        reg.deaffiliate(1001, 91);
        assert!(!reg.has_group_members(91));
    }

    #[test]
    fn test_has_group_members() {
        let mut reg = SubscriberRegistry::new();
        reg.register(1001);
        reg.register(1002);
        reg.register(1003);
        reg.affiliate(1001, 100);
        reg.affiliate(1002, 100);
        reg.affiliate(1003, 100);
        assert!(reg.has_group_members(100));

        // Deaffiliate one, should still have members
        reg.deaffiliate(1001, 100);
        assert!(reg.has_group_members(100));

        // Deregister a user, should still have members
        reg.deregister(1002);
        assert!(reg.has_group_members(100));

        // Deregister last user, should have no members
        reg.deregister(1003);
        assert!(!reg.has_group_members(100));
    }

    #[test]
    fn test_has_group_members_empty() {
        let reg = SubscriberRegistry::new();
        assert!(!reg.has_group_members(999));
    }

    #[test]
    fn test_register_overwrites_existing_subscriber() {
        let mut reg = SubscriberRegistry::new();
        reg.register(1001);
        reg.affiliate(1001, 91);
        assert!(reg.has_group_members(91));

        reg.register(1001);

        assert!(reg.is_registered(1001));
        reg.deaffiliate(1001, 91);
        assert!(!reg.has_group_members(91));
    }

    #[test]
    fn test_all_registered_issis() {
        let mut reg = SubscriberRegistry::new();
        reg.register(1001);
        reg.register(1002);
        reg.register(1003);
        let mut issis: Vec<u32> = reg.all_registered_issis().collect();
        issis.sort_unstable();
        assert_eq!(issis, vec![1001, 1002, 1003]);

        reg.deregister(1002);
        let mut issis: Vec<u32> = reg.all_registered_issis().collect();
        issis.sort_unstable();
        assert_eq!(issis, vec![1001, 1003]);
    }
}

impl Default for StackState {
    fn default() -> Self {
        Self {
            timeslot_alloc: TimeslotAllocator::default(),
            network_connected: false,
            subscribers: SubscriberRegistry::new(),
            live_sds_queue: VecDeque::new(),
            next_live_sds_id: 1,
            issi_whitelist_override: None,
            wx_override: None,
            telegram_override: None,
            active_call_ts: std::collections::HashMap::new(),
            ee_monitoring_windows: std::collections::HashMap::new(),
        }
    }
}
