use std::collections::HashMap;

use serde::Deserialize;
use toml::Value;

/// Restart-recovery configuration.
///
/// After a BS process restart (update / crash / service restart) the in-RAM MM registry is
/// empty, yet radios are still RF-camped on the cell — so the first group PTT fails ("no
/// listeners") until each radio happens to re-register on its own (often only on power-cycle).
///
/// When `enabled`, the BS persists a small JSON cache of known terminals (ISSI + their
/// persistent groups + energy-saving mode) and, on startup, proactively sends
/// D-LOCATION-UPDATE-COMMAND (ETSI EN 300 392-2 §16.4.4) to each cached terminal, TDMA-paced,
/// forcing them to re-register with a group identity report. The existing coverage-return
/// re-affiliation path then restores CMCE/Brew group state — PTT works again within seconds of
/// boot, without human intervention.
///
/// Default OFF: proactively keying COMMANDs at a batch of ISSIs right after boot is RF-affecting
/// (MCCH load), so it must be a deliberate operator choice, consistent with the other opt-in
/// capabilities in this stack.
#[derive(Debug, Clone)]
pub struct CfgRecovery {
    /// Master on/off for proactive restart recovery.
    pub enabled: bool,
    /// Optional scope filter. Empty = recover every ISSI in the persisted cache (mirrors the
    /// empty-whitelist = "all" semantics of [`super::sec_security::CfgSecurity`]). Non-empty =
    /// only replay COMMANDs to these ISSIs.
    pub issi_allowlist: Vec<u32>,
    /// Optional explicit path to the recovery cache JSON. `None` = the binary derives
    /// `<config-dir>/recovery_cache.json` (the radioid_cache.json convention).
    pub cache_path: Option<String>,
    /// Per-ISSI D-LOCATION-UPDATE-COMMAND re-send attempts at startup before giving up on a
    /// terminal that never answers (e.g. powered off mid-outage). Clamped 1..=500.
    pub max_replay_attempts: u32,
    /// Number of COMMANDs emitted per TDMA frame during the startup sweep, to bound MCCH load.
    /// Clamped 1..=18.
    pub replay_per_frame: u32,
    /// Debounce window (seconds) for coalescing a burst of registry changes into one atomic
    /// cache write, to spare SD-card wear. Clamped 1..=300.
    pub debounce_secs: u64,
    /// Hard cap on cached ISSIs (bounds disk size + boot replay time). Clamped 1..=65535.
    pub max_cached_issis: u32,
}

impl Default for CfgRecovery {
    fn default() -> Self {
        CfgRecovery {
            enabled: false,
            issi_allowlist: Vec::new(),
            cache_path: None,
            max_replay_attempts: 150,
            replay_per_frame: 1,
            debounce_secs: 5,
            max_cached_issis: 1024,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CfgRecoveryDto {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub issi_allowlist: Vec<u32>,
    #[serde(default)]
    pub cache_path: Option<String>,
    #[serde(default = "default_max_replay_attempts")]
    pub max_replay_attempts: u32,
    #[serde(default = "default_replay_per_frame")]
    pub replay_per_frame: u32,
    #[serde(default = "default_debounce_secs")]
    pub debounce_secs: u64,
    #[serde(default = "default_max_cached_issis")]
    pub max_cached_issis: u32,

    /// Captures any unrecognised key so parsing.rs can reject typos (e.g. `enable`,
    /// `max_replay_attempt`) rather than silently leaving the feature dormant.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

fn default_max_replay_attempts() -> u32 {
    150
}
fn default_replay_per_frame() -> u32 {
    1
}
fn default_debounce_secs() -> u64 {
    5
}
fn default_max_cached_issis() -> u32 {
    1024
}

pub fn apply_recovery_patch(dto: CfgRecoveryDto) -> CfgRecovery {
    CfgRecovery {
        enabled: dto.enabled,
        issi_allowlist: dto.issi_allowlist,
        // An empty/whitespace string means "use the default path" (matching the documented
        // `cache_path = ""` example), not a literal empty path that would disable persistence.
        cache_path: dto.cache_path.filter(|s| !s.trim().is_empty()),
        // Clamp to sane ranges so a bad TOML value can't wedge boot (house style — same as
        // hangtime_secs / periodic_registration_secs in sec_cell.rs).
        max_replay_attempts: dto.max_replay_attempts.clamp(1, 500),
        replay_per_frame: dto.replay_per_frame.clamp(1, 18),
        debounce_secs: dto.debounce_secs.clamp(1, 300),
        max_cached_issis: dto.max_cached_issis.clamp(1, 65535),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_defaults_apply_when_only_enabled_set() {
        // A minimal `[recovery]` table with just `enabled = true` must pick up the serde
        // field defaults (these are applied during deserialization, NOT via derive(Default)).
        let dto: CfgRecoveryDto = toml::from_str("enabled = true").unwrap();
        let c = apply_recovery_patch(dto);
        assert!(c.enabled);
        assert!(c.issi_allowlist.is_empty());
        assert_eq!(c.max_replay_attempts, 150);
        assert_eq!(c.replay_per_frame, 1);
        assert_eq!(c.debounce_secs, 5);
        assert_eq!(c.max_cached_issis, 1024);
    }

    #[test]
    fn clamps_out_of_range() {
        let dto = CfgRecoveryDto {
            enabled: true,
            max_replay_attempts: 0,
            replay_per_frame: 0,
            debounce_secs: 0,
            max_cached_issis: 0,
            ..Default::default()
        };
        let c = apply_recovery_patch(dto);
        assert_eq!(c.max_replay_attempts, 1);
        assert_eq!(c.replay_per_frame, 1);
        assert_eq!(c.debounce_secs, 1);
        assert_eq!(c.max_cached_issis, 1);

        let dto = CfgRecoveryDto { replay_per_frame: 999, max_cached_issis: 9_999_999, ..Default::default() };
        let c = apply_recovery_patch(dto);
        assert_eq!(c.replay_per_frame, 18);
        assert_eq!(c.max_cached_issis, 65535);
    }

    #[test]
    fn empty_cache_path_becomes_none() {
        // The documented `cache_path = ""` must mean "use the default", not a literal empty path.
        let dto = CfgRecoveryDto { cache_path: Some("   ".to_string()), ..Default::default() };
        assert_eq!(apply_recovery_patch(dto).cache_path, None);
        let dto = CfgRecoveryDto { cache_path: Some("/etc/fs/cache.json".to_string()), ..Default::default() };
        assert_eq!(apply_recovery_patch(dto).cache_path.as_deref(), Some("/etc/fs/cache.json"));
    }
}
