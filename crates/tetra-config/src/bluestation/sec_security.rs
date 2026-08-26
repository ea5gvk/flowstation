use std::collections::HashMap;

use serde::Deserialize;

/// How `issi_whitelist` is interpreted. A bare `Vec` cannot express "deny everyone": an operator
/// who empties the list to lock the cell down actually opens it fully under the legacy semantics.
/// This makes the posture explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WhitelistMode {
    /// No mode configured — legacy semantics: an empty list means "open network", a non-empty
    /// list is an allow-list. Default so existing configs behave exactly as before.
    #[default]
    Auto,
    /// Access control off: every ISSI is allowed whatever the list holds.
    Open,
    /// The list is authoritative. An EMPTY list therefore means DENY-ALL — the only way to
    /// express "lock the cell down", which `Auto` cannot.
    Enforce,
}

impl WhitelistMode {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(WhitelistMode::Auto),
            "open" | "off" | "disabled" => Some(WhitelistMode::Open),
            "enforce" | "strict" => Some(WhitelistMode::Enforce),
            _ => None,
        }
    }
}

/// Default cap on the MM client registry. Uplink is unauthenticated (EN 300 392-7 TEA is not
/// implemented), so any radio can claim any of the 2^24 ISSIs — without a cap a registration
/// flood grows the registry until the cell is OOM-killed.
pub const DEFAULT_MAX_REGISTERED_CLIENTS: usize = 2048;
/// Default accepted registrations per minute, per source ISSI. Generous for a real radio (T351
/// plus a post-PTT roaming update), tight enough that one forged ISSI cannot churn the registry.
pub const DEFAULT_REGISTRATION_RATE_LIMIT_PER_MIN: u32 = 30;

/// Access control / security configuration
#[derive(Debug, Clone)]
pub struct CfgSecurity {
    /// ISSI whitelist. Interpretation depends on `whitelist_mode`.
    /// Example config:
    ///   [security]
    ///   issi_whitelist = [2260571, 1001, 1002]
    ///   whitelist_mode = "enforce"   # empty list = deny-all
    pub issi_whitelist: Vec<u32>,
    /// See [`WhitelistMode`].
    pub whitelist_mode: WhitelistMode,
    /// Honour an unauthenticated U-ITSI-DETACH / migrating location update as a teardown of the
    /// claimed ISSI. There is no air-interface authentication, so such a PDU is forgeable and a
    /// replay is a targeted DoS; an operator who does not need detach at all can switch it off.
    pub honour_unauthenticated_detach: bool,
    /// Hard cap on the MM client registry (0 = unlimited, pre-hardening behaviour).
    pub max_registered_clients: usize,
    /// Accepted registrations per minute per source ISSI (0 = disabled).
    pub registration_rate_limit_per_min: u32,
    /// Send a D-AUTHENTICATION demand (one-way, SwMI authenticates the MS — EN 300 392-7
    /// clause 4.1.2) after every successful registration of an ISSI that has a key in
    /// `issi_keys`. ISSIs with no configured key are left unauthenticated regardless of this
    /// flag, so it is safe to enable while only some radios have been provisioned with a K.
    pub authentication_enabled: bool,
    /// Per-ISSI TETRA authentication key K (128 bits), used only for [`authentication_enabled`].
    ///
    /// SECURITY NOTE: this stores K in plaintext in `config.toml`. Anyone who can read that file
    /// (or the dashboard's config editor / backups) can impersonate the corresponding radio's
    /// authentication response and derive its DCK. Treat this file with the same care as an SSH
    /// private key: restrict its filesystem permissions, and if you use the dashboard's remote
    /// config editor, be aware it may transit and be stored wherever that connection is proxied.
    pub issi_keys: HashMap<u32, [u8; 16]>,
    /// STRICT MODE: refuse registration to any ISSI that has no key in [`Self::issi_keys`], and
    /// deregister a terminal that fails its authentication challenge.
    ///
    /// Requires [`Self::authentication_enabled`]; ignored on its own. OFF by default.
    ///
    /// ⚠️ Enabling this locks out every radio that has not been provisioned with a matching K —
    /// there is no grace period and no self-service enrolment. Provision the keys FIRST, confirm
    /// in the log that each terminal authenticates successfully, and only then turn this on.
    pub authentication_required: bool,
    /// Enable TETRA air-interface encryption (AIE) using TEA2 with a cell-wide Static Cipher Key
    /// — a security class 2 setup (ETSI EN 300 392-7 clause 6). OFF by default.
    ///
    /// EXPERIMENTAL / NOT INTEROPERABLE: the TB5 key-modification step (raw SCK + public network
    /// information -> the ECK actually fed to TEA2) is NOT implemented, so `sck` is used directly
    /// as the ECK. A compliant radio derives a different ECK from the same SCK and will therefore
    /// produce garbage in both directions. Only enable this for BS-to-BS testing against another
    /// FlowStation build carrying this same code — not on a cell serving real terminals.
    pub encryption_enabled: bool,
    /// Cell-wide Static Cipher Key (80 bits), used only when [`Self::encryption_enabled`] is set.
    /// Same plaintext-in-config caveat as `issi_keys` applies.
    pub sck: Option<[u8; 10]>,
}

impl Default for CfgSecurity {
    fn default() -> Self {
        CfgSecurity {
            issi_whitelist: Vec::new(),
            whitelist_mode: WhitelistMode::Auto,
            honour_unauthenticated_detach: true,
            max_registered_clients: DEFAULT_MAX_REGISTERED_CLIENTS,
            registration_rate_limit_per_min: DEFAULT_REGISTRATION_RATE_LIMIT_PER_MIN,
            authentication_enabled: false,
            issi_keys: HashMap::new(),
            authentication_required: false,
            encryption_enabled: false,
            sck: None,
        }
    }
}

impl CfgSecurity {
    /// Returns true if the given ISSI is allowed to register.
    pub fn is_issi_allowed(&self, issi: u32) -> bool {
        self.allows(issi, None)
    }

    /// Whitelist decision honouring an optional runtime (dashboard) override list, which replaces
    /// the configured list. The mode applies to whichever list is effective, so an operator who
    /// clears the list from the dashboard under `enforce` gets deny-all, not an open cell.
    pub fn allows(&self, issi: u32, override_list: Option<&[u32]>) -> bool {
        let list = override_list.unwrap_or(&self.issi_whitelist);
        match self.whitelist_mode {
            WhitelistMode::Open => true,
            WhitelistMode::Auto => list.is_empty() || list.contains(&issi),
            WhitelistMode::Enforce => list.contains(&issi),
        }
    }

    /// One-line description of the effective access-control posture, for the startup log. The
    /// whole point is that an operator can read the cell's real posture out of the log rather
    /// than inferring it from an empty TOML array.
    pub fn access_control_posture(&self) -> String {
        let n = self.issi_whitelist.len();
        match self.whitelist_mode {
            WhitelistMode::Open => "OPEN — access control disabled (whitelist_mode = \"open\")".to_string(),
            WhitelistMode::Auto if n == 0 => {
                "OPEN — no issi_whitelist configured; ANY ISSI may register (set whitelist_mode = \"enforce\" to lock down)".to_string()
            }
            WhitelistMode::Auto => format!("ALLOW-LIST — {n} ISSI(s) may register"),
            WhitelistMode::Enforce if n == 0 => "DENY-ALL — whitelist_mode = \"enforce\" with an empty issi_whitelist".to_string(),
            WhitelistMode::Enforce => format!("ALLOW-LIST (enforced) — {n} ISSI(s) may register"),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CfgSecurityDto {
    #[serde(default)]
    pub issi_whitelist: Vec<u32>,
    #[serde(default)]
    pub whitelist_mode: Option<String>,
    #[serde(default)]
    pub honour_unauthenticated_detach: Option<bool>,
    #[serde(default)]
    pub max_registered_clients: Option<usize>,
    #[serde(default)]
    pub registration_rate_limit_per_min: Option<u32>,
    #[serde(default)]
    pub authentication_enabled: Option<bool>,
    /// `{ issi = "hex32chars" }`, e.g. `issi_keys = { 2260571 = "0123456789abcdef0123456789abcdef" }`.
    /// NOTE: the map key comes in as a string here (TOML table/inline-table keys are always text
    /// in the data model, quoted or not) — the ISSI itself is parsed to u32 in `parse_issi_keys`.
    #[serde(default)]
    pub issi_keys: HashMap<String, String>,
    #[serde(default)]
    pub authentication_required: Option<bool>,
    #[serde(default)]
    pub encryption_enabled: Option<bool>,
    /// 20 hex characters (80-bit SCK), e.g. `sck = "00112233445566778899"`.
    #[serde(default)]
    pub sck: Option<String>,
}

/// Decode exactly `N` bytes from a hex string, or `None` if the length or characters are wrong.
fn parse_hex_key<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let hex = hex.trim();
    if hex.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte_out) in out.iter_mut().enumerate() {
        *byte_out = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Parse the cell-wide SCK. Logs and returns None on a malformed value rather than failing the
/// whole config load — a bad key leaves encryption off (see `AieContext`), it never falls back to
/// a zero key.
fn parse_sck(raw: Option<String>) -> Option<[u8; 10]> {
    let raw = raw?;
    match parse_hex_key::<10>(&raw) {
        Some(k) => Some(k),
        None => {
            tracing::error!(
                "security.sck: must be exactly 20 hex characters (80-bit key) — encryption will stay DISABLED"
            );
            None
        }
    }
}

/// Parse a 32-hex-character K into 16 bytes, and its ISSI key (a string, per TOML's data model —
/// see the note on `RawSecurityDto::issi_keys`) into a u32. Logs and skips (rather than failing
/// config load entirely) on a malformed entry, so one typo doesn't lock the operator out of an
/// otherwise valid config via the fallback-config mechanism.
fn parse_issi_keys(raw: HashMap<String, String>) -> HashMap<u32, [u8; 16]> {
    let mut out = HashMap::with_capacity(raw.len());
    for (issi_str, hex) in raw {
        let issi: u32 = match issi_str.trim().parse() {
            Ok(v) => v,
            Err(_) => {
                tracing::error!("security.issi_keys: \"{}\" is not a valid ISSI (u32) — skipping this entry", issi_str);
                continue;
            }
        };
        let hex = hex.trim();
        if hex.len() != 32 {
            tracing::error!(
                "security.issi_keys: K for ISSI {} is {} hex chars, expected 32 (16 bytes) — skipping, this ISSI will not be authenticated",
                issi,
                hex.len()
            );
            continue;
        }
        let mut k = [0u8; 16];
        let mut ok = true;
        for (i, byte_out) in k.iter_mut().enumerate() {
            match u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16) {
                Ok(b) => *byte_out = b,
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            tracing::error!("security.issi_keys: K for ISSI {} is not valid hex — skipping, this ISSI will not be authenticated", issi);
            continue;
        }
        out.insert(issi, k);
    }
    out
}

pub fn apply_security_patch(dto: CfgSecurityDto) -> CfgSecurity {
    let defaults = CfgSecurity::default();
    // An unrecognised mode falls back to "auto"; the effective posture is logged at startup
    // (see access_control_posture) so a typo can't silently pass for a lockdown.
    let whitelist_mode = dto
        .whitelist_mode
        .as_deref()
        .map(|s| WhitelistMode::parse(s).unwrap_or(WhitelistMode::Auto))
        .unwrap_or(WhitelistMode::Auto);
    CfgSecurity {
        issi_whitelist: dto.issi_whitelist,
        whitelist_mode,
        honour_unauthenticated_detach: dto.honour_unauthenticated_detach.unwrap_or(defaults.honour_unauthenticated_detach),
        max_registered_clients: dto.max_registered_clients.unwrap_or(defaults.max_registered_clients),
        registration_rate_limit_per_min: dto
            .registration_rate_limit_per_min
            .unwrap_or(defaults.registration_rate_limit_per_min),
        authentication_enabled: dto.authentication_enabled.unwrap_or(defaults.authentication_enabled),
        issi_keys: parse_issi_keys(dto.issi_keys),
        authentication_required: dto.authentication_required.unwrap_or(defaults.authentication_required),
        encryption_enabled: dto.encryption_enabled.unwrap_or(defaults.encryption_enabled),
        sck: parse_sck(dto.sck),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The footgun: an empty list must stay "open" under the legacy default, but `enforce` must
    /// make the same empty list mean deny-all.
    #[test]
    fn empty_whitelist_semantics_depend_on_mode() {
        let mut cfg = CfgSecurity::default();
        assert!(cfg.is_issi_allowed(1234), "empty list under auto = open network");

        cfg.whitelist_mode = WhitelistMode::Enforce;
        assert!(!cfg.is_issi_allowed(1234), "empty list under enforce = deny-all");

        cfg.issi_whitelist = vec![1234];
        assert!(cfg.is_issi_allowed(1234));
        assert!(!cfg.is_issi_allowed(5678));

        cfg.whitelist_mode = WhitelistMode::Open;
        assert!(cfg.is_issi_allowed(5678), "open ignores the list entirely");
    }

    /// The dashboard override replaces the list but not the mode.
    #[test]
    fn override_list_follows_the_configured_mode() {
        let mut cfg = CfgSecurity::default();
        cfg.issi_whitelist = vec![1];
        assert!(cfg.allows(2, Some(&[2])), "override list is authoritative");
        assert!(!cfg.allows(1, Some(&[2])), "config list is ignored when overridden");
        assert!(cfg.allows(9, Some(&[])), "empty override under auto = open");

        cfg.whitelist_mode = WhitelistMode::Enforce;
        assert!(!cfg.allows(9, Some(&[])), "empty override under enforce = deny-all");
    }

    #[test]
    fn issi_keys_parses_valid_hex_and_skips_malformed_entries() {
        let mut raw = HashMap::new();
        raw.insert("1001".to_string(), "0123456789abcdef0123456789abcdef".to_string());
        raw.insert("1002".to_string(), "tooshort".to_string()); // wrong length
        raw.insert("1003".to_string(), "zz23456789abcdef0123456789abcdef".to_string()); // not hex
        raw.insert("not_a_number".to_string(), "0123456789abcdef0123456789abcdef".to_string()); // bad ISSI

        let parsed = parse_issi_keys(raw);
        assert_eq!(parsed.len(), 1, "only the well-formed entry should survive");
        assert_eq!(
            parsed.get(&1001),
            Some(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])
        );
        assert!(!parsed.contains_key(&1002));
        assert!(!parsed.contains_key(&1003));
    }

    #[test]
    fn authentication_required_defaults_to_off() {
        let cfg = CfgSecurity::default();
        assert!(!cfg.authentication_required, "strict mode must never be the default");
        assert!(!cfg.authentication_enabled);
    }

    /// The gate in mm_bs requires BOTH flags; assert the config can express that combination and
    /// that `required` alone does not imply `enabled`.
    #[test]
    fn required_alone_does_not_enable_authentication() {
        let mut cfg = CfgSecurity::default();
        cfg.authentication_required = true;
        assert!(!cfg.authentication_enabled, "required must not silently switch authentication on");
    }

    #[test]
    fn sck_parses_only_a_well_formed_20_hex_char_key() {
        assert_eq!(
            parse_sck(Some("00112233445566778899".to_string())),
            Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99])
        );
        assert_eq!(parse_sck(None), None);
        assert_eq!(parse_sck(Some("001122".to_string())), None, "too short must not be accepted");
        assert_eq!(
            parse_sck(Some("00112233445566778899AABB".to_string())),
            None,
            "too long must not be accepted"
        );
        assert_eq!(
            parse_sck(Some("zz112233445566778899".to_string())),
            None,
            "non-hex must not be accepted"
        );
    }

    /// A malformed or absent key must leave encryption off rather than silently using zeros.
    #[test]
    fn bad_sck_does_not_produce_a_usable_key() {
        let mut cfg = CfgSecurity::default();
        cfg.encryption_enabled = true;
        cfg.sck = parse_sck(Some("not-a-valid-key".to_string()));
        assert!(cfg.sck.is_none(), "a rejected key must not become Some([0u8; 10])");
    }
}
