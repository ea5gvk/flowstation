use tetra_config::bluestation::SharedConfig;

/// Returns true if the Brew component is active
#[inline]
pub fn is_active(config: &SharedConfig) -> bool {
    config.config().brew.is_some()
}

/// Returns true if the SDS over Brew feature is enabled
#[inline]
pub fn feature_sds_enabled(config: &SharedConfig) -> bool {
    config.config().brew.as_ref().map_or(false, |brew| brew.feature_sds_enabled)
}

/// Returns true if the configured Brew server is TetraPack (core.tetrapack.online)
fn is_tetrapack(config: &SharedConfig) -> bool {
    if let Some(brew_config) = &config.config().brew {
        brew_config.host == "core.tetrapack.online"
    } else {
        false
    }
}

fn is_pbx_gateway_issi(config: &SharedConfig, issi: u32) -> bool {
    config
        .config()
        .brew
        .as_ref()
        .and_then(|brew| brew.pbx_gateway_issis.as_ref())
        .is_some_and(|allowed| allowed.contains(&issi))
}

/// Determine if a given GSSI should be routed over Brew, or is restricted to local handling
pub fn is_brew_gssi_routable(config: &SharedConfig, ssi: u32) -> bool {
    let Some(brew_config) = &config.config().brew else {
        // Brew not configured, so no routing to Brew
        return false;
    };
    if config.config().cell.local_ssi_ranges.contains(ssi) {
        // Range overridden as local
        return false;
    }

    // Check if whitelist is present and if so, check
    if let Some(whitelist) = &brew_config.whitelisted_ssis {
        if whitelist.contains(&ssi) {
            // Range explicitly whitelisted for routing to Brew
            return true;
        } else {
            // Not in whitelist - block routing to Brew
            return false;
        }
    }

    // No whitelist present, default to allow
    true
}

/// Determine whether a Brew-originated INBOUND call/SDS for a given GSSI may be admitted locally.
///
/// This is deliberately weaker than [`is_brew_gssi_routable`]. That predicate governs OUTBOUND
/// forwarding of *local* traffic to Brew and therefore honours `whitelisted_ssis` — which is
/// documented as "allow only calls for selected SSIs to be **forwarded through Brew**", i.e. an
/// outbound concept. Applying the whitelist to inbound admission wrongly blocks a bridging/foreign
/// GSSI that is absent from the whitelist (FH-FEAT-032 R3): a network call legitimately arriving
/// from an authenticated Brew connection must still reach the local MS camped on that group.
///
/// The `local_ssi_ranges` override is still honoured — those ranges are documented as local-only
/// ("Incoming brew traffic on these ranges will also be rejected"), so inbound traffic to them stays
/// rejected.
#[inline]
pub fn is_brew_inbound_allowed(config: &SharedConfig, ssi: u32) -> bool {
    is_active(config) && !config.config().cell.local_ssi_ranges.contains(ssi)
}

/// Determine if a given ISSI should be sent to the Brew server.
/// On TetraPack, subscriber ISSIs must be 7 digits (1_000_000..=9_999_999).
/// Special service ISSIs (e.g. 600 echo, short numbers) are always forwarded to Brew —
/// TetraPack Core handles them internally; blocking them here causes "Service Denied".
pub fn is_brew_issi_routable(config: &SharedConfig, issi: u32) -> bool {
    if config.config().brew.is_none() {
        return false;
    }
    if is_tetrapack(config) {
        // 7-digit subscriber ISSIs are always routable.
        // Short ISSIs (< 1_000_000) are service numbers handled by TetraPack Core —
        // let them through so the core can respond (echo test 600, etc.)
        (issi >= 1_000_000 && issi <= 9_999_999) || issi < 1_000_000 || is_pbx_gateway_issi(config, issi)
    } else {
        true
    }
}
