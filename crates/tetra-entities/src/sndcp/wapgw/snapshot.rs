//! Station status for the WAP pages, from the lite health registry.
//!
//! The registry has no call counters, so the call fields stay at 0; the radio count is 0 while
//! telemetry is off (it is only fed from the telemetry fan-out).

use tetra_config::bluestation::StackConfig;

use crate::health::{HealthThresholds, registry};
use crate::sndcp::wap_status::WapStatusSnapshot;

/// Health thresholds from `[health]`, as the health monitor builds them.
pub fn thresholds(cfg: &StackConfig) -> HealthThresholds {
    let h = &cfg.health;
    HealthThresholds {
        core_stall_critical_ms: h.core_stall_secs.saturating_mul(1000),
        radios_silent_degraded_secs: h.radios_silent_secs,
        periodic_registration_secs: cfg.cell.periodic_registration_secs as u64,
        dl_queue_degraded: h.dl_queue_degraded as usize,
        dl_queue_critical: h.dl_queue_critical as usize,
        sds_queue_degraded: h.sds_queue_degraded as usize,
        sds_queue_critical: h.sds_queue_critical as usize,
    }
}

pub fn station_snapshot(thresholds: &HealthThresholds) -> WapStatusSnapshot {
    let reg = registry();
    let health = reg.snapshot(thresholds);
    let overall = health.overall.as_str().to_ascii_uppercase();
    WapStatusSnapshot {
        title: "FlowStation".to_string(),
        stack_version: format!("v{}", env!("CARGO_PKG_VERSION")),
        service_state: overall.clone(),
        registered_ms: reg.registered_radios(),
        active_calls: 0,
        active_group_calls: 0,
        active_private_calls: 0,
        queued_sds: reg.sds_queue_depth(),
        uptime_secs: health.uptime_secs,
        last_activity: None,
        health_summary: Some(overall),
        health_lines: health
            .domains
            .iter()
            .map(|d| format!("{} {}", d.domain.as_str(), d.level.as_str()))
            .collect(),
        radio_lines: Vec::new(),
        call_lines: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sndcp::wap_status::render_wml2_status;

    #[test]
    fn snapshot_without_telemetry_renders() {
        let snap = station_snapshot(&HealthThresholds::default());
        assert_eq!(snap.title, "FlowStation");
        assert!(snap.stack_version.starts_with('v'));
        assert_eq!(snap.active_calls, 0);
        assert!(!snap.health_lines.is_empty());
        let page = render_wml2_status(&snap, 2048).expect("status page renders");
        assert!(page.contains("FlowStation"));
    }
}
