//! The health sampler thread.
//!
//! Wakes every `snapshot_interval`, rolls the registry into a [`HealthSnapshot`], and pushes it
//! down the telemetry channel (→ dashboard + Telegram). Optionally — only when
//! `restart_on_core_stall` is enabled — it also acts as a software watchdog: if the core loop
//! stops ticking for long enough it requests a service restart (debounced + rate-limited). It
//! reads atomics only and never touches RF/CMCE/UMAC, so it cannot stall the stack.
//! FlowStation-original work.

use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::net_telemetry::TelemetryEvent;
use crate::net_telemetry::channel::TelemetrySink;
use crate::service_control::{self, ServiceAction};

use super::registry::{HealthThresholds, registry};

/// Panic-storm escalation: catching panics at the router boundary keeps the cell alive, but each
/// catch is a dropped message. This many catches inside the window means the cell is not really
/// serving, so take the same controlled (cooldown-limited) restart path as a core stall.
const PANIC_STORM_BURST: u64 = 20;
const PANIC_STORM_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct HealthMonitorConfig {
    pub snapshot_interval: Duration,
    pub thresholds: HealthThresholds,
    /// Software watchdog: restart the service if the core loop stalls. Default off.
    pub restart_on_core_stall: bool,
    /// How long the core must stay stalled before a restart is requested.
    pub restart_after_critical: Duration,
    /// Minimum spacing between restart requests (anti-reboot-loop).
    pub restart_cooldown: Duration,
    /// Where to persist the last-restart timestamp so `restart_cooldown` survives the restart it
    /// triggers. `None` = in-memory only (cooldown resets at every boot).
    pub restart_state_path: Option<PathBuf>,
}

impl Default for HealthMonitorConfig {
    fn default() -> Self {
        Self {
            snapshot_interval: Duration::from_secs(5),
            thresholds: HealthThresholds::default(),
            restart_on_core_stall: false,
            restart_after_critical: Duration::from_secs(30),
            restart_cooldown: Duration::from_secs(600),
            restart_state_path: None,
        }
    }
}

/// Age of the persisted last-restart stamp, or `None` if absent/unreadable/in the future.
///
/// The cooldown has to outlive the restart it triggers: the in-memory `last_restart` dies with
/// the process, so a stall that reproduces at boot would otherwise restart every
/// `restart_after_critical` forever. One line, unix epoch seconds.
fn last_restart_age(path: &Path) -> Option<Duration> {
    let secs: u64 = std::fs::read_to_string(path).ok()?.trim().parse().ok()?;
    SystemTime::now().duration_since(UNIX_EPOCH + Duration::from_secs(secs)).ok()
}

fn store_last_restart(path: &Path) {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if let Err(e) = std::fs::write(path, format!("{}\n", secs)) {
        tracing::warn!("HEALTH: could not persist restart timestamp to {}: {}", path.display(), e);
    }
}

/// Shared restart path for every watchdog trigger: cooldown check → log → persist → request.
/// Returns true if a restart was actually requested.
fn request_restart(reason: &str, last_restart: &mut Option<Instant>, cooldown: Duration, state_path: Option<&Path>) -> bool {
    let now = Instant::now();
    if last_restart.is_some_and(|t| now.duration_since(t) < cooldown) {
        return false; // still in cooldown from a previous request
    }

    tracing::error!("HEALTH: {} — requesting service restart (watchdog)", reason);
    registry().record_action(format!("restart_service ({})", reason));
    if let Some(p) = state_path {
        // Persist BEFORE requesting: the request tears this process down.
        store_last_restart(p);
    }
    service_control::schedule_service_action(ServiceAction::Restart, Duration::ZERO);
    *last_restart = Some(now);
    true
}

/// Spawn the background health sampler. `sink` is a clone of the telemetry sink.
pub fn spawn_health_monitor(sink: TelemetrySink, cfg: HealthMonitorConfig) {
    let interval = cfg.snapshot_interval.max(Duration::from_secs(1));
    let stall_critical_ms = cfg.thresholds.core_stall_critical_ms.max(1_000);
    let restart_after = cfg.restart_after_critical.max(Duration::from_secs(1));
    let cooldown = cfg.restart_cooldown.max(Duration::from_secs(1));
    let state_path = cfg.restart_state_path.clone();

    // Seed the anti-reboot-loop guard from disk: without this the FIRST restart request tears the
    // process down and the fresh process starts with last_restart = None, so a stall that
    // reproduces at boot reboots forever and the cooldown never applies.
    let mut last_restart: Option<Instant> = None;
    if let Some(age) = state_path.as_deref().and_then(last_restart_age)
        && age < cooldown
    {
        tracing::warn!(
            "Health monitor: restart {}s ago (persisted) — watchdog cooldown active for another {}s",
            age.as_secs(),
            cooldown.saturating_sub(age).as_secs()
        );
        // If the host rebooted since, Instant can't go that far back — fall back to "now", which
        // is the conservative choice (full cooldown from startup).
        last_restart = Some(Instant::now().checked_sub(age).unwrap_or_else(Instant::now));
    }

    thread::Builder::new()
        .name("health-monitor".into())
        .spawn(move || {
            tracing::info!(
                "Health monitor started (interval {}s, watchdog restart {})",
                interval.as_secs(),
                if cfg.restart_on_core_stall { "ON" } else { "off" }
            );
            // Under the systemd watchdog a core stall is systemd's job: it also recovers a hung loop,
            // which never reads the stop flag our restart request sets. The panic storm stays ours.
            let systemd_watchdog = crate::sd_watchdog::watchdog_armed();
            if cfg.restart_on_core_stall && systemd_watchdog {
                tracing::info!("Health monitor: core-stall restart delegated to the systemd watchdog");
            }
            let mut stall_since: Option<Instant> = None;
            let mut panic_window_start = Instant::now();
            let mut panic_window_base = registry().caught_panics();
            loop {
                thread::sleep(interval);

                let snapshot = registry().snapshot(&cfg.thresholds);
                sink.send(TelemetryEvent::HealthSnapshot(snapshot));

                if !cfg.restart_on_core_stall {
                    continue;
                }

                // Panic storm: the router keeps the cell alive by dropping the offending
                // messages, but past a burst that is a cell that answers nothing — restart it
                // (same cooldown, so it can't reboot-loop).
                let panics = registry().caught_panics();
                let now = Instant::now();
                if now.duration_since(panic_window_start) >= PANIC_STORM_WINDOW {
                    panic_window_start = now;
                    panic_window_base = panics;
                } else if panics.saturating_sub(panic_window_base) >= PANIC_STORM_BURST {
                    let reason = format!(
                        "{} panics caught in {}s (entity dispatch)",
                        panics - panic_window_base,
                        PANIC_STORM_WINDOW.as_secs()
                    );
                    if request_restart(&reason, &mut last_restart, cooldown, state_path.as_deref()) {
                        panic_window_start = now;
                        panic_window_base = panics;
                    }
                }

                // Software watchdog. Only the core-loop liveness drives a restart — a Degraded
                // backhaul or congestion never reboots the station.
                if systemd_watchdog {
                    continue;
                }
                let age_ms = registry().tick_age_ms();
                if age_ms < stall_critical_ms {
                    stall_since = None;
                    continue;
                }
                let since = *stall_since.get_or_insert(now);
                if now.duration_since(since) < restart_after {
                    continue; // stalled, but not long enough yet
                }

                let reason = format!("core loop stalled {}s", age_ms / 1000);
                request_restart(&reason, &mut last_restart, cooldown, state_path.as_deref());
            }
        })
        .expect("failed to spawn health-monitor thread");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_restart_stamp_round_trips() {
        let path = std::env::temp_dir().join(format!("flowstation-health-restart-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);

        // No file yet → no cooldown to honour.
        assert!(last_restart_age(&path).is_none());

        // A stamp written now reads back as a very small age → cooldown still in force after a
        // restart, which is the whole point (the in-memory guard is gone by then).
        store_last_restart(&path);
        let age = last_restart_age(&path).expect("stamp should read back");
        assert!(age < Duration::from_secs(5), "unexpected age {:?}", age);

        // Garbage in the file must not be treated as "just restarted".
        std::fs::write(&path, "not-a-timestamp").unwrap();
        assert!(last_restart_age(&path).is_none());

        let _ = std::fs::remove_file(&path);
    }
}
