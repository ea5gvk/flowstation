//! systemd readiness and watchdog notifications (the sd_notify(3) protocol).
//!
//! Under a `Type=notify` unit systemd hands us `NOTIFY_SOCKET` (plus `WATCHDOG_USEC` when
//! `WatchdogSec=` is set). A small `sd-notify` thread sends `READY=1` once the core loop is really
//! ticking, then `WATCHDOG=1` every half watchdog period, but only while the core tick keeps moving:
//! a hung core loop (which the in-process `restart_on_core_stall` cannot recover, since the hung
//! loop never reads its stop flag) gets killed and restarted by systemd. Without `NOTIFY_SOCKET`,
//! e.g. the usual `Type=simple` unit, nothing is spawned and nothing is sent.
//! FlowStation-original work, written from the sd_notify(3) protocol description.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Baked into the READY status, so it is in the binary: tetra-live-monitor looks for it in a
/// freshly built binary before running it under `Type=notify`. Keep it in sync with
/// tetra-live-monitor.
pub const SD_NOTIFY_MARKER: &str = "flowstation-sd-notify-v1";
/// This file, relative to the source tree: the dashboard OTA looks for the marker here before
/// building under `Type=notify`, while the running binary is still intact.
pub const SD_NOTIFY_SOURCE: &str = "crates/tetra-entities/src/sd_watchdog.rs";

/// One multiframe of core ticks (18 frames x 4 timeslots, about 1 s): the stack is really up.
const READY_TICKS: u64 = 72;
/// Floor for the stall threshold, so a small `[health] core_stall_secs` can't make the watchdog
/// kill the station over a short hiccup.
const MIN_MAX_AGE_MS: u64 = 5_000;

#[derive(Debug, PartialEq, Eq)]
enum NotifyAddr {
    Path(PathBuf),
    /// Linux abstract socket (`@name` in `NOTIFY_SOCKET`), without the `@`.
    Abstract(String),
}

/// `NOTIFY_SOCKET` is an absolute path or `@` + an abstract name. Anything else is unsupported.
fn parse_notify_socket(value: &str) -> Option<NotifyAddr> {
    if let Some(name) = value.strip_prefix('@') {
        (!name.is_empty()).then(|| NotifyAddr::Abstract(name.to_string()))
    } else if value.starts_with('/') {
        Some(NotifyAddr::Path(PathBuf::from(value)))
    } else {
        None
    }
}

fn notify_addr() -> Option<NotifyAddr> {
    std::env::var("NOTIFY_SOCKET").ok().as_deref().and_then(parse_notify_socket)
}

#[cfg(unix)]
fn send_datagram(addr: &NotifyAddr, state: &str) -> std::io::Result<()> {
    use std::os::unix::net::UnixDatagram;

    let sock = UnixDatagram::unbound()?;
    match addr {
        NotifyAddr::Path(path) => sock.send_to(state.as_bytes(), path).map(|_| ()),
        #[cfg(target_os = "linux")]
        NotifyAddr::Abstract(name) => {
            use std::os::linux::net::SocketAddrExt;
            let to = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
            sock.send_to_addr(state.as_bytes(), &to).map(|_| ())
        }
        #[cfg(not(target_os = "linux"))]
        NotifyAddr::Abstract(_) => Err(std::io::ErrorKind::Unsupported.into()),
    }
}

#[cfg(not(unix))]
fn send_datagram(_addr: &NotifyAddr, _state: &str) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

/// Send one notification (newline-separated `KEY=VALUE` lines). No-op without `NOTIFY_SOCKET`.
fn notify(state: &str) {
    if let Some(addr) = notify_addr()
        && let Err(e) = send_datagram(&addr, state)
    {
        tracing::debug!("sd_notify: send to {:?} failed: {}", addr, e);
    }
}

/// Tell systemd we are shutting down (disarms its watchdog). Call once the core loop has returned.
pub fn notify_stopping() {
    notify("STOPPING=1\nSTATUS=FlowStation stopping");
}

/// Feed period per sd_watchdog_enabled(3): half of `WATCHDOG_USEC`, if it is set and non-zero and
/// `WATCHDOG_PID` (when present) names this process.
fn watchdog_interval_for(usec: Option<&str>, pid: Option<&str>, my_pid: u32) -> Option<Duration> {
    let usec: u64 = usec?.trim().parse().ok().filter(|&u| u > 0)?;
    if let Some(pid) = pid
        && pid.trim().parse::<u32>().ok() != Some(my_pid)
    {
        return None;
    }
    Some(Duration::from_micros(usec / 2))
}

/// The feed period if systemd is watching this process, `None` otherwise.
fn watchdog_interval() -> Option<Duration> {
    static INTERVAL: OnceLock<Option<Duration>> = OnceLock::new();
    *INTERVAL.get_or_init(|| {
        notify_addr()?;
        let usec = std::env::var("WATCHDOG_USEC").ok();
        let pid = std::env::var("WATCHDOG_PID").ok();
        watchdog_interval_for(usec.as_deref(), pid.as_deref(), std::process::id())
    })
}

/// True if the systemd watchdog is armed for this process (a hung core loop gets restarted).
pub fn watchdog_armed() -> bool {
    watchdog_interval().is_some()
}

fn ready_reached(ticks: u64, tick_age_ms: u64) -> bool {
    ticks >= READY_TICKS && tick_age_ms < 1_000
}

/// Oldest core tick that still counts as alive: `[health] core_stall_secs`, but never more than
/// one feed period (or a stall could go unnoticed for a whole check) and never under the floor.
fn effective_max_age_ms(core_stall_ms: u64, interval: Duration) -> u64 {
    core_stall_ms.min(interval.as_millis() as u64).max(MIN_MAX_AGE_MS)
}

fn should_feed(prev_ticks: u64, ticks: u64, tick_age_ms: u64, max_age_ms: u64, ota_hold: bool) -> bool {
    ota_hold || (ticks != prev_ticks && tick_age_ms < max_age_ms)
}

static OTA_HOLD_UNTIL: Mutex<Option<Instant>> = Mutex::new(None);

/// While alive (and at most `max`), the watchdog is fed even if the core stalls: the dashboard OTA
/// builds on this box. Released on drop.
pub struct OtaHold(());

pub fn ota_hold(max: Duration) -> OtaHold {
    if let Ok(mut until) = OTA_HOLD_UNTIL.lock() {
        *until = Instant::now().checked_add(max);
    }
    OtaHold(())
}

impl Drop for OtaHold {
    fn drop(&mut self) {
        if let Ok(mut until) = OTA_HOLD_UNTIL.lock() {
            *until = None;
        }
    }
}

fn ota_hold_active() -> bool {
    OTA_HOLD_UNTIL
        .lock()
        .ok()
        .and_then(|until| *until)
        .is_some_and(|t| Instant::now() < t)
}

/// True if the file at `path` carries [`SD_NOTIFY_MARKER`]: a binary that speaks sd_notify, or
/// the source of one.
pub fn file_has_marker(path: &Path) -> bool {
    let marker = SD_NOTIFY_MARKER.as_bytes();
    std::fs::read(path).is_ok_and(|bin| bin.windows(marker.len()).any(|w| w == marker))
}

/// Start the `sd-notify` thread if we run under a `Type=notify` unit; otherwise do nothing.
/// `core_stall` is `[health] core_stall_secs`.
pub fn spawn(running: Arc<AtomicBool>, core_stall: Duration) {
    if notify_addr().is_none() {
        tracing::info!("sd_notify: off (no NOTIFY_SOCKET)");
        return;
    }
    let interval = watchdog_interval();
    if let Err(e) = std::thread::Builder::new()
        .name("sd-notify".into())
        .spawn(move || run(running, core_stall, interval))
    {
        tracing::error!("sd_notify: could not start the thread: {}", e);
    }
}

fn run(running: Arc<AtomicBool>, core_stall: Duration, interval: Option<Duration>) {
    let reg = crate::health::registry();

    // READY only once the core loop is really turning (SDR open, a multiframe of ticks).
    while !ready_reached(reg.core_ticks(), reg.tick_age_ms()) {
        if !running.load(Ordering::Relaxed) {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    notify(&format!("READY=1\nSTATUS=FlowStation core ticking ({})", SD_NOTIFY_MARKER));
    tracing::info!("sd_notify: READY sent after {} core ticks", reg.core_ticks());

    let Some(interval) = interval else {
        return;
    };
    let max_age_ms = effective_max_age_ms(core_stall.as_millis() as u64, interval);
    tracing::info!(
        "sd_notify: systemd watchdog armed, WATCHDOG=1 every {} ms while the last core tick is under {} ms old",
        interval.as_millis(),
        max_age_ms
    );

    let mut prev_ticks = reg.core_ticks();
    loop {
        std::thread::sleep(interval);
        if !running.load(Ordering::Relaxed) {
            return; // shutting down: main sends STOPPING=1
        }
        let ticks = reg.core_ticks();
        let age_ms = reg.tick_age_ms();
        let hold = ota_hold_active();
        if should_feed(prev_ticks, ticks, age_ms, max_age_ms, hold) {
            if hold {
                notify("WATCHDOG=1\nSTATUS=OTA build in progress");
            } else {
                notify(&format!("WATCHDOG=1\nSTATUS=Core alive (tick age {} ms)", age_ms));
            }
        } else {
            tracing::error!(
                "sd_notify: core loop stalled {}s, withholding WATCHDOG=1 (systemd will restart the service)",
                age_ms / 1000
            );
            notify(&format!("STATUS=CORE STALLED {}s - watchdog withheld", age_ms / 1000));
        }
        prev_ticks = ticks;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_socket_forms() {
        assert_eq!(
            parse_notify_socket("/run/systemd/notify"),
            Some(NotifyAddr::Path(PathBuf::from("/run/systemd/notify")))
        );
        assert_eq!(parse_notify_socket("@sd-notify"), Some(NotifyAddr::Abstract("sd-notify".into())));
        assert_eq!(parse_notify_socket(""), None);
        assert_eq!(parse_notify_socket("@"), None);
        assert_eq!(parse_notify_socket("vsock:2:1234"), None);
        assert_eq!(parse_notify_socket("relative/path"), None);
    }

    #[test]
    fn watchdog_interval_follows_sd_watchdog_enabled() {
        let half = Some(Duration::from_secs(15));
        assert_eq!(watchdog_interval_for(Some("30000000"), Some("42"), 42), half);
        assert_eq!(watchdog_interval_for(Some("30000000"), None, 42), half);
        assert_eq!(watchdog_interval_for(Some("30000000"), Some("43"), 42), None);
        assert_eq!(watchdog_interval_for(Some("30000000"), Some("junk"), 42), None);
        assert_eq!(watchdog_interval_for(None, Some("42"), 42), None);
        assert_eq!(watchdog_interval_for(Some("0"), None, 42), None);
        assert_eq!(watchdog_interval_for(Some("junk"), None, 42), None);
    }

    #[test]
    fn ready_needs_a_multiframe_of_live_ticks() {
        assert!(!ready_reached(71, 0));
        assert!(ready_reached(72, 0));
        assert!(ready_reached(72, 999));
        assert!(!ready_reached(72, 1_000));
    }

    #[test]
    fn max_age_is_core_stall_capped_by_the_period_with_a_floor() {
        let period = Duration::from_secs(15);
        assert_eq!(effective_max_age_ms(10_000, period), 10_000);
        assert_eq!(effective_max_age_ms(2_000, period), 5_000);
        assert_eq!(effective_max_age_ms(600_000, period), 15_000);
    }

    #[test]
    fn feed_only_while_the_core_ticks() {
        assert!(!should_feed(100, 100, 0, 10_000, false)); // no tick since the last check
        assert!(!should_feed(100, 200, 10_000, 10_000, false)); // ticked, but too long ago
        assert!(should_feed(100, 200, 50, 10_000, false));
        assert!(should_feed(100, 100, 60_000, 10_000, true)); // OTA build in progress
    }

    #[test]
    fn ota_hold_lasts_until_drop_or_deadline() {
        let hold = ota_hold(Duration::from_secs(60));
        assert!(ota_hold_active());
        drop(hold);
        assert!(!ota_hold_active());
        let _expired = ota_hold(Duration::ZERO);
        assert!(!ota_hold_active());
    }

    #[test]
    fn marker_is_found_in_a_binary() {
        let path = std::env::temp_dir().join(format!("flowstation-sd-marker-{}", std::process::id()));
        std::fs::write(&path, [b"\x7fELF\0..".as_slice(), SD_NOTIFY_MARKER.as_bytes(), b"\0.."].concat()).unwrap();
        assert!(file_has_marker(&path));
        std::fs::write(&path, b"\x7fELF\0flowstation-sd-notify-v\0").unwrap();
        assert!(!file_has_marker(&path));
        let _ = std::fs::remove_file(&path);
        assert!(!file_has_marker(&path));
    }

    #[test]
    fn marker_is_in_the_source_the_ota_checks() {
        let tree = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert!(file_has_marker(&tree.join(SD_NOTIFY_SOURCE)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn datagram_reaches_a_path_socket() {
        use std::os::unix::net::UnixDatagram;
        let path = std::env::temp_dir().join(format!("flowstation-sd-notify-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let rx = UnixDatagram::bind(&path).unwrap();
        send_datagram(&NotifyAddr::Path(path.clone()), "READY=1\nSTATUS=x").unwrap();
        let mut buf = [0u8; 64];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1\nSTATUS=x");
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn datagram_reaches_an_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixDatagram};
        let name = format!("flowstation-sd-notify-test-{}", std::process::id());
        let rx = UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(name.as_bytes()).unwrap()).unwrap();
        send_datagram(&NotifyAddr::Abstract(name), "WATCHDOG=1").unwrap();
        let mut buf = [0u8; 64];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"WATCHDOG=1");
    }
}
