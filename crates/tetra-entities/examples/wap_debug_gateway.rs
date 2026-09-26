//! Runs only the WAP gateway, through the SNDCP entity and its debug UDP bearer, so that
//! `contrib/wap-debug/wtp_client.py` can talk to it without a radio or an SDR:
//!
//! ```text
//! cargo run -p tetra-entities --example wap_debug_gateway -- [config.toml]
//! python contrib/wap-debug/wtp_client.py 127.0.0.1 9200 / /status.xhtml
//! ```
//!
//! Without a config file it listens on 127.0.0.1:9200 and lets the debug ISSI 9990 browse (the
//! Internet side of this build only answers "not available").

use std::time::Duration;

use tetra_config::bluestation::{SharedConfig, from_file, from_toml_str};
use tetra_core::TdmaTime;
use tetra_entities::sndcp::sndcp_bs::Sndcp;
use tetra_entities::{MessageQueue, TetraEntityTrait};

const DEFAULT_CONFIG: &str = r#"
config_version = "0.6"
stack_mode = "Bs"

[phy_io]
backend = "None"

[net_info]
mcc = 901
mnc = 9999

[cell_info]
main_carrier = 1584
freq_band = 4
freq_offset = 0
duplex_spacing = 4
reverse_operation = false
location_area = 1

[wap]
enabled = true
debug_udp_listen = "127.0.0.1:9200"
debug_issi = 9990

[wap.browse]
enabled = true
allowed_issis = [9990]
"#;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cfg = match std::env::args().nth(1) {
        Some(path) => from_file(&path),
        None => from_toml_str(DEFAULT_CONFIG),
    }
    .unwrap_or_else(|e| {
        eprintln!("config: {e}");
        std::process::exit(1);
    });
    if !cfg.wap.enabled || cfg.wap.debug_udp_listen.is_none() {
        eprintln!("the config needs [wap] enabled = true and a debug_udp_listen address");
        std::process::exit(1);
    }
    let mut sndcp = Sndcp::new(SharedConfig::from_parts(cfg, None));
    let mut queue = MessageQueue::new();
    // A TDMA timeslot lasts ~14 ms; tick a little faster than that. The status pages read the
    // health registry, which expects core ticks.
    loop {
        tetra_entities::health::registry().note_tick();
        sndcp.tick_start(&mut queue, TdmaTime::default());
        std::thread::sleep(Duration::from_millis(5));
    }
}
