use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};

use serde::Deserialize;
use toml::Value;

/// WTP segmentation and reassembly (SAR) policy for responses larger than one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WapSarMode {
    /// Segment large responses, but stop segmenting for a terminal that aborted a segmented
    /// result with NOTIMPLEMENTEDSAR or MESSAGETOOLARGE.
    Auto,
    /// Never segment: every response fits in one datagram.
    Off,
    /// Always segment large responses.
    On,
}

/// How the XHTML-MP Content-Type goes in a WSP Reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WapContentTypeForm {
    /// Well-known short integer (0xC5) with a UTF-8 charset parameter.
    Short,
    /// Media type as text ("application/vnd.wap.xhtml+xml") with a UTF-8 charset parameter.
    Text,
}

/// `[wap.wtp]`: WTP transaction tuning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgWapWtp {
    pub sar: WapSarMode,
    /// Packets sent before waiting for the group acknowledgement.
    pub group_size: u8,
    /// Fixed part of the retransmission timer; the air time of the group is added on top.
    pub retry_base_ms: u64,
    /// Expected useful air rate, used to stretch the retransmission timer for large groups.
    pub air_rate_bytes_per_sec: u32,
    /// Retransmissions of a packet group before the transaction is aborted.
    pub max_retries: u8,
}

impl Default for CfgWapWtp {
    fn default() -> Self {
        Self {
            sar: WapSarMode::Auto,
            group_size: 3,
            retry_base_ms: 4000,
            air_rate_bytes_per_sec: 450,
            max_retries: 4,
        }
    }
}

/// `[wap.browse]`: Internet browsing through the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgWapBrowse {
    pub enabled: bool,
    /// Radios allowed to browse. Empty = nobody; every radio still gets the local status pages.
    pub allowed_issis: Vec<u32>,
    /// Search URL; the query is appended URL-encoded.
    pub search_url: String,
    /// Links shown on the home page.
    pub bookmarks: Vec<String>,
}

impl Default for CfgWapBrowse {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_issis: Vec::new(),
            search_url: default_search_url(),
            bookmarks: default_bookmarks(),
        }
    }
}

/// `[wap]`: WAP gateway for packet-data terminals (WTP/WSP over UDP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgWap {
    pub enabled: bool,
    /// Address the terminals send WAP requests to.
    pub gateway_ipv4: Ipv4Addr,
    /// Largest IPv4 datagram the gateway sends when the bearer gives no smaller limit.
    pub mtu: u16,
    /// Largest WSP response (caps the Client-SDU a terminal asks for).
    pub max_message_bytes: usize,
    /// Largest WSP request (caps the Server-SDU a terminal asks for).
    pub max_request_bytes: usize,
    pub content_type: WapContentTypeForm,
    /// Debug UDP bearer (test the gateway without a radio). None = off.
    pub debug_udp_listen: Option<SocketAddrV4>,
    /// Sources the debug UDP bearer accepts, as (network, prefix length). Empty = any.
    pub debug_udp_allowed_sources: Vec<(Ipv4Addr, u8)>,
    /// ISSI the debug UDP bearer's requests are handled as.
    pub debug_issi: u32,
    pub wtp: CfgWapWtp,
    pub browse: CfgWapBrowse,
}

impl Default for CfgWap {
    fn default() -> Self {
        Self {
            enabled: false,
            gateway_ipv4: Ipv4Addr::new(10, 0, 0, 1),
            mtu: 576,
            max_message_bytes: 8192,
            max_request_bytes: 1024,
            content_type: WapContentTypeForm::Short,
            debug_udp_listen: None,
            debug_udp_allowed_sources: vec![(Ipv4Addr::LOCALHOST, 32)],
            debug_issi: 0,
            wtp: CfgWapWtp::default(),
            browse: CfgWapBrowse::default(),
        }
    }
}

impl CfgWap {
    /// Whether `issi` may fetch pages from the Internet.
    pub fn browse_allowed(&self, issi: u32) -> bool {
        self.browse.enabled && self.browse.allowed_issis.contains(&issi)
    }

    /// Whether the debug UDP bearer accepts a datagram from `ip`.
    pub fn debug_source_allowed(&self, ip: Ipv4Addr) -> bool {
        self.debug_udp_allowed_sources.is_empty() || self.debug_udp_allowed_sources.iter().any(|&(net, len)| in_prefix(ip, net, len))
    }
}

fn in_prefix(ip: Ipv4Addr, net: Ipv4Addr, len: u8) -> bool {
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - u32::from(len)) };
    u32::from(ip) & mask == u32::from(net) & mask
}

#[derive(Debug, Clone, Deserialize)]
pub struct CfgWapWtpDto {
    #[serde(default = "default_sar")]
    pub sar: String,
    #[serde(default = "default_group_size")]
    pub group_size: u8,
    #[serde(default = "default_retry_base_ms")]
    pub retry_base_ms: u64,
    #[serde(default = "default_air_rate")]
    pub air_rate_bytes_per_sec: u32,
    #[serde(default = "default_max_retries")]
    pub max_retries: u8,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CfgWapBrowseDto {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_issis: Vec<u32>,
    #[serde(default = "default_search_url")]
    pub search_url: String,
    #[serde(default = "default_bookmarks")]
    pub bookmarks: Vec<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CfgWapDto {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_gateway_ipv4")]
    pub gateway_ipv4: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default = "default_max_message_bytes")]
    pub max_message_bytes: usize,
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_content_type")]
    pub content_type: String,
    #[serde(default)]
    pub debug_udp_listen: String,
    #[serde(default = "default_debug_sources")]
    pub debug_udp_allowed_sources: Vec<String>,
    #[serde(default)]
    pub debug_issi: u32,
    pub wtp: Option<CfgWapWtpDto>,
    pub browse: Option<CfgWapBrowseDto>,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

fn default_sar() -> String {
    "auto".to_string()
}
fn default_group_size() -> u8 {
    CfgWapWtp::default().group_size
}
fn default_retry_base_ms() -> u64 {
    CfgWapWtp::default().retry_base_ms
}
fn default_air_rate() -> u32 {
    CfgWapWtp::default().air_rate_bytes_per_sec
}
fn default_max_retries() -> u8 {
    CfgWapWtp::default().max_retries
}
fn default_search_url() -> String {
    "http://lite.duckduckgo.com/lite/?q=".to_string()
}
fn default_bookmarks() -> Vec<String> {
    vec![
        "http://68k.news/".to_string(),
        "http://wiby.me/".to_string(),
        "http://text.npr.org/".to_string(),
    ]
}
fn default_gateway_ipv4() -> String {
    "10.0.0.1".to_string()
}
fn default_mtu() -> u16 {
    576
}
fn default_max_message_bytes() -> usize {
    8192
}
fn default_max_request_bytes() -> usize {
    1024
}
fn default_content_type() -> String {
    "short".to_string()
}
fn default_debug_sources() -> Vec<String> {
    vec!["127.0.0.1/32".to_string()]
}

/// MTU values an SN-ACTIVATE PDP CONTEXT ACCEPT can announce (EN 300 392-2 clause 28.4.5.8).
const WAP_MTUS: [u16; 5] = [296, 576, 1006, 1500, 2002];

fn parse_cidr(s: &str) -> Result<(Ipv4Addr, u8), String> {
    let (ip, len) = s.split_once('/').unwrap_or((s, "32"));
    let ip: Ipv4Addr = ip
        .trim()
        .parse()
        .map_err(|_| format!("wap: debug_udp_allowed_sources: bad address in {s:?}"))?;
    let len: u8 = len
        .trim()
        .parse()
        .ok()
        .filter(|l| *l <= 32)
        .ok_or_else(|| format!("wap: debug_udp_allowed_sources: bad prefix length in {s:?}"))?;
    Ok((ip, len))
}

fn check_http_url(what: &str, url: &str) -> Result<(), String> {
    let lower = url.trim().to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Ok(())
    } else {
        Err(format!("wap: {what} must start with http:// or https:// ({url:?})"))
    }
}

pub fn apply_wap_patch(dto: CfgWapDto) -> Result<CfgWap, String> {
    let gateway_ipv4: Ipv4Addr = dto
        .gateway_ipv4
        .trim()
        .parse()
        .map_err(|_| format!("wap: gateway_ipv4 {:?} is not an IPv4 address", dto.gateway_ipv4))?;
    if !WAP_MTUS.contains(&dto.mtu) {
        return Err(format!("wap: mtu must be one of {:?}, got {}", WAP_MTUS, dto.mtu));
    }
    if !(512..=65_536).contains(&dto.max_message_bytes) {
        return Err("wap: max_message_bytes must be within 512..=65536".to_string());
    }
    if !(256..=65_536).contains(&dto.max_request_bytes) {
        return Err("wap: max_request_bytes must be within 256..=65536".to_string());
    }
    let content_type = match dto.content_type.trim() {
        "short" => WapContentTypeForm::Short,
        "text" => WapContentTypeForm::Text,
        other => return Err(format!("wap: content_type must be \"short\" or \"text\", got {other:?}")),
    };

    let debug_udp_listen = match dto.debug_udp_listen.trim() {
        "" => None,
        s => Some(
            s.parse::<SocketAddrV4>()
                .map_err(|_| format!("wap: debug_udp_listen {s:?} is not an IPv4 address:port"))?,
        ),
    };
    let debug_udp_allowed_sources = dto
        .debug_udp_allowed_sources
        .iter()
        .map(|s| parse_cidr(s))
        .collect::<Result<Vec<_>, _>>()?;
    // A debug bearer reachable from the LAN without a source list would be an open proxy and a
    // UDP amplifier (a small spoofed Invoke draws several full-size datagrams).
    if let Some(listen) = debug_udp_listen
        && !listen.ip().is_loopback()
        && debug_udp_allowed_sources.is_empty()
    {
        return Err("wap: debug_udp_listen outside 127.0.0.0/8 needs debug_udp_allowed_sources".to_string());
    }
    if dto.debug_issi > 0xFF_FFFF {
        return Err("wap: debug_issi must fit in 24 bits".to_string());
    }

    let wtp = match dto.wtp {
        None => CfgWapWtp::default(),
        Some(w) => {
            let sar = match w.sar.trim() {
                "auto" => WapSarMode::Auto,
                "off" => WapSarMode::Off,
                "on" => WapSarMode::On,
                other => return Err(format!("wap.wtp: sar must be \"auto\", \"off\" or \"on\", got {other:?}")),
            };
            if !(1..=32).contains(&w.group_size) {
                return Err("wap.wtp: group_size must be within 1..=32".to_string());
            }
            if !(500..=60_000).contains(&w.retry_base_ms) {
                return Err("wap.wtp: retry_base_ms must be within 500..=60000".to_string());
            }
            if w.air_rate_bytes_per_sec == 0 {
                return Err("wap.wtp: air_rate_bytes_per_sec must be > 0".to_string());
            }
            if !(1..=10).contains(&w.max_retries) {
                return Err("wap.wtp: max_retries must be within 1..=10".to_string());
            }
            CfgWapWtp {
                sar,
                group_size: w.group_size,
                retry_base_ms: w.retry_base_ms,
                air_rate_bytes_per_sec: w.air_rate_bytes_per_sec,
                max_retries: w.max_retries,
            }
        }
    };

    let browse = match dto.browse {
        None => CfgWapBrowse::default(),
        Some(b) => CfgWapBrowse {
            enabled: b.enabled,
            allowed_issis: b.allowed_issis,
            search_url: b.search_url,
            bookmarks: b.bookmarks,
        },
    };
    if browse.enabled && !dto.enabled {
        return Err("wap.browse: enabled = true needs [wap] enabled = true".to_string());
    }
    if let Some(issi) = browse.allowed_issis.iter().find(|&&i| i > 0xFF_FFFF) {
        return Err(format!("wap.browse: allowed_issis entry {issi} does not fit in 24 bits"));
    }
    check_http_url("browse.search_url", &browse.search_url)?;
    for url in &browse.bookmarks {
        check_http_url("browse.bookmarks entry", url)?;
    }

    Ok(CfgWap {
        enabled: dto.enabled,
        gateway_ipv4,
        mtu: dto.mtu,
        max_message_bytes: dto.max_message_bytes,
        max_request_bytes: dto.max_request_bytes,
        content_type,
        debug_udp_listen,
        debug_udp_allowed_sources,
        debug_issi: dto.debug_issi,
        wtp,
        browse,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dto(toml_src: &str) -> CfgWapDto {
        toml::from_str(toml_src).expect("wap dto parses")
    }

    #[test]
    fn empty_section_matches_default() {
        assert_eq!(apply_wap_patch(dto("")).unwrap(), CfgWap::default());
    }

    #[test]
    fn debug_sources_filter_by_prefix() {
        let cfg = apply_wap_patch(dto("debug_udp_allowed_sources = [\"10.33.1.0/24\", \"127.0.0.1\"]")).unwrap();
        assert!(cfg.debug_source_allowed(Ipv4Addr::new(10, 33, 1, 75)));
        assert!(cfg.debug_source_allowed(Ipv4Addr::LOCALHOST));
        assert!(!cfg.debug_source_allowed(Ipv4Addr::new(10, 33, 2, 1)));
        let open = apply_wap_patch(dto("debug_udp_allowed_sources = []")).unwrap();
        assert!(open.debug_source_allowed(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn bad_cidr_rejected() {
        assert!(apply_wap_patch(dto("debug_udp_allowed_sources = [\"10.0.0.0/33\"]")).is_err());
        assert!(apply_wap_patch(dto("debug_udp_allowed_sources = [\"10.0.0/24\"]")).is_err());
    }

    #[test]
    fn browse_needs_listed_issi() {
        let cfg = apply_wap_patch(dto("enabled = true\n[browse]\nenabled = true\nallowed_issis = [2260618]")).unwrap();
        assert!(cfg.browse_allowed(2260618));
        assert!(!cfg.browse_allowed(2260619));
        let nobody = apply_wap_patch(dto("enabled = true\n[browse]\nenabled = true")).unwrap();
        assert!(!nobody.browse_allowed(2260618));
    }

    #[test]
    fn bad_wtp_values_rejected() {
        assert!(apply_wap_patch(dto("[wtp]\nsar = \"maybe\"")).is_err());
        assert!(apply_wap_patch(dto("[wtp]\ngroup_size = 0")).is_err());
        assert!(apply_wap_patch(dto("[wtp]\nair_rate_bytes_per_sec = 0")).is_err());
    }

    #[test]
    fn bookmark_must_be_http() {
        assert!(apply_wap_patch(dto("[browse]\nbookmarks = [\"ftp://example.org/\"]")).is_err());
    }
}
