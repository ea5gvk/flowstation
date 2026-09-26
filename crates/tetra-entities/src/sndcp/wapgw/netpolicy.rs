//! Where the download pool may connect: public addresses only, on the allowed ports and domains.
//!
//! A radio must not reach the station's LAN, its loopback services, the VPN or the carrier-grade
//! NAT through the gateway. URLs are checked before every request (the first one and every
//! redirect), and every address a host name resolves to is checked by the pool's DNS resolver, so
//! the connection only ever goes to an address that was checked (no DNS rebinding).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tetra_config::bluestation::CfgWapBrowse;
use url::{Host, Url};

/// Why a URL or an address was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Scheme,
    Port(u16),
    /// A name that only makes sense inside a local network (`localhost`, `*.lan`, no dot, ...).
    LocalName,
    Address(IpAddr),
    /// On the deny list, or not on a non-empty allow list.
    Domain,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Scheme => write!(f, "only http and https"),
            Refusal::Port(p) => write!(f, "port {p} not allowed"),
            Refusal::LocalName => write!(f, "local host name"),
            Refusal::Address(ip) => write!(f, "address {ip} is not public"),
            Refusal::Domain => write!(f, "domain not allowed"),
        }
    }
}

impl std::error::Error for Refusal {}

#[derive(Debug, Clone)]
pub struct NetPolicy {
    allowed_ports: Vec<u16>,
    allowlist: Vec<String>,
    denylist: Vec<String>,
    /// Tests only: lets the pool reach a test server on 127.0.0.1.
    allow_loopback: bool,
}

/// IPv4 blocks that are not public Internet (RFC 6890 and friends).
const BLOCKED_V4: [(Ipv4Addr, u8); 15] = [
    (Ipv4Addr::new(0, 0, 0, 0), 8),       // "this network"
    (Ipv4Addr::new(10, 0, 0, 0), 8),      // private
    (Ipv4Addr::new(100, 64, 0, 0), 10),   // carrier-grade NAT (also Tailscale)
    (Ipv4Addr::new(127, 0, 0, 0), 8),     // loopback
    (Ipv4Addr::new(169, 254, 0, 0), 16),  // link-local
    (Ipv4Addr::new(172, 16, 0, 0), 12),   // private
    (Ipv4Addr::new(192, 0, 0, 0), 24),    // IETF protocol assignments
    (Ipv4Addr::new(192, 0, 2, 0), 24),    // documentation
    (Ipv4Addr::new(192, 88, 99, 0), 24),  // 6to4 relay anycast
    (Ipv4Addr::new(192, 168, 0, 0), 16),  // private
    (Ipv4Addr::new(198, 18, 0, 0), 15),   // benchmarking
    (Ipv4Addr::new(198, 51, 100, 0), 24), // documentation
    (Ipv4Addr::new(203, 0, 113, 0), 24),  // documentation
    (Ipv4Addr::new(224, 0, 0, 0), 4),     // multicast
    (Ipv4Addr::new(240, 0, 0, 0), 4),     // reserved and broadcast
];

/// Host name suffixes of local networks (checked with and without the leading dot).
const LOCAL_SUFFIXES: [&str; 7] = ["localhost", "local", "lan", "home.arpa", "internal", "intranet", "localdomain"];

fn in_v4(ip: Ipv4Addr, net: Ipv4Addr, len: u8) -> bool {
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - u32::from(len)) };
    u32::from(ip) & mask == u32::from(net) & mask
}

pub fn is_public_v4(ip: Ipv4Addr) -> bool {
    !BLOCKED_V4.iter().any(|&(net, len)| in_v4(ip, net, len))
}

/// Public IPv6: global unicast (2000::/3) outside the special blocks; addresses that embed an
/// IPv4 address are judged by that address.
pub fn is_public_v6(ip: Ipv6Addr) -> bool {
    let seg = ip.segments();
    // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d).
    if seg[..5] == [0; 5] && (seg[5] == 0xffff || seg[5] == 0) {
        if ip.is_unspecified() || ip.is_loopback() {
            return false;
        }
        let v4 = Ipv4Addr::new((seg[6] >> 8) as u8, seg[6] as u8, (seg[7] >> 8) as u8, seg[7] as u8);
        return is_public_v4(v4);
    }
    // NAT64 well-known prefix 64:ff9b::/96.
    if seg[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let v4 = Ipv4Addr::new((seg[6] >> 8) as u8, seg[6] as u8, (seg[7] >> 8) as u8, seg[7] as u8);
        return is_public_v4(v4);
    }
    // 6to4 (2002::/16) carries the IPv4 address in the next 32 bits.
    if seg[0] == 0x2002 {
        let v4 = Ipv4Addr::new((seg[1] >> 8) as u8, seg[1] as u8, (seg[2] >> 8) as u8, seg[2] as u8);
        return is_public_v4(v4);
    }
    let global_unicast = seg[0] & 0xe000 == 0x2000;
    let teredo = seg[0] == 0x2001 && seg[1] == 0;
    let documentation = seg[0] == 0x2001 && seg[1] == 0x0db8;
    let orchid_benchmark = seg[0] == 0x2001 && (seg[1] & 0xfff0 == 0x0010 || seg[1] & 0xfff0 == 0x0020 || seg[1] == 0x0002);
    global_unicast && !teredo && !documentation && !orchid_benchmark
}

pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_local_name(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    !host.contains('.')
        || LOCAL_SUFFIXES
            .iter()
            .any(|s| host == *s || host.strip_suffix(s).is_some_and(|rest| rest.ends_with('.')))
}

fn domain_matches(host: &str, entry: &str) -> bool {
    host == entry || host.strip_suffix(entry).is_some_and(|rest| rest.ends_with('.'))
}

impl NetPolicy {
    pub fn new(browse: &CfgWapBrowse) -> Self {
        Self {
            allowed_ports: browse.allowed_ports.clone(),
            allowlist: browse.domain_allowlist.clone(),
            denylist: browse.domain_denylist.clone(),
            allow_loopback: false,
        }
    }

    /// Tests only: also accept 127.0.0.0/8, so the pool can fetch from a local test server.
    #[cfg(test)]
    pub fn allowing_loopback(mut self) -> Self {
        self.allow_loopback = true;
        self
    }

    pub fn check_ip(&self, ip: IpAddr) -> Result<(), Refusal> {
        if is_public(ip) || (self.allow_loopback && ip.is_loopback()) {
            Ok(())
        } else {
            Err(Refusal::Address(ip))
        }
    }

    /// Every address a name resolved to must be public: one private answer refuses the host.
    pub fn check_resolved(&self, addrs: &[IpAddr]) -> Result<(), Refusal> {
        addrs.iter().try_for_each(|&ip| self.check_ip(ip))
    }

    /// Scheme, port, host (literal address or name) and domain lists of a URL about to be fetched.
    pub fn check_url(&self, url: &Url) -> Result<(), Refusal> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(Refusal::Scheme);
        }
        let port = url.port_or_known_default().ok_or(Refusal::Scheme)?;
        if !self.allowed_ports.contains(&port) {
            return Err(Refusal::Port(port));
        }
        match url.host() {
            None => Err(Refusal::LocalName),
            Some(Host::Ipv4(ip)) => self.check_ip(IpAddr::V4(ip)),
            Some(Host::Ipv6(ip)) => self.check_ip(IpAddr::V6(ip)),
            Some(Host::Domain(name)) => {
                let name = name.trim_end_matches('.');
                if is_local_name(name) {
                    return Err(Refusal::LocalName);
                }
                if self.denylist.iter().any(|d| domain_matches(name, d)) {
                    return Err(Refusal::Domain);
                }
                if !self.allowlist.is_empty() && !self.allowlist.iter().any(|d| domain_matches(name, d)) {
                    return Err(Refusal::Domain);
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> NetPolicy {
        NetPolicy::new(&CfgWapBrowse::default())
    }

    fn check(url: &str) -> Result<(), Refusal> {
        policy().check_url(&Url::parse(url).unwrap())
    }

    #[test]
    fn netpolicy_blocks_private_v4_v6_mapped_cgnat_linklocal() {
        let blocked = [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:192.168.1.1",
            "::ffff:127.0.0.1",
            "::192.168.1.1",
            "64:ff9b::a00:1",
            "2002:c0a8:0101::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "2001:db8::1",
            "2001:0:4136:e378::1",
            "100::1",
        ];
        for ip in blocked {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(!is_public(ip), "{ip} must be blocked");
            assert_eq!(policy().check_ip(ip), Err(Refusal::Address(ip)));
        }
        let public = [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "192.169.0.1",
            "93.184.215.14",
            "2a00:1450:4003:80e::200e",
            "2606:4700::6810:84e5",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:0808:0808::1",
        ];
        for ip in public {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(is_public(ip), "{ip} is public");
        }
    }

    #[test]
    fn literal_hosts_in_urls() {
        assert_eq!(check("http://192.168.1.1/"), Err(Refusal::Address("192.168.1.1".parse().unwrap())));
        assert_eq!(check("http://[::1]/"), Err(Refusal::Address("::1".parse().unwrap())));
        // WHATWG URL parsing turns the odd spellings into the real address first.
        assert_eq!(check("http://0x7f.1/"), Err(Refusal::Address("127.0.0.1".parse().unwrap())));
        assert_eq!(check("http://2130706433/"), Err(Refusal::Address("127.0.0.1".parse().unwrap())));
        assert_eq!(
            check("http://[::ffff:10.0.0.1]/"),
            Err(Refusal::Address("::ffff:a00:1".parse().unwrap()))
        );
        assert_eq!(check("http://8.8.8.8/"), Ok(()));
    }

    #[test]
    fn blocks_local_hostnames() {
        for url in [
            "http://localhost/",
            "http://LOCALHOST./",
            "http://foo.localhost/",
            "http://router/",
            "http://printer.local/",
            "http://nas.lan/",
            "http://pi.home.arpa/",
            "http://db.internal/",
        ] {
            assert_eq!(check(url), Err(Refusal::LocalName), "{url}");
        }
        assert_eq!(check("http://example.org/"), Ok(()));
        assert_eq!(check("http://lan.example.org/"), Ok(()), "only suffixes count");
    }

    #[test]
    fn allowlist_denylist_suffix() {
        let browse = CfgWapBrowse {
            domain_allowlist: vec!["wikipedia.org".to_string(), "npr.org".to_string()],
            domain_denylist: vec!["en.wikipedia.org".to_string()],
            ..Default::default()
        };
        let p = NetPolicy::new(&browse);
        let check = |u: &str| p.check_url(&Url::parse(u).unwrap());
        assert_eq!(check("https://es.m.wikipedia.org/wiki/TETRA"), Ok(()));
        assert_eq!(check("https://wikipedia.org/"), Ok(()));
        assert_eq!(check("http://text.npr.org/"), Ok(()));
        assert_eq!(check("https://en.wikipedia.org/"), Err(Refusal::Domain));
        assert_eq!(check("https://notwikipedia.org/"), Err(Refusal::Domain));
        assert_eq!(check("https://example.org/"), Err(Refusal::Domain));
    }

    #[test]
    fn ports_only_80_443() {
        assert_eq!(check("http://example.org:80/"), Ok(()));
        assert_eq!(check("https://example.org/"), Ok(()));
        assert_eq!(check("http://example.org:8080/"), Err(Refusal::Port(8080)));
        assert_eq!(check("https://example.org:22/"), Err(Refusal::Port(22)));
        assert_eq!(check("ftp://example.org/"), Err(Refusal::Scheme));
        assert_eq!(check("file:///etc/passwd"), Err(Refusal::Scheme));
    }

    #[test]
    fn resolved_addresses_all_checked() {
        let p = policy();
        let public: IpAddr = "93.184.215.14".parse().unwrap();
        let private: IpAddr = "10.0.0.5".parse().unwrap();
        assert_eq!(p.check_resolved(&[public]), Ok(()));
        assert_eq!(p.check_resolved(&[public, private]), Err(Refusal::Address(private)));
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(p.check_resolved(&[loopback]).is_err());
        assert_eq!(p.allowing_loopback().check_resolved(&[loopback]), Ok(()));
    }
}
