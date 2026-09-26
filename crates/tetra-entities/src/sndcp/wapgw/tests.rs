//! End-to-end tests: a simulated WTP initiator (the terminal) against the gateway.

use std::collections::{BTreeMap, VecDeque};

use super::fetcher::UnavailableFetcher;
use super::wtp::{GTR, TTR, initiator};
use super::*;
use crate::sndcp::wap_ip::write_uintvar;

const ISSI: u32 = 2_260_618;
const MS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const MS_PORT: u16 = 2049;

fn test_snapshot() -> WapStatusSnapshot {
    WapStatusSnapshot {
        title: "FlowStation".to_string(),
        stack_version: "v0.4.0".to_string(),
        service_state: "OK".to_string(),
        registered_ms: 2,
        active_calls: 0,
        active_group_calls: 0,
        active_private_calls: 0,
        queued_sds: 0,
        uptime_secs: 90,
        last_activity: None,
        health_summary: Some("OK".to_string()),
        health_lines: vec!["service ok".to_string()],
        radio_lines: Vec::new(),
        call_lines: Vec::new(),
    }
}

fn cfg() -> CfgWap {
    let mut cfg = CfgWap {
        enabled: true,
        ..Default::default()
    };
    cfg.browse.enabled = true;
    cfg.browse.allowed_issis = vec![ISSI];
    cfg
}

/// Answers every request with a page of `size` bytes (capped to the request's budget), or never
/// when `hold` is set. Records the budgets it was given.
struct PageFetcher {
    size: usize,
    hold: bool,
    ready: VecDeque<FetchReply>,
    budgets: std::sync::Arc<std::sync::Mutex<Vec<usize>>>,
}

impl PageFetcher {
    fn boxed(size: usize, hold: bool) -> (Box<dyn Fetcher>, std::sync::Arc<std::sync::Mutex<Vec<usize>>>) {
        let budgets = std::sync::Arc::default();
        let fetcher = PageFetcher {
            size,
            hold,
            ready: VecDeque::new(),
            budgets: std::sync::Arc::clone(&budgets),
        };
        (Box::new(fetcher), budgets)
    }
}

impl Fetcher for PageFetcher {
    fn submit(&mut self, req: FetchRequest) -> Result<(), FetchRequest> {
        self.budgets.lock().unwrap().push(req.budget);
        if !self.hold {
            let body: Vec<u8> = b"0123456789".iter().copied().cycle().take(self.size.min(req.budget)).collect();
            self.ready.push_back(FetchReply {
                id: req.id,
                page: Page {
                    status: status::OK,
                    kind: ContentKind::Xhtml,
                    body,
                },
            });
        }
        Ok(())
    }

    fn try_recv(&mut self) -> Option<FetchReply> {
        self.ready.pop_front()
    }
}

fn gateway_with(cfg: CfgWap, fetcher: Box<dyn Fetcher>) -> WapGateway {
    WapGateway::new(cfg, fetcher, Box::new(test_snapshot))
}

fn gateway() -> WapGateway {
    gateway_with(cfg(), Box::new(UnavailableFetcher::default()))
}

fn peer() -> WapPeer {
    WapPeer {
        issi: ISSI,
        ip: MS_IP,
        via: WapVia::Air,
    }
}

/// Deliver one datagram from the terminal and collect what the gateway sends back.
fn send(gw: &mut WapGateway, payload: Vec<u8>, now: Instant) -> Vec<Vec<u8>> {
    gw.on_udp(
        UdpIn {
            peer: peer(),
            src_port: MS_PORT,
            dst_port: WAP_PORT_CONNECTION,
            payload,
        },
        now,
    );
    collect(gw.poll(now))
}

fn collect(out: Vec<UdpOut>) -> Vec<Vec<u8>> {
    for o in &out {
        assert_eq!((o.peer, o.src_port, o.dst_port), (peer(), WAP_PORT_CONNECTION, MS_PORT));
    }
    out.into_iter().map(|o| o.payload).collect()
}

fn get_pdu(uri: &str) -> Vec<u8> {
    let mut wsp = vec![0x40];
    write_uintvar(uri.len(), &mut wsp);
    wsp.extend_from_slice(uri.as_bytes());
    wsp
}

fn get(tid: u16, uri: &str) -> Vec<u8> {
    initiator::invoke(tid, 2, TTR, false, false, &get_pdu(uri))
}

/// WSP Connect asking for Client-SDU and Server-SDU of 327680 octets, like the MXP600.
fn connect(tid: u16) -> Vec<u8> {
    let caps = [0x04, 0x80, 0x94, 0x80, 0x00, 0x04, 0x81, 0x94, 0x80, 0x00];
    let mut wsp = vec![0x01, 0x10, caps.len() as u8, 0x00];
    wsp.extend_from_slice(&caps);
    initiator::invoke(tid, 2, TTR, true, false, &wsp)
}

/// Fields of a Result / Segmented Result packet: (type, psn, flags, rid, tid, data).
fn result(pkt: &[u8]) -> (u8, u8, u8, bool, u16, &[u8]) {
    let ty = (pkt[0] >> 3) & 0x0f;
    let tid = u16::from_be_bytes([pkt[1], pkt[2]]);
    match ty {
        2 => (ty, 0, pkt[0] & (GTR | TTR), pkt[0] & 1 != 0, tid, &pkt[3..]),
        6 => (ty, pkt[3], pkt[0] & (GTR | TTR), pkt[0] & 1 != 0, tid, &pkt[4..]),
        _ => panic!("not a result packet: {pkt:02x?}"),
    }
}

/// Receive a whole segmented result like a terminal: Ack every group end, return the message.
fn receive_all(gw: &mut WapGateway, tid: u16, mut pkts: Vec<Vec<u8>>, now: Instant) -> Vec<u8> {
    let mut parts = BTreeMap::new();
    loop {
        let mut end = None;
        for p in &pkts {
            let (_, psn, flags, _, rtid, data) = result(p);
            assert_eq!(rtid, tid | 0x8000);
            parts.insert(psn, data.to_vec());
            if flags != 0 {
                end = Some((psn, flags));
            }
        }
        let (psn, flags) = end.expect("a group ends with GTR or TTR");
        let next = send(gw, initiator::ack(tid, Some(psn)), now);
        if flags & TTR != 0 {
            assert!(next.is_empty(), "nothing after the final Ack");
            return parts.into_values().flatten().collect();
        }
        pkts = next;
    }
}

#[test]
fn connect_reply_matches_spec_vector() {
    // Docs/wap-port-spec.md 7.4, with both SDU limits at 545 octets.
    let mut cfg = cfg();
    cfg.max_message_bytes = 545;
    cfg.max_request_bytes = 545;
    let mut gw = gateway_with(cfg, Box::new(UnavailableFetcher::default()));
    let out = send(&mut gw, connect(0x13cc), Instant::now());
    assert_eq!(
        out,
        vec![vec![
            0x12, 0x93, 0xcc, 0x02, 0x01, 0x08, 0x00, 0x03, 0x80, 0x84, 0x21, 0x03, 0x81, 0x84, 0x21
        ]]
    );
    assert_eq!(gw.sessions.get(&(MS_IP, MS_PORT)).map(|s| s.client_sdu), Some(545));
}

#[test]
fn resume_answers_empty_ok() {
    let mut gw = gateway();
    let out = send(
        &mut gw,
        initiator::invoke(0x13f5, 2, TTR, false, false, &[0x09, 0x01, 0x00]),
        Instant::now(),
    );
    assert_eq!(out, vec![vec![0x12, 0x93, 0xf5, 0x04, 0x20, 0x00]]);
}

#[test]
fn get_small_single_packet() {
    let t0 = Instant::now();
    let mut gw = gateway();
    let out = send(&mut gw, get(0x1234, "/status.wml"), t0);
    assert_eq!(out.len(), 1);
    assert_eq!(&out[0][..7], &[0x12, 0x92, 0x34, 0x04, 0x20, 0x04, 0x03]);
    assert_eq!(&out[0][7..10], &[0x88, 0x81, 0xea], "WML with UTF-8 charset");
    assert!(String::from_utf8_lossy(&out[0][10..]).starts_with("<wml>"));
    assert!(send(&mut gw, initiator::ack(0x1234, None), t0).is_empty());
    // A late copy of the Invoke is ignored while the transaction is remembered...
    assert!(send(&mut gw, initiator::invoke(0x1234, 2, TTR, true, false, &get_pdu("/")), t0).is_empty());
    // ... and forgotten after it.
    let later = t0 + DONE_HOLD + Duration::from_secs(1);
    assert!(gw.poll(later).is_empty());
    assert!(gw.txs.is_empty());
}

#[test]
fn home_page_over_two_packets() {
    let t0 = Instant::now();
    let mut gw = gateway();
    let first = send(&mut gw, get(7, "http://10.0.0.1/"), t0);
    let message = receive_all(&mut gw, 7, first, t0);
    assert_eq!(&message[..7], &[0x04, 0x20, 0x04, 0x03, 0xc5, 0x81, 0xea]);
    let body = String::from_utf8(message[7..].to_vec()).unwrap();
    assert!(body.contains("action=\"/go\""), "browsing ISSI gets the forms: {body}");
    assert!(body.len() <= home::HOME_MAX_BYTES);
}

#[test]
fn get_5kb_segments_and_groups() {
    let t0 = Instant::now();
    let (fetcher, _) = PageFetcher::boxed(5000, false);
    let mut gw = gateway_with(cfg(), fetcher);
    let out = send(&mut gw, get(0x1234, "http://68k.news/"), t0);
    assert_eq!(out[0], vec![0x18, 0x92, 0x34], "hold-on Ack before the result");
    let first: Vec<_> = out[1..].to_vec();
    let heads: Vec<_> = first.iter().map(|p| (result(p).0, result(p).1, result(p).2)).collect();
    assert_eq!(heads, vec![(2, 0, 0), (6, 1, 0), (6, 2, GTR)], "first group of 3");
    assert!(first.iter().all(|p| p.len() <= 576 - 28));
    let message = receive_all(&mut gw, 0x1234, first, t0);
    // 4 header octets of Reply + Content-Type, then the page.
    assert_eq!(message.len(), 7 + 5000);
    assert!(message[7..].starts_with(b"0123456789"));
    assert!(matches!(gw.txs.values().next().map(|t| &t.state), Some(TxState::Done { .. })));
}

#[test]
fn nack_retransmits_only_missing_with_rid() {
    let t0 = Instant::now();
    let (fetcher, _) = PageFetcher::boxed(3000, false);
    let mut gw = gateway_with(cfg(), fetcher);
    let out = send(&mut gw, get(9, "http://68k.news/"), t0);
    let group: Vec<_> = out[1..].to_vec();
    assert_eq!(group.len(), 3);
    // Packet 1 was lost: the terminal Nacks it after the group end.
    let again = send(&mut gw, initiator::nack(9, &[1]), t0);
    assert_eq!(again.len(), 1);
    let (_, psn, flags, rid, _, data) = result(&again[0]);
    assert_eq!((psn, flags, rid), (1, 0, true));
    assert_eq!(data, result(&group[1]).5);
    // The group is now complete: the rest follows.
    let next = send(&mut gw, initiator::ack(9, Some(2)), t0);
    assert_eq!(result(&next[0]).1, 3);
    let rest = receive_all(&mut gw, 9, next, t0);
    assert!(!rest.is_empty());
}

#[test]
fn timer_retransmits_gtr_then_aborts() {
    let t0 = Instant::now();
    let mut gw = gateway();
    let out = send(&mut gw, get(0x1234, "/status.wml"), t0);
    assert_eq!(out.len(), 1);
    let mut t = t0;
    for _ in 0..cfg().wtp.max_retries {
        t += Duration::from_secs(10);
        let again = collect(gw.poll(t));
        assert_eq!(again.len(), 1);
        let (_, psn, flags, rid, _, _) = result(&again[0]);
        assert_eq!((psn, flags, rid), (0, TTR, true));
    }
    t += Duration::from_secs(10);
    assert_eq!(collect(gw.poll(t)), vec![vec![0x20, 0x92, 0x34, 0x08]], "Abort NORESPONSE");
    assert!(gw.txs.is_empty());
}

#[test]
fn duplicate_invoke_during_fetch_sends_hold_on_only() {
    let t0 = Instant::now();
    let (fetcher, _) = PageFetcher::boxed(100, true);
    let mut gw = gateway_with(cfg(), fetcher);
    assert_eq!(send(&mut gw, get(3, "/go?u=wiby.me"), t0), vec![vec![0x18, 0x80, 0x03]]);
    let dup = initiator::invoke(3, 2, TTR, true, false, &get_pdu("/go?u=wiby.me"));
    assert_eq!(send(&mut gw, dup, t0), vec![vec![0x19, 0x80, 0x03]]);
    // A fetch that never ends is answered with 504.
    let out = collect(gw.poll(t0 + FETCH_GUARD + Duration::from_secs(1)));
    assert_eq!(out.len(), 1);
    assert_eq!(&result(&out[0]).5[..2], &[0x04, status::GATEWAY_TIMEOUT]);
}

#[test]
fn abort_notimplementedsar_falls_back() {
    let t0 = Instant::now();
    let (fetcher, budgets) = PageFetcher::boxed(5000, false);
    let mut gw = gateway_with(cfg(), fetcher);
    let out = send(&mut gw, get(1, "http://68k.news/"), t0);
    assert_eq!(out.len(), 4, "hold-on + first group");
    assert!(send(&mut gw, initiator::abort(1, 0, wtp::ABORT_REASON_NOTIMPLEMENTEDSAR), t0).is_empty());
    let out = send(&mut gw, get(2, "http://68k.news/"), t0);
    assert_eq!(out.len(), 2, "hold-on + one datagram");
    let (_, psn, flags, _, _, _) = result(&out[1]);
    assert_eq!((psn, flags), (0, TTR));
    assert!(out[1].len() <= 576 - 28);
    let budgets = budgets.lock().unwrap();
    assert_eq!(budgets[1], 576 - 28 - 3 - wsp::REPLY_OVERHEAD_MAX, "one Result packet");
    assert!(budgets[0] > budgets[1]);
}

#[test]
fn sar_off_keeps_home_in_one_datagram() {
    let mut cfg = cfg();
    cfg.wtp.sar = WapSarMode::Off;
    let mut gw = gateway_with(cfg, Box::new(UnavailableFetcher::default()));
    let out = send(&mut gw, get(4, "/"), Instant::now());
    assert_eq!(out.len(), 1);
    assert_eq!(result(&out[0]).2, TTR);
    assert!(out[0].len() <= 576 - 28);
}

#[test]
fn class0_disconnect_no_response() {
    let t0 = Instant::now();
    let mut gw = gateway();
    send(&mut gw, connect(1), t0);
    assert_eq!(gw.sessions.len(), 1);
    let out = send(&mut gw, initiator::invoke(2, 0, TTR, false, false, &[0x05, 0x01]), t0);
    assert!(out.is_empty());
    assert!(gw.sessions.is_empty());
}

#[test]
fn tidnew_resets_cache() {
    let t0 = Instant::now();
    let mut gw = gateway();
    send(&mut gw, get(5, "/status.wml"), t0);
    send(&mut gw, initiator::ack(5, None), t0);
    let dup = initiator::invoke(5, 2, TTR, true, false, &get_pdu("/status.wml"));
    assert!(send(&mut gw, dup, t0).is_empty(), "cached TID: duplicate");
    let renewed = initiator::invoke(5, 2, TTR, true, true, &get_pdu("/status.wml"));
    assert_eq!(send(&mut gw, renewed, t0).len(), 1, "TIDnew: a new transaction");
}

#[test]
fn unauthorized_issi_gets_403_without_fetch() {
    let (fetcher, budgets) = PageFetcher::boxed(100, false);
    let mut cfg = cfg();
    cfg.browse.allowed_issis = vec![1];
    let mut gw = gateway_with(cfg, fetcher);
    let out = send(&mut gw, get(6, "http://68k.news/"), Instant::now());
    assert_eq!(out.len(), 1);
    assert_eq!(&result(&out[0]).5[..2], &[0x04, status::FORBIDDEN]);
    assert!(budgets.lock().unwrap().is_empty());
}

#[test]
fn unavailable_fetcher_answers_503() {
    let t0 = Instant::now();
    let mut gw = gateway();
    let out = send(&mut gw, get(8, "/s?q=tetra"), t0);
    assert_eq!(out[0], vec![0x18, 0x80, 0x08]);
    let message = receive_all(&mut gw, 8, out[1..].to_vec(), t0);
    assert_eq!(&message[..2], &[0x04, status::SERVICE_UNAVAILABLE]);
    assert!(String::from_utf8_lossy(&message).contains("navegación no está disponible"));
}

#[test]
fn post_gets_405() {
    let mut gw = gateway();
    let post = initiator::invoke(10, 2, TTR, false, false, &[0x60, 0x01, b'/', 0x01, 0x83]);
    let out = send(&mut gw, post, Instant::now());
    assert_eq!(&result(&out[0]).5[..2], &[0x04, status::METHOD_NOT_ALLOWED]);
}

#[test]
fn segmented_invoke_with_lost_segment() {
    let t0 = Instant::now();
    let mut gw = gateway();
    let uri = format!("/status.wml?pad={}", "x".repeat(700));
    let wsp = get_pdu(&uri);
    let (a, rest) = wsp.split_at(300);
    let (b, c) = rest.split_at(300);
    assert!(send(&mut gw, initiator::invoke(11, 2, 0, false, false, a), t0).is_empty());
    // Packet 1 is lost; packet 2 ends the message.
    let out = send(&mut gw, initiator::segmented_invoke(11, 2, TTR, false, c), t0);
    assert_eq!(out, vec![vec![0x38, 0x80, 0x0b, 0x01, 0x01]], "Nack of PSN 1");
    let out = send(&mut gw, initiator::segmented_invoke(11, 1, 0, true, b), t0);
    assert_eq!(out.len(), 1, "the retransmission completes the message: result");
    assert_eq!(&result(&out[0]).5[..2], &[0x04, status::OK]);
}

#[test]
fn segmented_invoke_group_ack_and_size_limit() {
    let t0 = Instant::now();
    let mut gw = gateway();
    let out = send(&mut gw, initiator::invoke(12, 2, GTR, false, false, &[0x40, 0x05, b'/']), t0);
    assert_eq!(out, vec![vec![0x98, 0x80, 0x0c, 0x19, 0x00]], "group Ack with PSN 0");
    let big = vec![b'x'; 600];
    send(&mut gw, initiator::segmented_invoke(12, 1, 0, false, &big), t0);
    let out = send(&mut gw, initiator::segmented_invoke(12, 2, TTR, false, &big), t0);
    assert_eq!(
        out,
        vec![vec![0x20, 0x80, 0x0c, 0x09]],
        "Abort MESSAGETOOLARGE over max_request_bytes"
    );
}

#[test]
fn ports_9200_9201() {
    let t0 = Instant::now();
    let mut gw = gateway();
    for port in [WAP_PORT_CONNECTIONLESS, WAP_PORT_CONNECTION] {
        let npdu = build_ipv4_udp_npdu(MS_IP.octets(), [10, 0, 0, 1], MS_PORT, port, &get(port, "/status.wml"), 1, 64).unwrap();
        gw.on_ipv4(ISSI, &npdu, Some(296), t0).unwrap();
        let out = gw.poll(t0);
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].src_port, out[0].dst_port, out[0].peer.via), (port, MS_PORT, WapVia::Air));
        let ip = out[0].to_ipv4(Ipv4Addr::new(10, 0, 0, 1), 2).unwrap();
        let parsed = parse_ipv4_packet(&ip).unwrap();
        assert_eq!((parsed.source, parsed.destination), ([10, 0, 0, 1], MS_IP.octets()));
        let udp = parse_udp_datagram(parsed.payload).unwrap();
        assert_eq!((udp.source_port, udp.destination_port), (port, MS_PORT));
        assert!(ip.len() <= 296, "path limit from the bearer");
    }
    let to_http = build_ipv4_udp_npdu(MS_IP.octets(), [10, 0, 0, 1], MS_PORT, 80, b"x", 1, 64).unwrap();
    assert_eq!(gw.on_ipv4(ISSI, &to_http, None, t0), Err(WapInputError::WrongPort { port: 80 }));
    let elsewhere = build_ipv4_udp_npdu(MS_IP.octets(), [8, 8, 8, 8], MS_PORT, 9201, b"x", 1, 64).unwrap();
    assert!(matches!(
        gw.on_ipv4(ISSI, &elsewhere, None, t0),
        Err(WapInputError::WrongDestination { .. })
    ));
}

#[test]
fn peer_lost_drops_state() {
    let t0 = Instant::now();
    let mut gw = gateway();
    send(&mut gw, connect(1), t0);
    send(&mut gw, get(2, "/status.wml"), t0);
    gw.set_path_limits(ISSI, 296);
    gw.on_peer_lost(ISSI);
    assert!(gw.sessions.is_empty() && gw.txs.is_empty() && gw.path_limits.is_empty());
}
