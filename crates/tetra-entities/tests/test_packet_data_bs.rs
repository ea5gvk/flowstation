//! `[packet_data]`: the SNDCP bearer between the radios and the WAP gateway, tested with the real
//! LLC, MLE and SNDCP entities and a simulated radio on the other side of the MAC.

mod common;

use std::collections::HashMap;
use std::net::Ipv4Addr;

use common::ComponentTest;
use tetra_config::bluestation::{StackConfig, StackMode};
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{BitBuffer, Sap, SsiType, TdmaTime, TetraAddress, TxReporter, TxState, debug};
use tetra_entities::sndcp::ip::{build_ipv4_udp_npdu, parse_ipv4_packet, parse_udp_datagram};
use tetra_entities::sndcp::transfer::{
    SndcpDataTransmitRequest, SndcpDataTransmitResponseResult, SndcpEndOfData, SndcpPacketDataResourceRequest,
    SndcpPhaseModulationResourceRequest, SndcpReconnect, SndcpTransferRejectCause, decode_data_transmit_response, decode_end_of_data,
    decode_not_supported, encode_data_transmit_request, encode_end_of_data, encode_reconnect,
};
use tetra_entities::sndcp::unitdata::{decode_sn_unitdata_pdu, encode_sn_unitdata};
use tetra_pdus::llc::enums::llc_pdu_type::LlcPduType;
use tetra_pdus::llc::pdus::{bl_ack::BlAck, bl_adata::BlAdata, bl_data::BlData, bl_udata::BlUdata};
use tetra_pdus::mle::enums::mle_protocol_discriminator::MleProtocolDiscriminator;
use tetra_saps::ltpd::LtpdBearer;
use tetra_saps::sapmsg::{SapMsg, SapMsgInner};
use tetra_saps::tla::{TlaTlDataIndBl, TlaTlUnitdataIndBl};
use tetra_saps::tma::{TmaUnitdataInd, TmaUnitdataReq};

const MAIN_CARRIER: u16 = 1521;
const ISSI: u32 = 2_260_618;
const ISSI2: u32 = 2_260_619;
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const RADIO_PORT: u16 = 2049;
/// Captured PCO content of a Motorola DEMAND: CHAP Challenge and CHAP Response, both id 5.
const REAL_PCO_HEX: &str =
    "0c22318010500180aac20e0caf974bc75e02f44494d455452415f50c2231a0205001a10db3b2df8c57cce0db8712b16aa9cb5a361646d696";

// ---------------------------------------------------------------------------------------------
// Configuration and SN-PDUs as a radio sends them
// ---------------------------------------------------------------------------------------------

fn config(packet_data: bool, wap: bool) -> StackConfig {
    let mut cfg = ComponentTest::get_default_test_config(StackMode::Bs);
    cfg.cell.sndcp_service = true;
    cfg.packet_data.enabled = packet_data;
    cfg.wap.enabled = wap;
    cfg
}

fn hex_to_bits(hex: &str) -> String {
    hex.chars().map(|c| format!("{:04b}", c.to_digit(16).unwrap())).collect()
}

/// SN-ACTIVATE PDP CONTEXT DEMAND (table 28.24): dynamic IPv4 unless `static_ip`, with the real
/// Motorola PCO when `pco`.
fn demand(nsapi: u8, static_ip: Option<Ipv4Addr>, pco: bool) -> String {
    let mut s = format!("00000001{nsapi:04b}");
    match static_ip {
        Some(ip) => s.push_str(&format!("000{:032b}", u32::from(ip))),
        None => s.push_str("001"),
    }
    s.push_str("0001"); // packet data MS type B
    s.push_str("00000000"); // PCOMP negotiation
    if pco {
        let pco = hex_to_bits(REAL_PCO_HEX);
        s.push_str("10"); // o-bit, access point name index absent
        s.push_str("10001"); // M-bit, PCO
        s.push_str(&format!("{:011b}", pco.len()));
        s.push_str(&pco);
        s.push('0');
    } else {
        s.push('0');
    }
    s
}

fn transmit_request(nsapi: u8, slots: Option<(u8, bool)>) -> String {
    let resource_request = match slots {
        None => SndcpPacketDataResourceRequest::None,
        Some((n, unspecified)) => SndcpPacketDataResourceRequest::PhaseModulation(SndcpPhaseModulationResourceRequest {
            uplink_timeslots: n,
            downlink_timeslots: n,
            full_phase_modulation_capability_timeslots: n,
            unspecified_phase_modulation_resource: unspecified,
        }),
    };
    encode_data_transmit_request(&SndcpDataTransmitRequest {
        nsapi,
        logical_link_status: false,
        resource_request,
    })
    .unwrap()
    .to_bitstr()
}

fn end_of_data() -> String {
    encode_end_of_data(&SndcpEndOfData {
        immediate_service_change: false,
    })
    .unwrap()
    .to_bitstr()
}

/// SN-DEACTIVATE PDP CONTEXT DEMAND (table 28.32) for one NSAPI, or for all.
fn deactivate(nsapi: Option<u8>) -> String {
    match nsapi {
        Some(n) => format!("001000000001{n:04b}0"),
        None => "0010000000000".to_string(),
    }
}

fn unitdata(nsapi: u8, npdu: &[u8]) -> String {
    encode_sn_unitdata(nsapi, 0, 0, &BitBuffer::from_bytes(npdu)).unwrap().to_bitstr()
}

/// A UDP datagram from the radio at `src` to the gateway's WAP port.
fn datagram(src: Ipv4Addr, dst: Ipv4Addr, port: u16, payload: &[u8]) -> Vec<u8> {
    build_ipv4_udp_npdu(src.octets(), dst.octets(), RADIO_PORT, port, payload, 7, 64).unwrap()
}

/// WTP Invoke, class 2, of a WSP GET (WAP-224 and WAP-230, the MXP600's form).
fn wtp_get(tid: u16, uri: &str) -> Vec<u8> {
    let mut v = vec![0x0a];
    v.extend_from_slice(&(tid & 0x7fff).to_be_bytes());
    v.push(0x12);
    v.push(0x40);
    v.push(uri.len() as u8);
    v.extend_from_slice(uri.as_bytes());
    v
}

/// WTP Invoke, class 2, of a WSP Connect asking for large SDUs, like the MXP600.
fn wtp_connect(tid: u16) -> Vec<u8> {
    let caps = [0x04, 0x80, 0x94, 0x80, 0x00, 0x04, 0x81, 0x94, 0x80, 0x00];
    let mut v = vec![0x0a];
    v.extend_from_slice(&(tid & 0x7fff).to_be_bytes());
    v.extend_from_slice(&[0x12, 0x01, 0x10, caps.len() as u8, 0x00]);
    v.extend_from_slice(&caps);
    v
}

/// WTP Ack from the initiator, with the PSN TPI when `psn` is given.
fn wtp_ack(tid: u16, psn: Option<u8>) -> Vec<u8> {
    let tid = (tid & 0x7fff).to_be_bytes();
    match psn {
        None => vec![0x18, tid[0], tid[1]],
        Some(psn) => vec![0x98, tid[0], tid[1], 0x19, psn],
    }
}

// ---------------------------------------------------------------------------------------------
// The radio on the other side of the MAC
// ---------------------------------------------------------------------------------------------

/// One PDU the LLC handed to the MAC.
#[derive(Debug, Clone)]
struct Down {
    issi: u32,
    llc: LlcPduType,
    link_id: u32,
    stealing: bool,
    chan_alloc: bool,
    /// The SN-PDU (bits after the MLE discriminator) when the TL-SDU is for SNDCP.
    sn: Option<String>,
}

impl Down {
    fn sn_type(&self) -> Option<u8> {
        self.sn.as_ref().and_then(|s| u8::from_str_radix(s.get(0..4)?, 2).ok())
    }

    fn sn_buf(&self) -> BitBuffer {
        BitBuffer::from_bitstr(self.sn.as_deref().expect("an SN-PDU"))
    }
}

/// The stack from the LLC up (LLC, MLE, SNDCP) with a simulated radio under the MAC: every PDU the
/// LLC hands down is reported transmitted and every BL-DATA acknowledged, as the air would.
struct Air {
    test: ComponentTest,
    ticks: usize,
    ns: HashMap<u32, u8>,
    acks: Vec<(u32, u8, usize)>,
    /// Report the PDUs transmitted (off: the MAC holds them).
    transmit: bool,
    held: Vec<TxReporter>,
    down: Vec<Down>,
}

impl Air {
    fn new(cfg: StackConfig) -> Self {
        let mut test = ComponentTest::from_config(cfg, Some(TdmaTime::default()));
        test.populate_entities(
            vec![TetraEntity::Llc, TetraEntity::Mle, TetraEntity::Sndcp],
            vec![TetraEntity::Umac, TetraEntity::Mm, TetraEntity::Cmce],
        );
        Self {
            test,
            ticks: 0,
            ns: HashMap::new(),
            acks: Vec::new(),
            transmit: true,
            held: Vec::new(),
            down: Vec::new(),
        }
    }

    fn step(&mut self) {
        let due: Vec<(u32, u8)> = self.acks.iter().filter(|a| a.2 <= self.ticks).map(|a| (a.0, a.1)).collect();
        self.acks.retain(|a| a.2 > self.ticks);
        for (issi, nr) in due {
            let mut pdu = BitBuffer::new_autoexpand(8);
            BlAck { has_fcs: false, nr }.to_bitbuf(&mut pdu);
            pdu.seek(0);
            self.test.submit_message(tma_ind(issi, pdu, 1));
        }
        self.test.run_stack(Some(1));
        self.ticks += 1;
        for msg in self.test.dump_sinks() {
            let SapMsgInner::TmaUnitdataReq(req) = msg.msg else { continue };
            let down = parse_down(&req);
            if let Some(reporter) = req.tx_reporter {
                if self.transmit {
                    if reporter.get_state() == TxState::Pending {
                        reporter.mark_transmitted();
                    }
                } else {
                    self.held.push(reporter);
                }
            }
            if let Some(ns) = down_ns(&req.pdu) {
                self.acks.push((down.issi, ns, self.ticks + 1));
            }
            self.down.push(down);
        }
    }

    fn run(&mut self, ticks: usize) {
        for _ in 0..ticks {
            self.step();
        }
    }

    /// Send an uplink LLC PDU from `issi` on the MCCH: it goes in on a tick whose uplink slot is
    /// TS1 (downlink TS3, two slots ahead).
    fn uplink(&mut self, issi: u32, llc_pdu: BitBuffer) {
        while self.ticks % 4 != 2 {
            self.step();
        }
        self.test.submit_message(tma_ind(issi, llc_pdu, 1));
        self.step();
    }

    /// An SN-PDU on the acknowledged basic link (BL-DATA).
    fn send(&mut self, issi: u32, sn: &str) {
        let ns = self.ns.entry(issi).or_insert(0);
        let mut pdu = BitBuffer::new_autoexpand(64);
        BlData { has_fcs: false, ns: *ns }.to_bitbuf(&mut pdu);
        *ns ^= 1;
        append_bits(&mut pdu, &format!("100{sn}"));
        self.uplink(issi, pdu);
    }

    /// An SN-PDU on the unacknowledged basic link (BL-UDATA).
    fn send_unack(&mut self, issi: u32, sn: &str) {
        let mut pdu = BitBuffer::new_autoexpand(64);
        BlUdata { has_fcs: false }.to_bitbuf(&mut pdu);
        append_bits(&mut pdu, &format!("100{sn}"));
        self.uplink(issi, pdu);
    }

    /// The SN-PDUs that came down since the last call.
    fn take_sn(&mut self) -> Vec<Down> {
        std::mem::take(&mut self.down).into_iter().filter(|d| d.sn.is_some()).collect()
    }

    /// Run until an SN-PDU comes down (at most `ticks`).
    fn next_sn(&mut self, ticks: usize) -> Option<Down> {
        for _ in 0..ticks {
            if let Some(i) = self.down.iter().position(|d| d.sn.is_some()) {
                return Some(self.down.remove(i));
            }
            self.step();
        }
        let i = self.down.iter().position(|d| d.sn.is_some())?;
        Some(self.down.remove(i))
    }

    /// Activate a PDP context for `issi` and bring it to READY; returns its address.
    fn attach(&mut self, issi: u32, nsapi: u8) -> Ipv4Addr {
        self.send(issi, &demand(nsapi, None, false));
        let accept = self.next_sn(8).expect("ACCEPT");
        let ip = accept_ip(&accept);
        self.send(issi, &transmit_request(nsapi, Some((1, false))));
        let response = self.next_sn(8).expect("RESPONSE");
        assert_eq!(
            decode_data_transmit_response(&response.sn_buf()).unwrap().result,
            SndcpDataTransmitResponseResult::Accepted
        );
        ip
    }
}

fn append_bits(pdu: &mut BitBuffer, bits: &str) {
    let mut src = BitBuffer::from_bitstr(bits);
    pdu.copy_bits(&mut src, bits.len());
    pdu.seek(0);
}

fn tma_ind(issi: u32, pdu: BitBuffer, ts: u32) -> SapMsg {
    SapMsg {
        sap: Sap::TmaSap,
        src: TetraEntity::Umac,
        dest: TetraEntity::Llc,
        msg: SapMsgInner::TmaUnitdataInd(TmaUnitdataInd {
            carrier_num: MAIN_CARRIER,
            pdu: Some(pdu),
            main_address: TetraAddress::new(issi, SsiType::Issi),
            scrambling_code: 0,
            link_id: ts,
            endpoint_id: 0,
            new_endpoint_id: None,
            css_endpoint_id: None,
            air_interface_encryption: 0,
            chan_change_response_req: false,
            chan_change_handle: None,
            chan_info: None,
        }),
    }
}

/// N(S) of a BL-DATA / BL-ADATA going down.
fn down_ns(pdu: &BitBuffer) -> Option<u8> {
    let mut pdu = pdu.clone();
    match LlcPduType::try_from(pdu.peek_bits(4)?).ok()? {
        LlcPduType::BlData => BlData::from_bitbuf(&mut pdu).ok().map(|p| p.ns),
        LlcPduType::BlAdata => BlAdata::from_bitbuf(&mut pdu).ok().map(|p| p.ns),
        _ => None,
    }
}

fn parse_down(req: &TmaUnitdataReq) -> Down {
    let mut pdu = req.pdu.clone();
    let llc = LlcPduType::try_from(pdu.peek_bits(4).unwrap()).unwrap();
    match llc {
        LlcPduType::BlData => {
            BlData::from_bitbuf(&mut pdu).unwrap();
        }
        LlcPduType::BlAdata => {
            BlAdata::from_bitbuf(&mut pdu).unwrap();
        }
        LlcPduType::BlUdata => {
            BlUdata::from_bitbuf(&mut pdu).unwrap();
        }
        LlcPduType::BlAck => {
            BlAck::from_bitbuf(&mut pdu).unwrap();
        }
        other => panic!("unexpected LLC PDU {other:?} going down"),
    }
    let sn = (pdu.get_len_remaining() >= 3 && pdu.read_bits(3) == Some(MleProtocolDiscriminator::Sndcp.into_raw()))
        .then(|| BitBuffer::from_bitbuffer_pos(&pdu).to_bitstr());
    Down {
        issi: req.main_address.ssi,
        llc,
        link_id: req.link_id,
        stealing: req.stealing_permission,
        chan_alloc: req.chan_alloc.is_some(),
        sn,
    }
}

/// Fields of an SN-ACTIVATE PDP CONTEXT ACCEPT (table 28.23): (NSAPI, READY, TIA, IPv4, MTU code,
/// rest after the MTU).
fn accept_fields(sn: &str) -> (u8, u8, u8, Ipv4Addr, u8, String) {
    let f = |o: usize, n: usize| u64::from_str_radix(&sn[o..o + n], 2).unwrap();
    assert_eq!(f(0, 4), 0, "SN-ACTIVATE PDP CONTEXT ACCEPT: {sn}");
    (
        f(4, 4) as u8,
        f(11, 4) as u8,
        f(23, 3) as u8,
        Ipv4Addr::from(f(26, 32) as u32),
        f(66, 3) as u8,
        sn[69..].to_string(),
    )
}

fn accept_ip(down: &Down) -> Ipv4Addr {
    accept_fields(down.sn.as_deref().unwrap()).3
}

/// The WTP packet inside a downlink SN-UNITDATA, with the IPv4 datagram's size.
fn wtp_down(down: &Down, radio_ip: Ipv4Addr) -> (Vec<u8>, usize) {
    assert_eq!(down.sn_type(), Some(4), "SN-UNITDATA");
    let unitdata = decode_sn_unitdata_pdu(&down.sn_buf()).unwrap();
    let mut npdu = unitdata.n_pdu.clone();
    let mut octets = Vec::new();
    while let Some(b) = npdu.read_bits(8) {
        octets.push(b as u8);
    }
    let ip = parse_ipv4_packet(&octets).unwrap();
    assert_eq!((Ipv4Addr::from(ip.source), Ipv4Addr::from(ip.destination)), (GATEWAY, radio_ip));
    let udp = parse_udp_datagram(ip.payload).unwrap();
    assert_eq!(udp.destination_port, RADIO_PORT);
    (udp.payload.to_vec(), octets.len())
}

// ---------------------------------------------------------------------------------------------
// MLE routing (LTPD bearer)
// ---------------------------------------------------------------------------------------------

fn tl_ind(pd: MleProtocolDiscriminator, unack: bool) -> SapMsg {
    let mut sdu = BitBuffer::new(11);
    sdu.write_bits(pd.into_raw(), 3);
    sdu.write_bits(0b1010_1100, 8);
    sdu.seek(0);
    let addr = TetraAddress::new(ISSI, SsiType::Issi);
    let msg = if unack {
        SapMsgInner::TlaTlUnitdataIndBl(TlaTlUnitdataIndBl {
            main_address: addr,
            link_id: 0,
            endpoint_id: 0,
            new_endpoint_id: None,
            css_endpoint_id: None,
            tl_sdu: Some(sdu),
            scrambling_code: 0,
            fcs_flag: false,
            air_interface_encryption: 0,
            chan_change_resp_req: false,
            chan_change_handle: None,
            chan_info: None,
            report: None,
        })
    } else {
        SapMsgInner::TlaTlDataIndBl(TlaTlDataIndBl {
            main_address: addr,
            link_id: 1,
            endpoint_id: 0,
            new_endpoint_id: None,
            css_endpoint_id: None,
            tl_sdu: Some(sdu),
            scrambling_code: 0,
            fcs_flag: false,
            air_interface_encryption: 0,
            chan_change_resp_req: false,
            chan_change_handle: None,
            chan_info: None,
            req_handle: 0,
        })
    };
    SapMsg {
        sap: Sap::TlaSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Mle,
        msg,
    }
}

fn through_mle(packet_data: bool, msg: SapMsg) -> Vec<SapMsg> {
    let mut test = ComponentTest::from_config(config(packet_data, false), None);
    test.populate_entities(
        vec![TetraEntity::Mle],
        vec![TetraEntity::Sndcp, TetraEntity::Mm, TetraEntity::Cmce, TetraEntity::Llc],
    );
    test.submit_message(msg);
    test.deliver_all_messages();
    test.dump_sinks()
}

#[test]
fn tl_unitdata_for_sndcp_is_dropped_with_packet_data_off() {
    assert!(through_mle(false, tl_ind(MleProtocolDiscriminator::Sndcp, true)).is_empty());
}

#[test]
fn tl_unitdata_for_sndcp_reaches_sndcp_as_basic_unack() {
    let out = through_mle(true, tl_ind(MleProtocolDiscriminator::Sndcp, true));
    assert_eq!(out.len(), 1);
    assert_eq!((out[0].sap, out[0].dest), (Sap::TlpdSap, TetraEntity::Sndcp));
    let SapMsgInner::LtpdMleUnitdataInd(ind) = &out[0].msg else {
        panic!("LTPD indication expected");
    };
    assert_eq!(ind.bearer, LtpdBearer::BasicUnack);
    assert_eq!(ind.received_tetra_address.ssi, ISSI);
    assert_eq!(ind.sdu.peek_bits(8), Some(0b1010_1100), "cursor after the MLE discriminator");
}

#[test]
fn tl_unitdata_for_cmce_or_mm_is_still_dropped() {
    for pd in [MleProtocolDiscriminator::Cmce, MleProtocolDiscriminator::Mm] {
        assert!(through_mle(true, tl_ind(pd, true)).is_empty(), "{pd:?}");
    }
}

#[test]
fn tl_data_for_sndcp_is_basic_ack() {
    for packet_data in [false, true] {
        let out = through_mle(packet_data, tl_ind(MleProtocolDiscriminator::Sndcp, false));
        assert_eq!(out.len(), 1);
        let SapMsgInner::LtpdMleUnitdataInd(ind) = &out[0].msg else {
            panic!("LTPD indication expected");
        };
        assert_eq!((ind.bearer, ind.link_id), (LtpdBearer::BasicAck, 1));
    }
}

/// An advanced-link PDU from a radio makes nothing go down, with `[packet_data]` on (it is only
/// logged, as the field probe) or off.
#[test]
fn advanced_link_pdus_produce_nothing() {
    for packet_data in [false, true] {
        let mut air = Air::new(config(packet_data, false));
        // AL-SETUP (LLC PDU type 8) and AL-DATA (type 9).
        air.uplink(ISSI, BitBuffer::from_bitstr("1000000000000000000000000000"));
        air.uplink(ISSI, BitBuffer::from_bitstr("1001000000000000000000000000"));
        air.run(4);
        assert!(air.down.is_empty(), "packet_data {packet_data}: {:?}", air.down);
    }
}

// ---------------------------------------------------------------------------------------------
// Runtime: PDP contexts, READY / STANDBY, transfer control
// ---------------------------------------------------------------------------------------------

#[test]
fn demand_with_real_pco_gets_pool_address_and_chap_success() {
    debug::setup_logging_verbose();
    let mut air = Air::new(config(true, true));
    air.send(ISSI, &demand(1, None, true));
    let accept = air.next_sn(8).expect("ACCEPT");
    assert_eq!(
        (accept.issi, accept.llc == LlcPduType::BlUdata),
        (ISSI, false),
        "acknowledged basic link"
    );
    assert!(!accept.chan_alloc && !accept.stealing);
    let (nsapi, ready, tia, ip, mtu, rest) = accept_fields(accept.sn.as_deref().unwrap());
    assert_eq!((nsapi, ready, tia, ip, mtu), (1, 10, 2, Ipv4Addr::new(10, 0, 0, 2), 2));
    // The optional section is the stub's CHAP Success, identifier 5 echoed.
    assert_eq!(rest.len(), 81);
    assert_eq!(&rest[..5], "10001");
    assert_eq!(&rest[48..64], "0000001100000101", "CHAP Success, id 5");
}

#[test]
fn two_radios_get_distinct_addresses_and_static_is_granted() {
    let mut air = Air::new(config(true, false));
    air.send(ISSI, &demand(1, None, false));
    let a = accept_ip(&air.next_sn(8).unwrap());
    air.send(ISSI2, &demand(1, None, false));
    let b = accept_ip(&air.next_sn(8).unwrap());
    assert_eq!((a, b), (Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3)));
    air.send(3_000_001, &demand(2, Some(Ipv4Addr::new(10, 9, 9, 9)), false));
    let accept = air.next_sn(8).unwrap();
    let (_, _, tia, ip, _, rest) = accept_fields(accept.sn.as_deref().unwrap());
    assert_eq!((tia, ip, rest.as_str()), (1, Ipv4Addr::new(10, 9, 9, 9), "0"));
    // A static request for an address another radio holds is refused (cause 9).
    air.send(3_000_002, &demand(1, Some(a), false));
    let reject = air.next_sn(8).unwrap();
    assert_eq!(
        reject.sn.as_deref(),
        Some("00110001000010010"),
        "REJECT, NSAPI 1, cause 9 (static address in use)"
    );
}

#[test]
fn full_pool_rejects_and_redemand_replaces_the_context() {
    let mut cfg = config(true, false);
    cfg.packet_data.pool_first = Ipv4Addr::new(10, 0, 0, 7);
    cfg.packet_data.pool_last = Ipv4Addr::new(10, 0, 0, 7);
    let mut air = Air::new(cfg);
    air.send(ISSI, &demand(1, None, false));
    assert_eq!(accept_ip(&air.next_sn(8).unwrap()), Ipv4Addr::new(10, 0, 0, 7));
    air.send(ISSI2, &demand(1, None, false));
    let reject = air.next_sn(8).unwrap();
    assert_eq!(reject.sn.as_deref(), Some("00110001000001110"), "REJECT, cause 7 (pool empty)");
    // The same radio activating again gets the address back (the old context is released).
    air.send(ISSI, &demand(1, None, false));
    assert_eq!(accept_ip(&air.next_sn(8).unwrap()), Ipv4Addr::new(10, 0, 0, 7));
}

#[test]
fn deactivate_returns_the_address_to_the_pool() {
    let mut cfg = config(true, false);
    cfg.packet_data.pool_last = Ipv4Addr::new(10, 0, 0, 2);
    let mut air = Air::new(cfg);
    air.send(ISSI, &demand(3, None, false));
    air.next_sn(8).unwrap();
    air.send(ISSI, &deactivate(Some(3)));
    let accept = air.next_sn(8).unwrap();
    assert_eq!(accept.sn.as_deref(), Some("00010000000100110"), "DEACTIVATE ACCEPT, NSAPI 3");
    air.send(ISSI2, &demand(1, None, false));
    assert_eq!(accept_ip(&air.next_sn(8).unwrap()), Ipv4Addr::new(10, 0, 0, 2));
    // "Deactivate all" for a radio with nothing active is still answered.
    air.send(ISSI, &deactivate(None));
    assert_eq!(air.next_sn(8).unwrap().sn.as_deref(), Some("0001000000000"));
}

#[test]
fn transmit_request_and_reconnect_accepted_without_channel() {
    let mut air = Air::new(config(true, false));
    // Without a context: rejected, unknown NSAPI.
    air.send(ISSI, &transmit_request(1, None));
    let rejected = air.next_sn(8).unwrap();
    assert_eq!(
        decode_data_transmit_response(&rejected.sn_buf()).unwrap().result,
        SndcpDataTransmitResponseResult::Rejected(SndcpTransferRejectCause::UnknownNsapi)
    );
    air.send(ISSI, &demand(1, None, true));
    air.next_sn(8).unwrap();
    // The MXP600's forms: one slot, four unspecified, four specific.
    for slots in [Some((1, false)), Some((4, true)), Some((4, false)), None] {
        air.send(ISSI, &transmit_request(1, slots));
        let response = air.next_sn(8).expect("RESPONSE");
        assert_eq!(response.llc == LlcPduType::BlUdata, false, "acknowledged basic link");
        assert!(!response.chan_alloc, "no channel assignment on the MCCH");
        assert_eq!(response.link_id, 0);
        let decoded = decode_data_transmit_response(&response.sn_buf()).unwrap();
        assert_eq!((decoded.nsapi, decoded.result), (1, SndcpDataTransmitResponseResult::Accepted));
    }
    let reconnect = encode_reconnect(&SndcpReconnect {
        nsapi: Some(1),
        resource_request: SndcpPacketDataResourceRequest::PhaseModulation(SndcpPhaseModulationResourceRequest {
            uplink_timeslots: 4,
            downlink_timeslots: 4,
            full_phase_modulation_capability_timeslots: 4,
            unspecified_phase_modulation_resource: false,
        }),
    })
    .unwrap()
    .to_bitstr();
    air.send(ISSI, &reconnect);
    let response = air.next_sn(8).unwrap();
    assert_eq!(
        decode_data_transmit_response(&response.sn_buf()).unwrap().result,
        SndcpDataTransmitResponseResult::Accepted
    );
    // END OF DATA from the radio is answered with END OF DATA.
    air.send(ISSI, &end_of_data());
    let eod = air.next_sn(8).unwrap();
    assert!(!decode_end_of_data(&eod.sn_buf()).unwrap().immediate_service_change);
}

/// READY expiry on the TDMA clock (the STANDBY expiry is a unit test of the runtime: 10 min of
/// ticks is too long here).
#[test]
fn ready_expiry_sends_end_of_data() {
    let mut cfg = config(true, false);
    cfg.packet_data.ready_timer_code = 8; // 10 s announced, 8 s here
    let mut air = Air::new(cfg);
    air.attach(ISSI, 1);
    air.take_sn();
    // 8 s = 565 slots, plus up to one housekeeping period; not before.
    air.run(560);
    assert!(air.take_sn().is_empty(), "READY still running");
    let eod = air.next_sn(80).expect("END OF DATA at READY expiry");
    assert_eq!((eod.issi, eod.sn_type(), eod.llc == LlcPduType::BlUdata), (ISSI, Some(8), false));
    assert!(!decode_end_of_data(&eod.sn_buf()).unwrap().immediate_service_change);
    // In STANDBY the context is kept: a new TRANSMIT REQUEST brings it back to READY.
    air.send(ISSI, &transmit_request(1, None));
    let ok = air.next_sn(8).unwrap();
    assert_eq!(
        decode_data_transmit_response(&ok.sn_buf()).unwrap().result,
        SndcpDataTransmitResponseResult::Accepted
    );
}

/// Activating the same NSAPI again or deactivating it drops the radio's WSP sessions in the
/// gateway (seen in the dashboard status the gateway publishes once a second).
#[test]
fn redemand_and_deactivate_drop_the_gateway_sessions() {
    let mut air = Air::new(config(true, true));
    let ip = air.attach(ISSI, 1);
    air.take_sn();
    let sessions = |air: &mut Air| -> usize {
        std::thread::sleep(std::time::Duration::from_millis(1100));
        air.run(1);
        air.test
            .config
            .state_read()
            .wap_status
            .sessions
            .iter()
            .filter(|s| s.issi == ISSI)
            .count()
    };
    air.send_unack(ISSI, &unitdata(1, &datagram(ip, GATEWAY, 9201, &wtp_connect(0x60))));
    let reply = air.next_sn(200).expect("ConnectReply");
    let (wtp, _) = wtp_down(&reply, ip);
    assert_eq!(&wtp[..4], &[0x12, 0x80, 0x60, 0x02], "WTP Result with WSP ConnectReply");
    air.send_unack(ISSI, &unitdata(1, &datagram(ip, GATEWAY, 9201, &wtp_ack(0x60, None))));
    assert_eq!(sessions(&mut air), 1);
    air.send(ISSI, &demand(1, None, false));
    assert_eq!(accept_ip(&air.next_sn(8).unwrap()), ip, "same address again");
    assert_eq!(sessions(&mut air), 0, "re-activation drops the session");

    air.send(ISSI, &transmit_request(1, None));
    air.next_sn(8).unwrap();
    air.send_unack(ISSI, &unitdata(1, &datagram(ip, GATEWAY, 9201, &wtp_connect(0x61))));
    air.next_sn(200).expect("ConnectReply");
    air.send_unack(ISSI, &unitdata(1, &datagram(ip, GATEWAY, 9201, &wtp_ack(0x61, None))));
    assert_eq!(sessions(&mut air), 1);
    air.send(ISSI, &deactivate(Some(1)));
    air.next_sn(8).unwrap();
    assert_eq!(sessions(&mut air), 0, "deactivation drops the session");
}

#[test]
fn deregistration_releases_the_context() {
    let mut air = Air::new(config(true, false));
    air.test.config.state_write().subscribers.register(ISSI);
    air.attach(ISSI, 1);
    air.run(80); // seen registered
    air.test.config.state_write().subscribers.deregister(ISSI);
    air.run(80);
    air.take_sn();
    air.send(ISSI, &transmit_request(1, None));
    assert!(matches!(
        decode_data_transmit_response(&air.next_sn(8).unwrap().sn_buf()).unwrap().result,
        SndcpDataTransmitResponseResult::Rejected(_)
    ));
}

#[test]
fn unsupported_types_get_not_supported_and_garbage_gets_nothing() {
    let mut air = Air::new(config(true, true));
    air.send(ISSI, "11010000000000"); // SN-MODIFY
    let ns = air.next_sn(8).unwrap();
    assert_eq!(decode_not_supported(&ns.sn_buf()).unwrap().not_supported_pdu_type, 13);
    for garbage in [
        "",
        "0",
        "0000",
        "0010",
        "0100",
        "0100000100000000",
        "0110",
        "1001",
        "1111",
        "0101000100000000",
        "0111",
        "1011",
    ] {
        air.send(ISSI, garbage);
        air.run(8);
        assert!(air.take_sn().is_empty(), "{garbage:?} must get no answer");
    }
}

// ---------------------------------------------------------------------------------------------
// End to end: a WSP GET from a radio to the gateway's home page and back
// ---------------------------------------------------------------------------------------------

#[test]
fn wsp_get_of_the_home_page_end_to_end() {
    debug::setup_logging_verbose();
    let mut air = Air::new(config(true, true));
    let ip = air.attach(ISSI, 1);
    assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 2));
    air.take_sn();

    air.send_unack(ISSI, &unitdata(1, &datagram(ip, GATEWAY, 9201, &wtp_get(0x21, "/"))));
    let mut parts: std::collections::BTreeMap<u8, Vec<u8>> = std::collections::BTreeMap::new();
    let mut packets = 0;
    loop {
        let down = air.next_sn(400).expect("the gateway's answer comes down");
        assert_eq!(
            (down.issi, down.llc, down.link_id),
            (ISSI, LlcPduType::BlUdata, 0),
            "SN-UNITDATA on the MCCH"
        );
        assert!(!down.stealing && !down.chan_alloc);
        let (wtp, size) = wtp_down(&down, ip);
        assert!(size <= 320, "datagram of {size} bytes over the basic link");
        packets += 1;
        let ty = (wtp[0] >> 3) & 0x0f;
        let flags = wtp[0] & 0x06;
        assert_eq!(u16::from_be_bytes([wtp[1], wtp[2]]), 0x8021);
        let (psn, data) = match ty {
            2 => (0, &wtp[3..]),
            6 => (wtp[3], &wtp[4..]),
            _ => panic!("WTP PDU type {ty}: {wtp:02x?}"),
        };
        parts.insert(psn, data.to_vec());
        if flags & 0x02 != 0 {
            air.send_unack(
                ISSI,
                &unitdata(1, &datagram(ip, GATEWAY, 9201, &wtp_ack(0x21, (ty == 6).then_some(psn)))),
            );
            break;
        }
        if flags & 0x04 != 0 {
            air.send_unack(ISSI, &unitdata(1, &datagram(ip, GATEWAY, 9201, &wtp_ack(0x21, Some(psn)))));
        }
    }
    assert!(packets > 1, "the home page does not fit one basic-link datagram");
    let reply: Vec<u8> = parts.into_values().flatten().collect();
    assert_eq!(&reply[..2], &[0x04, 0x20], "WSP Reply, 200 OK");
    let body = String::from_utf8_lossy(&reply);
    assert!(body.contains("FlowStation") && body.trim_end().ends_with("</html>"), "{body}");
    // The final Ack ends the transaction: nothing more comes down.
    air.run(200);
    assert!(air.take_sn().is_empty());
}

#[test]
fn spoofed_source_or_other_destination_gets_nothing() {
    let mut air = Air::new(config(true, true));
    let ip = air.attach(ISSI, 1);
    air.take_sn();
    air.send_unack(
        ISSI,
        &unitdata(1, &datagram(Ipv4Addr::new(10, 0, 0, 99), GATEWAY, 9201, &wtp_get(1, "/status.wml"))),
    );
    air.send_unack(
        ISSI,
        &unitdata(1, &datagram(ip, Ipv4Addr::new(8, 8, 8, 8), 9201, &wtp_get(2, "/status.wml"))),
    );
    air.send_unack(ISSI, &unitdata(1, &datagram(ip, GATEWAY, 80, &wtp_get(3, "/status.wml"))));
    air.send_unack(ISSI, &unitdata(2, &datagram(ip, GATEWAY, 9201, &wtp_get(4, "/status.wml")))); // no context on NSAPI 2
    air.run(100);
    assert!(air.take_sn().is_empty());
}

#[test]
fn wap_off_drops_datagrams_without_panic() {
    let mut air = Air::new(config(true, false));
    let ip = air.attach(ISSI, 1);
    air.take_sn();
    air.send_unack(ISSI, &unitdata(1, &datagram(ip, GATEWAY, 9201, &wtp_get(1, "/"))));
    air.run(100);
    assert!(air.take_sn().is_empty());
}

#[test]
fn second_datagram_waits_until_the_first_left_the_mac() {
    let mut air = Air::new(config(true, true));
    let ip = air.attach(ISSI, 1);
    air.take_sn();
    air.transmit = false;
    // The home page answers with a group of several datagrams at once.
    air.send_unack(ISSI, &unitdata(1, &datagram(ip, GATEWAY, 9201, &wtp_get(0x30, "/"))));
    let first = air.next_sn(400).expect("first datagram");
    assert_eq!(first.sn_type(), Some(4));
    air.run(200);
    assert!(air.take_sn().is_empty(), "the MCCH holds one data PDU at a time");
    for reporter in air.held.drain(..) {
        if reporter.get_state() == TxState::Pending {
            reporter.mark_transmitted();
        }
    }
    air.transmit = true;
    let second = air.next_sn(8).expect("second datagram once the first went out");
    assert_eq!(second.sn_type(), Some(4));
}

#[test]
fn nothing_goes_down_to_a_radio_in_a_call() {
    let mut air = Air::new(config(true, true));
    let ip = air.attach(ISSI, 1);
    air.take_sn();
    air.test.config.state_write().active_call_ts.insert(ISSI, (MAIN_CARRIER, 2, 4));
    air.run(80);
    air.send_unack(ISSI, &unitdata(1, &datagram(ip, GATEWAY, 9201, &wtp_get(0x40, "/status.wml"))));
    air.run(300);
    assert!(air.take_sn().is_empty(), "radio on a traffic channel");
    air.test.config.state_write().active_call_ts.clear();
    let down = air.next_sn(200).expect("delivered after the call");
    assert_eq!(down.sn_type(), Some(4));
    // A group call of a group the radio is in holds it too.
    air.test.config.state_write().subscribers.register(ISSI);
    air.test.config.state_write().subscribers.affiliate(ISSI, 91);
    air.test.config.state_write().active_call_ts.insert(91, (MAIN_CARRIER, 3, 5));
    air.send_unack(ISSI, &unitdata(1, &datagram(ip, GATEWAY, 9201, &wtp_get(0x41, "/status.wml"))));
    air.run(300);
    assert!(air.take_sn().is_empty(), "radio listening to its group");
    air.test.config.state_write().active_call_ts.clear();
    assert!(air.next_sn(200).is_some());
}

// ---------------------------------------------------------------------------------------------
// Voice first: with the bearer on and no data, voice, SDS, registration and DGNA produce exactly
// the same messages as with it off
// ---------------------------------------------------------------------------------------------

const GSSI: u32 = 91;
const SECONDARY_CARRIER: u16 = 1522;

/// The stack from the LLC up (LLC, MLE, MM, CMCE, SNDCP), MAC and Brew as sinks, the radios'
/// PDUs coming in under the LLC. Every tick's output is kept as its sorted Debug lines (sorted:
/// entities keep calls in hash maps, whose order changes from run to run).
struct Voice {
    test: ComponentTest,
    dgna: tetra_entities::net_control::CommandDispatcher,
    ns: HashMap<u32, u8>,
    acks: Vec<(u32, u8, usize)>,
    ticks: usize,
    log: Vec<String>,
    msgs: Vec<SapMsg>,
}

impl Voice {
    fn new(packet_data: bool, secondary: bool) -> Self {
        let mut cfg = config(packet_data, packet_data);
        if secondary {
            cfg.cell.secondary_carrier = Some(SECONDARY_CARRIER);
        }
        let mut test = ComponentTest::from_config(cfg, Some(TdmaTime::default()));
        test.populate_entities(
            vec![TetraEntity::Llc, TetraEntity::Mle, TetraEntity::Cmce, TetraEntity::Sndcp],
            vec![TetraEntity::Umac, TetraEntity::Brew],
        );
        let (dgna, endpoint) = tetra_entities::net_control::make_control_link();
        let mm = tetra_entities::mm::mm_bs::MmBs::new(test.get_shared_config(), None, Some(endpoint));
        test.register_entity(mm);
        Self {
            test,
            dgna,
            ns: HashMap::new(),
            acks: Vec::new(),
            ticks: 0,
            log: Vec::new(),
            msgs: Vec::new(),
        }
    }

    /// Run `ticks` ticks; the radios behave like the air: every PDU is reported transmitted and
    /// each BL-DATA to a radio is acknowledged two slots later.
    fn run(&mut self, ticks: usize) {
        for _ in 0..ticks {
            let due: Vec<(u32, u8)> = self.acks.iter().filter(|a| a.2 <= self.ticks).map(|a| (a.0, a.1)).collect();
            self.acks.retain(|a| a.2 > self.ticks);
            for (issi, nr) in due {
                let mut pdu = BitBuffer::new_autoexpand(8);
                BlAck { has_fcs: false, nr }.to_bitbuf(&mut pdu);
                pdu.seek(0);
                self.test.submit_message(tma_ind(issi, pdu, 1));
            }
            self.test.run_stack(Some(1));
            self.ticks += 1;
            let msgs = self.test.dump_sinks();
            let mut lines: Vec<String> = msgs.iter().map(|m| format!("{m:?}")).collect();
            lines.sort();
            for line in lines {
                self.log.push(format!("{} {line}", self.ticks));
            }
            for m in &msgs {
                let SapMsgInner::TmaUnitdataReq(req) = &m.msg else { continue };
                if let Some(reporter) = &req.tx_reporter
                    && reporter.get_state() == TxState::Pending
                {
                    reporter.mark_transmitted();
                }
                if req.main_address.ssi_type != SsiType::Gssi
                    && let Some(ns) = down_ns(&req.pdu)
                {
                    self.acks.push((req.main_address.ssi, ns, self.ticks + 1));
                }
            }
            self.msgs.extend(msgs);
        }
    }

    /// A PDU of protocol `pd` from `issi` on the MCCH (BL-DATA, uplink slot TS1).
    fn uplink(&mut self, issi: u32, pd: MleProtocolDiscriminator, sdu: BitBuffer) {
        while self.ticks % 4 != 2 {
            self.run(1);
        }
        let ns = self.ns.entry(issi).or_insert(0);
        let mut pdu = BitBuffer::new_autoexpand(96);
        BlData { has_fcs: false, ns: *ns }.to_bitbuf(&mut pdu);
        *ns ^= 1;
        pdu.write_bits(pd.into_raw(), 3);
        let mut sdu = BitBuffer::from_bitbuffer(&sdu);
        let len = sdu.get_len();
        pdu.copy_bits(&mut sdu, len);
        pdu.seek(0);
        self.test.submit_message(tma_ind(issi, pdu, 1));
        self.run(1);
    }

    fn cmce(&mut self, issi: u32, sdu: BitBuffer) {
        self.uplink(issi, MleProtocolDiscriminator::Cmce, sdu);
    }

    /// Register `issi` and affiliate it to `gssi` in CMCE, as the MM does.
    fn register(&mut self, issi: u32, gssi: Option<u32>) {
        use tetra_saps::control::brew::{BrewSubscriberAction, MmSubscriberUpdate};
        let mut update = |groups: Vec<u32>, action| {
            self.test.submit_message(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Mm,
                dest: TetraEntity::Cmce,
                msg: SapMsgInner::MmSubscriberUpdate(MmSubscriberUpdate { issi, groups, action }),
            });
        };
        update(Vec::new(), BrewSubscriberAction::Register);
        if let Some(gssi) = gssi {
            update(vec![gssi], BrewSubscriberAction::Affiliate);
        }
        let mut state = self.test.config.state_write();
        state.subscribers.register(issi);
        if let Some(gssi) = gssi {
            state.subscribers.affiliate(issi, gssi);
        }
        drop(state);
        self.run(1);
    }

    /// Call identifier of the last D-SETUP that went down to `ssi`.
    fn d_setup_call_id(&self, ssi: u32) -> u16 {
        use tetra_pdus::cmce::enums::cmce_pdu_type_dl::CmcePduTypeDl;
        use tetra_pdus::cmce::pdus::d_setup::DSetup;
        self.msgs
            .iter()
            .rev()
            .find_map(|m| {
                let SapMsgInner::TmaUnitdataReq(req) = &m.msg else { return None };
                if req.main_address.ssi != ssi {
                    return None;
                }
                let mut pdu = req.pdu.clone();
                match LlcPduType::try_from(pdu.peek_bits(4)?).ok()? {
                    LlcPduType::BlData => BlData::from_bitbuf(&mut pdu).ok().map(|_| ())?,
                    LlcPduType::BlAdata => BlAdata::from_bitbuf(&mut pdu).ok().map(|_| ())?,
                    LlcPduType::BlUdata => BlUdata::from_bitbuf(&mut pdu).ok().map(|_| ())?,
                    _ => return None,
                }
                if pdu.read_bits(3)? != MleProtocolDiscriminator::Cmce.into_raw() {
                    return None;
                }
                if CmcePduTypeDl::try_from(pdu.peek_bits(5)?).ok()? != CmcePduTypeDl::DSetup {
                    return None;
                }
                DSetup::from_bitbuf(&mut pdu).ok().map(|d| d.call_identifier)
            })
            .expect("a D-SETUP went down")
    }
}

fn u_setup(called_ssi: u32, group: bool, duplex: bool, call_priority: u8) -> BitBuffer {
    use tetra_pdus::cmce::enums::party_type_identifier::PartyTypeIdentifier;
    use tetra_pdus::cmce::fields::basic_service_information::BasicServiceInformation;
    use tetra_pdus::cmce::pdus::u_setup::USetup;
    use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;
    use tetra_saps::control::enums::communication_type::CommunicationType;
    let u_setup = USetup {
        area_selection: 0,
        hook_method_selection: !group,
        simplex_duplex_selection: duplex,
        basic_service_information: BasicServiceInformation {
            circuit_mode_type: CircuitModeType::TchS,
            encryption_flag: false,
            communication_type: if group { CommunicationType::P2Mp } else { CommunicationType::P2p },
            slots_per_frame: None,
            speech_service: Some(0),
        },
        request_to_transmit_send_data: false,
        call_priority,
        clir_control: 0,
        called_party_type_identifier: PartyTypeIdentifier::Ssi,
        called_party_ssi: Some(called_ssi as u64),
        called_party_short_number_address: None,
        called_party_extension: None,
        external_subscriber_number: None,
        facility: None,
        dm_ms_address: None,
        proprietary: None,
    };
    let mut sdu = BitBuffer::new_autoexpand(80);
    u_setup.to_bitbuf(&mut sdu).expect("Failed to serialize USetup");
    sdu.seek(0);
    sdu
}

fn u_connect(call_id: u16, duplex: bool) -> BitBuffer {
    use tetra_pdus::cmce::pdus::u_connect::UConnect;
    let mut sdu = BitBuffer::new_autoexpand(80);
    UConnect {
        call_identifier: call_id,
        hook_method_selection: true,
        simplex_duplex_selection: duplex,
        basic_service_information: None,
        facility: None,
        proprietary: None,
    }
    .to_bitbuf(&mut sdu)
    .expect("Failed to serialize UConnect");
    sdu.seek(0);
    sdu
}

fn u_tx_ceased(call_id: u16) -> BitBuffer {
    use tetra_pdus::cmce::pdus::u_tx_ceased::UTxCeased;
    let mut sdu = BitBuffer::new_autoexpand(80);
    UTxCeased {
        call_identifier: call_id,
        facility: None,
        dm_ms_address: None,
        proprietary: None,
    }
    .to_bitbuf(&mut sdu)
    .expect("Failed to serialize UTxCeased");
    sdu.seek(0);
    sdu
}

fn u_disconnect(call_id: u16) -> BitBuffer {
    use tetra_pdus::cmce::enums::disconnect_cause::DisconnectCause;
    use tetra_pdus::cmce::pdus::u_disconnect::UDisconnect;
    let mut sdu = BitBuffer::new_autoexpand(80);
    UDisconnect {
        call_identifier: call_id,
        disconnect_cause: DisconnectCause::UserRequestedDisconnection,
        facility: None,
        proprietary: None,
    }
    .to_bitbuf(&mut sdu)
    .expect("Failed to serialize UDisconnect");
    sdu.seek(0);
    sdu
}

fn u_sds_data(dest_ssi: u32, payload: u16) -> BitBuffer {
    use tetra_pdus::cmce::enums::party_type_identifier::PartyTypeIdentifier;
    use tetra_pdus::cmce::pdus::u_sds_data::USdsData;
    use tetra_saps::control::enums::sds_user_data::SdsUserData;
    let mut sdu = BitBuffer::new_autoexpand(80);
    USdsData {
        area_selection: 0,
        called_party_type_identifier: PartyTypeIdentifier::Ssi,
        called_party_short_number_address: None,
        called_party_ssi: Some(dest_ssi as u64),
        called_party_extension: None,
        user_defined_data: SdsUserData::Type1(payload),
        external_subscriber_number: None,
        dm_ms_address: None,
    }
    .to_bitbuf(&mut sdu)
    .expect("Failed to serialize U-SDS-DATA");
    sdu.seek(0);
    sdu
}

fn u_location_update_demand(issi: u32) -> BitBuffer {
    use tetra_pdus::mm::enums::location_update_type::LocationUpdateType;
    use tetra_pdus::mm::pdus::u_location_update_demand::ULocationUpdateDemand;
    let mut sdu = BitBuffer::new_autoexpand(32);
    ULocationUpdateDemand {
        location_update_type: LocationUpdateType::RoamingLocationUpdating,
        request_to_append_la: false,
        cipher_control: false,
        ciphering_parameters: None,
        class_of_ms: None,
        energy_saving_mode: None,
        la_information: None,
        ssi: Some(issi as u64),
        address_extension: None,
        group_identity_location_demand: None,
        group_report_response: None,
        authentication_uplink: None,
        extended_capabilities: None,
        proprietary: None,
    }
    .to_bitbuf(&mut sdu)
    .expect("serialize U-LOCATION-UPDATE-DEMAND");
    sdu.seek(0);
    sdu
}

/// Run `scenario` with the bearer off and on (no data traffic) and require the same output.
fn same_with_and_without_packet_data(secondary: bool, scenario: impl Fn(&mut Voice)) -> Vec<String> {
    let mut off = Voice::new(false, secondary);
    scenario(&mut off);
    let mut on = Voice::new(true, secondary);
    scenario(&mut on);
    assert_eq!(off.log.len(), on.log.len(), "as many messages with [packet_data] on");
    for (a, b) in off.log.iter().zip(&on.log) {
        assert_eq!(a, b, "first difference with [packet_data] on");
    }
    off.log
}

fn count(log: &[String], what: &str) -> usize {
    log.iter().filter(|l| l.contains(what)).count()
}

#[test]
fn group_call_is_the_same_with_packet_data_on() {
    let log = same_with_and_without_packet_data(false, |v| {
        v.register(ISSI, Some(GSSI));
        v.register(ISSI2, Some(GSSI));
        v.cmce(ISSI, u_setup(GSSI, true, false, 0));
        v.run(20);
        let call_id = v.d_setup_call_id(GSSI);
        v.cmce(ISSI, u_tx_ceased(call_id));
        // Hangtime (5 s) and the D-RELEASE.
        v.run(450);
    });
    assert!(count(&log, "Open(") >= 1, "the group call opened a circuit");
    assert!(count(&log, "CallEnded") >= 1, "and ended after the hangtime");
}

#[test]
fn simplex_individual_call_is_the_same_with_packet_data_on() {
    let log = same_with_and_without_packet_data(false, |v| {
        v.register(ISSI2, None);
        v.cmce(ISSI, u_setup(ISSI2, false, false, 0));
        v.run(10);
        let call_id = v.d_setup_call_id(ISSI2);
        v.cmce(ISSI2, u_connect(call_id, false));
        v.run(10);
        v.cmce(ISSI, u_tx_ceased(call_id));
        v.run(10);
        v.cmce(ISSI, u_disconnect(call_id));
        v.run(60);
    });
    assert!(count(&log, "Open(") >= 1);
}

#[test]
fn duplex_individual_calls_are_the_same_with_packet_data_on() {
    let log = same_with_and_without_packet_data(false, |v| {
        v.register(ISSI2, None);
        v.cmce(ISSI, u_setup(ISSI2, false, true, 0));
        v.run(10);
        let call_id = v.d_setup_call_id(ISSI2);
        v.cmce(ISSI2, u_connect(call_id, true));
        v.run(10);
        v.cmce(ISSI, u_disconnect(call_id));
        v.run(60);
    });
    assert!(count(&log, "Open(") >= 2, "a duplex call opens two circuits");
}

/// Two duplex calls need four slots: the second one goes to the secondary carrier.
#[test]
fn duplex_calls_on_two_carriers_are_the_same_with_packet_data_on() {
    let log = same_with_and_without_packet_data(true, |v| {
        v.register(ISSI2, None);
        v.register(ISSI2 + 2, None);
        v.cmce(ISSI, u_setup(ISSI2, false, true, 0));
        v.run(10);
        let first = v.d_setup_call_id(ISSI2);
        v.cmce(ISSI2, u_connect(first, true));
        v.run(10);
        v.cmce(ISSI + 2, u_setup(ISSI2 + 2, false, true, 0));
        v.run(10);
        let second = v.d_setup_call_id(ISSI2 + 2);
        v.cmce(ISSI2 + 2, u_connect(second, true));
        v.run(10);
        v.cmce(ISSI, u_disconnect(first));
        v.cmce(ISSI + 2, u_disconnect(second));
        v.run(60);
    });
    assert!(count(&log, "Open(") >= 4);
    assert!(count(&log, "carrier_num: 1522") >= 1, "the second call on the secondary carrier");
}

#[test]
fn local_sds_is_the_same_with_packet_data_on() {
    let log = same_with_and_without_packet_data(false, |v| {
        v.register(ISSI2, None);
        v.cmce(ISSI, u_sds_data(ISSI2, 0xABCD));
        v.run(20);
    });
    assert!(
        log.iter()
            .any(|l| l.contains("TmaUnitdataReq") && l.contains(&format!("ssi: {ISSI2}")))
    );
}

#[test]
fn registration_and_dgna_are_the_same_with_packet_data_on() {
    let log = same_with_and_without_packet_data(false, |v| {
        v.uplink(ISSI, MleProtocolDiscriminator::Mm, u_location_update_demand(ISSI));
        v.run(20);
        v.dgna.send(tetra_entities::net_control::ControlCommand::Dgna {
            issi: ISSI,
            gssi: 100,
            mnemonic: None,
            attachment_mode: 0,
            attach: true,
        });
        v.run(40);
    });
    assert!(
        count(&log, &format!("ssi: {ISSI}")) >= 2,
        "D-LOCATION UPDATE ACCEPT and the DGNA went down"
    );
}

#[test]
fn emergency_call_in_a_full_cell_is_the_same_with_packet_data_on() {
    let log = same_with_and_without_packet_data(false, |v| {
        for (i, g) in [101u32, 102, 103, 199].into_iter().enumerate() {
            v.register(2_000_001 + i as u32, Some(g));
        }
        for (i, g) in [101u32, 102, 103].into_iter().enumerate() {
            v.cmce(3_000_001 + i as u32, u_setup(g, true, false, 0));
            v.run(4);
        }
        v.cmce(3_000_099, u_setup(199, true, false, 15));
        v.run(20);
    });
    assert!(count(&log, "CallEnded") >= 1, "the emergency call pre-empted one");
}
