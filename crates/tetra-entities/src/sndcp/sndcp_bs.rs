use super::packet_data::PacketDataRuntime;
use super::wapgw::WapService;
use crate::{MessageQueue, TetraEntityTrait};
use std::time::Instant;
use tetra_config::bluestation::SharedConfig;
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{BitBuffer, Sap, TdmaTime, TetraAddress};
use tetra_saps::ltpd::LtpdMleUnitdataInd;
use tetra_saps::tla::TlaTlDataReqBl;
use tetra_saps::{SapMsg, SapMsgInner};

// TETRA packet data (SNDCP). Air interface: ETSI EN 300 392-2 clause 28; PDU contents tables 28.23
// (SN-ACTIVATE PDP CONTEXT ACCEPT) and 28.24 (SN-ACTIVATE PDP CONTEXT DEMAND).

/// MLE protocol discriminator value for SNDCP (3 bits, 0b100). The MS's MLE routes the downlink SDU
/// to its SNDCP entity, mirroring the uplink (mle_bs.rs).
pub(crate) const MLE_DISCRIMINATOR_SNDCP: u64 = 0b100;
/// SN-PDU type for SN-ACTIVATE PDP CONTEXT (4 bits, 0x0). DEMAND on uplink, ACCEPT on downlink.
const SN_PDU_ACTIVATE_PDP_CONTEXT: u64 = 0x0;
const SN_PDU_DEACTIVATE_PDP_CONTEXT_ACCEPT: u64 = 0x1;
const SN_PDU_DEACTIVATE_PDP_CONTEXT_DEMAND: u8 = 0x2;
const SN_PDU_ACTIVATE_PDP_CONTEXT_REJECT: u64 = 0x3;

// SN-ACTIVATE PDP CONTEXT ACCEPT mandatory field values (clause 28.4.5.*).
const PDU_PRIORITY_MAX: u64 = 4; // 0..7, mid (28.103)
const READY_TIMER: u8 = 8; // 8 = 10 s (28.112)
const STANDBY_TIMER: u64 = 5; // 5 = 10 min (28.122)
const RESPONSE_WAIT_TIMER: u64 = 8; // 8 = 10 s (28.116)
pub(crate) const TIA_IPV4_STATIC: u8 = 1; // Type identifier in accept: 1 = IPv4 Static Address (28.126)
pub(crate) const TIA_IPV4_DYNAMIC: u8 = 2; // 2 = IPv4 Dynamic Address
const MTU_1500: u8 = 4; // 4 = 1500 octets (28.79)
/// Address handed to a MS that requested a dynamic IPv4 (ATID != 0). Static requests get the address
/// the MS asked for, echoed back.
const POOL_IPV4: u32 = 0xC0A8_01B4; // 192.168.1.180

// CHAP authentication carried in the Protocol configuration options (PCO) type-3 element.
// Motorola/Dimetra radios run PPP CHAP (RFC 1994) inside PDP context activation: the DEMAND's PCO
// carries the MS's CHAP Response (username + MD5 hash). The SwMI must reply with a CHAP Success in
// the ACCEPT's PCO or the MS aborts the data session ("data server not responding").
const PCO_TYPE34_ID: u64 = 1; // Table 28.127: type-3/4 element identifier for PCO
const PPP_PROTO_CHAP: u64 = 0xC223; // RFC 3232 configuration protocol identifier for CHAP
const PPP_CONFIG_PROTOCOL_PPP: u64 = 0; // Table 28.105: configuration protocol 0000 = PPP
const CHAP_CODE_SUCCESS: u64 = 3; // RFC 1994 CHAP code: 3 = Success
/// PCO content length, in bits, for a bare CHAP Success: configuration protocol(4) +
/// protocol identity(16) + length-of-contents(8) + CHAP Success packet(4 octets = 32) = 60.
const PCO_CHAP_SUCCESS_BITS: u64 = 60;

pub struct Sndcp {
    config: SharedConfig,
    /// WAP gateway, only with `[wap] enabled`.
    wap: Option<WapService>,
    /// Packet-data bearer, only with `[packet_data] enabled`; without it the stub answers.
    runtime: Option<PacketDataRuntime>,
}

/// The mandatory header of an SN-ACTIVATE PDP CONTEXT DEMAND (table 28.24) and the CHAP identifier
/// its PCO carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Demand {
    pub nsapi: u8,
    /// Address type identifier in demand: 0 = static IPv4, 1 = dynamic IPv4, 2..5 other.
    pub atid: u8,
    /// The address asked for with ATID 0.
    pub static_ipv4: Option<u32>,
    pub chap_id: Option<u8>,
}

/// Decode a DEMAND: type(4) version(4) NSAPI(4) ATID(3) [IPv4(32) when ATID == 0]. `demand` is the
/// SNDCP PDU bit-string (after the 3-bit MLE discriminator). Missing fields fall back as the stub
/// always did: NSAPI 1, ATID 0.
pub(crate) fn parse_demand(demand: &str) -> Demand {
    let bits = |off: usize, n: usize| -> Option<u64> { demand.get(off..off + n).and_then(|s| u64::from_str_radix(s, 2).ok()) };
    let nsapi = bits(8, 4).unwrap_or(1) as u8;
    let atid = bits(12, 3).unwrap_or(0) as u8;
    Demand {
        nsapi,
        atid,
        static_ipv4: if atid == 0 { bits(15, 32).map(|ip| ip as u32) } else { None },
        chap_id: find_chap_response_id(demand),
    }
}

/// SN-ACTIVATE PDP CONTEXT ACCEPT (table 28.23) prefixed with the MLE discriminator: `ipv4` with
/// type identifier `tia`, the READY timer and MTU codes given, and, if the DEMAND carried PPP CHAP,
/// the PCO with the CHAP Success the MS waits for.
pub(crate) fn encode_pdp_accept(nsapi: u8, tia: u8, ipv4: u32, mtu_code: u8, ready_code: u8, chap_id: Option<u8>) -> BitBuffer {
    let mut sdu = BitBuffer::new_autoexpand(16);
    sdu.write_bits(MLE_DISCRIMINATOR_SNDCP, 3);
    sdu.write_bits(SN_PDU_ACTIVATE_PDP_CONTEXT, 4); // SN PDU type = ACCEPT
    sdu.write_bits(u64::from(nsapi), 4); // NSAPI (echo)
    sdu.write_bits(PDU_PRIORITY_MAX, 3);
    sdu.write_bits(u64::from(ready_code), 4);
    sdu.write_bits(STANDBY_TIMER, 4);
    sdu.write_bits(RESPONSE_WAIT_TIMER, 4);
    sdu.write_bits(u64::from(tia), 3); // Type identifier in accept (IPv4 present)
    sdu.write_bits(u64::from(ipv4), 32); // IP Address IPv4 (conditional on TIA = 1/2)
    sdu.write_bits(0, 8); // PCOMP negotiation = 0 (no header compression → no conditional fields)
    sdu.write_bits(u64::from(mtu_code), 3); // Maximum transmission unit

    // Optional elements (annex E.1). If the DEMAND carried PPP CHAP authentication the MS is
    // waiting for a CHAP Success — without it the data session never opens ("data server not
    // responding"). Append a PCO type-3 element carrying the Success; otherwise close the PDU
    // with an o-bit of 0.
    if let Some(id) = chap_id {
        for bit in chap_success_optional_section(id).bytes() {
            sdu.write_bits(u64::from(bit - b'0'), 1);
        }
    } else {
        sdu.write_bits(0, 1); // o-bit = 0: no optional elements → PDU ends
    }
    sdu.seek(0);
    sdu
}

/// SN-ACTIVATE PDP CONTEXT REJECT (table 28.25) prefixed with the MLE discriminator; `cause` from
/// table 28.46.
pub(crate) fn encode_pdp_reject(nsapi: u8, cause: u8) -> BitBuffer {
    let mut sdu = BitBuffer::new(3 + 4 + 4 + 8 + 1);
    sdu.write_bits(MLE_DISCRIMINATOR_SNDCP, 3);
    sdu.write_bits(SN_PDU_ACTIVATE_PDP_CONTEXT_REJECT, 4);
    sdu.write_bits(u64::from(nsapi), 4);
    sdu.write_bits(u64::from(cause), 8);
    sdu.write_bits(0, 1); // o-bit: no PCO
    sdu.seek(0);
    sdu
}

/// Which contexts an SN-DEACTIVATE PDP CONTEXT DEMAND / ACCEPT names (table 28.68).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Deactivation {
    All,
    Nsapi(u8),
}

/// Decode an SN-DEACTIVATE PDP CONTEXT DEMAND (table 28.32): type(4) deactivation type(8)
/// [NSAPI(4) unless the type is 0]; optional elements are ignored. `pdu` is the SNDCP PDU
/// bit-string. None if it is not a DEMAND or is too short.
pub(crate) fn decode_deactivate_demand(pdu: &str) -> Option<Deactivation> {
    let bits = |off: usize, n: usize| -> Option<u8> { pdu.get(off..off + n).and_then(|s| u8::from_str_radix(s, 2).ok()) };
    if bits(0, 4)? != SN_PDU_DEACTIVATE_PDP_CONTEXT_DEMAND {
        return None;
    }
    match bits(4, 8)? {
        0 => Some(Deactivation::All),
        // 1 names the NSAPI; with the reserved values the NSAPI is present too (note 1).
        _ => Some(Deactivation::Nsapi(bits(12, 4)?)),
    }
}

/// SN-DEACTIVATE PDP CONTEXT ACCEPT (table 28.33) prefixed with the MLE discriminator, echoing the
/// DEMAND's deactivation.
pub(crate) fn encode_deactivate_accept(deactivation: Deactivation) -> BitBuffer {
    let mut sdu = BitBuffer::new_autoexpand(24);
    sdu.write_bits(MLE_DISCRIMINATOR_SNDCP, 3);
    sdu.write_bits(SN_PDU_DEACTIVATE_PDP_CONTEXT_ACCEPT, 4);
    match deactivation {
        Deactivation::All => sdu.write_bits(0, 8),
        Deactivation::Nsapi(nsapi) => {
            sdu.write_bits(1, 8);
            sdu.write_bits(u64::from(nsapi), 4);
        }
    }
    sdu.write_bits(0, 1); // o-bit: no optional elements
    sdu.seek(0);
    sdu
}

/// TL-DATA request on the acknowledged basic link carrying `sdu` to `addr`, as the stub has always
/// sent its ACCEPT.
pub(crate) fn tl_data_req(addr: TetraAddress, link_id: u32, endpoint_id: u32, sdu: BitBuffer) -> SapMsg {
    SapMsg {
        sap: Sap::TlaSap,
        src: TetraEntity::Sndcp,
        dest: TetraEntity::Llc,
        msg: SapMsgInner::TlaTlDataReqBl(TlaTlDataReqBl {
            main_address: addr,
            link_id,
            endpoint_id,
            tl_sdu: sdu,
            stealing_permission: false,
            subscriber_class: 0,
            fcs_flag: false,
            air_interface_encryption: None,
            stealing_repeats_flag: None,
            data_class_info: None,
            req_handle: 0,
            graceful_degradation: None,
            chan_alloc: None,
            follow_uplink_channel: false,
            tx_reporter: None,
        }),
    }
}

impl Sndcp {
    pub fn new(config: SharedConfig) -> Self {
        let wap = WapService::start(&config);
        let runtime = PacketDataRuntime::new(&config);
        Self { config, wap, runtime }
    }

    /// Reply to an SN-ACTIVATE PDP CONTEXT DEMAND with a spec-conformant SN-ACTIVATE PDP CONTEXT
    /// ACCEPT (table 28.23): echo the requested NSAPI and grant the IPv4 the MS asked for (or one
    /// from the pool for a dynamic request), with mandatory timers/MTU and no optional elements.
    /// `demand` is the SNDCP PDU bit-string (after the 3-bit MLE discriminator).
    fn send_pdp_accept(&self, queue: &mut MessageQueue, ind: &LtpdMleUnitdataInd, demand: &str) {
        let d = parse_demand(demand);
        let (tia, ipv4) = if d.atid == 0 {
            // Static: the MS asked for a specific IPv4 — grant it.
            (TIA_IPV4_STATIC, d.static_ipv4.unwrap_or(POOL_IPV4))
        } else {
            // Dynamic (or other): assign one from the pool.
            (TIA_IPV4_DYNAMIC, POOL_IPV4)
        };
        let sdu = encode_pdp_accept(d.nsapi, tia, ipv4, MTU_1500, READY_TIMER, d.chap_id);

        tracing::info!(
            "SNDCP: -> SN-ACTIVATE PDP CONTEXT ACCEPT to {:?}: NSAPI={} TIA={} IPv4={}.{}.{}.{} CHAP-Success={} ({} bits)",
            ind.received_tetra_address,
            d.nsapi,
            tia,
            (ipv4 >> 24) & 0xff,
            (ipv4 >> 16) & 0xff,
            (ipv4 >> 8) & 0xff,
            ipv4 & 0xff,
            d.chap_id.map(|id| format!("id={id}")).unwrap_or_else(|| "none".into()),
            sdu.get_len()
        );

        // Acknowledged basic link (the DEMAND arrived acknowledged), addressed to the requesting MS.
        queue.push_back(tl_data_req(ind.received_tetra_address, ind.link_id, ind.endpoint_id, sdu));
    }
}

/// Build the optional-element section (annex E.1) of an ACCEPT that grants a CHAP Success with the
/// given identifier: the o-bit, the three absent type-2 presence bits (SNDCP network endpoint id,
/// SwMI IPv6 information, SwMI Mobile IPv4 information — table 28.23), the PCO type-3 element, and
/// the closing m-bit. Returned MSB-first as a bit string for direct append to the PDU. Kept as the
/// single source of truth so the wire encoding and its unit test cannot drift apart.
pub(crate) fn chap_success_optional_section(chap_id: u8) -> String {
    let mut s = String::with_capacity(81);
    s.push('1'); // o-bit = 1: optional elements follow
    s.push_str("000"); // type-2 presence bits, in table order, all absent
    s.push('1'); // M-bit = 1: a type-3/4 element follows
    s.push_str(&format!("{PCO_TYPE34_ID:04b}")); // type-3/4 element identifier (PCO = 1)
    s.push_str(&format!("{PCO_CHAP_SUCCESS_BITS:011b}")); // length indicator (bits)
    // PCO content (table 28.105): PPP / CHAP / one Success packet.
    s.push_str(&format!("{PPP_CONFIG_PROTOCOL_PPP:04b}")); // configuration protocol = PPP
    s.push_str(&format!("{PPP_PROTO_CHAP:016b}")); // protocol identity = CHAP (C223H)
    s.push_str(&format!("{:08b}", 4)); // length of protocol identity contents = 4 octets
    // CHAP Success packet (RFC 1994): code=3, identifier echoed from the MS Response, length=4
    // (header only, no message).
    s.push_str(&format!("{CHAP_CODE_SUCCESS:08b}"));
    s.push_str(&format!("{chap_id:08b}"));
    s.push_str(&format!("{:016b}", 4));
    s.push('0'); // M-bit = 0: no more type-3/4 elements (last bit in the PDU)
    s
}

/// Scan an SN-ACTIVATE PDP CONTEXT DEMAND bit-string for a PPP CHAP packet carried in its Protocol
/// configuration options element and return the identifier of the MS's CHAP Response (RFC 1994 code
/// 2), to be echoed in the Success we send back. Falls back to a Challenge's (code 1) identifier if
/// no Response is present, or `None` if the DEMAND carries no CHAP at all (e.g. PAP or no auth → we
/// leave the ACCEPT without a PCO).
///
/// The scan locates the 16-bit CHAP configuration-protocol identifier (C223H) at any bit offset —
/// the PCO is bit-packed, not byte-aligned — then reads the CHAP packet's code/identifier from the
/// fixed offsets that follow (8-bit length-of-contents, then code, then identifier). The CHAP code
/// is validated to reject a coincidental C223H bit pattern inside a hash value.
pub(crate) fn find_chap_response_id(demand: &str) -> Option<u8> {
    const CHAP_PROTO_ID: &str = "1100001000100011"; // C223H, MSB first
    let read = |off: usize| -> Option<u8> { demand.get(off..off + 8).and_then(|s| u8::from_str_radix(s, 2).ok()) };
    let mut fallback = None;
    let mut from = 0;
    while let Some(rel) = demand.get(from..).and_then(|s| s.find(CHAP_PROTO_ID)) {
        let marker = from + rel;
        // After C223H: length-of-contents (8 bits), then the CHAP packet (code, identifier, ...).
        match (read(marker + 16 + 8), read(marker + 16 + 16)) {
            (Some(2), Some(id)) => return Some(id),                           // Response — echo this identifier
            (Some(1), Some(id)) if fallback.is_none() => fallback = Some(id), // Challenge
            _ => {}
        }
        from = marker + CHAP_PROTO_ID.len();
    }
    fallback
}

impl TetraEntityTrait for Sndcp {
    fn entity(&self) -> TetraEntity {
        TetraEntity::Sndcp
    }

    fn tick_start(&mut self, queue: &mut MessageQueue, _ts: TdmaTime) {
        if let Some(runtime) = self.runtime.as_mut() {
            runtime.tick(queue, &self.config, self.wap.as_mut(), Instant::now());
        } else if let Some(wap) = self.wap.as_mut() {
            for out in wap.tick(&self.config, Instant::now()) {
                tracing::debug!("WAP: no bearer to ISSI {} yet, reply dropped", out.peer.issi);
            }
        }
    }

    fn rx_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        // Decode the SN-PDU type and, for an SN-ACTIVATE PDP CONTEXT DEMAND, return an ACCEPT.
        // Never panics: a garbled PDU must not take down the stack.
        let SapMsgInner::LtpdMleUnitdataInd(ind) = &message.msg else {
            tracing::debug!("SNDCP: unhandled prim (sap={:?}): {:?}", message.sap, message.msg);
            return;
        };
        if let Some(runtime) = self.runtime.as_mut() {
            runtime.rx(queue, ind, self.wap.as_mut(), &self.config, Instant::now());
            return;
        }

        // The SDU still carries the leading 3-bit MLE protocol discriminator (0b100 = SNDCP); the
        // SNDCP PDU proper — which begins with a 4-bit SN-PDU type — starts after it.
        let raw = ind.sdu.dump_bin_unformatted();
        let pdu = raw.get(3..).unwrap_or("");
        let sn_type = pdu.get(0..4).and_then(|s| u8::from_str_radix(s, 2).ok());
        // SN-PDU type table (ETSI EN 300 392-2 clause 28.4.5, "SN PDU type").
        let name = match sn_type {
            Some(0) => "SN-ACTIVATE PDP CONTEXT (DEMAND/ACCEPT)",
            Some(1) => "SN-DEACTIVATE PDP CONTEXT ACCEPT",
            Some(2) => "SN-DEACTIVATE PDP CONTEXT DEMAND",
            Some(3) => "SN-ACTIVATE PDP CONTEXT REJECT",
            Some(4) => "SN-UNITDATA",
            Some(5) => "SN-DATA",
            Some(6) => "SN-DATA TRANSMIT REQUEST",
            Some(7) => "SN-DATA TRANSMIT RESPONSE",
            Some(8) => "SN-END OF DATA",
            Some(9) => "SN-RECONNECT",
            Some(10) => "SN-PAGE REQUEST/RESPONSE",
            Some(11) => "SN-NOT SUPPORTED",
            Some(12) => "SN-DATA PRIORITY",
            Some(13) => "SN-MODIFY",
            _ => "reserved/unknown",
        };
        tracing::info!(
            "SNDCP: <- packet-data PDU from {:?} — SN-PDU type 0x{} ({}), {} bits",
            ind.received_tetra_address,
            sn_type.map(|n| format!("{n:x}")).unwrap_or_else(|| "?".into()),
            name,
            pdu.len(),
        );

        if sn_type == Some(SN_PDU_ACTIVATE_PDP_CONTEXT as u8) {
            self.send_pdp_accept(queue, ind, pdu);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bits(hex: &str) -> String {
        hex.chars().map(|c| format!("{:04b}", c.to_digit(16).unwrap())).collect()
    }

    #[test]
    fn finds_chap_response_identifier_in_real_demand_pco() {
        // Captured SN-ACTIVATE PDP CONTEXT DEMAND PCO content from a Motorola radio: a CHAP
        // Challenge (id 5, name "DIMETRA…") followed by a CHAP Response (id 5, username "admin").
        let pco = hex_to_bits(
            "0c22318010500180aac20e0caf974bc75e02f44494d455452415f50\
             c2231a0205001a10db3b2df8c57cce0db8712b16aa9cb5a361646d696",
        );
        assert_eq!(find_chap_response_id(&pco), Some(5));
    }

    #[test]
    fn prefers_response_over_challenge_and_skips_non_chap_bits() {
        let mut s = String::from("101"); // leading bits that are not part of any C223H marker
        s.push_str("1100001000100011"); // C223H
        s.push_str("00000110"); // length-of-contents (ignored by the scan)
        s.push_str("00000001"); // CHAP code = 1 (Challenge)
        s.push_str("00001001"); // identifier = 9
        s.push_str("1100001000100011"); // C223H
        s.push_str("00000110"); // length-of-contents
        s.push_str("00000010"); // CHAP code = 2 (Response)
        s.push_str("00000111"); // identifier = 7
        assert_eq!(find_chap_response_id(&s), Some(7));
    }

    #[test]
    fn shipped_config_leaves_the_wap_gateway_off() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../example_config/config.toml");
        let cfg = tetra_config::bluestation::from_file(path).expect("example config parses");
        let sndcp = Sndcp::new(SharedConfig::from_parts(cfg, None));
        assert!(sndcp.wap.is_none());
    }

    /// Captured PCO content of a Motorola DEMAND: CHAP Challenge id 5 ("DIMETRA…") and CHAP
    /// Response id 5 (username "admin").
    const REAL_PCO_HEX: &str = "0c22318010500180aac20e0caf974bc75e02f44494d455452415f50\
                                c2231a0205001a10db3b2df8c57cce0db8712b16aa9cb5a361646d696";

    /// SN-ACTIVATE PDP CONTEXT DEMAND (table 28.24), dynamic IPv4, NSAPI 1, with the real PCO as
    /// its only optional element.
    fn demand_with_real_pco() -> String {
        let pco = hex_to_bits(REAL_PCO_HEX);
        let mut s = String::from("0000000100010010000"); // type 0, version 1, NSAPI 1, ATID 1, MS type 0
        s.push_str("00000000"); // PCOMP negotiation
        s.push_str("10"); // o-bit = 1, Access point name index absent
        s.push_str("10001"); // M-bit = 1, type-3 element PCO
        s.push_str(&format!("{:011b}", pco.len()));
        s.push_str(&pco);
        s.push('0'); // M-bit = 0
        s
    }

    /// Static IPv4 10.20.30.40 on NSAPI 2 with no optional elements.
    fn static_demand_without_options() -> String {
        let mut s = String::from("000000010010000"); // type 0, version 1, NSAPI 2, ATID 0
        s.push_str(&format!("{:032b}", 0x0A14_1E28u32));
        s.push_str("0000000000000"); // MS type 0, PCOMP 0, o-bit 0
        s
    }

    /// What the SNDCP entity sends back for `demand` (MLE discriminator included).
    fn accept_for(demand: &str) -> BitBuffer {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../example_config/config.toml");
        let cfg = tetra_config::bluestation::from_file(path).expect("example config parses");
        let mut sndcp = Sndcp::new(SharedConfig::from_parts(cfg, None));
        let mut queue = MessageQueue::new();
        let ind = LtpdMleUnitdataInd {
            sdu: BitBuffer::from_bitstr(&format!("100{demand}")),
            endpoint_id: 0,
            link_id: 1,
            received_tetra_address: tetra_core::TetraAddress::new(2_260_618, tetra_core::SsiType::Issi),
            chan_change_resp_req: false,
            chan_change_handle: None,
            bearer: tetra_saps::ltpd::LtpdBearer::BasicAck,
        };
        sndcp.rx_prim(
            &mut queue,
            SapMsg {
                sap: Sap::TlpdSap,
                src: TetraEntity::Mle,
                dest: TetraEntity::Sndcp,
                msg: SapMsgInner::LtpdMleUnitdataInd(ind),
            },
        );
        let msg = queue.pop_front().expect("an ACCEPT");
        assert!(queue.pop_front().is_none());
        let SapMsgInner::TlaTlDataReqBl(req) = msg.msg else {
            panic!("ACCEPT goes out as TL-DATA: {:?}", msg.msg);
        };
        assert_eq!((req.link_id, req.chan_alloc.is_none(), req.tx_reporter.is_none()), (1, true, true));
        req.tl_sdu
    }

    /// Golden vectors captured from the stub before the packet-data runtime existed: with
    /// `[packet_data]` off the ACCEPT must stay bit for bit the same (Motorola/DIMETRA CHAP).
    #[test]
    fn stub_accept_is_bit_exact() {
        let with_chap = accept_for(&demand_with_real_pco());
        assert_eq!(
            (with_chap.dump_hex(), with_chap.get_len()),
            ("8032161605400DA0048883C0C22304030500040".to_string(), 153)
        );
        let plain = accept_for(&static_demand_without_options());
        assert_eq!((plain.dump_hex(), plain.get_len()), ("8052160850A0F140040".to_string(), 73));
    }

    #[test]
    fn demand_parses_like_the_stub() {
        let d = parse_demand(&demand_with_real_pco());
        assert_eq!((d.nsapi, d.atid, d.static_ipv4, d.chap_id), (1, 1, None, Some(5)));
        let s = parse_demand(&static_demand_without_options());
        assert_eq!((s.nsapi, s.atid, s.static_ipv4, s.chap_id), (2, 0, Some(0x0A14_1E28), None));
        // A truncated DEMAND falls back to NSAPI 1, static, no address, as the stub did.
        let t = parse_demand("0000");
        assert_eq!((t.nsapi, t.atid, t.static_ipv4), (1, 0, None));
    }

    #[test]
    fn reject_layout() {
        let r = encode_pdp_reject(3, 7);
        // Discriminator, type 3, NSAPI 3, cause 7 (dynamic address pool empty), o-bit 0.
        assert_eq!(r.to_bitstr(), "10000110011000001110");
    }

    #[test]
    fn deactivate_demand_and_accept_round_trip() {
        assert_eq!(decode_deactivate_demand("0010000000000"), Some(Deactivation::All));
        assert_eq!(decode_deactivate_demand("00100000000101010"), Some(Deactivation::Nsapi(5)));
        // An SNDCP network endpoint identifier after the o-bit is ignored.
        assert_eq!(
            decode_deactivate_demand(&format!("00100000000101011{:016b}0", 0xBEEF)),
            Some(Deactivation::Nsapi(5))
        );
        assert_eq!(decode_deactivate_demand("001000000001"), None, "NSAPI missing");
        assert_eq!(decode_deactivate_demand("0000000000000"), None, "not a DEMAND");
        assert_eq!(encode_deactivate_accept(Deactivation::All).to_bitstr(), "1000001000000000");
        assert_eq!(encode_deactivate_accept(Deactivation::Nsapi(5)).to_bitstr(), "10000010000000101010");
    }

    #[test]
    fn no_chap_in_demand_returns_none() {
        assert_eq!(find_chap_response_id(&"0".repeat(256)), None);
    }

    #[test]
    fn optional_section_layout_matches_spec() {
        let sec = chap_success_optional_section(5);
        // o-bit(1) + type-2 P-bits(3) + M-bit(1) + id(4) + length(11) + PCO(60) + M-bit(1) = 81.
        assert_eq!(sec.len(), 81);
        assert_eq!(&sec[0..4], "1000"); // o-bit=1, three absent type-2 presence bits
        assert_eq!(&sec[4..5], "1"); // M-bit = 1
        assert_eq!(&sec[5..9], "0001"); // type-3/4 element identifier = 1 (PCO)
        assert_eq!(&sec[9..20], &format!("{PCO_CHAP_SUCCESS_BITS:011b}")); // length indicator
        assert_eq!(&sec[20..24], "0000"); // configuration protocol = PPP
        assert_eq!(&sec[24..40], "1100001000100011"); // protocol identity = CHAP
        assert_eq!(&sec[40..48], "00000100"); // length of contents = 4 octets
        assert_eq!(&sec[48..56], "00000011"); // CHAP code = 3 (Success)
        assert_eq!(&sec[56..64], "00000101"); // identifier echoed = 5
        assert_eq!(&sec[64..80], "0000000000000100"); // CHAP length = 4
        assert_eq!(&sec[80..81], "0"); // closing M-bit = 0
    }
}
