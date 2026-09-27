//! SNDCP packet-data runtime for `[packet_data]` (EN 300 392-2 clause 28): PDP contexts with an
//! IPv4 address from the pool (the ACCEPT keeps the stub's CHAP Success for DIMETRA radios),
//! READY and STANDBY, SN-DATA TRANSMIT REQUEST / RESPONSE, SN-RECONNECT, SN-END OF DATA, and the
//! radios' datagrams to and from the WAP gateway on the common control channel (no channel is
//! assigned): SN-UNITDATA on the unacknowledged basic link, SN-DATA on the acknowledged advanced
//! link. Each answer goes back on the bearer the radio's last datagram came on.
//!
//! Voice first: nothing goes down to a radio while it is in a call (its gateway timers wait), and
//! at most one data PDU of the whole runtime waits in the MAC for the MCCH, so a call set-up waits
//! behind one data PDU at most.
//!
//! The SNDCP timers run on the TDMA clock (one tick per timeslot); the gateway keeps wall-clock
//! time for WTP.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::time::Instant;

use tetra_config::bluestation::{SharedConfig, StackState, ready_timer_ms};
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{BitBuffer, Sap, TetraAddress, TxReporter, TxState};
use tetra_saps::ltpd::{LtpdBearer, LtpdMleUnitdataInd};
use tetra_saps::tla::{TlDataReqAl, TlaTlUnitdataReqBl};
use tetra_saps::{SapMsg, SapMsgInner};

use super::ip::{bitbuffer_npdu_octets, parse_ipv4_packet};
use super::sndcp_bs::{
    Deactivation, MLE_DISCRIMINATOR_SNDCP, TIA_IPV4_DYNAMIC, TIA_IPV4_STATIC, decode_deactivate_demand, encode_deactivate_accept,
    encode_pdp_accept, encode_pdp_reject, parse_demand, tl_data_req,
};
use super::transfer::{
    SndcpDataTransmitResponse, SndcpDataTransmitResponseResult, SndcpEndOfData, SndcpNotSupported, SndcpPacketDataResourceRequest,
    SndcpTransferRejectCause, decode_data_transmit_request, decode_reconnect, encode_data_transmit_response, encode_end_of_data,
    encode_not_supported,
};
use super::unitdata::{SNDCP_NO_COMPRESSION, decode_sn_data_pdu, decode_sn_unitdata_pdu, encode_sn_data, encode_sn_unitdata};
use super::wapgw::{UdpOut, WapService, WapVia};
use crate::MessageQueue;

/// Timeslots in `ms` milliseconds (a timeslot lasts 85/6 ms).
const fn slots(ms: u64) -> u64 {
    (ms * 6).div_ceil(85)
}

/// Housekeeping (timers, registrations, calls) about once a second.
const HOUSEKEEPING_SLOTS: u64 = 72;
/// The station's READY timer runs this much shorter than the one announced (clause 28.2.6.2
/// NOTE 1: the SwMI ends READY first).
const READY_MARGIN_MS: u64 = 2_000;
/// STANDBY timer announced in the ACCEPT (code 5 = 10 min, table 28.122).
const STANDBY_MS: u64 = 600_000;
/// Downlink datagrams waiting for one context; the oldest goes when full.
const MAX_DL_QUEUE: usize = 16;
/// A data PDU the MAC never reports on stops holding the MCCH after this long.
const INFLIGHT_GUARD_SLOTS: u64 = slots(10_000);
/// Largest datagram sent back in one SN-UNITDATA on the basic link: N.251 (2595 bits without
/// FCS) less the MLE discriminator and the SN-UNITDATA header, with a margin.
const BL_MAX_DATAGRAM: usize = 320;
/// What N.271 holds besides the datagram: the AL FCS (4 octets), the SN-DATA header (2) and the
/// MLE discriminator (3 bits, one octet).
const AL_OVERHEAD: usize = 7;
/// Bound on PDP contexts (dynamic pool plus static addresses).
const MAX_CONTEXTS: usize = 2048;
/// Radios remembered for the one-warning-per-radio rule on malformed PDUs.
const MAX_WARNED: usize = 1024;

// SN-PDU types (clause 28.4.5, "SN PDU type").
const SN_ACTIVATE_PDP_CONTEXT: u8 = 0;
const SN_DEACTIVATE_PDP_CONTEXT_ACCEPT: u8 = 1;
const SN_DEACTIVATE_PDP_CONTEXT_DEMAND: u8 = 2;
const SN_ACTIVATE_PDP_CONTEXT_REJECT: u8 = 3;
const SN_UNITDATA: u8 = 4;
const SN_DATA: u8 = 5;
const SN_DATA_TRANSMIT_REQUEST: u8 = 6;
const SN_DATA_TRANSMIT_RESPONSE: u8 = 7;
const SN_END_OF_DATA: u8 = 8;
const SN_RECONNECT: u8 = 9;
const SN_PAGE: u8 = 10;
const SN_NOT_SUPPORTED: u8 = 11;
const SN_DATA_PRIORITY: u8 = 12;
const SN_MODIFY: u8 = 13;

// Activation reject causes (table 28.46).
const REJECT_UNDEFINED: u8 = 0;
const REJECT_POOL_EMPTY: u8 = 7;
const REJECT_STATIC_NOT_CORRECT: u8 = 8;
const REJECT_STATIC_IN_USE: u8 = 9;
const REJECT_STATIC_NOT_ALLOWED: u8 = 10;
const REJECT_MAX_CONTEXTS: u8 = 19;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CtxState {
    Standby,
    Ready,
}

#[derive(Debug, Default, Clone, Copy)]
struct Counters {
    up: u32,
    up_bytes: usize,
    down: u32,
    down_bytes: usize,
}

struct Ctx {
    addr: TetraAddress,
    ip: Ipv4Addr,
    state: CtxState,
    /// Timeslot at which the running READY or STANDBY timer expires.
    deadline: u64,
    /// IPv4 N-PDUs waiting to go down.
    dl: VecDeque<Vec<u8>>,
    /// The radio was seen registered: losing the registration then releases the context.
    seen_registered: bool,
    in_call: bool,
    /// Traffic since the context last entered READY.
    counters: Counters,
    /// Bearer of the last datagram from the radio, which its answers take.
    reply_bearer: LtpdBearer,
}

struct Inflight {
    key: (u32, u8),
    reporter: TxReporter,
    since: u64,
}

pub struct PacketDataRuntime {
    pool_first: u32,
    pool_last: u32,
    gateway: Ipv4Addr,
    mtu: u16,
    mtu_code: u8,
    ready_code: u8,
    ready_slots: u64,
    standby_slots: u64,
    ctxs: HashMap<(u32, u8), Ctx>,
    by_ip: HashMap<Ipv4Addr, (u32, u8)>,
    /// Timeslots since start.
    clock: u64,
    next_housekeeping: u64,
    /// The data PDU waiting in the MAC for the MCCH.
    inflight: Option<Inflight>,
    last_served: Option<(u32, u8)>,
    /// ISSIs whose gateway retransmission timers are paused.
    paused: HashSet<u32>,
    warned: HashSet<u32>,
    ip_identification: u16,
}

/// MTU code of the ACCEPT (table 28.79); `[wap] mtu` only takes these values.
fn mtu_code(mtu: u16) -> u8 {
    match mtu {
        296 => 1,
        1006 => 3,
        1500 => 4,
        2002 => 5,
        _ => 2,
    }
}

/// The SN-PDU prefixed with the MLE discriminator for SNDCP, as the MS's MLE expects it.
fn mle_sdu(pdu: &BitBuffer) -> BitBuffer {
    let mut pdu = BitBuffer::from_bitbuffer(pdu);
    pdu.seek(0);
    let len = pdu.get_len();
    let mut sdu = BitBuffer::new(3 + len);
    sdu.write_bits(MLE_DISCRIMINATOR_SNDCP, 3);
    sdu.copy_bits(&mut pdu, len);
    sdu.seek(0);
    sdu
}

fn field(bits: &str, off: usize, n: usize) -> Option<u8> {
    bits.get(off..off + n).and_then(|s| u8::from_str_radix(s, 2).ok())
}

fn valid_nsapi(nsapi: u8) -> bool {
    (1..=14).contains(&nsapi)
}

/// Whether `issi` is on a traffic channel: in an individual call, or affiliated to a group with a
/// call up (the same live map the SDS path uses).
fn in_call(state: &StackState, issi: u32) -> bool {
    state.active_call_ts.contains_key(&issi)
        || state
            .subscribers
            .attached_groups_of(issi)
            .iter()
            .any(|g| state.active_call_ts.contains_key(g))
}

fn resources(request: &SndcpPacketDataResourceRequest) -> String {
    match request {
        SndcpPacketDataResourceRequest::None => "no resource request".to_string(),
        SndcpPacketDataResourceRequest::PhaseModulation(r) => format!(
            "asks {} UL / {} DL slot(s){}",
            r.uplink_timeslots,
            r.downlink_timeslots,
            if r.unspecified_phase_modulation_resource {
                ", unspecified"
            } else {
                ""
            }
        ),
    }
}

impl PacketDataRuntime {
    /// None unless `[packet_data] enabled`.
    pub fn new(config: &SharedConfig) -> Option<Self> {
        let cfg = config.config();
        let pd = &cfg.packet_data;
        if !pd.enabled {
            return None;
        }
        let announced_ms = ready_timer_ms(pd.ready_timer_code).unwrap_or(30_000);
        let ready_ms = announced_ms.saturating_sub(READY_MARGIN_MS).max(announced_ms / 2);
        if !cfg.cell.sndcp_service {
            tracing::warn!("SNDCP: [packet_data] is on but cell_info sndcp_service = false: radios will not start packet data");
        }
        if !cfg.cell.advanced_link {
            tracing::warn!("SNDCP: [packet_data] is on but cell_info advanced_link = false: some radios need it for packet data");
        }
        if !cfg.wap.enabled {
            tracing::warn!("SNDCP: [packet_data] is on but [wap] is off: the radios' datagrams have nowhere to go");
        }
        let fetch_ms = cfg.wap.wtp.hold_on_ms + cfg.wap.browse.timeout_secs * 1000;
        if cfg.wap.enabled && ready_ms <= fetch_ms {
            tracing::warn!(
                "SNDCP: READY ({} ms) is not longer than a download may take ({} ms): a page may come back after READY ended",
                ready_ms,
                fetch_ms
            );
        }
        tracing::info!(
            "SNDCP: packet data on the MCCH (pool {}..{}, gateway {}, MTU {}, READY {} ms announced / {} ms here)",
            pd.pool_first,
            pd.pool_last,
            cfg.wap.gateway_ipv4,
            cfg.wap.mtu,
            announced_ms,
            ready_ms
        );
        Some(Self {
            pool_first: u32::from(pd.pool_first),
            pool_last: u32::from(pd.pool_last),
            gateway: cfg.wap.gateway_ipv4,
            mtu: cfg.wap.mtu,
            mtu_code: mtu_code(cfg.wap.mtu),
            ready_code: pd.ready_timer_code,
            ready_slots: slots(ready_ms),
            standby_slots: slots(STANDBY_MS),
            ctxs: HashMap::new(),
            by_ip: HashMap::new(),
            clock: 0,
            next_housekeeping: HOUSEKEEPING_SLOTS,
            inflight: None,
            last_served: None,
            paused: HashSet::new(),
            warned: HashSet::new(),
            ip_identification: 0,
        })
    }

    /// Largest datagram the gateway may send back on `bearer`: the MTU, and N.251 on the basic
    /// link or the negotiated N.271 on the advanced link.
    fn max_reply_bytes(&self, bearer: LtpdBearer) -> usize {
        let bearer_max = match bearer {
            LtpdBearer::Advanced { max_sdu_bytes, .. } => usize::from(max_sdu_bytes).saturating_sub(AL_OVERHEAD),
            LtpdBearer::BasicAck | LtpdBearer::BasicUnack => BL_MAX_DATAGRAM,
        };
        usize::from(self.mtu).min(bearer_max)
    }

    /// One uplink SN-PDU (the SDU still carries the 3-bit MLE discriminator).
    pub fn rx(
        &mut self,
        queue: &mut MessageQueue,
        ind: &LtpdMleUnitdataInd,
        wap: Option<&mut WapService>,
        config: &SharedConfig,
        now: Instant,
    ) {
        let issi = ind.received_tetra_address.ssi;
        let raw = ind.sdu.dump_bin_unformatted();
        let bits = raw.get(3..).unwrap_or("");
        let sn_type = field(bits, 0, 4);
        tracing::debug!(
            "SNDCP: <- ISSI {} SN-PDU type {:?}, {} bits, {:?}",
            issi,
            sn_type,
            bits.len(),
            ind.bearer
        );
        match sn_type {
            Some(SN_ACTIVATE_PDP_CONTEXT) => self.on_demand(queue, ind, bits, wap),
            Some(SN_DEACTIVATE_PDP_CONTEXT_DEMAND) => self.on_deactivate(queue, ind, bits, wap),
            Some(SN_UNITDATA) => self.on_user_data(ind, bits, wap, config, now),
            Some(SN_DATA) if matches!(ind.bearer, LtpdBearer::Advanced { .. }) => self.on_user_data(ind, bits, wap, config, now),
            Some(SN_DATA) => tracing::debug!(
                "SNDCP: SN-DATA from ISSI {} on the basic link (table 28.16 allows it only on the advanced link), dropped",
                issi
            ),
            Some(SN_DATA_TRANSMIT_REQUEST) => self.on_transmit_request(queue, ind, bits, wap, now),
            Some(SN_END_OF_DATA) => self.on_end_of_data(queue, ind, wap, now),
            Some(SN_RECONNECT) => self.on_reconnect(queue, ind, bits, wap, now),
            Some(t @ (SN_PAGE | SN_DATA_PRIORITY | SN_MODIFY)) => {
                tracing::info!("SNDCP: SN-PDU type {} from ISSI {} not supported, SN-NOT SUPPORTED sent", t, issi);
                if let Ok(pdu) = encode_not_supported(&SndcpNotSupported { not_supported_pdu_type: t }) {
                    queue.push_back(tl_data_req(ind.received_tetra_address, ind.link_id, ind.endpoint_id, mle_sdu(&pdu)));
                }
            }
            Some(SN_NOT_SUPPORTED) => {
                tracing::info!("SNDCP: ISSI {} does not support SN-PDU type {:?}", issi, field(bits, 4, 4));
            }
            Some(SN_DEACTIVATE_PDP_CONTEXT_ACCEPT | SN_ACTIVATE_PDP_CONTEXT_REJECT | SN_DATA_TRANSMIT_RESPONSE) => {
                tracing::debug!(
                    "SNDCP: ISSI {} sent SN-PDU type {:?}, which only the station sends; dropped",
                    issi,
                    sn_type
                );
            }
            _ => self.warn_malformed(issi, "unknown SN-PDU type"),
        }
    }

    fn warn_malformed(&mut self, issi: u32, what: &str) {
        if self.warned.len() >= MAX_WARNED {
            self.warned.clear();
        }
        if self.warned.insert(issi) {
            tracing::warn!(
                "SNDCP: malformed SN-PDU from ISSI {} ({}), dropped (further ones logged at debug)",
                issi,
                what
            );
        } else {
            tracing::debug!("SNDCP: malformed SN-PDU from ISSI {} ({}), dropped", issi, what);
        }
    }

    fn has_ctx(&self, issi: u32) -> bool {
        self.ctxs.keys().any(|k| k.0 == issi)
    }

    /// Lowest free pool address.
    fn allocate(&self) -> Option<Ipv4Addr> {
        (self.pool_first..=self.pool_last)
            .map(Ipv4Addr::from)
            .find(|ip| *ip != self.gateway && !self.by_ip.contains_key(ip))
    }

    fn remove_ctx(&mut self, key: (u32, u8)) -> Option<Ctx> {
        let ctx = self.ctxs.remove(&key)?;
        if self.by_ip.get(&ctx.ip) == Some(&key) {
            self.by_ip.remove(&ctx.ip);
        }
        Some(ctx)
    }

    /// The radio has no context left: the gateway forgets it.
    fn release_issi(&mut self, issi: u32, wap: Option<&mut WapService>) {
        if self.has_ctx(issi) {
            return;
        }
        self.paused.remove(&issi);
        if let Some(wap) = wap {
            wap.peer_lost(issi);
        }
    }

    /// Pause the gateway's retransmission timers of `issi` while nothing can go down to it
    /// (STANDBY, or in a call), and resume them when something can.
    fn sync_pause(&mut self, issi: u32, wap: Option<&mut WapService>, now: Instant) {
        let Some(wap) = wap else { return };
        if !self.has_ctx(issi) {
            return;
        }
        let reachable = self
            .ctxs
            .iter()
            .any(|(k, c)| k.0 == issi && c.state == CtxState::Ready && !c.in_call);
        if reachable {
            if self.paused.remove(&issi) {
                wap.resume_timers(issi, now);
            }
        } else if self.paused.insert(issi) {
            wap.pause_timers(issi);
        }
    }

    fn on_demand(&mut self, queue: &mut MessageQueue, ind: &LtpdMleUnitdataInd, bits: &str, mut wap: Option<&mut WapService>) {
        let addr = ind.received_tetra_address;
        let issi = addr.ssi;
        // Type, version, NSAPI and ATID at least.
        if bits.len() < 15 {
            self.warn_malformed(issi, "short SN-ACTIVATE PDP CONTEXT DEMAND");
            return;
        }
        let demand = parse_demand(bits);
        let nsapi = demand.nsapi;
        let reply = |pdu: BitBuffer| tl_data_req(addr, ind.link_id, ind.endpoint_id, pdu);
        let key = (issi, nsapi);
        let replaced = self.remove_ctx(key).is_some();
        if replaced {
            tracing::info!("SNDCP: ISSI {} NSAPI {} activates again, the old context is released", issi, nsapi);
            if let Some(wap) = wap.as_deref_mut() {
                wap.peer_lost(issi);
            }
            self.paused.remove(&issi);
        }
        let grant = if !valid_nsapi(nsapi) {
            Err((REJECT_UNDEFINED, "reserved NSAPI"))
        } else if self.ctxs.len() >= MAX_CONTEXTS {
            Err((REJECT_MAX_CONTEXTS, "too many PDP contexts"))
        } else if demand.atid == 0 {
            match demand.static_ipv4.map(Ipv4Addr::from) {
                None => Err((REJECT_STATIC_NOT_CORRECT, "static address missing")),
                Some(ip) if ip == self.gateway => Err((REJECT_STATIC_NOT_ALLOWED, "static address is the gateway's")),
                Some(ip) if self.by_ip.get(&ip).is_some_and(|k| *k != key) => Err((REJECT_STATIC_IN_USE, "static address in use")),
                Some(ip) => Ok((TIA_IPV4_STATIC, ip)),
            }
        } else {
            self.allocate()
                .map(|ip| (TIA_IPV4_DYNAMIC, ip))
                .ok_or((REJECT_POOL_EMPTY, "pool empty"))
        };
        let (tia, ip) = match grant {
            Ok(grant) => grant,
            Err((cause, why)) => {
                tracing::info!("SNDCP: PDP reject ISSI {} NSAPI {} (cause {}, {})", issi, nsapi, cause, why);
                queue.push_back(reply(encode_pdp_reject(nsapi, cause)));
                return;
            }
        };
        let static_note = if tia == TIA_IPV4_STATIC {
            if (self.pool_first..=self.pool_last).contains(&u32::from(ip)) {
                "static"
            } else {
                "static, outside the pool"
            }
        } else {
            "dynamic"
        };
        tracing::info!(
            "SNDCP: PDP activate ISSI {} NSAPI {} -> IP {} ({}, {}), MTU {}",
            issi,
            nsapi,
            ip,
            static_note,
            demand
                .chap_id
                .map(|id| format!("CHAP id {id}"))
                .unwrap_or_else(|| "no CHAP".to_string()),
            self.mtu
        );
        queue.push_back(reply(encode_pdp_accept(
            nsapi,
            tia,
            u32::from(ip),
            self.mtu_code,
            self.ready_code,
            demand.chap_id,
        )));
        self.by_ip.insert(ip, key);
        self.ctxs.insert(
            key,
            Ctx {
                addr,
                ip,
                state: CtxState::Standby,
                deadline: self.clock + self.standby_slots,
                dl: VecDeque::new(),
                seen_registered: false,
                in_call: false,
                counters: Counters::default(),
                reply_bearer: LtpdBearer::BasicUnack,
            },
        );
    }

    fn on_deactivate(&mut self, queue: &mut MessageQueue, ind: &LtpdMleUnitdataInd, bits: &str, wap: Option<&mut WapService>) {
        let issi = ind.received_tetra_address.ssi;
        let Some(deactivation) = decode_deactivate_demand(bits) else {
            self.warn_malformed(issi, "short SN-DEACTIVATE PDP CONTEXT DEMAND");
            return;
        };
        let keys: Vec<(u32, u8)> = match deactivation {
            Deactivation::All => self.ctxs.keys().filter(|k| k.0 == issi).copied().collect(),
            Deactivation::Nsapi(nsapi) => vec![(issi, nsapi)],
        };
        let released = keys.into_iter().filter(|k| self.remove_ctx(*k).is_some()).count();
        tracing::info!(
            "SNDCP: PDP deactivate ISSI {} ({:?}): {} context(s) released",
            issi,
            deactivation,
            released
        );
        queue.push_back(tl_data_req(
            ind.received_tetra_address,
            ind.link_id,
            ind.endpoint_id,
            encode_deactivate_accept(deactivation),
        ));
        if released > 0 {
            self.release_issi(issi, wap);
        }
    }

    /// SN-DATA TRANSMIT RESPONSE for `nsapi`: accepted with no channel assignment (the data stays
    /// on the MCCH) when the context exists, which enters READY.
    #[allow(clippy::too_many_arguments)]
    fn respond_transmit(
        &mut self,
        queue: &mut MessageQueue,
        ind: &LtpdMleUnitdataInd,
        nsapi: u8,
        what: &str,
        detail: &str,
        wap: Option<&mut WapService>,
        now: Instant,
    ) {
        let issi = ind.received_tetra_address.ssi;
        let (ready_slots, clock) = (self.ready_slots, self.clock);
        let result = match self.ctxs.get_mut(&(issi, nsapi)) {
            Some(ctx) => {
                if ctx.state != CtxState::Ready {
                    ctx.counters = Counters::default();
                }
                ctx.state = CtxState::Ready;
                ctx.deadline = clock + ready_slots;
                tracing::info!(
                    "SNDCP: {} ISSI {} NSAPI {} ({}) -> RESPONSE accepted, no channel (MCCH), READY",
                    what,
                    issi,
                    nsapi,
                    detail
                );
                SndcpDataTransmitResponseResult::Accepted
            }
            None => {
                tracing::info!(
                    "SNDCP: {} ISSI {} NSAPI {} ({}) -> RESPONSE rejected (no PDP context)",
                    what,
                    issi,
                    nsapi,
                    detail
                );
                SndcpDataTransmitResponseResult::Rejected(SndcpTransferRejectCause::UnknownNsapi)
            }
        };
        if let Ok(pdu) = encode_data_transmit_response(&SndcpDataTransmitResponse { nsapi, result }) {
            queue.push_back(tl_data_req(ind.received_tetra_address, ind.link_id, ind.endpoint_id, mle_sdu(&pdu)));
        }
        self.sync_pause(issi, wap, now);
    }

    fn on_transmit_request(
        &mut self,
        queue: &mut MessageQueue,
        ind: &LtpdMleUnitdataInd,
        bits: &str,
        wap: Option<&mut WapService>,
        now: Instant,
    ) {
        let issi = ind.received_tetra_address.ssi;
        let (nsapi, detail) = match decode_data_transmit_request(&BitBuffer::from_bitstr(bits)) {
            Ok(r) => (
                r.nsapi,
                format!(
                    "link status {}, {}",
                    u8::from(r.logical_link_status),
                    resources(&r.resource_request)
                ),
            ),
            // The runtime needs only the NSAPI: an odd resource request still gets its answer.
            Err(e) => match field(bits, 4, 4).filter(|n| valid_nsapi(*n)) {
                Some(nsapi) => (nsapi, format!("rest not decoded: {e:?}")),
                None => {
                    self.warn_malformed(issi, "SN-DATA TRANSMIT REQUEST");
                    return;
                }
            },
        };
        self.respond_transmit(queue, ind, nsapi, "SN-DATA TRANSMIT REQUEST", &detail, wap, now);
    }

    fn on_reconnect(&mut self, queue: &mut MessageQueue, ind: &LtpdMleUnitdataInd, bits: &str, wap: Option<&mut WapService>, now: Instant) {
        let issi = ind.received_tetra_address.ssi;
        let (nsapi, detail) = match decode_reconnect(&BitBuffer::from_bitstr(bits)) {
            Ok(r) => (r.nsapi, resources(&r.resource_request)),
            Err(e) => match field(bits, 4, 1) {
                Some(1) => (field(bits, 5, 4).filter(|n| valid_nsapi(*n)), format!("rest not decoded: {e:?}")),
                Some(0) => (None, format!("rest not decoded: {e:?}")),
                _ => {
                    self.warn_malformed(issi, "SN-RECONNECT");
                    return;
                }
            },
        };
        // Without data to send the radio names no NSAPI: answer for its first context.
        let nsapi = nsapi.or_else(|| self.ctxs.keys().filter(|k| k.0 == issi).map(|k| k.1).min());
        match nsapi {
            Some(nsapi) => self.respond_transmit(queue, ind, nsapi, "SN-RECONNECT", &detail, wap, now),
            None => tracing::info!("SNDCP: SN-RECONNECT from ISSI {} without a PDP context, ignored", issi),
        }
    }

    fn on_end_of_data(&mut self, queue: &mut MessageQueue, ind: &LtpdMleUnitdataInd, wap: Option<&mut WapService>, now: Instant) {
        let issi = ind.received_tetra_address.ssi;
        let (standby_slots, clock) = (self.standby_slots, self.clock);
        for (key, ctx) in self.ctxs.iter_mut().filter(|(k, _)| k.0 == issi) {
            if ctx.state == CtxState::Ready {
                ctx.state = CtxState::Standby;
                ctx.deadline = clock + standby_slots;
                let c = ctx.counters;
                tracing::info!(
                    "SNDCP: SN-END OF DATA from ISSI {} NSAPI {} -> STANDBY (N-PDU up {} / down {}, {} / {} bytes)",
                    issi,
                    key.1,
                    c.up,
                    c.down,
                    c.up_bytes,
                    c.down_bytes
                );
            }
        }
        if let Ok(pdu) = encode_end_of_data(&SndcpEndOfData {
            immediate_service_change: false,
        }) {
            queue.push_back(tl_data_req(ind.received_tetra_address, ind.link_id, ind.endpoint_id, mle_sdu(&pdu)));
        }
        self.sync_pause(issi, wap, now);
    }

    /// A datagram from a radio: SN-UNITDATA (basic link) or SN-DATA (advanced link).
    fn on_user_data(
        &mut self,
        ind: &LtpdMleUnitdataInd,
        bits: &str,
        mut wap: Option<&mut WapService>,
        config: &SharedConfig,
        now: Instant,
    ) {
        let issi = ind.received_tetra_address.ssi;
        let (name, decoded) = if field(bits, 0, 4) == Some(SN_DATA) {
            ("SN-DATA", decode_sn_data_pdu(&BitBuffer::from_bitstr(bits)))
        } else {
            ("SN-UNITDATA", decode_sn_unitdata_pdu(&BitBuffer::from_bitstr(bits)))
        };
        let unitdata = match decoded {
            Ok(u) => u,
            Err(e) => {
                tracing::debug!("SNDCP: {} from ISSI {} not usable ({:?}), dropped", name, issi, e);
                return;
            }
        };
        let key = (issi, unitdata.nsapi);
        let (ready_slots, clock) = (self.ready_slots, self.clock);
        // An SN-UNITDATA sent on the acknowledged basic link is answered as on the unacknowledged one.
        let bearer = match ind.bearer {
            LtpdBearer::BasicAck => LtpdBearer::BasicUnack,
            other => other,
        };
        let max_reply = self.max_reply_bytes(bearer);
        let Some(ctx) = self.ctxs.get_mut(&key) else {
            tracing::debug!(
                "SNDCP: {} from ISSI {} NSAPI {} without a PDP context, dropped",
                name,
                issi,
                unitdata.nsapi
            );
            return;
        };
        let Ok(npdu) = bitbuffer_npdu_octets(&unitdata.n_pdu) else {
            tracing::debug!("SNDCP: {} from ISSI {} is not whole octets, dropped", name, issi);
            return;
        };
        if ctx.state != CtxState::Ready {
            ctx.counters = Counters::default();
        }
        ctx.state = CtxState::Ready;
        ctx.deadline = clock + ready_slots;
        ctx.counters.up += 1;
        ctx.counters.up_bytes += npdu.len();
        ctx.reply_bearer = bearer;
        // Anti-spoofing: a radio only sends from the address its context holds.
        let ctx_ip = ctx.ip;
        match parse_ipv4_packet(&npdu) {
            Ok(ip) if Ipv4Addr::from(ip.source) == ctx_ip => {}
            Ok(ip) => {
                tracing::debug!(
                    "SNDCP: ISSI {} sent from {} but holds {}, dropped",
                    issi,
                    Ipv4Addr::from(ip.source),
                    ctx_ip
                );
                return;
            }
            Err(e) => {
                tracing::debug!("SNDCP: ISSI {} sent an N-PDU that is not IPv4 ({:?}), dropped", issi, e);
                return;
            }
        }
        self.sync_pause(issi, wap.as_deref_mut(), now);
        let Some(wap) = wap else {
            tracing::debug!("SNDCP: datagram from ISSI {} dropped, [wap] is off", issi);
            return;
        };
        if let Err(e) = wap.on_air_ipv4(config, issi, &npdu, Some(max_reply), now) {
            tracing::debug!("SNDCP: datagram from ISSI {} not for the gateway ({:?}), dropped", issi, e);
        }
    }

    /// One stack tick: run the gateway, route its answers to the contexts, run the timers once a
    /// second and hand one datagram to the LLC when the MCCH is free of data.
    pub fn tick(&mut self, queue: &mut MessageQueue, config: &SharedConfig, mut wap: Option<&mut WapService>, now: Instant) {
        self.clock += 1;
        if let Some(wap) = wap.as_deref_mut() {
            for out in wap.tick(config, now) {
                self.queue_downlink(out);
            }
        }
        if self.clock >= self.next_housekeeping {
            self.next_housekeeping = self.clock + HOUSEKEEPING_SLOTS;
            self.housekeeping(queue, config, wap.as_deref_mut(), now);
        }
        self.deliver(queue, config, wap, now);
    }

    fn next_ip_identification(&mut self) -> u16 {
        self.ip_identification = self.ip_identification.wrapping_add(1);
        self.ip_identification
    }

    fn queue_downlink(&mut self, out: UdpOut) {
        if out.peer.via != WapVia::Air {
            return;
        }
        let key = match self.by_ip.get(&out.peer.ip) {
            Some(key) if key.0 == out.peer.issi => *key,
            _ => {
                tracing::debug!(
                    "SNDCP: no PDP context of ISSI {} holds {}, reply dropped",
                    out.peer.issi,
                    out.peer.ip
                );
                return;
            }
        };
        let identification = self.next_ip_identification();
        let npdu = match out.to_ipv4(self.gateway, identification) {
            Ok(npdu) => npdu,
            Err(e) => {
                tracing::debug!("SNDCP: reply to ISSI {} not built ({:?})", out.peer.issi, e);
                return;
            }
        };
        let Some(ctx) = self.ctxs.get_mut(&key) else { return };
        ctx.dl.push_back(npdu);
        if ctx.dl.len() > MAX_DL_QUEUE {
            ctx.dl.pop_front();
            tracing::debug!("SNDCP: downlink queue of ISSI {} full, oldest datagram dropped", key.0);
        }
    }

    fn housekeeping(&mut self, queue: &mut MessageQueue, config: &SharedConfig, mut wap: Option<&mut WapService>, now: Instant) {
        if self.ctxs.is_empty() {
            return;
        }
        let mut issis: Vec<u32> = self.ctxs.keys().map(|k| k.0).collect();
        issis.sort_unstable();
        issis.dedup();
        let status: HashMap<u32, (bool, bool)> = {
            let state = config.state_read();
            issis
                .iter()
                .map(|&issi| (issi, (state.subscribers.is_registered(issi), in_call(&state, issi))))
                .collect()
        };
        let (clock, standby_slots) = (self.clock, self.standby_slots);
        let mut released = Vec::new();
        let mut ended = Vec::new();
        for (key, ctx) in self.ctxs.iter_mut() {
            let (registered, call) = status.get(&key.0).copied().unwrap_or((false, false));
            if registered {
                ctx.seen_registered = true;
            } else if ctx.seen_registered {
                released.push((*key, "radio deregistered"));
                continue;
            }
            ctx.in_call = call;
            if clock < ctx.deadline {
                continue;
            }
            match ctx.state {
                CtxState::Ready => {
                    ctx.state = CtxState::Standby;
                    ctx.deadline = clock + standby_slots;
                    ended.push((*key, ctx.addr, ctx.counters));
                }
                CtxState::Standby => released.push((*key, "STANDBY expired")),
            }
        }
        ended.sort_unstable_by_key(|e| e.0);
        for (key, addr, c) in ended {
            tracing::info!(
                "SNDCP: READY expired for ISSI {} NSAPI {}: SN-END OF DATA, STANDBY (N-PDU up {} / down {}, {} / {} bytes)",
                key.0,
                key.1,
                c.up,
                c.down,
                c.up_bytes,
                c.down_bytes
            );
            if let Ok(pdu) = encode_end_of_data(&SndcpEndOfData {
                immediate_service_change: false,
            }) {
                queue.push_back(tl_data_req(addr, 0, 0, mle_sdu(&pdu)));
            }
        }
        released.sort_unstable();
        for (key, why) in released {
            if let Some(ctx) = self.remove_ctx(key) {
                tracing::info!(
                    "SNDCP: PDP context of ISSI {} NSAPI {} ({}) released: {}",
                    key.0,
                    key.1,
                    ctx.ip,
                    why
                );
            }
            self.release_issi(key.0, wap.as_deref_mut());
        }
        for issi in issis {
            self.sync_pause(issi, wap.as_deref_mut(), now);
        }
    }

    /// The next context in READY with something to send, round robin.
    fn next_to_serve(&self) -> Option<(u32, u8)> {
        let mut keys: Vec<(u32, u8)> = self
            .ctxs
            .iter()
            .filter(|(_, c)| c.state == CtxState::Ready && !c.in_call && !c.dl.is_empty())
            .map(|(k, _)| *k)
            .collect();
        keys.sort_unstable();
        let after = self.last_served;
        keys.iter().find(|k| after.is_none_or(|last| **k > last)).or(keys.first()).copied()
    }

    fn deliver(&mut self, queue: &mut MessageQueue, config: &SharedConfig, wap: Option<&mut WapService>, now: Instant) {
        if let Some(inflight) = &self.inflight {
            // Final: sent (basic link), or acknowledged, lost or discarded (advanced link).
            let done = inflight.reporter.is_in_final_state();
            if !done && self.clock - inflight.since < INFLIGHT_GUARD_SLOTS {
                return;
            }
            if !done {
                tracing::debug!("SNDCP: no final report on the last data PDU, not waiting for it any longer");
            } else if inflight.reporter.get_state() == TxState::Acknowledged
                && let Some(ctx) = self.ctxs.get_mut(&inflight.key)
                && ctx.state == CtxState::Ready
            {
                // READY restarts when the peer confirms an SN-DATA (clause 28.2.6.2).
                ctx.deadline = self.clock + self.ready_slots;
            }
            self.inflight = None;
        }
        let Some(key) = self.next_to_serve() else { return };
        // Voice first, on the live call map: a radio that has just gone into a call gets nothing.
        if in_call(&config.state_read(), key.0) {
            if let Some(ctx) = self.ctxs.get_mut(&key) {
                ctx.in_call = true;
            }
            self.sync_pause(key.0, wap, now);
            return;
        }
        let (ready_slots, clock) = (self.ready_slots, self.clock);
        let Some(ctx) = self.ctxs.get_mut(&key) else { return };
        let Some(npdu) = ctx.dl.pop_front() else { return };
        let bearer = ctx.reply_bearer;
        let al_number = match bearer {
            LtpdBearer::Advanced { al_number, .. } => Some(al_number),
            LtpdBearer::BasicAck | LtpdBearer::BasicUnack => None,
        };
        if al_number.is_none() && npdu.len() > BL_MAX_DATAGRAM {
            tracing::debug!(
                "SNDCP: datagram of {} bytes for ISSI {} does not fit the basic link, dropped",
                npdu.len(),
                key.0
            );
            return;
        }
        let n_pdu = BitBuffer::from_bytes(&npdu);
        let encoded = match al_number {
            Some(_) => encode_sn_data(key.1, SNDCP_NO_COMPRESSION, SNDCP_NO_COMPRESSION, &n_pdu),
            None => encode_sn_unitdata(key.1, SNDCP_NO_COMPRESSION, SNDCP_NO_COMPRESSION, &n_pdu),
        };
        let pdu = match encoded {
            Ok(pdu) => pdu,
            Err(e) => {
                tracing::debug!("SNDCP: datagram PDU for ISSI {} not built ({:?})", key.0, e);
                return;
            }
        };
        ctx.deadline = clock + ready_slots;
        ctx.counters.down += 1;
        ctx.counters.down_bytes += npdu.len();
        let (msg, reporter) = match al_number {
            Some(al_number) => {
                let reporter = TxReporter::new();
                tracing::debug!(
                    "SNDCP: -> ISSI {} SN-DATA on advanced link {}, {} bytes",
                    key.0,
                    al_number + 1,
                    npdu.len()
                );
                let msg = SapMsgInner::TlaTlDataReqAl(TlDataReqAl {
                    main_address: ctx.addr,
                    al_number,
                    tl_sdu: mle_sdu(&pdu),
                    tx_reporter: Some(reporter.clone()),
                });
                (msg, reporter)
            }
            None => {
                let reporter = TxReporter::new_unacked();
                tracing::debug!("SNDCP: -> ISSI {} SN-UNITDATA, {} bytes", key.0, npdu.len());
                let msg = SapMsgInner::TlaTlUnitdataReqBl(TlaTlUnitdataReqBl {
                    main_address: ctx.addr,
                    link_id: 0,
                    endpoint_id: 0,
                    tl_sdu: mle_sdu(&pdu),
                    stealing_permission: false,
                    subscriber_class: 0,
                    fcs_flag: false,
                    air_interface_encryption: None,
                    packet_data_flag: true,
                    n_tlsdu_repeats: 0,
                    data_class_info: None,
                    req_handle: 0,
                    chan_alloc: None,
                    tx_reporter: Some(reporter.clone()),
                });
                (msg, reporter)
            }
        };
        queue.push_back(SapMsg {
            sap: Sap::TlaSap,
            src: TetraEntity::Sndcp,
            dest: TetraEntity::Llc,
            msg,
        });
        self.inflight = Some(Inflight {
            key,
            reporter,
            since: clock,
        });
        self.last_served = Some(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn slots_follow_the_timeslot_length() {
        assert_eq!(slots(85), 6);
        assert_eq!(slots(1_000), 71);
        assert_eq!(slots(28_000), 1977);
    }

    #[test]
    fn mtu_codes_match_table_28_79() {
        assert_eq!([296, 576, 1006, 1500, 2002].map(mtu_code), [1, 2, 3, 4, 5]);
    }

    #[test]
    fn mle_sdu_prefixes_the_sndcp_discriminator() {
        let sdu = mle_sdu(&BitBuffer::from_bitstr("1011"));
        assert_eq!(sdu.to_bitstr(), "1001011");
    }

    const ISSI: u32 = 2_260_618;

    fn shared_config() -> SharedConfig {
        let toml = r#"
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

[packet_data]
enabled = true
"#;
        SharedConfig::from_parts(tetra_config::bluestation::from_toml_str(toml).unwrap(), None)
    }

    fn ind(sn: &str) -> LtpdMleUnitdataInd {
        LtpdMleUnitdataInd {
            sdu: BitBuffer::from_bitstr(&format!("100{sn}")),
            endpoint_id: 0,
            link_id: 1,
            received_tetra_address: TetraAddress::issi(ISSI),
            chan_change_resp_req: false,
            chan_change_handle: None,
            bearer: tetra_saps::ltpd::LtpdBearer::BasicAck,
        }
    }

    /// Runtime with one context of ISSI on NSAPI 1 (10.0.0.2) in READY.
    fn ready_runtime(config: &SharedConfig, wap: &mut WapService, now: Instant) -> PacketDataRuntime {
        let mut rt = PacketDataRuntime::new(config).expect("[packet_data] enabled");
        let mut queue = MessageQueue::new();
        rt.rx(&mut queue, &ind("0000000100010010001000000000"), Some(wap), config, now);
        rt.rx(&mut queue, &ind("01100001000"), Some(wap), config, now);
        assert_eq!(
            rt.ctxs.get(&(ISSI, 1)).map(|c| (c.ip, c.state)),
            Some((Ipv4Addr::new(10, 0, 0, 2), CtxState::Ready))
        );
        rt
    }

    fn get_status_page(rt: &mut PacketDataRuntime, config: &SharedConfig, wap: &mut WapService, now: Instant) {
        let mut wtp = vec![0x0a, 0x00, 0x51, 0x12, 0x40, 11];
        wtp.extend_from_slice(b"/status.wml");
        let npdu = super::super::ip::build_ipv4_udp_npdu([10, 0, 0, 2], [10, 0, 0, 1], 2049, 9201, &wtp, 1, 64).unwrap();
        let pdu = encode_sn_unitdata(1, 0, 0, &BitBuffer::from_bytes(&npdu)).unwrap();
        let mut sn = ind(&pdu.to_bitstr());
        sn.bearer = tetra_saps::ltpd::LtpdBearer::BasicUnack;
        rt.rx(&mut MessageQueue::new(), &sn, Some(wap), config, now);
    }

    fn unitdata_reqs(queue: &mut MessageQueue) -> usize {
        let mut n = 0;
        while let Some(msg) = queue.pop_front() {
            if matches!(msg.msg, SapMsgInner::TlaTlUnitdataReqBl(_)) {
                n += 1;
            }
        }
        n
    }

    /// A radio in a call gets nothing, and the gateway's retransmission timers wait for it: a
    /// minute later the result is still the only datagram queued (no retransmission, no Abort),
    /// and it goes down once the call is over.
    #[test]
    fn a_call_holds_the_data_and_pauses_the_gateway_timers() {
        let config = shared_config();
        let mut wap = WapService::start(&config).unwrap();
        let t0 = Instant::now();
        let mut rt = ready_runtime(&config, &mut wap, t0);
        config.state_write().active_call_ts.insert(ISSI, (1584, 2, 4));
        get_status_page(&mut rt, &config, &mut wap, t0);
        let mut queue = MessageQueue::new();
        rt.tick(&mut queue, &config, Some(&mut wap), t0);
        assert_eq!(unitdata_reqs(&mut queue), 0, "radio in a call");
        assert!(rt.paused.contains(&ISSI));
        for i in 0..HOUSEKEEPING_SLOTS {
            rt.tick(
                &mut queue,
                &config,
                Some(&mut wap),
                t0 + Duration::from_secs(60) + Duration::from_millis(i),
            );
        }
        assert_eq!(unitdata_reqs(&mut queue), 0);
        assert_eq!(rt.ctxs[&(ISSI, 1)].dl.len(), 1, "no retransmission and no Abort while paused");
        config.state_write().active_call_ts.clear();
        let t1 = t0 + Duration::from_secs(61);
        for _ in 0..HOUSEKEEPING_SLOTS {
            rt.tick(&mut queue, &config, Some(&mut wap), t1);
        }
        assert!(!rt.paused.contains(&ISSI));
        assert_eq!(unitdata_reqs(&mut queue), 1, "the result goes down after the call");
        assert!(wap.has_open_transactions(ISSI), "the transaction survived the call");
    }

    /// READY expiry: SN-END OF DATA, STANDBY and the gateway paused; STANDBY expiry: the context and
    /// its address are released.
    #[test]
    fn ready_then_standby_expiry() {
        let config = shared_config();
        let mut wap = WapService::start(&config).unwrap();
        let now = Instant::now();
        let mut rt = ready_runtime(&config, &mut wap, now);
        let mut queue = MessageQueue::new();
        let deadline = rt.ctxs[&(ISSI, 1)].deadline;
        rt.clock = deadline - 1;
        rt.housekeeping(&mut queue, &config, Some(&mut wap), now);
        assert!(queue.pop_front().is_none(), "READY still running");
        rt.clock = deadline;
        rt.housekeeping(&mut queue, &config, Some(&mut wap), now);
        let Some(SapMsgInner::TlaTlDataReqBl(eod)) = queue.pop_front().map(|m| m.msg) else {
            panic!("SN-END OF DATA expected");
        };
        assert_eq!(
            eod.tl_sdu.to_bitstr(),
            "100100000",
            "discriminator, END OF DATA, no service change, o-bit"
        );
        assert_eq!(rt.ctxs[&(ISSI, 1)].state, CtxState::Standby);
        assert!(rt.paused.contains(&ISSI));
        let standby_deadline = rt.ctxs[&(ISSI, 1)].deadline;
        assert_eq!(standby_deadline - deadline, rt.standby_slots);
        rt.clock = standby_deadline - 1;
        rt.housekeeping(&mut queue, &config, Some(&mut wap), now);
        assert!(rt.ctxs.contains_key(&(ISSI, 1)));
        rt.clock = standby_deadline;
        rt.housekeeping(&mut queue, &config, Some(&mut wap), now);
        assert!(rt.ctxs.is_empty() && rt.by_ip.is_empty() && rt.paused.is_empty());
        assert_eq!(rt.allocate(), Some(Ipv4Addr::new(10, 0, 0, 2)), "address back in the pool");
    }
}
