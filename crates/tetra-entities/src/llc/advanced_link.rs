// SPDX-FileCopyrightText: Historical upstream contributors
// SPDX-FileCopyrightText: 2026 Chris YO3TCO / Nexus-BS Project
// SPDX-License-Identifier: Apache-2.0 AND PolyForm-Noncommercial-1.0.0
// SPDX-FileComment: Modified by Nexus-BS Project; see CHANGES-NEXUS.md for change notices.
// SPDX-FileComment: Advanced link engine for flowstation-miura by EA5GVK. The AL-SETUP negotiation, the TL-SDU FCS and segmentation, the reassembly and the selective AL-ACK building and reading are adapted from Nexus-BS llc_bs_ms.rs; the pacing on the MCCH, the per-segment MAC reports, the receive window, the timers and AL-DISC / AL-RECONNECT are written for flowstation-miura.

//! Original acknowledged advanced link of the BS LLC (EN 300 392-2 clauses 22.2.2 and 22.3.3),
//! used by the packet-data bearer on the MCCH. One original advanced link per radio.
//!
//! - AL-SETUP from a radio is answered at once: "success" with its parameters, as Nexus-BS does
//!   with the MXP600, or "service change" when it asks for more than 1 phase-modulation slot or
//!   for an extended link, which the radio confirms with an AL-SETUP "success". Downlink
//!   retransmissions are bounded here (N.273 up to 3, N.274 up to 5) whatever was agreed.
//! - Downlink TL-SDUs get their FCS and are cut in segments that fit one SCH/F MAC-RESOURCE
//!   together with a slot grant the MAC may add, so the MAC never fragments them. AL-DATA-AR /
//!   AL-FINAL-AR every fourth segment, on the last one and on the last retransmitted one; T.252
//!   re-asks with the last segment; missing segments go again up to N.274 times, then the whole
//!   TL-SDU up to N.273 times; after that the link is closed with AL-DISC.
//! - Voice first: the engine never steals (every PDU goes on the MCCH with link 0, or on the
//!   radio's packet-data channel) and keeps at most one data segment waiting in the MAC, so a call
//!   set-up waits behind one segment at most. A link on a packet-data channel of several slots,
//!   whose PDUs never go on the MCCH, keeps one segment per slot of its channel in the MAC
//!   instead. While a radio is in a call its TL-SDU under way waits: no segments, T.252 held.
//! - Uplink segments are reassembled within the TL-SDU window, checked against the FCS and
//!   delivered in N(S) order as TL-DATA indications; AL-DATA-AR / AL-FINAL-AR get an AL-ACK
//!   (complete, selective or "repeat").
//! - AL-RNR stops new TL-SDUs until AL-ACK or T.271; AL-RECONNECT is accepted for a link that
//!   exists here; AL-DISC "close" is answered "success".

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{BitBuffer, Sap, TetraAddress, TxReporter, TxState, frames};
use tetra_pdus::llc::consts::consts::{N262_AL_MAX_CONNECTION_SETUP_RETRIES, N263_AL_MAX_DISCONNECTION_RETRIES};
use tetra_pdus::llc::consts::timers::{T252_ACK_WAITING_TIMER, T271_RECEIVER_NOT_READY_FOR_TX_TIMER};
use tetra_pdus::llc::enums::llc_pdu_type::LlcPduType;
use tetra_pdus::llc::pdus::al_ack::{AlAck, AlAckBlock};
use tetra_pdus::llc::pdus::al_data::AlData;
use tetra_pdus::llc::pdus::al_disc::{AlDisc, AlDiscReport};
use tetra_pdus::llc::pdus::al_reconnect::{AlReconnect, AlReconnectReport};
use tetra_pdus::llc::pdus::al_setup::AlSetup;
use tetra_saps::tla::{TlDataIndAl, TlDataReqAl};
use tetra_saps::tma::{TmaUnitdataInd, TmaUnitdataReq};
use tetra_saps::{SapMsg, SapMsgInner};

use crate::MessageQueue;
use crate::llc::components::fcs;
use crate::umac::subcomp::bs_sched::SCH_F_CAP;

/// AL-DATA / AL-FINAL header (type, FINAL, AR, N(S), S(S)).
const AL_DATA_HEADER_BITS: usize = 17;
/// MAC-RESOURCE header addressed to an SSI with a usage marker and a slot grant (clause 21.4.3.1),
/// the largest the MAC builds for an individual PDU without a channel allocation.
pub const MAC_RESOURCE_HEADER_BITS: usize = 57;
/// Payload of one AL-DATA / AL-FINAL: the segment and its MAC-RESOURCE fill one SCH/F.
pub const AL_SEGMENT_BITS: usize = SCH_F_CAP - MAC_RESOURCE_HEADER_BITS - AL_DATA_HEADER_BITS;
/// Largest AL-ACK / AL-RNR, so that it too fits one SCH/F.
const AL_ACK_MAX_BITS: usize = SCH_F_CAP - MAC_RESOURCE_HEADER_BITS;
/// An acknowledgement is requested at least every this many segments.
const SEGMENTS_PER_ACK_REQUEST: usize = 4;

/// Negotiation limit by default: 1 phase-modulation slot (the data rides on the MCCH or a 1-slot
/// PDCH). `[packet_data] pdch_max_slots` raises it (`AdvancedLinkEngine::set_max_timeslots`).
const MAX_TIMESLOTS: u8 = 1;
/// Retransmissions of our TL-SDUs at most (fewer retries on the shared MCCH): N.273 and N.274
/// are the radio's as agreed, the station just gives up sooner.
const MAX_N273: u8 = 3;
const MAX_N274: u8 = 5;

const T252_SLOTS: u64 = T252_ACK_WAITING_TIMER as u64;
const T271_SLOTS: u64 = T271_RECEIVER_NOT_READY_FOR_TX_TIMER as u64;
/// Wait for the radio's answer to an AL-SETUP "service change" or an AL-DISC before sending it
/// again. The radio answers by random access on a busy MCCH, so this is longer than T.261 and
/// T.263 (4 signalling frames, the MS's defaults).
const ANSWER_WAIT_SLOTS: u64 = frames!(18) as u64;
/// A segment the MAC never reports on stops holding the MCCH after this long (about 10 s).
const INFLIGHT_GUARD_SLOTS: u64 = 706;
/// A link without any traffic for an hour is forgotten without signalling.
const LINK_IDLE_SLOTS: u64 = 254_118;
const MAX_LINKS: usize = 1024;
/// TL-SDUs waiting on one link behind the one being sent.
const MAX_QUEUED_SDUS: usize = 8;
/// At most one unsolicited AL-DISC per radio in this time (about 2 s).
const DISC_RATE_SLOTS: u64 = 144;

/// N.271 in octets for its code (table 21.23): 32 << code.
pub fn n271_octets(code: u8) -> usize {
    32usize << code.min(7)
}

fn report_transmitted(r: &TxReporter) {
    if r.get_state() == TxState::Pending {
        r.mark_transmitted();
    }
}

fn report_acknowledged(r: &TxReporter) {
    report_transmitted(r);
    if r.get_state() == TxState::Transmitted && !r.is_in_final_state() {
        r.mark_acknowledged();
    }
}

fn report_failed(r: &TxReporter) {
    match r.get_state() {
        TxState::Pending => r.mark_discarded(),
        TxState::Transmitted if !r.is_in_final_state() => r.mark_lost(),
        _ => {}
    }
}

/// The AL-SETUP answer to a radio's proposal: its parameters ("success"), or 1 slot or an
/// original link instead ("service change"), always a non-augmented original acknowledged link
/// (clause 22.2.2.1).
pub fn negotiate_setup(proposal: &AlSetup) -> AlSetup {
    negotiate_setup_with(proposal, MAX_TIMESLOTS)
}

/// `negotiate_setup` with at most `max_timeslots` phase-modulation slots: N.264 is the lower of
/// the radio's proposal and that (the responder may only lower it, clause 22.2.2.1 NOTE 2 and
/// 28.3.4.2 b NOTE 5).
pub fn negotiate_setup_with(proposal: &AlSetup, max_timeslots: u8) -> AlSetup {
    let mut answer = *proposal;
    let mut changed = false;
    if let Some(aug) = proposal.augmented {
        let window = if aug.extended_advanced_link {
            changed = true;
            aug.extended_window_size_code.unwrap_or(1).clamp(1, 3)
        } else {
            aug.original_window_size_code.unwrap_or(1).clamp(1, 3)
        };
        answer.window_size_code = window;
        answer.augmented = None;
    }
    if answer.connection_width {
        answer = answer.response_with_lower_phase_mod_timeslots(max_timeslots);
        changed |= answer.setup_report == AlSetup::SETUP_REPORT_SERVICE_CHANGE;
    }
    answer.ns = None;
    answer.setup_report = if changed {
        AlSetup::SETUP_REPORT_SERVICE_CHANGE
    } else {
        AlSetup::SETUP_REPORT_SUCCESS
    };
    answer
}

fn setup_summary(s: &AlSetup) -> String {
    let slots = match (s.connection_width, s.uplink_timeslots) {
        (true, Some(n)) => format!("{} slot(s)", n + 1),
        _ => "no slot request".to_string(),
    };
    format!(
        "N.271 {} octets, N.272 {}, N.273 {}, N.274 {}, {}",
        n271_octets(s.max_tl_sdu_len_code),
        s.window_size_code,
        s.max_tl_sdu_retransmissions,
        s.max_segment_retransmissions,
        slots
    )
}

struct Segment {
    bits: BitBuffer,
    acked: bool,
    need_tx: bool,
    /// Transmissions started, the first one included.
    sends: u8,
    /// MAC report of the transmission under way, and whether it asks for an acknowledgement.
    in_mac: Option<(TxReporter, bool)>,
    /// Order in which its last transmission left the MAC.
    done_order: Option<u64>,
}

struct TxSdu {
    ns: u8,
    segments: Vec<Segment>,
    octets: usize,
    service: TxReporter,
    /// Whole TL-SDU retransmissions so far (N.273).
    sdu_retx: u8,
    retransmissions: u32,
    /// T.252: started when an acknowledgement request left the MAC.
    ack_wait: Option<u64>,
    /// `done_order` of the last acknowledgement request that left the MAC: an acknowledgement
    /// speaks only of segments sent up to it.
    last_ar_order: u64,
}

enum RxSdu {
    Partial {
        segments: BTreeMap<u8, BitBuffer>,
        final_ss: Option<u8>,
        bits: usize,
    },
    /// Complete and correct, waiting for an older TL-SDU to be delivered first.
    Complete(BitBuffer),
    /// All segments came but the FCS failed: the sender must repeat it.
    FcsFailed,
}

impl RxSdu {
    fn new() -> Self {
        RxSdu::Partial {
            segments: BTreeMap::new(),
            final_ss: None,
            bits: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkState {
    Connected,
    /// AL-DISC "close" sent (`retries` resends so far), waiting for "success".
    Disconnecting {
        retries: u8,
        sent_at: u64,
    },
}

struct Link {
    addr: TetraAddress,
    al_number: u8,
    n271: usize,
    window: u8,
    n273: u8,
    n274: u8,
    state: LinkState,
    last_activity: u64,
    // Sending side.
    next_ns: u8,
    queue: VecDeque<(BitBuffer, TxReporter)>,
    tx: Option<TxSdu>,
    rnr_since: Option<u64>,
    /// The radio is in a call: sending waits.
    held: bool,
    /// On a packet-data channel of several slots: last report on a segment in the MAC (or when
    /// one went in), for the guard against a MAC that never reports.
    in_mac_since: Option<u64>,
    // Receiving side: V(R), the TL-SDUs in the window and the delivered ones not acknowledged yet.
    vr: u8,
    rx: HashMap<u8, RxSdu>,
    acks_owed: Vec<u8>,
}

impl Link {
    fn new(addr: TetraAddress, setup: &AlSetup, now: u64) -> Self {
        Self {
            addr,
            al_number: setup.advanced_link_number,
            n271: n271_octets(setup.max_tl_sdu_len_code),
            window: setup.window_size_code.clamp(1, 3),
            n273: setup.max_tl_sdu_retransmissions.min(MAX_N273),
            n274: setup.max_segment_retransmissions.min(MAX_N274),
            state: LinkState::Connected,
            last_activity: now,
            next_ns: 0,
            queue: VecDeque::new(),
            tx: None,
            rnr_since: None,
            held: false,
            in_mac_since: None,
            vr: 0,
            rx: HashMap::new(),
            acks_owed: Vec::new(),
        }
    }

    /// Every TL-SDU still to send or being sent fails (link reset or closed).
    fn fail_all(&mut self) {
        if let Some(tx) = self.tx.take() {
            report_failed(&tx.service);
        }
        for (_, reporter) in self.queue.drain(..) {
            report_failed(&reporter);
        }
    }

    fn connected(&self) -> bool {
        self.state == LinkState::Connected
    }
}

struct PendingSetup {
    addr: TetraAddress,
    answer: AlSetup,
    sent_at: u64,
    retries: u8,
}

struct Inflight {
    ssi: u32,
    reporter: TxReporter,
    since: u64,
}

pub struct AdvancedLinkEngine {
    links: HashMap<u32, Link>,
    pending: HashMap<u32, PendingSetup>,
    /// Timeslots since the engine started.
    clock: u64,
    /// The data segment waiting in the MAC for the MCCH.
    inflight: Option<Inflight>,
    last_served: Option<u32>,
    /// Transmissions that left the MAC, counted.
    order: u64,
    /// Last unsolicited AL-DISC per radio.
    disc_sent: HashMap<u32, u64>,
    /// Messages pushed since the last tick.
    activity: bool,
    /// Radios on a packet-data channel (carrier, timeslot, number of slots): their PDUs go there.
    pdch_routes: HashMap<u32, (u16, u8, usize)>,
    /// Radios in a call (among those with something to send): their sending waits.
    in_call: HashSet<u32>,
    /// Phase-modulation slots an AL-SETUP is answered with at most (N.264).
    max_timeslots: u8,
}

impl Default for AdvancedLinkEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AdvancedLinkEngine {
    pub fn new() -> Self {
        tracing::info!("LLC: advanced link on ({} bits per segment)", AL_SEGMENT_BITS);
        Self {
            links: HashMap::new(),
            pending: HashMap::new(),
            clock: 0,
            inflight: None,
            last_served: None,
            order: 0,
            disc_sent: HashMap::new(),
            activity: false,
            pdch_routes: HashMap::new(),
            in_call: HashSet::new(),
            max_timeslots: MAX_TIMESLOTS,
        }
    }

    /// Answer AL-SETUPs with at most `n` phase-modulation slots (`[packet_data] pdch_max_slots`).
    pub fn set_max_timeslots(&mut self, n: u8) {
        self.max_timeslots = n.clamp(1, 4);
    }

    /// The radios now on a packet-data channel (`[packet_data] bearer = "pdch"`): carrier, the
    /// slot their PDUs go to and the channel's number of slots.
    pub fn set_pdch_routes(&mut self, routes: HashMap<u32, (u16, u8, usize)>) {
        self.pdch_routes = routes;
    }

    /// Slots of the packet-data channel of `ssi`: 1 without one (the MCCH).
    fn width(&self, ssi: u32) -> usize {
        self.pdch_routes.get(&ssi).map_or(1, |r| r.2.max(1))
    }

    /// Radios with a TL-SDU to send or under way.
    pub fn busy_ssis(&self) -> Vec<u32> {
        self.links
            .iter()
            .filter(|(_, l)| l.tx.is_some() || !l.queue.is_empty())
            .map(|(ssi, _)| *ssi)
            .collect()
    }

    /// The radios of `busy_ssis` now in a call.
    pub fn set_in_call(&mut self, ssis: HashSet<u32>) {
        self.in_call = ssis;
    }

    /// Nothing to send and no link to look after.
    pub fn is_idle(&self) -> bool {
        self.links.is_empty() && self.pending.is_empty()
    }

    /// Carrier and link id the PDUs of `ssi` go on: its packet-data channel, else the MCCH of the
    /// main carrier.
    fn route(&self, ssi: u32, main_carrier: u16) -> (u16, u32) {
        self.pdch_routes
            .get(&ssi)
            .map_or((main_carrier, 0), |&(carrier, ts, _)| (carrier, u32::from(ts)))
    }

    fn push_pdu(&mut self, queue: &mut MessageQueue, addr: TetraAddress, pdu: BitBuffer, reporter: Option<TxReporter>, main: u16) {
        let (carrier, link_id) = self.route(addr.ssi, main);
        queue.push_back(SapMsg {
            sap: Sap::TmaSap,
            src: TetraEntity::Llc,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                carrier_num: Some(carrier),
                req_handle: 0,
                pdu,
                main_address: addr,
                link_id,
                endpoint_id: 0,
                // Never stolen from a call: advanced link PDUs wait for the MCCH.
                stealing_permission: false,
                subscriber_class: 0,
                air_interface_encryption: None,
                stealing_repeats_flag: None,
                data_category: None,
                chan_alloc: None,
                tx_reporter: reporter,
            }),
        });
        self.activity = true;
    }

    fn send_setup(&mut self, queue: &mut MessageQueue, addr: TetraAddress, setup: &AlSetup, main: u16) {
        let mut pdu = BitBuffer::new_autoexpand(32);
        setup.to_bitbuf(&mut pdu);
        pdu.seek(0);
        tracing::debug!("LLC: -> ISSI {} {}", addr.ssi, setup);
        self.push_pdu(queue, addr, pdu, None, main);
    }

    fn send_disc(&mut self, queue: &mut MessageQueue, addr: TetraAddress, disc: AlDisc, main: u16) {
        let mut pdu = BitBuffer::new_autoexpand(16);
        disc.to_bitbuf(&mut pdu);
        pdu.seek(0);
        tracing::debug!("LLC: -> ISSI {} {}", addr.ssi, disc);
        self.push_pdu(queue, addr, pdu, None, main);
    }

    fn send_ack(&mut self, queue: &mut MessageQueue, addr: TetraAddress, ack: AlAck, main: u16) {
        let mut pdu = BitBuffer::new_autoexpand(32);
        ack.to_bitbuf(&mut pdu);
        pdu.seek(0);
        tracing::debug!("LLC: -> ISSI {} {}", addr.ssi, ack);
        self.push_pdu(queue, addr, pdu, None, main);
    }

    /// Whether `ssi` has an established advanced link.
    pub fn has_link(&self, ssi: u32) -> bool {
        self.links.get(&ssi).is_some_and(Link::connected)
    }

    // -----------------------------------------------------------------------------------------
    // Uplink
    // -----------------------------------------------------------------------------------------

    /// An advanced link PDU from a radio (AL-SETUP, AL-DATA / AL-FINAL, AL-ACK / AL-RNR,
    /// AL-RECONNECT, AL-DISC).
    pub fn rx(&mut self, queue: &mut MessageQueue, prim: &TmaUnitdataInd, mut pdu: BitBuffer, pdu_type: LlcPduType, main: u16) {
        pdu.seek(0);
        match pdu_type {
            LlcPduType::AlSetup => match AlSetup::from_bitbuf(&mut pdu) {
                Ok(setup) => self.rx_setup(queue, prim.main_address, setup, main),
                Err(e) => tracing::warn!("LLC: AL-SETUP from ISSI {} not decoded ({:?})", prim.main_address.ssi, e),
            },
            LlcPduType::AlDataAlFinal => match AlData::from_bitbuf(&mut pdu) {
                Ok(header) => {
                    let segment = BitBuffer::from_bitbuffer_pos(&pdu);
                    self.rx_data(queue, prim, header, segment, main);
                }
                Err(e) => tracing::warn!("LLC: AL-DATA from ISSI {} not decoded ({:?})", prim.main_address.ssi, e),
            },
            LlcPduType::AlAckAlRnr => match AlAck::from_bitbuf(&mut pdu) {
                Ok(ack) => self.rx_ack(queue, prim.main_address, ack, main),
                Err(e) => tracing::warn!("LLC: AL-ACK from ISSI {} not decoded ({:?})", prim.main_address.ssi, e),
            },
            LlcPduType::AlReconnect => match AlReconnect::from_bitbuf(&mut pdu) {
                Ok(reconnect) => self.rx_reconnect(queue, prim.main_address, reconnect, main),
                Err(e) => tracing::warn!("LLC: AL-RECONNECT from ISSI {} not decoded ({:?})", prim.main_address.ssi, e),
            },
            LlcPduType::AlDisc => match AlDisc::from_bitbuf(&mut pdu) {
                Ok(disc) => self.rx_disc(queue, prim.main_address, disc, main),
                Err(e) => tracing::warn!("LLC: AL-DISC from ISSI {} not decoded ({:?})", prim.main_address.ssi, e),
            },
            other => tracing::debug!(
                "LLC: {} from ISSI {} not handled by the advanced link",
                other,
                prim.main_address.ssi
            ),
        }
    }

    fn rx_setup(&mut self, queue: &mut MessageQueue, addr: TetraAddress, setup: AlSetup, main: u16) {
        let ssi = addr.ssi;
        tracing::debug!("LLC: <- ISSI {} {}", ssi, setup);
        if !setup.acknowledged_service {
            tracing::info!(
                "LLC: AL-SETUP from ISSI {} for an unacknowledged advanced link {} -> AL-DISC (service not supported)",
                ssi,
                setup.advanced_link_number + 1
            );
            let disc = AlDisc {
                acknowledged_service: false,
                advanced_link_number: setup.advanced_link_number,
                report: AlDiscReport::ServiceNotSupported,
            };
            self.send_disc(queue, addr, disc, main);
            return;
        }
        if setup.setup_report == AlSetup::SETUP_REPORT_SUCCESS {
            // The radio accepts our "service change" (or confirms a link already up).
            if let Some(link) = self.links.get(&ssi)
                && link.connected()
                && link.al_number == setup.advanced_link_number
            {
                tracing::debug!("LLC: AL-SETUP success from ISSI {} for the link already up", ssi);
                return;
            }
            let agreed = match self.pending.remove(&ssi) {
                Some(p) if p.answer.advanced_link_number == setup.advanced_link_number => p.answer,
                _ => negotiate_setup_with(&setup, self.max_timeslots),
            };
            self.establish(addr, &agreed);
            tracing::info!(
                "LLC: AL-SETUP success from ISSI {} -> advanced link {} up ({})",
                ssi,
                agreed.advanced_link_number + 1,
                setup_summary(&agreed)
            );
            return;
        }
        let answer = negotiate_setup_with(&setup, self.max_timeslots);
        let report = match setup.setup_report {
            AlSetup::SETUP_REPORT_SERVICE_DEFINITION => "service definition",
            AlSetup::SETUP_REPORT_SERVICE_CHANGE => "service change",
            AlSetup::SETUP_REPORT_RESET => "reset",
            _ => "other report",
        };
        if let Some(mut old) = self.links.remove(&ssi) {
            tracing::info!("LLC: advanced link {} of ISSI {} reset by a new AL-SETUP", old.al_number + 1, ssi);
            old.fail_all();
        }
        if answer.setup_report == AlSetup::SETUP_REPORT_SUCCESS {
            self.pending.remove(&ssi);
            self.establish(addr, &answer);
        } else {
            self.pending.insert(
                ssi,
                PendingSetup {
                    addr,
                    answer,
                    sent_at: self.clock,
                    retries: 0,
                },
            );
        }
        tracing::info!(
            "LLC: AL-SETUP from ISSI {} AL {} ({}, {}) -> {} ({})",
            ssi,
            setup.advanced_link_number + 1,
            report,
            setup_summary(&setup),
            if answer.setup_report == AlSetup::SETUP_REPORT_SUCCESS {
                "success"
            } else {
                "service change"
            },
            setup_summary(&answer)
        );
        self.send_setup(queue, addr, &answer, main);
    }

    fn establish(&mut self, addr: TetraAddress, setup: &AlSetup) {
        if self.links.len() >= MAX_LINKS
            && !self.links.contains_key(&addr.ssi)
            && let Some(oldest) = self.links.iter().min_by_key(|(_, l)| l.last_activity).map(|(k, _)| *k)
            && let Some(mut old) = self.links.remove(&oldest)
        {
            tracing::debug!("LLC: too many advanced links, forgetting the one of ISSI {}", oldest);
            old.fail_all();
        }
        if let Some(mut old) = self.links.insert(addr.ssi, Link::new(addr, setup, self.clock)) {
            old.fail_all();
        }
    }

    fn rx_data(&mut self, queue: &mut MessageQueue, prim: &TmaUnitdataInd, header: AlData, segment: BitBuffer, main: u16) {
        let addr = prim.main_address;
        let ssi = addr.ssi;
        tracing::debug!("LLC: <- ISSI {} {} ({} bits)", ssi, header, segment.get_len());
        let clock = self.clock;
        let Some(link) = self.links.get_mut(&ssi).filter(|l| l.connected()) else {
            if self.pending.contains_key(&ssi) {
                tracing::debug!("LLC: {} from ISSI {} before it accepted the AL-SETUP, dropped", header, ssi);
                return;
            }
            // Data on a link we do not know (lost here, or closed while the radio was away):
            // tell the radio to close it, so it sets up a new one.
            let recent = self.disc_sent.get(&ssi).is_some_and(|t| clock.saturating_sub(*t) < DISC_RATE_SLOTS);
            if header.acknowledgement_requested && !recent && !self.links.contains_key(&ssi) {
                if self.disc_sent.len() >= MAX_LINKS {
                    self.disc_sent.clear();
                }
                self.disc_sent.insert(ssi, clock);
                tracing::info!("LLC: {} from ISSI {} without an advanced link -> AL-DISC (close)", header, ssi);
                let disc = AlDisc {
                    acknowledged_service: true,
                    advanced_link_number: 0,
                    report: AlDiscReport::Close,
                };
                self.send_disc(queue, addr, disc, main);
            } else {
                tracing::debug!("LLC: {} from ISSI {} without an advanced link, dropped", header, ssi);
            }
            return;
        };
        link.last_activity = clock;
        let window = link.window;
        let offset = header.ns.wrapping_sub(link.vr) & 7;
        if offset >= window {
            if offset >= 8 - window {
                // Below the window: delivered already, our acknowledgement got lost.
                tracing::debug!("LLC: ISSI {} repeats delivered TL-SDU N(S) {}", ssi, header.ns);
                if header.acknowledgement_requested {
                    let ack = AlAck::complete(header.ns);
                    self.send_ack(queue, addr, ack, main);
                }
            } else {
                tracing::debug!(
                    "LLC: ISSI {} TL-SDU N(S) {} outside the window (V(R) {}), dropped",
                    ssi,
                    header.ns,
                    link.vr
                );
            }
            return;
        }
        let max_bits = link.n271 * 8;
        let entry = link.rx.entry(header.ns).or_insert_with(RxSdu::new);
        if matches!(entry, RxSdu::FcsFailed) {
            *entry = RxSdu::new();
        }
        let mut done = None;
        if let RxSdu::Partial { segments, final_ss, bits } = entry {
            if !segments.contains_key(&header.ss) {
                *bits += segment.get_len();
                segments.insert(header.ss, segment);
            }
            if header.final_segment {
                *final_ss = Some(header.ss);
            }
            if *bits > max_bits {
                tracing::info!(
                    "LLC: ISSI {} TL-SDU N(S) {} longer than N.271 ({} octets), discarded",
                    ssi,
                    header.ns,
                    link.n271
                );
                *entry = RxSdu::FcsFailed;
            } else if let Some(fin) = *final_ss
                && (0..=fin).all(|ss| segments.contains_key(&ss))
            {
                let count = fin as usize + 1;
                let mut sdu = BitBuffer::new_autoexpand(*bits);
                for ss in 0..=fin {
                    if let Some(seg) = segments.get(&ss) {
                        let mut seg = BitBuffer::from_bitbuffer(seg);
                        seg.seek(0);
                        let len = seg.get_len();
                        sdu.copy_bits(&mut seg, len);
                    }
                }
                sdu.seek(0);
                if sdu.get_len() >= 32 && fcs::check_fcs(&sdu) {
                    let end = sdu.get_raw_end() - 32;
                    sdu.set_raw_end(end);
                    tracing::info!(
                        "LLC: AL {} ISSI {} TL-SDU N(S) {} up: {} bytes in {} segment(s)",
                        link.al_number + 1,
                        ssi,
                        header.ns,
                        sdu.get_len() / 8,
                        count
                    );
                    done = Some(sdu);
                } else {
                    tracing::info!(
                        "LLC: AL {} ISSI {} TL-SDU N(S) {} failed its FCS, asking for it again",
                        link.al_number + 1,
                        ssi,
                        header.ns
                    );
                    *entry = RxSdu::FcsFailed;
                }
            }
        }
        if let Some(sdu) = done {
            *entry = RxSdu::Complete(sdu);
        }
        // Deliver in N(S) order.
        let mut delivered = Vec::new();
        while let Some(RxSdu::Complete(_)) = link.rx.get(&link.vr) {
            if let Some(RxSdu::Complete(sdu)) = link.rx.remove(&link.vr) {
                delivered.push(sdu);
            }
            link.acks_owed.push(link.vr);
            // Only the last N.272 are still below the window a repeat can come from.
            if link.acks_owed.len() > usize::from(link.window) {
                link.acks_owed.remove(0);
            }
            link.vr = (link.vr + 1) & 7;
        }
        let (al_number, n271) = (link.al_number, link.n271);
        for sdu in delivered {
            queue.push_back(SapMsg {
                sap: Sap::TlaSap,
                src: TetraEntity::Llc,
                dest: TetraEntity::Mle,
                msg: SapMsgInner::TlaTlDataIndAl(TlDataIndAl {
                    main_address: addr,
                    al_number,
                    max_sdu_bytes: n271.min(u16::MAX as usize) as u16,
                    link_id: prim.link_id,
                    carrier_num: prim.carrier_num,
                    tl_sdu: sdu,
                }),
            });
            self.activity = true;
        }
        if header.acknowledgement_requested {
            let ack = self.build_ack(ssi, header.ns);
            self.send_ack(queue, addr, ack, main);
        }
    }

    /// AL-ACK for an acknowledgement request on TL-SDU `ns_ar` (clause 22.3.3.2.3): blocks for the
    /// delivered TL-SDUs not acknowledged yet, then for the ones in the window up to `ns_ar` (and
    /// newer ones with data), as many as fit one SCH/F.
    fn build_ack(&mut self, ssi: u32, ns_ar: u8) -> AlAck {
        let Some(link) = self.links.get_mut(&ssi) else {
            return AlAck::complete(ns_ar);
        };
        let vr = link.vr;
        let ar_offset = ns_ar.wrapping_sub(vr) & 7;
        let mut owed: Vec<u8> = link.acks_owed.drain(..).collect();
        // A request on a TL-SDU delivered already (below the window) is answered "received".
        if ar_offset >= 8 - link.window && !owed.contains(&ns_ar) {
            owed.push(ns_ar);
        }
        owed.sort_unstable_by_key(|n| n.wrapping_sub(vr) & 7);
        let mut blocks: Vec<AlAckBlock> = owed.into_iter().map(AlAckBlock::complete).collect();
        for off in 0..link.window {
            let n = (vr + off) & 7;
            let block = match link.rx.get(&n) {
                Some(RxSdu::Complete(_)) => AlAckBlock::complete(n),
                Some(RxSdu::FcsFailed) => AlAckBlock::repeat_entire(n),
                Some(RxSdu::Partial { segments, final_ss, .. }) => selective_block(n, segments, *final_ss),
                // Older than the requested one and nothing received yet.
                None if ar_offset < link.window && off < ar_offset => AlAckBlock::selective(n, 0, 0, 1),
                None => continue,
            };
            blocks.push(block);
        }
        if blocks.is_empty() {
            blocks.push(AlAckBlock::complete(ns_ar));
        }
        // Fit the blocks in one SCH/F: shorten a long bitmap, leave out the newest blocks.
        let mut room = AL_ACK_MAX_BITS - 5;
        let mut fitted = Vec::new();
        for mut block in blocks {
            let need = 9 + if block.is_selective_segment_ack() {
                8 + block.acknowledgement_length as usize - 1
            } else {
                0
            };
            if need > room {
                if block.is_selective_segment_ack() && room >= 17 {
                    block.acknowledgement_length = (room - 16) as u8;
                    block.acknowledgement_bitmap &= (1u64 << (block.acknowledgement_length - 1)) - 1;
                    fitted.push(block);
                }
                break;
            }
            room -= need;
            fitted.push(block);
        }
        AlAck::with_blocks(true, fitted)
    }

    fn rx_ack(&mut self, queue: &mut MessageQueue, addr: TetraAddress, ack: AlAck, main: u16) {
        let ssi = addr.ssi;
        tracing::debug!("LLC: <- ISSI {} {}", ssi, ack);
        let clock = self.clock;
        let Some(link) = self.links.get_mut(&ssi).filter(|l| l.connected()) else {
            tracing::debug!("LLC: {} from ISSI {} without an advanced link, dropped", ack, ssi);
            return;
        };
        link.last_activity = clock;
        if ack.receiver_ready {
            if link.rnr_since.take().is_some() {
                tracing::info!("LLC: ISSI {} receiver ready again (AL-ACK)", ssi);
            }
        } else if link.rnr_since.replace(clock).is_none() {
            tracing::info!("LLC: ISSI {} receiver not ready (AL-RNR), new TL-SDUs wait up to T.271", ssi);
        }
        let Some(tx) = link.tx.as_mut() else {
            return;
        };
        let Some(block) = ack.acknowledgement_blocks.iter().find(|b| b.nr == tx.ns).copied() else {
            tracing::debug!("LLC: {} from ISSI {} is not about TL-SDU N(S) {}", ack, ssi, tx.ns);
            return;
        };
        tx.ack_wait = None;
        let mut failed = false;
        if block.acknowledges_complete_tl_sdu() {
            for seg in &mut tx.segments {
                seg.acked = true;
                seg.need_tx = false;
            }
        } else if block.requests_repeat_entire_tl_sdu() {
            if tx.sdu_retx < link.n273 {
                restart_sdu(tx);
                tracing::info!("LLC: ISSI {} asks TL-SDU N(S) {} again (attempt {})", ssi, tx.ns, tx.sdu_retx + 1);
            } else {
                failed = true;
            }
        } else if block.is_selective_segment_ack() {
            let last_ar = tx.last_ar_order;
            for seg_idx in 0..tx.segments.len() {
                let seg = &mut tx.segments[seg_idx];
                match block.segment_acknowledged(seg_idx as u8) {
                    Some(true) => {
                        seg.acked = true;
                        seg.need_tx = false;
                    }
                    Some(false) => {
                        let sent_before_ar = seg.done_order.is_some_and(|o| o <= last_ar);
                        if !seg.acked && seg.in_mac.is_none() && sent_before_ar {
                            seg.need_tx = true;
                        }
                    }
                    None => {}
                }
            }
        }
        if failed {
            self.fail_link(queue, ssi, "the radio asked for the TL-SDU once more than N.273", main);
            return;
        }
        let Some(link) = self.links.get_mut(&ssi) else { return };
        if link.tx.as_ref().is_some_and(|tx| tx.segments.iter().all(|s| s.acked)) {
            if let Some(tx) = link.tx.take() {
                report_acknowledged(&tx.service);
                tracing::info!(
                    "LLC: AL {} ISSI {} TL-SDU N(S) {} down acknowledged: {} bytes, {} segment(s), {} retransmission(s)",
                    link.al_number + 1,
                    ssi,
                    tx.ns,
                    tx.octets,
                    tx.segments.len(),
                    tx.retransmissions
                );
            }
        }
    }

    fn rx_reconnect(&mut self, queue: &mut MessageQueue, addr: TetraAddress, reconnect: AlReconnect, main: u16) {
        let ssi = addr.ssi;
        tracing::debug!("LLC: <- ISSI {} {}", ssi, reconnect);
        if reconnect.report != AlReconnectReport::Propose {
            return;
        }
        let known = reconnect.acknowledged_service
            && self
                .links
                .get(&ssi)
                .is_some_and(|l| l.connected() && l.al_number == reconnect.advanced_link_number);
        tracing::info!(
            "LLC: AL-RECONNECT from ISSI {} for advanced link {} -> {}",
            ssi,
            reconnect.advanced_link_number + 1,
            if known { "accept" } else { "reject (no such link here)" }
        );
        if let Some(link) = self.links.get_mut(&ssi) {
            link.last_activity = self.clock;
        }
        let answer = AlReconnect {
            report: if known {
                AlReconnectReport::Accept
            } else {
                AlReconnectReport::Reject
            },
            ..reconnect
        };
        let mut pdu = BitBuffer::new_autoexpand(16);
        answer.to_bitbuf(&mut pdu);
        pdu.seek(0);
        self.push_pdu(queue, addr, pdu, None, main);
    }

    fn rx_disc(&mut self, queue: &mut MessageQueue, addr: TetraAddress, disc: AlDisc, main: u16) {
        let ssi = addr.ssi;
        tracing::debug!("LLC: <- ISSI {} {}", ssi, disc);
        self.pending.remove(&ssi);
        let removed = match self.links.get(&ssi) {
            Some(link) if link.al_number == disc.advanced_link_number || disc.report == AlDiscReport::Close => self.links.remove(&ssi),
            _ => None,
        };
        if let Some(mut link) = removed {
            link.fail_all();
        }
        match disc.report {
            AlDiscReport::Close => {
                tracing::info!(
                    "LLC: AL-DISC (close) from ISSI {} for advanced link {} -> AL-DISC (success), link released",
                    ssi,
                    disc.advanced_link_number + 1
                );
                let answer = AlDisc {
                    report: AlDiscReport::Success,
                    ..disc
                };
                self.send_disc(queue, addr, answer, main);
            }
            report => tracing::info!(
                "LLC: AL-DISC ({:?}) from ISSI {} for advanced link {}, link released",
                report,
                ssi,
                disc.advanced_link_number + 1
            ),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Downlink
    // -----------------------------------------------------------------------------------------

    /// A TL-SDU for the advanced link of a radio. Its reporter is Discarded right away when the
    /// link does not exist or the TL-SDU (with its FCS) is longer than N.271.
    pub fn tx_request(&mut self, prim: TlDataReqAl) {
        let service = prim.tx_reporter.unwrap_or_else(TxReporter::new);
        let ssi = prim.main_address.ssi;
        let Some(link) = self.links.get_mut(&ssi) else {
            tracing::debug!("LLC: TL-DATA for ISSI {} on an advanced link that is not up, discarded", ssi);
            report_failed(&service);
            return;
        };
        let octets = (prim.tl_sdu.get_len() + 32).div_ceil(8);
        let why = if !link.connected() {
            Some("the link is being closed".to_string())
        } else if link.al_number != prim.al_number {
            Some(format!("the radio's link is number {}", link.al_number + 1))
        } else if octets > link.n271 {
            Some(format!("{} octets with the FCS, N.271 is {}", octets, link.n271))
        } else if link.queue.len() >= MAX_QUEUED_SDUS {
            Some("too many TL-SDUs waiting".to_string())
        } else {
            None
        };
        if let Some(why) = why {
            tracing::info!(
                "LLC: TL-DATA for ISSI {} on advanced link {} discarded: {}",
                ssi,
                prim.al_number + 1,
                why
            );
            report_failed(&service);
            return;
        }
        link.queue.push_back((prim.tl_sdu, service));
    }

    /// One tick: timers, MAC reports, and at most one new data segment for the MCCH.
    pub fn tick_end(&mut self, queue: &mut MessageQueue, main: u16) -> bool {
        self.clock += 1;
        let clock = self.clock;
        self.activity = false;

        // Our AL-SETUP "service change" unanswered: send it again, up to N.262 times.
        let mut resend = Vec::new();
        self.pending.retain(|ssi, p| {
            if clock.saturating_sub(p.sent_at) < ANSWER_WAIT_SLOTS {
                return true;
            }
            if u32::from(p.retries) >= N262_AL_MAX_CONNECTION_SETUP_RETRIES {
                tracing::info!("LLC: ISSI {} never accepted the AL-SETUP service change, forgotten", ssi);
                return false;
            }
            p.retries += 1;
            p.sent_at = clock;
            resend.push((p.addr, p.answer));
            true
        });
        for (addr, answer) in resend {
            self.send_setup(queue, addr, &answer, main);
        }

        let ssis: Vec<u32> = self.links.keys().copied().collect();
        for ssi in ssis {
            self.link_timers(queue, ssi, main);
        }

        self.send_next_segment(queue, main);
        self.send_multislot_segments(queue, main);
        self.activity
    }

    fn link_timers(&mut self, queue: &mut MessageQueue, ssi: u32, main: u16) {
        let clock = self.clock;
        let Some(link) = self.links.get_mut(&ssi) else { return };
        if let LinkState::Disconnecting { retries, sent_at } = link.state {
            if clock.saturating_sub(sent_at) < ANSWER_WAIT_SLOTS {
                return;
            }
            if u32::from(retries) >= N263_AL_MAX_DISCONNECTION_RETRIES {
                tracing::info!("LLC: advanced link of ISSI {} released (no answer to AL-DISC)", ssi);
                self.links.remove(&ssi);
                return;
            }
            link.state = LinkState::Disconnecting {
                retries: retries + 1,
                sent_at: clock,
            };
            let (addr, disc) = (link.addr, close_pdu(link.al_number));
            self.send_disc(queue, addr, disc, main);
            return;
        }
        let held = self.in_call.contains(&ssi);
        if held != link.held {
            link.held = held;
            tracing::info!(
                "LLC: ISSI {} {}",
                ssi,
                if held {
                    "in a call: its advanced link waits"
                } else {
                    "out of the call: its advanced link goes on"
                }
            );
        }
        if link.rnr_since.is_some_and(|t| clock.saturating_sub(t) >= T271_SLOTS) {
            tracing::info!("LLC: ISSI {} AL-RNR expired (T.271), sending again", ssi);
            link.rnr_since = None;
        }
        if link.tx.is_none() && link.queue.is_empty() && clock.saturating_sub(link.last_activity) >= LINK_IDLE_SLOTS {
            tracing::info!("LLC: advanced link of ISSI {} idle for an hour, forgotten", ssi);
            self.links.remove(&ssi);
            return;
        }
        let Some(tx) = link.tx.as_mut() else { return };
        // MAC reports on the segments under way.
        let mut reported = false;
        for seg in &mut tx.segments {
            let Some((reporter, ar)) = seg.in_mac.as_ref() else { continue };
            match reporter.get_state() {
                TxState::Pending => {}
                TxState::Discarded => {
                    seg.in_mac = None;
                    seg.sends = seg.sends.saturating_sub(1);
                    seg.need_tx = !seg.acked;
                    reported = true;
                }
                _ => {
                    self.order += 1;
                    seg.done_order = Some(self.order);
                    if *ar {
                        tx.ack_wait = Some(clock);
                        tx.last_ar_order = self.order;
                    }
                    seg.in_mac = None;
                    reported = true;
                }
            }
        }
        if reported {
            link.in_mac_since = tx.segments.iter().any(|s| s.in_mac.is_some()).then_some(clock);
        }
        if tx.segments.iter().all(|s| s.sends > 0 && !s.need_tx && s.in_mac.is_none()) {
            report_transmitted(&tx.service);
        }
        // In a call: T.252 holds (the radio cannot answer).
        if held {
            if let Some(t) = tx.ack_wait.as_mut() {
                *t += 1;
            }
            return;
        }
        // T.252: no acknowledgement came. Ask again with the last segment sent, unless others are
        // still to go (the last of those asks).
        let busy = tx.segments.iter().any(|s| s.need_tx || s.in_mac.is_some());
        if !busy
            && tx.ack_wait.is_some_and(|t| clock.saturating_sub(t) >= T252_SLOTS)
            && let Some(last) = tx.segments.iter_mut().rev().find(|s| !s.acked)
        {
            tracing::debug!("LLC: ISSI {} no AL-ACK for TL-SDU N(S) {} within T.252, asking again", ssi, tx.ns);
            last.need_tx = true;
            tx.ack_wait = None;
        }
    }

    /// Close the link after a TL-SDU failed: AL-DISC "close", resent until answered.
    fn fail_link(&mut self, queue: &mut MessageQueue, ssi: u32, why: &str, main: u16) {
        let Some(link) = self.links.get_mut(&ssi) else { return };
        if let Some(tx) = link.tx.as_ref() {
            tracing::info!(
                "LLC: AL {} ISSI {} TL-SDU N(S) {} failed ({}), closing the link with AL-DISC",
                link.al_number + 1,
                ssi,
                tx.ns,
                why
            );
        }
        link.fail_all();
        link.rx.clear();
        link.state = LinkState::Disconnecting {
            retries: 0,
            sent_at: self.clock,
        };
        let (addr, disc) = (link.addr, close_pdu(link.al_number));
        self.send_disc(queue, addr, disc, main);
    }

    /// The next link on the MCCH or a one-slot channel with a segment to send, round robin.
    fn next_to_serve(&self) -> Option<u32> {
        let mut ssis: Vec<u32> = self
            .links
            .iter()
            .filter(|(ssi, l)| {
                l.connected()
                    && !self.in_call.contains(ssi)
                    && self.width(**ssi) == 1
                    && match &l.tx {
                        Some(tx) => tx.segments.iter().all(|s| s.in_mac.is_none()) && tx.segments.iter().any(|s| s.need_tx),
                        None => !l.queue.is_empty() && l.rnr_since.is_none(),
                    }
            })
            .map(|(k, _)| *k)
            .collect();
        ssis.sort_unstable();
        let after = self.last_served;
        ssis.iter().find(|k| after.is_none_or(|last| **k > last)).or(ssis.first()).copied()
    }

    fn send_next_segment(&mut self, queue: &mut MessageQueue, main: u16) {
        if let Some(inflight) = &self.inflight {
            let pending = inflight.reporter.get_state() == TxState::Pending;
            if pending && self.clock.saturating_sub(inflight.since) < INFLIGHT_GUARD_SLOTS {
                return;
            }
            if pending {
                tracing::debug!(
                    "LLC: the MAC never reported the AL segment for ISSI {}, not waiting for it any longer",
                    inflight.ssi
                );
                let ssi = inflight.ssi;
                if let Some(tx) = self.links.get_mut(&ssi).and_then(|l| l.tx.as_mut()) {
                    for seg in &mut tx.segments {
                        if seg.in_mac.take().is_some() {
                            seg.need_tx = !seg.acked;
                        }
                    }
                }
            }
            self.inflight = None;
        }
        let Some(ssi) = self.next_to_serve() else { return };
        self.last_served = Some(ssi);
        let Some(reporter) = self.send_segment(queue, ssi, main) else { return };
        self.inflight = Some(Inflight {
            ssi,
            reporter,
            since: self.clock,
        });
    }

    /// Links on a packet-data channel of several slots (whose PDUs never go on the MCCH): each
    /// keeps up to one segment per slot of its channel in the MAC, outside the one-segment rule
    /// of the MCCH. Segments the MAC never reports on go again after `INFLIGHT_GUARD_SLOTS`.
    fn send_multislot_segments(&mut self, queue: &mut MessageQueue, main: u16) {
        let clock = self.clock;
        let mut ssis: Vec<u32> = self
            .links
            .iter()
            .filter(|(ssi, l)| l.connected() && !self.in_call.contains(ssi) && self.width(**ssi) > 1)
            .map(|(ssi, _)| *ssi)
            .collect();
        ssis.sort_unstable();
        for ssi in ssis {
            let width = self.width(ssi);
            let in_mac = |l: &Link| l.tx.as_ref().map_or(0, |tx| tx.segments.iter().filter(|s| s.in_mac.is_some()).count());
            if let Some(link) = self.links.get_mut(&ssi) {
                if in_mac(link) == 0 {
                    link.in_mac_since = None;
                } else if link.in_mac_since.is_some_and(|t| clock.saturating_sub(t) >= INFLIGHT_GUARD_SLOTS)
                    && let Some(tx) = link.tx.as_mut()
                {
                    tracing::debug!(
                        "LLC: the MAC never reported the AL segments for ISSI {}, not waiting for them any longer",
                        ssi
                    );
                    for seg in &mut tx.segments {
                        if seg.in_mac.take().is_some() {
                            seg.need_tx = !seg.acked;
                        }
                    }
                    link.in_mac_since = None;
                }
            }
            loop {
                let Some(link) = self.links.get(&ssi) else { break };
                let more = match &link.tx {
                    Some(tx) => tx.segments.iter().any(|s| s.need_tx && !s.acked && s.in_mac.is_none()),
                    None => !link.queue.is_empty() && link.rnr_since.is_none(),
                };
                if !more || in_mac(link) >= width || self.send_segment(queue, ssi, main).is_none() {
                    break;
                }
                if let Some(link) = self.links.get_mut(&ssi)
                    && link.in_mac_since.is_none()
                {
                    link.in_mac_since = Some(clock);
                }
            }
        }
    }

    /// Push the next segment of the link of `ssi` to the MAC: the first one to send that is not
    /// there yet, of the TL-SDU under way or of the next one queued. A segment past N.274 sends
    /// the whole TL-SDU again (N.273), once nothing of it is left in the MAC; past N.273 the link
    /// is closed. Returns the segment's report.
    fn send_segment(&mut self, queue: &mut MessageQueue, ssi: u32, main: u16) -> Option<TxReporter> {
        let clock = self.clock;
        let width = self.width(ssi);
        let link = self.links.get_mut(&ssi)?;
        link.last_activity = clock;
        if link.tx.is_none() {
            let (sdu, service) = link.queue.pop_front()?;
            let ns = link.next_ns;
            link.next_ns = (ns + 1) & 7;
            link.tx = Some(start_sdu(ns, sdu, service));
        }
        let (n273, n274, al_number, addr) = (link.n273, link.n274, link.al_number, link.addr);
        let tx = link.tx.as_mut()?;
        let idx = tx.segments.iter().position(|s| s.need_tx && !s.acked && s.in_mac.is_none())?;
        if tx.segments[idx].sends > n274 {
            if tx.segments.iter().any(|s| s.in_mac.is_some()) {
                return None;
            }
            if tx.sdu_retx >= n273 {
                self.fail_link(queue, ssi, "N.274 and N.273 exhausted", main);
                return None;
            }
            restart_sdu(tx);
            tracing::info!(
                "LLC: AL {} ISSI {} segment {} of TL-SDU N(S) {} exhausted N.274, sending the whole TL-SDU again (attempt {})",
                al_number + 1,
                ssi,
                idx,
                tx.ns,
                tx.sdu_retx + 1
            );
        }
        let idx = tx.segments.iter().position(|s| s.need_tx && !s.acked && s.in_mac.is_none())?;
        let last = tx.segments.len() - 1;
        let others_waiting = tx.segments[idx + 1..].iter().any(|s| s.need_tx && !s.acked);
        // On a channel of several slots fewer acknowledgement requests (each answer makes the
        // half-duplex radio deaf around it): one every SEGMENTS_PER_ACK_REQUEST per slot.
        let ar = idx == last || (idx + 1) % (SEGMENTS_PER_ACK_REQUEST * width) == 0 || !others_waiting;
        let header = AlData {
            final_segment: idx == last,
            acknowledgement_requested: ar,
            ns: tx.ns,
            ss: idx as u8,
        };
        let seg = &mut tx.segments[idx];
        if seg.sends > 0 {
            tx.retransmissions += 1;
        }
        seg.sends += 1;
        seg.need_tx = false;
        let reporter = TxReporter::new_unacked();
        seg.in_mac = Some((reporter.clone(), ar));
        let mut pdu = BitBuffer::new_autoexpand(AL_DATA_HEADER_BITS + seg.bits.get_len());
        header.to_bitbuf(&mut pdu);
        let mut bits = BitBuffer::from_bitbuffer(&seg.bits);
        bits.seek(0);
        let len = bits.get_len();
        pdu.copy_bits(&mut bits, len);
        pdu.seek(0);
        tracing::debug!("LLC: -> ISSI {} {} ({} bits)", ssi, header, len);
        self.push_pdu(queue, addr, pdu, Some(reporter.clone()), main);
        Some(reporter)
    }
}

fn close_pdu(al_number: u8) -> AlDisc {
    AlDisc {
        acknowledged_service: true,
        advanced_link_number: al_number,
        report: AlDiscReport::Close,
    }
}

/// The TL-SDU with its FCS (clause 22.3.3.2.6), cut in segments.
fn start_sdu(ns: u8, sdu: BitBuffer, service: TxReporter) -> TxSdu {
    let mut src = BitBuffer::from_bitbuffer(&sdu);
    src.seek(0);
    let sdu_bits = src.get_len();
    let mut with_fcs = BitBuffer::new_autoexpand(sdu_bits + 32);
    with_fcs.copy_bits(&mut src, sdu_bits);
    let fcs_value = fcs::compute_fcs(&with_fcs, 0, with_fcs.get_len());
    with_fcs.write_bits(fcs_value as u64, 32);
    with_fcs.seek(0);
    let mut segments = Vec::new();
    while with_fcs.get_len_remaining() > 0 {
        let n = with_fcs.get_len_remaining().min(AL_SEGMENT_BITS);
        let mut bits = BitBuffer::new_autoexpand(n);
        bits.copy_bits(&mut with_fcs, n);
        bits.seek(0);
        segments.push(Segment {
            bits,
            acked: false,
            need_tx: true,
            sends: 0,
            in_mac: None,
            done_order: None,
        });
    }
    TxSdu {
        ns,
        segments,
        octets: sdu_bits.div_ceil(8),
        service,
        sdu_retx: 0,
        retransmissions: 0,
        ack_wait: None,
        last_ar_order: 0,
    }
}

/// Send the whole TL-SDU again with the same segmentation (clause 22.3.3.2.4).
fn restart_sdu(tx: &mut TxSdu) {
    tx.sdu_retx += 1;
    tx.ack_wait = None;
    for seg in &mut tx.segments {
        seg.acked = false;
        seg.need_tx = true;
        seg.sends = 0;
        seg.done_order = None;
    }
}

/// Selective acknowledgement block for a TL-SDU still incomplete (table 21.13): S(R) is the
/// eldest missing segment, the bitmap covers the ones after it up to the highest received (or the
/// final one).
fn selective_block(ns: u8, segments: &BTreeMap<u8, BitBuffer>, final_ss: Option<u8>) -> AlAckBlock {
    let highest_received = segments.keys().next_back().copied().unwrap_or(0);
    let highest = final_ss.unwrap_or(highest_received);
    let first_missing = (0..=highest)
        .find(|ss| !segments.contains_key(ss))
        .unwrap_or_else(|| highest.saturating_add(1));
    let highest = highest.max(first_missing);
    let len = highest
        .saturating_sub(first_missing)
        .saturating_add(1)
        .min(AlAckBlock::ACK_LENGTH_MAX_SELECTIVE_SEGMENTS);
    let mut bitmap = 0u64;
    for offset in 1..len {
        if segments.contains_key(&first_missing.saturating_add(offset)) {
            bitmap |= 1u64 << (offset - 1);
        }
    }
    AlAckBlock::selective(ns, first_missing, bitmap, len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tetra_core::SsiType;
    use tetra_pdus::umac::enums::basic_slotgrant_cap_alloc::BasicSlotgrantCapAlloc;
    use tetra_pdus::umac::enums::basic_slotgrant_granting_delay::BasicSlotgrantGrantingDelay;
    use tetra_pdus::umac::fields::basic_slotgrant::BasicSlotgrant;
    use tetra_pdus::umac::pdus::mac_resource::MacResource;

    const ISSI: u32 = 2_260_618;
    const MAIN: u16 = 1521;

    /// The largest MAC-RESOURCE header the MAC puts on a PDU for an ISSI: address, usage marker
    /// and an integrated slot grant.
    fn largest_header() -> MacResource {
        MacResource {
            fill_bits: false,
            pos_of_grant: 0,
            encryption_mode: 0,
            random_access_flag: true,
            length_ind: 0,
            addr: Some(TetraAddress::new(ISSI, SsiType::Issi)),
            event_label: None,
            usage_marker: Some(5),
            power_control_element: None,
            slot_granting_element: Some(BasicSlotgrant {
                capacity_allocation: BasicSlotgrantCapAlloc::FirstSubslotGranted,
                granting_delay: BasicSlotgrantGrantingDelay::CapAllocAtNextOpportunity,
            }),
            chan_alloc_element: None,
        }
    }

    #[test]
    fn a_segment_and_the_largest_mac_resource_header_fill_one_sch_f() {
        assert_eq!(largest_header().compute_header_len(), MAC_RESOURCE_HEADER_BITS);
        assert_eq!(MAC_RESOURCE_HEADER_BITS + AL_DATA_HEADER_BITS + AL_SEGMENT_BITS, SCH_F_CAP);
        assert_eq!(AL_SEGMENT_BITS, 194);
    }

    #[test]
    fn a_full_segment_with_a_slot_grant_is_not_fragmented_by_the_mac() {
        use crate::umac::subcomp::bs_frag::BsFragger;
        let mut pdu = BitBuffer::new_autoexpand(SCH_F_CAP);
        AlData {
            final_segment: false,
            acknowledgement_requested: true,
            ns: 7,
            ss: 255,
        }
        .to_bitbuf(&mut pdu);
        for _ in 0..AL_SEGMENT_BITS / 2 {
            pdu.write_bits(0b10, 2);
        }
        pdu.seek(0);
        let mut fragger = BsFragger::new(largest_header(), pdu, None);
        let mut block = BitBuffer::new(SCH_F_CAP);
        assert!(fragger.get_next_chunk(&mut block), "one SCH/F, no MAC-FRAG");
    }

    fn proposal() -> AlSetup {
        AlSetup {
            acknowledged_service: true,
            advanced_link_number: 0,
            max_tl_sdu_len_code: 6,
            connection_width: false,
            advanced_link_symmetry: false,
            uplink_timeslots: None,
            downlink_timeslots: None,
            throughput_code: 6,
            window_size_code: 1,
            max_tl_sdu_retransmissions: 3,
            max_segment_retransmissions: 3,
            setup_report: AlSetup::SETUP_REPORT_SERVICE_DEFINITION,
            ns: None,
            augmented: None,
        }
    }

    /// The radio's parameters are agreed as proposed ("success"), as Nexus-BS answers the
    /// MXP600; only a request for more than one slot gets "service change".
    #[test]
    fn negotiation_keeps_the_radios_parameters_but_the_slots() {
        let answer = negotiate_setup(&proposal());
        assert_eq!(answer.setup_report, AlSetup::SETUP_REPORT_SUCCESS);
        assert_eq!(
            AlSetup {
                setup_report: AlSetup::SETUP_REPORT_SERVICE_DEFINITION,
                ..answer
            },
            proposal()
        );
        let mut big = proposal();
        big.max_tl_sdu_len_code = 7;
        big.max_tl_sdu_retransmissions = 7;
        big.max_segment_retransmissions = 15;
        big.window_size_code = 3;
        let answer = negotiate_setup(&big);
        assert_eq!(answer.setup_report, AlSetup::SETUP_REPORT_SUCCESS);
        assert_eq!(
            AlSetup {
                setup_report: AlSetup::SETUP_REPORT_SERVICE_DEFINITION,
                ..answer
            },
            big
        );
        big.connection_width = true;
        big.uplink_timeslots = Some(3);
        let answer = negotiate_setup(&big);
        assert_eq!(answer.setup_report, AlSetup::SETUP_REPORT_SERVICE_CHANGE);
        assert_eq!(
            (
                answer.max_tl_sdu_len_code,
                answer.max_tl_sdu_retransmissions,
                answer.max_segment_retransmissions,
                answer.window_size_code,
                answer.uplink_timeslots
            ),
            (7, 7, 15, 3, Some(0))
        );
        // Lower values are never raised.
        let mut small = proposal();
        small.max_tl_sdu_len_code = 1;
        small.max_tl_sdu_retransmissions = 0;
        small.max_segment_retransmissions = 0;
        let answer = negotiate_setup(&small);
        assert_eq!(answer.setup_report, AlSetup::SETUP_REPORT_SUCCESS);
        assert_eq!(
            (
                answer.max_tl_sdu_len_code,
                answer.max_tl_sdu_retransmissions,
                answer.max_segment_retransmissions
            ),
            (1, 0, 0)
        );
    }

    #[test]
    fn an_extended_link_is_answered_with_an_original_one() {
        let mut ext = proposal();
        ext.window_size_code = 0;
        ext.augmented = Some(tetra_pdus::llc::pdus::al_setup::AlSetupAugmented {
            extended_advanced_link: true,
            original_window_size_code: None,
            extended_window_size_code: Some(8),
            reserved: 0,
        });
        let answer = negotiate_setup(&ext);
        assert_eq!(answer.setup_report, AlSetup::SETUP_REPORT_SERVICE_CHANGE);
        assert!(answer.augmented.is_none() && answer.is_original_acknowledged_non_augmented());
        assert_eq!(answer.window_size_code, 3);
    }

    #[test]
    fn selective_blocks_follow_table_21_13() {
        let seg = |ss: &[u8]| ss.iter().map(|s| (*s, BitBuffer::new(8))).collect::<BTreeMap<u8, BitBuffer>>();
        // 0 and 1 received, final unknown: S(R) 2, length 1.
        let b = selective_block(0, &seg(&[0, 1]), None);
        assert_eq!((b.sr, b.acknowledgement_length, b.acknowledgement_bitmap), (Some(2), 1, 0));
        // Only 1 received: S(R) 0, length 2, bitmap "1".
        let b = selective_block(0, &seg(&[1]), None);
        assert_eq!((b.sr, b.acknowledgement_length, b.acknowledgement_bitmap), (Some(0), 2, 1));
        // 0, 2 and final 4 received: S(R) 1, then 2 yes, 3 no, 4 yes.
        let b = selective_block(3, &seg(&[0, 2, 4]), Some(4));
        assert_eq!(
            (b.nr, b.sr, b.acknowledgement_length, b.acknowledgement_bitmap),
            (3, Some(1), 4, 0b101)
        );
    }

    fn ind(pdu: BitBuffer) -> TmaUnitdataInd {
        TmaUnitdataInd {
            carrier_num: MAIN,
            pdu: Some(pdu),
            main_address: TetraAddress::new(ISSI, SsiType::Issi),
            scrambling_code: 0,
            link_id: 1,
            endpoint_id: 0,
            new_endpoint_id: None,
            css_endpoint_id: None,
            air_interface_encryption: 0,
            chan_change_response_req: false,
            chan_change_handle: None,
            chan_info: None,
        }
    }

    fn setup_link(engine: &mut AdvancedLinkEngine, queue: &mut MessageQueue, n274: u8, n273: u8) {
        let mut p = proposal();
        p.max_segment_retransmissions = n274;
        p.max_tl_sdu_retransmissions = n273;
        let mut pdu = BitBuffer::new_autoexpand(32);
        p.to_bitbuf(&mut pdu);
        pdu.seek(0);
        engine.rx(queue, &ind(pdu.clone()), pdu, LlcPduType::AlSetup, MAIN);
        assert!(engine.has_link(ISSI));
        while queue.pop_front().is_some() {}
    }

    /// Run ticks reporting every data segment transmitted; returns the AL-DATA headers sent.
    fn run(engine: &mut AdvancedLinkEngine, queue: &mut MessageQueue, ticks: usize) -> Vec<AlData> {
        let mut sent = Vec::new();
        for _ in 0..ticks {
            engine.tick_end(queue, MAIN);
            while let Some(msg) = queue.pop_front() {
                let SapMsgInner::TmaUnitdataReq(req) = msg.msg else { continue };
                assert!(!req.stealing_permission && req.chan_alloc.is_none() && req.link_id == 0);
                let mut pdu = req.pdu.clone();
                if pdu.peek_bits(4) == Some(9) {
                    sent.push(AlData::from_bitbuf(&mut pdu).unwrap());
                }
                if let Some(r) = req.tx_reporter {
                    r.mark_transmitted();
                }
            }
        }
        sent
    }

    fn ack(engine: &mut AdvancedLinkEngine, queue: &mut MessageQueue, ack: AlAck) {
        let mut pdu = BitBuffer::new_autoexpand(32);
        ack.to_bitbuf(&mut pdu);
        pdu.seek(0);
        engine.rx(queue, &ind(pdu.clone()), pdu, LlcPduType::AlAckAlRnr, MAIN);
    }

    fn request(engine: &mut AdvancedLinkEngine, octets: usize) -> TxReporter {
        let reporter = TxReporter::new();
        engine.tx_request(TlDataReqAl {
            main_address: TetraAddress::new(ISSI, SsiType::Issi),
            al_number: 0,
            tl_sdu: BitBuffer::from_bytes(&vec![0x5a; octets]),
            tx_reporter: Some(reporter.clone()),
        });
        reporter
    }

    /// The radio sends TL-SDU `ns` (one octet `byte` and its FCS) in two segments, `which` of them
    /// (0, 1), asking for an acknowledgement on the last one sent when `ar`. Returns the octets
    /// delivered up and the AL-ACK blocks as (N(R), complete, S(R)).
    fn radio_sends(
        engine: &mut AdvancedLinkEngine,
        queue: &mut MessageQueue,
        ns: u8,
        byte: u8,
        which: &[u8],
        ar: bool,
    ) -> (Vec<u8>, Vec<(u8, bool, Option<u8>)>) {
        let mut sdu = BitBuffer::new_autoexpand(40);
        sdu.write_bits(byte as u64, 8);
        let value = fcs::compute_fcs(&sdu, 0, 8);
        sdu.write_bits(value as u64, 32);
        sdu.seek(0);
        let halves = [sdu.read_bits(20).unwrap(), sdu.read_bits(20).unwrap()];
        for (i, ss) in which.iter().enumerate() {
            let mut pdu = BitBuffer::new_autoexpand(40);
            AlData {
                final_segment: *ss == 1,
                acknowledgement_requested: ar && i + 1 == which.len(),
                ns,
                ss: *ss,
            }
            .to_bitbuf(&mut pdu);
            pdu.write_bits(halves[*ss as usize], 20);
            pdu.seek(0);
            engine.rx(queue, &ind(pdu.clone()), pdu, LlcPduType::AlDataAlFinal, MAIN);
        }
        let (mut up, mut blocks) = (Vec::new(), Vec::new());
        while let Some(msg) = queue.pop_front() {
            match msg.msg {
                SapMsgInner::TlaTlDataIndAl(ind) => up.push(ind.tl_sdu.peek_bits(8).unwrap() as u8),
                SapMsgInner::TmaUnitdataReq(req) => {
                    let ack = AlAck::from_bitbuf(&mut req.pdu.clone()).unwrap();
                    blocks.extend(
                        ack.acknowledgement_blocks
                            .iter()
                            .map(|b| (b.nr, b.acknowledges_complete_tl_sdu(), b.sr)),
                    );
                }
                _ => {}
            }
        }
        (up, blocks)
    }

    #[test]
    fn acks_name_only_the_tl_sdus_received() {
        let mut engine = AdvancedLinkEngine::new();
        let mut queue = MessageQueue::new();
        setup_link(&mut engine, &mut queue, 3, 3);
        assert_eq!(
            radio_sends(&mut engine, &mut queue, 0, 0xa0, &[0, 1], true),
            (vec![0xa0], vec![(0, true, None)])
        );
        for ns in 1..6 {
            radio_sends(&mut engine, &mut queue, ns, ns, &[0, 1], false);
        }
        let (up, blocks) = radio_sends(&mut engine, &mut queue, 6, 6, &[0, 1], true);
        assert_eq!(up, vec![6]);
        assert_eq!(blocks, vec![(6, true, None)], "no block for TL-SDUs not sent yet");
        // A repeat of a delivered TL-SDU is acknowledged again, not delivered again.
        assert_eq!(
            radio_sends(&mut engine, &mut queue, 6, 6, &[1], true),
            (vec![], vec![(6, true, None)])
        );
    }

    #[test]
    fn a_window_of_three_delivers_in_order() {
        let mut engine = AdvancedLinkEngine::new();
        let mut queue = MessageQueue::new();
        let mut p = proposal();
        p.window_size_code = 3;
        let mut pdu = BitBuffer::new_autoexpand(32);
        p.to_bitbuf(&mut pdu);
        pdu.seek(0);
        engine.rx(&mut queue, &ind(pdu.clone()), pdu, LlcPduType::AlSetup, MAIN);
        while queue.pop_front().is_some() {}
        // TL-SDU 0 loses its first segment; TL-SDU 1 comes whole.
        let (up, blocks) = radio_sends(&mut engine, &mut queue, 0, 0xb0, &[1], true);
        assert!(up.is_empty());
        assert_eq!(blocks, vec![(0, false, Some(0))]);
        let (up, blocks) = radio_sends(&mut engine, &mut queue, 1, 0xb1, &[0, 1], true);
        assert!(up.is_empty(), "held until TL-SDU 0");
        assert_eq!(blocks, vec![(0, false, Some(0)), (1, true, None)]);
        let (up, blocks) = radio_sends(&mut engine, &mut queue, 0, 0xb0, &[0], true);
        assert_eq!(up, vec![0xb0, 0xb1], "delivered in N(S) order");
        assert_eq!(blocks, vec![(0, true, None), (1, true, None)]);
        // Outside the window (V(R) is 2, window 3): N(S) 5 is dropped.
        let (up, blocks) = radio_sends(&mut engine, &mut queue, 5, 0xb5, &[0, 1], true);
        assert!(up.is_empty() && blocks.is_empty());
    }

    #[test]
    fn one_segment_at_a_time_and_complete_ack() {
        let mut engine = AdvancedLinkEngine::new();
        let mut queue = MessageQueue::new();
        setup_link(&mut engine, &mut queue, 3, 3);
        // 100 octets + FCS = 832 bits = 5 segments.
        let service = request(&mut engine, 100);
        let mut sent = Vec::new();
        for _ in 0..5 {
            engine.tick_end(&mut queue, MAIN);
            let mut n = 0;
            while let Some(msg) = queue.pop_front() {
                let SapMsgInner::TmaUnitdataReq(req) = msg.msg else { continue };
                n += 1;
                let mut pdu = req.pdu.clone();
                sent.push(AlData::from_bitbuf(&mut pdu).unwrap());
                // Not reported yet: nothing more goes down.
                engine.tick_end(&mut queue, MAIN);
                assert!(queue.pop_front().is_none(), "one segment in the MAC at a time");
                req.tx_reporter.unwrap().mark_transmitted();
            }
            assert_eq!(n, 1);
        }
        assert_eq!(
            sent.iter()
                .map(|h| (h.ss, h.acknowledgement_requested, h.final_segment))
                .collect::<Vec<_>>(),
            vec![
                (0, false, false),
                (1, false, false),
                (2, false, false),
                (3, true, false),
                (4, true, true)
            ]
        );
        engine.tick_end(&mut queue, MAIN);
        assert_eq!(service.get_state(), TxState::Transmitted);
        ack(&mut engine, &mut queue, AlAck::complete(0));
        assert_eq!(service.get_state(), TxState::Acknowledged);
        // The next TL-SDU takes N(S) 1.
        let _ = request(&mut engine, 10);
        let sent = run(&mut engine, &mut queue, 2);
        assert_eq!(sent[0].ns, 1);
    }

    #[test]
    fn selective_ack_resends_only_the_missing_segment() {
        let mut engine = AdvancedLinkEngine::new();
        let mut queue = MessageQueue::new();
        setup_link(&mut engine, &mut queue, 3, 3);
        let service = request(&mut engine, 100);
        run(&mut engine, &mut queue, 8);
        // Segment 2 lost.
        ack(&mut engine, &mut queue, AlAck::selective(true, 0, 2, 0b11, 3));
        let sent = run(&mut engine, &mut queue, 4);
        assert_eq!(
            sent.iter().map(|h| (h.ss, h.acknowledgement_requested)).collect::<Vec<_>>(),
            vec![(2, true)]
        );
        ack(&mut engine, &mut queue, AlAck::complete(0));
        assert_eq!(service.get_state(), TxState::Acknowledged);
    }

    #[test]
    fn an_ack_does_not_resend_segments_sent_after_its_request() {
        let mut engine = AdvancedLinkEngine::new();
        let mut queue = MessageQueue::new();
        setup_link(&mut engine, &mut queue, 3, 3);
        let _service = request(&mut engine, 100);
        // Segments 0..3 out (3 asks), then 4 too.
        run(&mut engine, &mut queue, 5);
        // The answer to the request on segment 3: all up to 3 received, 4 unknown.
        ack(&mut engine, &mut queue, AlAck::selective(true, 0, 4, 0, 1));
        assert!(run(&mut engine, &mut queue, 3).is_empty(), "segment 4 left after that request");
    }

    /// N.273 and N.274 as agreed with the radio, but at most 3 and 5 retries here.
    #[test]
    fn retries_are_bounded_whatever_was_agreed() {
        let mut engine = AdvancedLinkEngine::new();
        let mut queue = MessageQueue::new();
        setup_link(&mut engine, &mut queue, 15, 7);
        let link = &engine.links[&ISSI];
        assert_eq!((link.n273, link.n274, link.n271), (3, 5, 2048));
    }

    #[test]
    fn t252_asks_again_then_n274_then_n273_then_disc() {
        let mut engine = AdvancedLinkEngine::new();
        let mut queue = MessageQueue::new();
        // N.274 = 1, N.273 = 1.
        setup_link(&mut engine, &mut queue, 1, 1);
        let service = request(&mut engine, 10);
        let mut headers = Vec::new();
        let mut discs = 0;
        for _ in 0..(T252_SLOTS as usize + 2) * 6 {
            if !engine.has_link(ISSI) {
                break;
            }
            engine.tick_end(&mut queue, MAIN);
            while let Some(msg) = queue.pop_front() {
                let SapMsgInner::TmaUnitdataReq(req) = msg.msg else { continue };
                let mut pdu = req.pdu.clone();
                match pdu.peek_bits(4) {
                    Some(9) => headers.push(AlData::from_bitbuf(&mut pdu).unwrap()),
                    Some(15) => {
                        assert_eq!(AlDisc::from_bitbuf(&mut pdu).unwrap().report, AlDiscReport::Close);
                        discs += 1;
                    }
                    other => panic!("unexpected {other:?}"),
                }
                if let Some(r) = req.tx_reporter {
                    r.mark_transmitted();
                }
            }
        }
        // Single segment: first send, one T.252 retry (N.274 = 1), then the whole TL-SDU again
        // (N.273 = 1) with its own retry, then failure.
        assert_eq!(headers.len(), 4, "{headers:?}");
        assert!(headers.iter().all(|h| h.acknowledgement_requested && h.final_segment));
        assert_eq!(discs, 1);
        assert_eq!(service.get_state(), TxState::Lost);
        assert!(!engine.has_link(ISSI));
        // No answer to AL-DISC: sent again N.263 times, then the link is gone.
        let mut more = 0;
        for _ in 0..(ANSWER_WAIT_SLOTS as usize + 1) * 5 {
            engine.tick_end(&mut queue, MAIN);
            while queue.pop_front().is_some() {
                more += 1;
            }
        }
        assert_eq!(more, N263_AL_MAX_DISCONNECTION_RETRIES as usize);
        assert!(engine.links.is_empty());
    }

    /// While its radio is in a call a link sends nothing (no T.252 re-ask, no new TL-SDU) and
    /// T.252 holds; after the call it goes on.
    #[test]
    fn a_radio_in_a_call_holds_its_link() {
        let mut engine = AdvancedLinkEngine::new();
        let mut queue = MessageQueue::new();
        setup_link(&mut engine, &mut queue, 3, 3);
        let first = request(&mut engine, 10);
        assert_eq!(run(&mut engine, &mut queue, 2).len(), 1, "one segment, asking for an ack");
        assert_eq!(engine.busy_ssis(), vec![ISSI]);
        engine.set_in_call(HashSet::from([ISSI]));
        let _second = request(&mut engine, 10);
        for _ in 0..3 * T252_SLOTS as usize {
            engine.tick_end(&mut queue, MAIN);
            assert!(queue.pop_front().is_none(), "nothing during the call");
        }
        engine.set_in_call(HashSet::new());
        ack(&mut engine, &mut queue, AlAck::complete(0));
        assert_eq!(first.get_state(), TxState::Acknowledged);
        let sent = run(&mut engine, &mut queue, 2);
        assert_eq!(sent.first().map(|h| h.ns), Some(1), "the next TL-SDU after the call");
    }

    #[test]
    fn rnr_holds_new_tl_sdus_until_ack_or_t271() {
        let mut engine = AdvancedLinkEngine::new();
        let mut queue = MessageQueue::new();
        setup_link(&mut engine, &mut queue, 3, 3);
        let first = request(&mut engine, 10);
        run(&mut engine, &mut queue, 2);
        let mut rnr = AlAck::complete(0);
        rnr.receiver_ready = false;
        ack(&mut engine, &mut queue, rnr);
        assert_eq!(first.get_state(), TxState::Acknowledged, "AL-RNR acknowledges too");
        let _second = request(&mut engine, 10);
        assert!(run(&mut engine, &mut queue, 10).is_empty(), "receiver not ready");
        ack(&mut engine, &mut queue, AlAck::complete(0));
        assert_eq!(run(&mut engine, &mut queue, 2).len(), 1, "AL-ACK: ready again");
        // T.271 alone also lets the next TL-SDU go.
        ack(&mut engine, &mut queue, {
            let mut r = AlAck::complete(1);
            r.receiver_ready = false;
            r
        });
        let _third = request(&mut engine, 10);
        assert!(run(&mut engine, &mut queue, T271_SLOTS as usize - 2).is_empty());
        assert_eq!(run(&mut engine, &mut queue, 4).len(), 1);
    }

    #[test]
    fn requests_that_do_not_fit_are_discarded_at_once() {
        let mut engine = AdvancedLinkEngine::new();
        let mut queue = MessageQueue::new();
        let no_link = request(&mut engine, 10);
        assert_eq!(no_link.get_state(), TxState::Discarded);
        setup_link(&mut engine, &mut queue, 3, 3);
        // N.271 2048 octets include the FCS.
        assert_eq!(request(&mut engine, 2045).get_state(), TxState::Discarded);
        assert_eq!(request(&mut engine, 2044).get_state(), TxState::Pending);
        let unacked = TxReporter::new_unacked();
        engine.tx_request(TlDataReqAl {
            main_address: TetraAddress::new(ISSI, SsiType::Issi),
            al_number: 1,
            tl_sdu: BitBuffer::from_bytes(&[1]),
            tx_reporter: Some(unacked.clone()),
        });
        assert_eq!(unacked.get_state(), TxState::Discarded, "wrong link number");
    }

    #[test]
    fn no_sequence_of_events_panics_a_reporter() {
        // Discards, late and duplicate ACKs, a new AL-SETUP in the middle, AL-DISC: every service
        // reporter ends in a final state without an invalid transition.
        let mut engine = AdvancedLinkEngine::new();
        let mut queue = MessageQueue::new();
        setup_link(&mut engine, &mut queue, 2, 1);
        let a = request(&mut engine, 60);
        let b = request(&mut engine, 60);
        for i in 0..40 {
            engine.tick_end(&mut queue, MAIN);
            while let Some(msg) = queue.pop_front() {
                let SapMsgInner::TmaUnitdataReq(req) = msg.msg else { continue };
                if let Some(r) = req.tx_reporter {
                    if i % 3 == 0 {
                        r.mark_discarded();
                    } else {
                        r.mark_transmitted();
                    }
                }
            }
            if i == 10 {
                ack(&mut engine, &mut queue, AlAck::complete(0));
                ack(&mut engine, &mut queue, AlAck::complete(0));
                ack(&mut engine, &mut queue, AlAck::repeat_entire(1));
            }
            if i == 20 {
                setup_link(&mut engine, &mut queue, 2, 1);
            }
        }
        assert!(
            a.is_in_final_state() && b.is_in_final_state(),
            "{:?} {:?}",
            a.get_state(),
            b.get_state()
        );
        let c = request(&mut engine, 30);
        run(&mut engine, &mut queue, 3);
        let mut pdu = BitBuffer::new_autoexpand(16);
        close_pdu(0).to_bitbuf(&mut pdu);
        pdu.seek(0);
        engine.rx(&mut queue, &ind(pdu.clone()), pdu, LlcPduType::AlDisc, MAIN);
        assert!(c.is_in_final_state());
        ack(&mut engine, &mut queue, AlAck::complete(2));
        run(&mut engine, &mut queue, 5);
    }

    const ISSI2: u32 = 2_260_619;
    const ISSI3: u32 = 2_260_620;

    /// The answer lowers the radio's slots to the cap and never raises them (22.2.2.1 NOTE 2).
    #[test]
    fn negotiation_lowers_the_slots_to_the_cap() {
        let mut four = proposal();
        four.connection_width = true;
        four.uplink_timeslots = Some(3);
        let answer = negotiate_setup_with(&four, 3);
        assert_eq!(
            (answer.setup_report, answer.uplink_timeslots),
            (AlSetup::SETUP_REPORT_SERVICE_CHANGE, Some(2))
        );
        let answer = negotiate_setup_with(&four, 4);
        assert_eq!(
            (answer.setup_report, answer.uplink_timeslots),
            (AlSetup::SETUP_REPORT_SUCCESS, Some(3))
        );
        assert_eq!(negotiate_setup_with(&four, 1), negotiate_setup(&four));
        let mut two = four;
        two.uplink_timeslots = Some(1);
        let answer = negotiate_setup_with(&two, 3);
        assert_eq!((answer.setup_report, answer.uplink_timeslots), (AlSetup::SETUP_REPORT_SUCCESS, Some(1)));
    }

    #[test]
    fn an_engine_with_a_cap_answers_it() {
        let mut engine = AdvancedLinkEngine::new();
        engine.set_max_timeslots(3);
        let mut queue = MessageQueue::new();
        let mut four = proposal();
        four.connection_width = true;
        four.uplink_timeslots = Some(3);
        let mut pdu = BitBuffer::new_autoexpand(32);
        four.to_bitbuf(&mut pdu);
        pdu.seek(0);
        engine.rx(&mut queue, &ind(pdu.clone()), pdu, LlcPduType::AlSetup, MAIN);
        let Some(SapMsgInner::TmaUnitdataReq(req)) = queue.pop_front().map(|m| m.msg) else {
            panic!("an answer");
        };
        let answer = AlSetup::from_bitbuf(&mut req.pdu.clone()).unwrap();
        assert_eq!(
            (answer.setup_report, answer.uplink_timeslots),
            (AlSetup::SETUP_REPORT_SERVICE_CHANGE, Some(2))
        );
    }

    /// The link of `issi` up, as `setup_link` does for ISSI.
    fn setup_link_of(engine: &mut AdvancedLinkEngine, queue: &mut MessageQueue, issi: u32) {
        let mut pdu = BitBuffer::new_autoexpand(32);
        proposal().to_bitbuf(&mut pdu);
        pdu.seek(0);
        let mut i = ind(pdu.clone());
        i.main_address = TetraAddress::new(issi, SsiType::Issi);
        engine.rx(queue, &i, pdu, LlcPduType::AlSetup, MAIN);
        assert!(engine.has_link(issi));
        while queue.pop_front().is_some() {}
    }

    fn request_to(engine: &mut AdvancedLinkEngine, issi: u32, octets: usize) -> TxReporter {
        let reporter = TxReporter::new();
        engine.tx_request(TlDataReqAl {
            main_address: TetraAddress::new(issi, SsiType::Issi),
            al_number: 0,
            tl_sdu: BitBuffer::from_bytes(&vec![0x5a; octets]),
            tx_reporter: Some(reporter.clone()),
        });
        reporter
    }

    /// The AL-DATA pushed to the MAC since the last call: (ISSI, header, report, link id).
    fn pushed(queue: &mut MessageQueue) -> Vec<(u32, AlData, TxReporter, u32)> {
        let mut out = Vec::new();
        while let Some(msg) = queue.pop_front() {
            let SapMsgInner::TmaUnitdataReq(req) = msg.msg else { continue };
            let mut pdu = req.pdu.clone();
            if pdu.peek_bits(4) == Some(9) {
                out.push((
                    req.main_address.ssi,
                    AlData::from_bitbuf(&mut pdu).unwrap(),
                    req.tx_reporter.expect("reported"),
                    req.link_id,
                ));
            }
        }
        out
    }

    /// A link on a channel of three slots keeps three segments in the MAC, one more as each
    /// leaves it, all to its channel; one acknowledgement request per twelve segments and on the
    /// last.
    #[test]
    fn a_multislot_link_keeps_up_to_width_segments_in_the_mac() {
        for (octets, requests) in [(100usize, vec![4u8]), (300, vec![11, 12])] {
            let mut engine = AdvancedLinkEngine::new();
            let mut queue = MessageQueue::new();
            setup_link(&mut engine, &mut queue, 3, 3);
            engine.set_pdch_routes(HashMap::from([(ISSI, (MAIN, 4, 3))]));
            let service = request(&mut engine, octets);
            engine.tick_end(&mut queue, MAIN);
            let first = pushed(&mut queue);
            assert_eq!(first.iter().map(|p| (p.1.ss, p.3)).collect::<Vec<_>>(), vec![(0, 4), (1, 4), (2, 4)]);
            engine.tick_end(&mut queue, MAIN);
            assert!(pushed(&mut queue).is_empty(), "three in the MAC");
            first[0].2.mark_transmitted();
            engine.tick_end(&mut queue, MAIN);
            let next = pushed(&mut queue);
            assert_eq!(next.iter().map(|p| p.1.ss).collect::<Vec<_>>(), vec![3]);
            let mut all: Vec<(u32, AlData, TxReporter, u32)> = first.into_iter().chain(next).collect();
            for _ in 0..20 {
                for p in &all {
                    if p.2.get_state() == TxState::Pending {
                        p.2.mark_transmitted();
                    }
                }
                engine.tick_end(&mut queue, MAIN);
                all.extend(pushed(&mut queue));
            }
            assert_eq!(all.len(), (octets * 8 + 32).div_ceil(AL_SEGMENT_BITS));
            assert!(all.iter().all(|p| p.3 == 4));
            let ar: Vec<u8> = all.iter().filter(|p| p.1.acknowledgement_requested).map(|p| p.1.ss).collect();
            assert_eq!(ar, requests, "{octets} octets");
            assert_eq!(service.get_state(), TxState::Transmitted);
        }
    }

    /// The segments of a multislot link never go on the MCCH, so they do not take its one
    /// segment: a link on the MCCH still gets it, and its segment in the MAC still holds the other
    /// MCCH links; the multislot link's pushes never touch that rule.
    #[test]
    fn a_multislot_link_does_not_hold_the_mcch() {
        let mut engine = AdvancedLinkEngine::new();
        let mut queue = MessageQueue::new();
        setup_link(&mut engine, &mut queue, 3, 3);
        setup_link_of(&mut engine, &mut queue, ISSI2);
        setup_link_of(&mut engine, &mut queue, ISSI3);
        engine.set_pdch_routes(HashMap::from([(ISSI, (MAIN, 4, 3))]));
        let _a = request(&mut engine, 100);
        let _b = request_to(&mut engine, ISSI2, 100);
        engine.tick_end(&mut queue, MAIN);
        let p = pushed(&mut queue);
        assert_eq!(p.iter().filter(|x| x.0 == ISSI).count(), 3);
        assert_eq!(p.iter().filter(|x| x.0 == ISSI2).map(|x| x.3).collect::<Vec<_>>(), vec![0], "one on the MCCH");
        let gate = |e: &AdvancedLinkEngine| (e.inflight.as_ref().map(|i| i.ssi), e.last_served);
        assert_eq!(gate(&engine), (Some(ISSI2), Some(ISSI2)));
        let _c = request_to(&mut engine, ISSI3, 10);
        p.iter().find(|x| x.0 == ISSI).unwrap().2.mark_transmitted();
        engine.tick_end(&mut queue, MAIN);
        let p2 = pushed(&mut queue);
        assert_eq!(p2.iter().map(|x| x.0).collect::<Vec<_>>(), vec![ISSI], "the MCCH is still held");
        assert_eq!(gate(&engine), (Some(ISSI2), Some(ISSI2)));
    }

    /// A segment still in the MAC is never pushed again, and a TL-SDU is started again (N.274
    /// exhausted) only once nothing of it is left in the MAC: each segment then goes once.
    #[test]
    fn a_segment_in_the_mac_is_not_pushed_twice() {
        let mut engine = AdvancedLinkEngine::new();
        let mut queue = MessageQueue::new();
        setup_link(&mut engine, &mut queue, 1, 1);
        engine.set_pdch_routes(HashMap::from([(ISSI, (MAIN, 4, 2))]));
        let _service = request(&mut engine, 40);
        engine.tick_end(&mut queue, MAIN);
        let first = pushed(&mut queue);
        assert_eq!(first.iter().map(|p| p.1.ss).collect::<Vec<_>>(), vec![0, 1]);
        // Segment 1 out and reported missing, twice: past N.274 while segment 0 is in the MAC.
        first[1].2.mark_transmitted();
        engine.tick_end(&mut queue, MAIN);
        ack(&mut engine, &mut queue, AlAck::selective(true, 0, 0, 0, 2));
        engine.tick_end(&mut queue, MAIN);
        let again = pushed(&mut queue);
        assert_eq!(again.iter().map(|p| p.1.ss).collect::<Vec<_>>(), vec![1]);
        again[0].2.mark_transmitted();
        engine.tick_end(&mut queue, MAIN);
        ack(&mut engine, &mut queue, AlAck::selective(true, 0, 0, 0, 2));
        engine.tick_end(&mut queue, MAIN);
        assert!(pushed(&mut queue).is_empty(), "no restart while segment 0 is in the MAC");
        first[0].2.mark_transmitted();
        engine.tick_end(&mut queue, MAIN);
        let restart = pushed(&mut queue);
        assert_eq!(restart.iter().map(|p| p.1.ss).collect::<Vec<_>>(), vec![0, 1], "each once");
    }

    /// A one-slot channel is one segment at a time, as the MCCH.
    #[test]
    fn a_one_slot_route_is_one_segment_at_a_time() {
        let mut engine = AdvancedLinkEngine::new();
        let mut queue = MessageQueue::new();
        setup_link(&mut engine, &mut queue, 3, 3);
        engine.set_pdch_routes(HashMap::from([(ISSI, (MAIN, 4, 1))]));
        let _service = request(&mut engine, 100);
        for _ in 0..5 {
            engine.tick_end(&mut queue, MAIN);
            let p = pushed(&mut queue);
            assert_eq!(p.len(), 1);
            assert_eq!(p[0].3, 4);
            engine.tick_end(&mut queue, MAIN);
            assert!(pushed(&mut queue).is_empty(), "one segment in the MAC at a time");
            p[0].2.mark_transmitted();
        }
    }
}
