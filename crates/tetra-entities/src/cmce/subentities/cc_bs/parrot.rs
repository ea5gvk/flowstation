// SPDX-FileCopyrightText: Historical upstream contributors
// SPDX-FileCopyrightText: 2026 Chris YO3TCO / Nexus-BS Project
// SPDX-License-Identifier: Apache-2.0 AND PolyForm-Noncommercial-1.0.0
// SPDX-FileComment: Modified by Nexus-BS Project; see CHANGES-NEXUS.md for change notices.
// SPDX-FileComment: Adapted for flowstation-miura (carrier_num, configurable ISSI and recording limit, repeated U-SETUP) by EA5GVK.

//! Local Parrot/Papagal simplex test service — `parrot_issi` (default 99999).
//!
//! The service records validated UL TCH/S frames from one caller, plays the
//! exact frame payloads back after the caller releases PTT, then clears the
//! private call. Playback is paced by TDMA ticks and intentionally separate
//! from normal local P2P handling.

use std::collections::VecDeque;

use tetra_saps::lcmc::LcmcMleUnitdataInd;
use tetra_saps::tmd::TmdCircuitDataReq;

use super::*;

const TETRA_FRAMES_PER_SECOND: i32 = 18;
const TCH_S_TRAFFIC_FRAMES_PER_SECOND: usize = 17;
const TETRA_TIMESLOTS_PER_SECOND: i32 = TETRA_FRAMES_PER_SECOND * 4;
const PARROT_PLAYBACK_START_GUARD_TIMESLOTS: i32 = 12;
const PARROT_PLAYBACK_DRAIN_TIMESLOTS: i32 = 16;
const PARROT_PLAYBACK_GUARD_SECONDS: i32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ParrotState {
    Recording,
    Playing,
    Releasing,
}

#[derive(Debug)]
pub(super) struct ParrotSession {
    carrier_num: u16,
    ts: u8,
    call_id: u16,
    caller: TetraAddress,
    parrot_issi: u32,
    max_frames: usize,
    playback_deadline_timeslots: i32,
    frames: VecDeque<Vec<u8>>,
    state: ParrotState,
    last_frame_at: Option<TdmaTime>,
    playback_started_at: Option<TdmaTime>,
    playback_release_started_at: Option<TdmaTime>,
    playback_finished: bool,
}

impl ParrotSession {
    pub(super) fn new(carrier_num: u16, ts: u8, call_id: u16, caller: TetraAddress, parrot_issi: u32, max_secs: u32) -> Self {
        Self {
            carrier_num,
            ts,
            call_id,
            caller,
            parrot_issi,
            max_frames: max_secs as usize * TCH_S_TRAFFIC_FRAMES_PER_SECOND,
            playback_deadline_timeslots: (max_secs as i32 + PARROT_PLAYBACK_GUARD_SECONDS) * TETRA_TIMESLOTS_PER_SECOND,
            frames: VecDeque::new(),
            state: ParrotState::Recording,
            last_frame_at: None,
            playback_started_at: None,
            playback_release_started_at: None,
            playback_finished: false,
        }
    }

    pub(super) fn call_id(&self) -> u16 {
        self.call_id
    }

    pub(super) fn state(&self) -> ParrotState {
        self.state
    }

    pub(super) fn caller_issi(&self) -> u32 {
        self.caller.ssi
    }

    pub(super) fn parrot_issi(&self) -> u32 {
        self.parrot_issi
    }

    pub(super) fn owns_slot(&self, carrier_num: u16, ts: u8) -> bool {
        self.carrier_num == carrier_num && self.ts == ts
    }

    /// Record one UL frame of the session's slot. Returns false when the frame is not recorded:
    /// another slot, recording over, or the limit reached.
    pub(super) fn record_ul_frame(&mut self, carrier_num: u16, ts: u8, data: Vec<u8>) -> bool {
        if !self.owns_slot(carrier_num, ts) || self.state != ParrotState::Recording {
            return false;
        }
        if self.frames.len() >= self.max_frames {
            tracing::debug!(
                "CMCE: parrot recording limit reached call_id={} max_frames={}",
                self.call_id,
                self.max_frames
            );
            return false;
        }
        self.frames.push_back(data);
        true
    }

    pub(super) fn recorded_len(&self) -> usize {
        self.frames.len()
    }

    pub(super) fn start_playback(&mut self, now: TdmaTime) -> bool {
        if self.state != ParrotState::Recording {
            return false;
        }
        self.state = ParrotState::Playing;
        self.last_frame_at = None;
        self.playback_started_at = Some(now);
        self.playback_release_started_at = None;
        self.playback_finished = false;
        true
    }

    pub(super) fn finish_without_playback(&mut self) -> Option<usize> {
        if self.state != ParrotState::Recording {
            return None;
        }
        let recorded = self.frames.len();
        self.frames.clear();
        self.state = ParrotState::Releasing;
        self.playback_release_started_at = None;
        self.playback_finished = false;
        Some(recorded)
    }

    pub(super) fn next_playback_msg(&mut self, now: TdmaTime) -> Option<SapMsg> {
        if self.state == ParrotState::Releasing {
            if self
                .playback_release_started_at
                .is_some_and(|release_started_at| release_started_at.age(now) >= PARROT_PLAYBACK_DRAIN_TIMESLOTS)
            {
                self.playback_release_started_at = None;
                self.playback_finished = true;
            }
            return None;
        }
        if self.state != ParrotState::Playing {
            return None;
        }
        if self
            .playback_started_at
            .is_some_and(|started_at| started_at.age(now) >= self.playback_deadline_timeslots)
        {
            let remaining = self.frames.len();
            self.frames.clear();
            self.state = ParrotState::Releasing;
            self.playback_release_started_at = None;
            self.playback_finished = true;
            tracing::warn!(
                "CMCE: parrot playback guard expired call_id={} remaining_frames={}",
                self.call_id,
                remaining
            );
            return None;
        }
        if now.t != self.ts || now.f == 18 {
            return None;
        }
        if self
            .playback_started_at
            .is_some_and(|started_at| started_at.age(now) < PARROT_PLAYBACK_START_GUARD_TIMESLOTS)
        {
            return None;
        }
        if self.last_frame_at == Some(now) {
            return None;
        }

        let Some(data) = self.frames.pop_front() else {
            self.state = ParrotState::Releasing;
            self.playback_release_started_at = Some(self.last_frame_at.unwrap_or(now));
            return None;
        };
        self.last_frame_at = Some(now);

        Some(SapMsg {
            sap: Sap::TmdSap,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::TmdCircuitDataReq(TmdCircuitDataReq {
                carrier_num: self.carrier_num,
                ts: self.ts,
                data,
            }),
        })
    }

    pub(super) fn take_playback_finished(&mut self) -> bool {
        std::mem::take(&mut self.playback_finished)
    }
}

impl CcBsSubentity {
    /// True when a private U-SETUP to `called_ssi` is for the parrot service. This is the only
    /// place that reads `parrot_enabled`: a session already running always runs to its end.
    pub(super) fn parrot_intercepts(&self, called_ssi: u32) -> bool {
        let config = self.config.config();
        config.cell.parrot_enabled && called_ssi == config.cell.parrot_issi
    }

    /// Answer a U-SETUP toward `parrot_issi` locally: simplex only, one session for the whole
    /// BS. The caller gets the floor at once; its voice is recorded until U-TX CEASED.
    pub(super) fn fsm_on_u_setup_parrot(&mut self, queue: &mut MessageQueue, message: &SapMsg, pdu: &USetup, calling_party: TetraAddress) {
        let SapMsgInner::LcmcMleUnitdataInd(prim) = &message.msg else {
            tracing::error!("BUG: unexpected message in fsm_on_u_setup_parrot");
            return;
        };
        let (parrot_issi, max_secs) = {
            let config = self.config.config();
            (config.cell.parrot_issi, config.cell.parrot_max_secs)
        };

        if calling_party.ssi == parrot_issi {
            self.parrot_reject_setup(
                queue,
                prim,
                calling_party,
                DisconnectCause::RequestedServiceNotAvailable,
                "caller is the parrot ISSI",
            );
            return;
        }
        if pdu.simplex_duplex_selection {
            self.parrot_reject_setup(
                queue,
                prim,
                calling_party,
                DisconnectCause::IncompatibleTrafficCase,
                "service is simplex-only",
            );
            return;
        }
        if let Some((call_id, state)) = self.find_individual_call_by_issi(calling_party.ssi) {
            // The LLC hands up every retransmitted BL-DATA, so a lost BL-ACK brings the same
            // U-SETUP again. Like a group late entry, answer it with the session's D-CONNECT.
            let own_session = self
                .parrot_session
                .as_ref()
                .is_some_and(|session| session.call_id() == call_id && session.state() == ParrotState::Recording);
            if let Some(call) = self.individual_calls.get(&call_id).filter(|_| own_session) {
                let (carrier_num, ts, usage) = (call.calling_carrier_num, call.calling_ts, call.calling_usage);
                tracing::info!(
                    "CMCE: parrot: repeated U-SETUP from ISSI {} for its own call_id={}, repeating D-CONNECT",
                    calling_party.ssi,
                    call_id
                );
                self.send_parrot_d_connect(queue, prim, pdu, calling_party, call_id, carrier_num, ts, usage);
                return;
            }
            tracing::info!(
                "CMCE: parrot: ISSI {} already in individual call_id={} state={:?}",
                calling_party.ssi,
                call_id,
                state
            );
            self.parrot_reject_setup(
                queue,
                prim,
                calling_party,
                DisconnectCause::ConcurrentSetUpNotSupported,
                "caller busy",
            );
            return;
        }
        if self.parrot_session.is_some() {
            self.parrot_reject_setup(queue, prim, calling_party, DisconnectCause::CalledPartyBusy, "parrot busy");
            return;
        }
        if self.is_locally_registered_issi(parrot_issi) {
            tracing::warn!(
                "CMCE: ISSI {} is registered locally but is also the parrot ISSI: the parrot answers the call",
                parrot_issi
            );
        }

        let allocated = {
            let mut state = self.config.state_write();
            self.circuits
                .allocate_circuit_with_allocator(
                    Direction::Both,
                    pdu.basic_service_information.communication_type,
                    false,
                    &mut state.timeslot_alloc,
                    TimeslotOwner::Cmce,
                )
                .cloned()
        };
        let circuit = match allocated {
            Ok(circuit) => circuit,
            Err(err) => {
                tracing::info!("CMCE: parrot: no circuit for ISSI {}: {:?}", calling_party.ssi, err);
                self.parrot_reject_setup(
                    queue,
                    prim,
                    calling_party,
                    DisconnectCause::CongestionInInfrastructure,
                    "no circuit",
                );
                return;
            }
        };
        let (call_id, carrier_num, ts, usage) = (circuit.call_id, circuit.carrier_num, circuit.ts, circuit.usage);
        let parrot_addr = TetraAddress::new(parrot_issi, SsiType::Issi);

        let call = IndividualCall {
            calling_addr: calling_party,
            called_addr: parrot_addr,
            calling_handle: prim.handle,
            calling_link_id: prim.link_id,
            calling_endpoint_id: prim.endpoint_id,
            called_handle: None,
            called_link_id: None,
            called_endpoint_id: None,
            calling_carrier_num: carrier_num,
            calling_ts: ts,
            called_carrier_num: carrier_num,
            called_ts: ts,
            calling_usage: usage,
            called_usage: usage,
            simplex_duplex: false,
            priority: pdu.call_priority,
            state: IndividualCallState::CallSetupPending,
            formal_state: CcFormalState::Idle.after(CcFormalEvent::SetupRequest),
            setup_timer_started: Some(self.dltime),
            setup_timeout: Some(CallTimeoutSetupPhase::T10s),
            active_timer_started: None,
            call_timeout: Self::p2p_call_timeout(false),
            called_over_brew: false,
            calling_over_brew: false,
            // No network leg: the parrot is local.
            network_entity: TetraEntity::Brew,
            brew_uuid: None,
            network_call: None,
            connect_request_sent: false,
            // The caller holds the floor from set-up.
            floor_holder: Some(calling_party.ssi),
            queued_tx_demand: None,
            floor_released_at: None,
        };
        if let Err(err) = self.fsm_individual_create_setup_call(call_id, call) {
            tracing::warn!("CMCE: parrot call_id={} could not be created: {:?}", call_id, err);
            let _ = self.circuits.close_circuit_slot(Direction::Both, carrier_num, ts);
            self.release_timeslot_slot(CarrierSlot { carrier_num, ts });
            self.parrot_reject_setup(queue, prim, calling_party, DisconnectCause::NoIdleCcEntity, "call not created");
            return;
        }
        if let Err(err) = self.fsm_individual_transition_to_active(call_id) {
            tracing::warn!("CMCE: parrot call_id={} could not be activated: {:?}", call_id, err);
        }

        // Same line as a local P2P set-up, so log monitors show the call.
        tracing::info!(
            "rx_u_setup_p2p: call from ISSI {} to ISSI {} -> call_id={} carrier={} ts={} usage={} (parrot service answering)",
            calling_party.ssi,
            parrot_issi,
            call_id,
            carrier_num,
            ts,
            usage
        );

        Self::signal_umac_circuit_open(queue, &circuit, self.dltime, None, None, CircuitDlMediaSource::LocalParrot);

        // Keep the caller's hook method, so the answer is not shown as a modified call.
        self.send_d_call_proceeding(queue, message, pdu, call_id, CallTimeoutSetupPhase::T10s, pdu.hook_method_selection);
        self.send_parrot_d_connect(queue, prim, pdu, calling_party, call_id, carrier_num, ts, usage);

        self.parrot_session = Some(ParrotSession::new(carrier_num, ts, call_id, calling_party, parrot_issi, max_secs));

        // notify_umac = true arms the UL inactivity timer: a caller who never talks is released.
        self.notify_floor_granted(
            queue,
            GroupFloorGrant {
                call_id,
                source_issi: calling_party.ssi,
                dest_gssi: parrot_issi,
                carrier_num,
                ts,
                is_group: false,
            },
            true,
            BrewNotification::Never,
        );
    }

    /// D-CONNECT (floor granted to the caller) with the channel allocation of the parrot circuit.
    fn send_parrot_d_connect(
        &self,
        queue: &mut MessageQueue,
        prim: &LcmcMleUnitdataInd,
        pdu: &USetup,
        calling_party: TetraAddress,
        call_id: u16,
        carrier_num: u16,
        ts: u8,
        usage: u8,
    ) {
        let d_connect = DConnect {
            call_identifier: call_id,
            call_time_out: Self::p2p_call_timeout(false),
            hook_method_selection: pdu.hook_method_selection,
            simplex_duplex_selection: false,
            transmission_grant: TransmissionGrant::Granted,
            transmission_request_permission: false,
            call_ownership: true,
            call_priority: None,
            basic_service_information: None,
            temporary_address: None,
            notification_indicator: None,
            facility: None,
            proprietary: None,
        };
        tracing::info!("-> {:?}", d_connect);
        let mut connect_sdu = BitBuffer::new_autoexpand(30);
        d_connect.to_bitbuf(&mut connect_sdu).expect("Failed to serialize DConnect");
        connect_sdu.seek(0);

        let mut timeslots = [false; 4];
        timeslots[ts as usize - 1] = true;
        queue.push_back(SapMsg {
            sap: Sap::LcmcSap,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LcmcMleUnitdataReq(LcmcMleUnitdataReq {
                sdu: connect_sdu,
                handle: prim.handle,
                endpoint_id: prim.endpoint_id,
                link_id: prim.link_id,
                layer2service: Layer2Service::Unacknowledged,
                pdu_prio: 0,
                layer2_qos: 0,
                stealing_permission: false,
                stealing_repeats_flag: false,
                chan_alloc: Some(CmceChanAllocReq {
                    usage: Some(usage),
                    alloc_type: ChanAllocType::Replace,
                    carrier: Some(carrier_num),
                    timeslots,
                    ul_dl_assigned: UlDlAssignment::Both,
                }),
                main_address: calling_party,
                tx_reporter: None,
            }),
        });
    }

    fn parrot_reject_setup(
        &mut self,
        queue: &mut MessageQueue,
        prim: &LcmcMleUnitdataInd,
        calling_party: TetraAddress,
        cause: DisconnectCause,
        reason: &str,
    ) {
        let call_id = self.circuits.get_next_call_id();
        tracing::info!(
            "CMCE: parrot rejecting U-SETUP from ISSI {} call_id={} cause={} ({})",
            calling_party.ssi,
            call_id,
            cause,
            reason
        );
        let sdu = Self::build_d_release(call_id, cause);
        queue.push_back(Self::build_sapmsg_direct(
            sdu,
            self.dltime,
            calling_party,
            prim.handle,
            prim.link_id,
            prim.endpoint_id,
        ));
    }

    /// U-TX CEASED hook, called before the generic individual handling. Returns true when the
    /// parrot handled it. Anything that is not the parrot caller's own call returns false.
    pub(super) fn parrot_on_u_tx_ceased(&mut self, queue: &mut MessageQueue, call_id: u16, sender: TetraAddress) -> bool {
        let Some(session) = self.parrot_session.as_mut() else {
            return false;
        };
        if session.call_id() != call_id {
            return false;
        }
        // Forced by the UL inactivity timer while the parrot "talks": nothing to do.
        if sender.ssi == session.parrot_issi() {
            return true;
        }
        if sender.ssi != session.caller_issi() {
            return false;
        }
        let Some(call) = self.individual_calls.get(&call_id).cloned() else {
            return false;
        };

        match session.state() {
            ParrotState::Recording => {
                let recorded = session.recorded_len();
                if recorded == 0 {
                    session.finish_without_playback();
                    tracing::warn!(
                        "U-TX CEASED (parrot) call_id={} from ISSI {} -> no recorded frames, releasing",
                        call_id,
                        sender.ssi
                    );
                    self.release_individual_call(queue, call_id, DisconnectCause::SwmiRequestedDisconnection);
                    return true;
                }
                session.start_playback(self.dltime);
                tracing::info!(
                    "U-TX CEASED (parrot) call_id={} from ISSI {} -> starting paced playback; recorded_frames={}",
                    call_id,
                    sender.ssi,
                    recorded
                );
                if let Some(call) = self.individual_calls.get_mut(&call_id) {
                    call.grant_floor(call.called_addr);
                }
                self.send_parrot_d_tx_granted(queue, &call, call_id);
                let slot = CallTimeslot {
                    call_id,
                    carrier_num: call.calling_carrier_num,
                    ts: call.calling_ts,
                };
                self.notify_remote_floor_granted(queue, slot);
                // Dashboard only: the parrot is now the speaker.
                self.notify_floor_granted(
                    queue,
                    GroupFloorGrant {
                        call_id,
                        source_issi: call.called_addr.ssi,
                        dest_gssi: call.calling_addr.ssi,
                        carrier_num: slot.carrier_num,
                        ts: slot.ts,
                        is_group: false,
                    },
                    false,
                    BrewNotification::Never,
                );
            }
            // The radio repeats U-TX CEASED until it is answered: confirm the parrot's turn again.
            ParrotState::Playing => self.send_parrot_d_tx_granted(queue, &call, call_id),
            ParrotState::Releasing => {}
        }
        true
    }

    /// D-TX GRANTED (granted to other user = the parrot) to the caller on its traffic channel.
    fn send_parrot_d_tx_granted(&self, queue: &mut MessageQueue, call: &IndividualCall, call_id: u16) {
        let d_tx_granted = DTxGranted {
            call_identifier: call_id,
            transmission_grant: TransmissionGrant::GrantedToOtherUser.into_raw() as u8,
            transmission_request_permission: false,
            encryption_control: false,
            reserved: false,
            notification_indicator: None,
            transmitting_party_type_identifier: Some(1),
            transmitting_party_address_ssi: Some(call.called_addr.ssi as u64),
            transmitting_party_extension: None,
            external_subscriber_number: None,
            facility: None,
            dm_ms_address: None,
            proprietary: None,
        };
        tracing::info!(
            "FSM -> D-TX GRANTED (parrot, GrantedToOtherUser) call_id={} to ISSI {}",
            call_id,
            call.calling_addr.ssi
        );
        let mut sdu = BitBuffer::new_autoexpand(50);
        d_tx_granted.to_bitbuf(&mut sdu).expect("Failed to serialize DTxGranted");
        sdu.seek(0);
        queue.push_back(Self::build_sapmsg_stealing_ul_dl(
            sdu,
            self.dltime,
            call.calling_addr,
            call.calling_carrier_num,
            call.calling_ts,
            Some(call.calling_usage),
            UlDlAssignment::Dl,
        ));
    }

    /// Per tick: send the next playback frame and release the call once playback has drained.
    pub(super) fn drive_parrot_session(&mut self, queue: &mut MessageQueue) {
        let Some(session) = self.parrot_session.as_mut() else {
            return;
        };
        let call_id = session.call_id();
        // A call removed without release_individual_call (e.g. the circuit manager's safety
        // close) must not leave the service busy forever.
        if !self.individual_calls.contains_key(&call_id) {
            tracing::info!("CMCE: parrot call_id={} is gone, dropping its session", call_id);
            self.parrot_session = None;
            return;
        }
        if let Some(msg) = session.next_playback_msg(self.dltime) {
            queue.push_back(msg);
        }
        if session.take_playback_finished() {
            tracing::info!("CMCE: parrot playback complete, releasing call_id={}", call_id);
            self.release_individual_call(queue, call_id, DisconnectCause::SwmiRequestedDisconnection);
        }
    }

    /// Drop the parrot session if it belongs to `call_id`. True when it did: the call's called
    /// party is the virtual parrot and gets no D-RELEASE.
    pub(super) fn take_parrot_session_if(&mut self, call_id: u16) -> bool {
        if !self.parrot_session.as_ref().is_some_and(|session| session.call_id() == call_id) {
            return false;
        }
        tracing::info!("CMCE: parrot session released call_id={}", call_id);
        self.parrot_session = None;
        true
    }

    /// UL voice of a LocalParrot circuit, already packed by UMAC. Recorded while the caller
    /// talks; afterwards it is consumed and dropped.
    pub fn handle_parrot_ul_frame(&mut self, carrier_num: u16, ts: u8, data: Vec<u8>) {
        let Some(session) = self.parrot_session.as_mut() else {
            tracing::debug!("CMCE: parrot UL frame carrier={} ts={} without a session, dropped", carrier_num, ts);
            return;
        };
        if session.record_ul_frame(carrier_num, ts, data) {
            tracing::trace!(
                "CMCE: parrot service recorded frame call_id={} carrier={} ts={} frames={}",
                session.call_id(),
                carrier_num,
                ts,
                session.recorded_len()
            );
        } else {
            tracing::trace!(
                "CMCE: parrot service consumed non-recorded UL frame call_id={} carrier={} ts={}",
                session.call_id(),
                carrier_num,
                ts
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAIN_CARRIER: u16 = 1521;

    fn session() -> ParrotSession {
        ParrotSession::new(MAIN_CARRIER, 2, 42, TetraAddress::issi(1001), 99_999, 20)
    }

    #[test]
    fn parrot_recording_is_limited_to_twenty_seconds() {
        let mut session = session();
        let max_frames = 20 * TCH_S_TRAFFIC_FRAMES_PER_SECOND;

        for seq in 0..(max_frames + 5) {
            assert_eq!(session.record_ul_frame(MAIN_CARRIER, 2, vec![seq as u8; 35]), seq < max_frames);
        }

        assert_eq!(session.recorded_len(), max_frames);
    }

    #[test]
    fn parrot_recording_limit_follows_max_secs() {
        let mut session = ParrotSession::new(MAIN_CARRIER, 2, 42, TetraAddress::issi(1001), 99_999, 3);
        for seq in 0..100u8 {
            session.record_ul_frame(MAIN_CARRIER, 2, vec![seq; 35]);
        }
        assert_eq!(session.recorded_len(), 3 * TCH_S_TRAFFIC_FRAMES_PER_SECOND);
    }

    #[test]
    fn parrot_records_only_its_own_carrier_and_timeslot() {
        let mut session = session();

        assert!(!session.record_ul_frame(MAIN_CARRIER + 1, 2, vec![0; 35]), "same ts, other carrier");
        assert!(!session.record_ul_frame(MAIN_CARRIER, 3, vec![0; 35]), "same carrier, other ts");
        assert_eq!(session.recorded_len(), 0);
        assert!(session.owns_slot(MAIN_CARRIER, 2));
        assert!(!session.owns_slot(MAIN_CARRIER + 1, 2));

        assert!(session.record_ul_frame(MAIN_CARRIER, 2, vec![0; 35]));
        assert_eq!(session.recorded_len(), 1);
    }

    #[test]
    fn parrot_playback_guard_forces_completion() {
        let mut session = session();
        assert!(session.record_ul_frame(MAIN_CARRIER, 2, vec![0; 35]));

        let start = TdmaTime { h: 0, m: 1, f: 1, t: 1 };
        assert!(session.start_playback(start));
        let after_deadline = start.add_timeslots((20 + PARROT_PLAYBACK_GUARD_SECONDS) * TETRA_TIMESLOTS_PER_SECOND);

        assert!(session.next_playback_msg(after_deadline).is_none());
        assert!(session.take_playback_finished());
        assert_eq!(session.recorded_len(), 0);
    }

    #[test]
    fn parrot_playback_skips_frame_18_and_drains_before_finish() {
        let mut session = session();
        assert!(session.record_ul_frame(MAIN_CARRIER, 2, vec![1; 35]));

        let start = TdmaTime { h: 0, m: 1, f: 14, t: 2 };
        assert!(session.start_playback(start));
        let frame_18 = TdmaTime { h: 0, m: 1, f: 18, t: 2 };
        assert!(
            session.next_playback_msg(frame_18).is_none(),
            "frame 18 is not RF-sendable traffic in the current UMAC scheduler"
        );
        assert_eq!(session.recorded_len(), 1);

        let next_multiframe_t2 = frame_18.add_timeslots(4);
        let msg = session.next_playback_msg(next_multiframe_t2).expect("playback frame");
        let SapMsgInner::TmdCircuitDataReq(req) = msg.msg else {
            panic!("playback must be a TmdCircuitDataReq");
        };
        assert_eq!((req.carrier_num, req.ts, req.data), (MAIN_CARRIER, 2, vec![1; 35]));
        assert_eq!(session.recorded_len(), 0);

        let empty_probe = next_multiframe_t2.add_timeslots(4);
        assert!(session.next_playback_msg(empty_probe).is_none());
        assert!(
            !session.take_playback_finished(),
            "release should wait for a small RF drain guard after the last queued playback frame"
        );

        let after_drain = next_multiframe_t2.add_timeslots(PARROT_PLAYBACK_DRAIN_TIMESLOTS + 4);
        assert!(session.next_playback_msg(after_drain).is_none());
        assert!(session.take_playback_finished());
    }

    /// A parrot call removed without `release_individual_call` (the circuit manager's safety
    /// close does that) must not keep the service busy: the next tick drops the session.
    #[test]
    fn parrot_session_of_a_vanished_call_is_dropped_on_the_next_tick() {
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
parrot_enabled = true
"#;
        let cfg = tetra_config::bluestation::parsing::from_toml_str(toml).expect("parrot test config must parse");
        let mut cc = CcBsSubentity::new(SharedConfig::from_parts(cfg, None));
        cc.parrot_session = Some(ParrotSession::new(1584, 2, 42, TetraAddress::issi(1001), 99_999, 20));
        assert!(!cc.individual_calls.contains_key(&42));

        let mut queue = MessageQueue::new();
        cc.tick_start(&mut queue, TdmaTime { h: 0, m: 1, f: 1, t: 2 });

        assert!(cc.parrot_session.is_none(), "the orphaned session must be dropped");
        assert!(queue.pop_front().is_none(), "nothing to send for a call that no longer exists");
    }
}
