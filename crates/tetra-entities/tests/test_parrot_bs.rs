// SPDX-FileCopyrightText: Historical upstream contributors
// SPDX-FileCopyrightText: 2026 Chris YO3TCO / Nexus-BS Project
// SPDX-License-Identifier: Apache-2.0 AND PolyForm-Noncommercial-1.0.0
// SPDX-FileComment: Modified by Nexus-BS Project; see CHANGES-NEXUS.md for change notices.
// SPDX-FileComment: Parrot tests adapted for flowstation-miura (carrier_num, configurable ISSI, packed TCH/S) by EA5GVK.

mod common;

use tetra_config::bluestation::{CfgBrew, SharedConfig, StackConfig, StackMode};
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{BitBuffer, Direction, Sap, SsiType, TdmaTime, TetraAddress, TimeslotOwner, debug};
use tetra_entities::cmce::cmce_bs::CmceBs;
use tetra_entities::net_telemetry::{TelemetryEvent, telemetry_channel};
use tetra_pdus::cmce::enums::{
    cmce_pdu_type_dl::CmcePduTypeDl, disconnect_cause::DisconnectCause, party_type_identifier::PartyTypeIdentifier,
    transmission_grant::TransmissionGrant,
};
use tetra_pdus::cmce::fields::basic_service_information::BasicServiceInformation;
use tetra_pdus::cmce::pdus::{
    d_call_proceeding::DCallProceeding, d_connect::DConnect, d_release::DRelease, d_tx_granted::DTxGranted, u_disconnect::UDisconnect,
    u_setup::USetup, u_tx_ceased::UTxCeased,
};
use tetra_saps::control::call_control::{CallControl, Circuit, CircuitDlMediaSource};
use tetra_saps::control::enums::{circuit_mode_type::CircuitModeType, communication_type::CommunicationType};
use tetra_saps::lcmc::enums::ul_dl_assignment::UlDlAssignment;
use tetra_saps::lcmc::{LcmcMleUnitdataInd, LcmcMleUnitdataReq};
use tetra_saps::sapmsg::{SapMsg, SapMsgInner};
use tetra_saps::tmd::{TmdCircuitDataInd, TmdCircuitDataReq};
use tetra_saps::tmv::enums::logical_chans::LogicalChannel;

use crate::common::ComponentTest;

const CALLER: u32 = 1000001;
const OTHER: u32 = 1000003;
const PARROT: u32 = 99_999;
const MAIN_CARRIER: u16 = 1521;
const SECONDARY_CARRIER: u16 = 1522;
const TCH_S_BITS: usize = 274;

// ─── CMCE helpers ────────────────────────────────────────────────────────────

fn parrot_config() -> StackConfig {
    let mut config = ComponentTest::get_default_test_config(StackMode::Bs);
    config.cell.parrot_enabled = true;
    config
}

fn cmce_test(config: StackConfig) -> ComponentTest {
    let mut test = ComponentTest::from_config(config, Some(TdmaTime { h: 0, m: 1, f: 1, t: 1 }));
    test.populate_entities(
        vec![TetraEntity::Cmce],
        vec![TetraEntity::Mle, TetraEntity::Umac, TetraEntity::Brew],
    );
    test
}

fn lcmc_ind(sender_issi: u32, sdu: BitBuffer) -> SapMsg {
    SapMsg {
        sap: Sap::LcmcSap,
        src: TetraEntity::Mle,
        dest: TetraEntity::Cmce,
        msg: SapMsgInner::LcmcMleUnitdataInd(LcmcMleUnitdataInd {
            sdu,
            handle: 1,
            endpoint_id: 1,
            link_id: 1,
            received_tetra_address: TetraAddress::new(sender_issi, SsiType::Issi),
            chan_change_resp_req: false,
            chan_change_handle: None,
        }),
    }
}

fn u_setup_msg(calling_issi: u32, called_issi: u32, duplex: bool, hook: bool) -> SapMsg {
    let u_setup = USetup {
        area_selection: 0,
        hook_method_selection: hook,
        simplex_duplex_selection: duplex,
        basic_service_information: BasicServiceInformation {
            circuit_mode_type: CircuitModeType::TchS,
            encryption_flag: false,
            communication_type: CommunicationType::P2p,
            slots_per_frame: None,
            speech_service: Some(0),
        },
        request_to_transmit_send_data: false,
        call_priority: 0,
        clir_control: 0,
        called_party_type_identifier: PartyTypeIdentifier::Ssi,
        called_party_ssi: Some(called_issi as u64),
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
    lcmc_ind(calling_issi, sdu)
}

fn u_tx_ceased_msg(sender_issi: u32, call_id: u16) -> SapMsg {
    let pdu = UTxCeased {
        call_identifier: call_id,
        facility: None,
        dm_ms_address: None,
        proprietary: None,
    };
    let mut sdu = BitBuffer::new_autoexpand(80);
    pdu.to_bitbuf(&mut sdu).expect("Failed to serialize UTxCeased");
    sdu.seek(0);
    lcmc_ind(sender_issi, sdu)
}

fn u_disconnect_msg(sender_issi: u32, call_id: u16) -> SapMsg {
    let pdu = UDisconnect {
        call_identifier: call_id,
        disconnect_cause: DisconnectCause::UserRequestedDisconnection,
        facility: None,
        proprietary: None,
    };
    let mut sdu = BitBuffer::new_autoexpand(80);
    pdu.to_bitbuf(&mut sdu).expect("Failed to serialize UDisconnect");
    sdu.seek(0);
    lcmc_ind(sender_issi, sdu)
}

/// One packed UL frame of a LocalParrot circuit, as UMAC hands it to CMCE.
fn ul_frame_to_cmce(carrier_num: u16, ts: u8, data: Vec<u8>) -> SapMsg {
    SapMsg {
        sap: Sap::TmdSap,
        src: TetraEntity::Umac,
        dest: TetraEntity::Cmce,
        msg: SapMsgInner::TmdCircuitDataInd(TmdCircuitDataInd { carrier_num, ts, data }),
    }
}

fn ul_inactivity_msg(carrier_num: u16, ts: u8) -> SapMsg {
    SapMsg {
        sap: Sap::Control,
        src: TetraEntity::Umac,
        dest: TetraEntity::Cmce,
        msg: SapMsgInner::CmceCallControl(CallControl::UlInactivityTimeout { carrier_num, ts }),
    }
}

fn lcmc_reqs(msgs: &[SapMsg], issi: u32, pdu_type: CmcePduTypeDl) -> Vec<&LcmcMleUnitdataReq> {
    msgs.iter()
        .filter_map(|msg| match &msg.msg {
            SapMsgInner::LcmcMleUnitdataReq(prim)
                if msg.dest == TetraEntity::Mle
                    && prim.main_address.ssi == issi
                    && prim.sdu.peek_bits(5).and_then(|t| CmcePduTypeDl::try_from(t).ok()) == Some(pdu_type) =>
            {
                Some(prim)
            }
            _ => None,
        })
        .collect()
}

fn d_connect_to(msgs: &[SapMsg], issi: u32) -> Option<(DConnect, &LcmcMleUnitdataReq)> {
    let prim = *lcmc_reqs(msgs, issi, CmcePduTypeDl::DConnect).first()?;
    Some((DConnect::from_bitbuf(&mut prim.sdu.clone()).expect("DConnect"), prim))
}

fn d_call_proceeding_to(msgs: &[SapMsg], issi: u32) -> Option<DCallProceeding> {
    let prim = *lcmc_reqs(msgs, issi, CmcePduTypeDl::DCallProceeding).first()?;
    Some(DCallProceeding::from_bitbuf(&mut prim.sdu.clone()).expect("DCallProceeding"))
}

fn d_releases_to(msgs: &[SapMsg], issi: u32) -> Vec<DRelease> {
    lcmc_reqs(msgs, issi, CmcePduTypeDl::DRelease)
        .into_iter()
        .map(|prim| DRelease::from_bitbuf(&mut prim.sdu.clone()).expect("DRelease"))
        .collect()
}

fn d_tx_granted_to(msgs: &[SapMsg], issi: u32) -> Vec<(DTxGranted, &LcmcMleUnitdataReq)> {
    lcmc_reqs(msgs, issi, CmcePduTypeDl::DTxGranted)
        .into_iter()
        .map(|prim| (DTxGranted::from_bitbuf(&mut prim.sdu.clone()).expect("DTxGranted"), prim))
        .collect()
}

fn opened_circuits(msgs: &[SapMsg]) -> Vec<Circuit> {
    msgs.iter()
        .filter_map(|msg| match &msg.msg {
            SapMsgInner::CmceCallControl(CallControl::Open(circuit)) => Some(circuit.clone()),
            _ => None,
        })
        .collect()
}

fn count_control(msgs: &[SapMsg], dest: TetraEntity, pred: impl Fn(&CallControl) -> bool) -> usize {
    msgs.iter()
        .filter(|msg| msg.dest == dest && matches!(&msg.msg, SapMsgInner::CmceCallControl(cc) if pred(cc)))
        .count()
}

fn playback_frames(msgs: &[SapMsg]) -> Vec<(u16, u8, Vec<u8>)> {
    msgs.iter()
        .filter_map(|msg| match &msg.msg {
            SapMsgInner::TmdCircuitDataReq(req) if msg.dest == TetraEntity::Umac => Some((req.carrier_num, req.ts, req.data.clone())),
            _ => None,
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
struct ParrotCall {
    call_id: u16,
    carrier_num: u16,
    ts: u8,
}

/// Set up a parrot call from `caller` and return it, with the set-up messages.
fn start_parrot_call(test: &mut ComponentTest, caller: u32, parrot_issi: u32) -> (ParrotCall, Vec<SapMsg>) {
    test.submit_message(u_setup_msg(caller, parrot_issi, false, false));
    test.run_stack(Some(1));
    let msgs = test.dump_sinks();
    let (d_connect, _) = d_connect_to(&msgs, caller).expect("parrot set-up should answer the caller with D-CONNECT");
    let open = opened_circuits(&msgs)
        .into_iter()
        .next()
        .expect("parrot set-up should open a circuit");
    assert_eq!(open.dl_media_source, CircuitDlMediaSource::LocalParrot);
    let call = ParrotCall {
        call_id: d_connect.call_identifier,
        carrier_num: open.carrier_num,
        ts: open.ts,
    };
    (call, msgs)
}

/// Run ticks until a D-RELEASE reaches `issi` (or `max_ticks` pass); returns everything sent.
fn run_until_release(test: &mut ComponentTest, issi: u32, max_ticks: usize) -> Vec<SapMsg> {
    let mut msgs = Vec::new();
    for _ in 0..max_ticks {
        test.run_stack(Some(1));
        msgs.extend(test.dump_sinks());
        if !d_releases_to(&msgs, issi).is_empty() {
            break;
        }
    }
    msgs
}

fn assert_released_caller_only(msgs: &[SapMsg], call: ParrotCall) {
    let releases = d_releases_to(msgs, CALLER);
    assert!(!releases.is_empty(), "the caller must get a D-RELEASE");
    for release in &releases {
        assert_eq!(release.call_identifier, call.call_id);
        assert_eq!(release.disconnect_cause, DisconnectCause::SwmiRequestedDisconnection);
    }
    assert!(
        d_releases_to(msgs, PARROT).is_empty(),
        "no D-RELEASE may address the virtual parrot ISSI"
    );
    assert_eq!(
        count_control(msgs, TetraEntity::Umac, |cc| matches!(
            cc,
            CallControl::CloseSlot { carrier_num, ts, .. } if *carrier_num == call.carrier_num && *ts == call.ts
        )),
        1,
        "the parrot circuit must be closed"
    );
    assert_eq!(
        count_control(
            msgs,
            TetraEntity::Umac,
            |cc| matches!(cc, CallControl::CallEnded { call_id, .. } if *call_id == call.call_id)
        ),
        1
    );
}

// ─── CMCE: set-up ────────────────────────────────────────────────────────────

#[test]
fn test_parrot_setup_answers_locally_with_simplex_connect() {
    debug::setup_logging_verbose();

    let mut test = ComponentTest::from_config(parrot_config(), Some(TdmaTime { h: 0, m: 1, f: 1, t: 1 }));
    test.populate_entities(vec![], vec![TetraEntity::Mle, TetraEntity::Umac, TetraEntity::Brew]);
    let (sink, source) = telemetry_channel();
    test.register_entity(CmceBs::new(test.config.clone(), Some(sink), None));

    test.submit_message(u_setup_msg(CALLER, PARROT, false, true));
    test.run_stack(Some(1));
    let msgs = test.dump_sinks();

    let proceeding = d_call_proceeding_to(&msgs, CALLER).expect("parrot should answer with D-CALL PROCEEDING");
    assert!(proceeding.hook_method_selection, "the caller's hook method is kept");
    let (d_connect, connect_prim) = d_connect_to(&msgs, CALLER).expect("parrot should answer with D-CONNECT");
    assert_eq!(d_connect.transmission_grant, TransmissionGrant::Granted);
    assert!(d_connect.hook_method_selection, "the caller's hook method is kept");
    assert!(!d_connect.simplex_duplex_selection, "the parrot is simplex-only");
    assert!(d_connect.call_ownership);

    let opens = opened_circuits(&msgs);
    assert_eq!(opens.len(), 1);
    let open = &opens[0];
    assert_eq!(open.dl_media_source, CircuitDlMediaSource::LocalParrot);
    assert_eq!((open.peer_carrier_num, open.peer_ts), (None, None));
    let chan_alloc = connect_prim.chan_alloc.as_ref().expect("D-CONNECT carries the channel allocation");
    assert_eq!(chan_alloc.carrier, Some(open.carrier_num));
    assert!(chan_alloc.timeslots[open.ts as usize - 1]);

    assert_eq!(
        count_control(&msgs, TetraEntity::Umac, |cc| matches!(
            cc,
            CallControl::FloorGranted {
                source_issi: CALLER,
                dest_gssi: PARROT,
                ..
            }
        )),
        1,
        "the caller gets the floor at once, arming the UL inactivity timer"
    );
    assert!(
        !msgs.iter().any(|msg| msg.dest == TetraEntity::Brew),
        "the parrot is local: nothing may go to Brew"
    );
    assert!(d_releases_to(&msgs, CALLER).is_empty());

    let mut started = None;
    while let Some(event) = source.try_recv() {
        if let TelemetryEvent::IndividualCallStarted {
            call_id,
            calling_issi,
            called_issi,
            simplex,
            ts,
            ..
        } = event
        {
            started = Some((call_id, calling_issi, called_issi, simplex, ts));
        }
    }
    assert_eq!(started, Some((d_connect.call_identifier, CALLER, PARROT, true, open.ts)));
}

#[test]
fn test_parrot_rejects_duplex_without_opening_a_circuit() {
    debug::setup_logging_verbose();

    let mut test = cmce_test(parrot_config());
    test.submit_message(u_setup_msg(CALLER, PARROT, true, false));
    test.run_stack(Some(1));
    let msgs = test.dump_sinks();

    let releases = d_releases_to(&msgs, CALLER);
    assert_eq!(releases.len(), 1);
    assert_eq!(releases[0].disconnect_cause, DisconnectCause::IncompatibleTrafficCase);
    assert!(opened_circuits(&msgs).is_empty());
    assert!(d_connect_to(&msgs, CALLER).is_none());
}

#[test]
fn test_parrot_second_caller_gets_busy() {
    debug::setup_logging_verbose();

    let mut test = cmce_test(parrot_config());
    let _ = start_parrot_call(&mut test, CALLER, PARROT);

    test.submit_message(u_setup_msg(OTHER, PARROT, false, false));
    test.run_stack(Some(1));
    let msgs = test.dump_sinks();

    let releases = d_releases_to(&msgs, OTHER);
    assert_eq!(releases.len(), 1);
    assert_eq!(releases[0].disconnect_cause, DisconnectCause::CalledPartyBusy);
    assert!(opened_circuits(&msgs).is_empty());
}

#[test]
fn test_parrot_rejects_a_call_from_its_own_issi() {
    debug::setup_logging_verbose();

    let mut test = cmce_test(parrot_config());
    test.submit_message(u_setup_msg(PARROT, PARROT, false, false));
    test.run_stack(Some(1));
    let msgs = test.dump_sinks();

    let releases = d_releases_to(&msgs, PARROT);
    assert_eq!(releases.len(), 1);
    assert_eq!(releases[0].disconnect_cause, DisconnectCause::RequestedServiceNotAvailable);
    assert!(opened_circuits(&msgs).is_empty());
}

#[test]
fn test_parrot_answers_on_the_configured_issi_only() {
    debug::setup_logging_verbose();

    let mut config = parrot_config();
    config.cell.parrot_issi = 12345;
    let mut test = cmce_test(config);

    let (call, _) = start_parrot_call(&mut test, CALLER, 12345);
    assert!(call.call_id > 0);

    // 99999 is now an ordinary ISSI: not registered and no Brew, so it is rejected as always.
    test.submit_message(u_setup_msg(OTHER, PARROT, false, false));
    test.run_stack(Some(1));
    let msgs = test.dump_sinks();
    assert!(opened_circuits(&msgs).is_empty());
    let releases = d_releases_to(&msgs, OTHER);
    assert_eq!(releases.len(), 1);
    assert_eq!(releases[0].disconnect_cause, DisconnectCause::RequestedServiceNotAvailable);
}

#[test]
fn test_parrot_uses_the_secondary_carrier_when_the_main_one_is_full() {
    debug::setup_logging_verbose();

    let mut config = parrot_config();
    config.cell.secondary_carrier = Some(SECONDARY_CARRIER);
    let mut test = cmce_test(config);
    for _ in 0..3 {
        let slot = test
            .config
            .state_write()
            .timeslot_alloc
            .allocate_any_slot(TimeslotOwner::Cmce)
            .expect("free slot");
        assert_eq!(slot.carrier_num, MAIN_CARRIER, "main carrier ts2-4 are handed out first");
    }

    let (call, msgs) = start_parrot_call(&mut test, CALLER, PARROT);
    assert_eq!(call.carrier_num, SECONDARY_CARRIER);
    let (_, connect_prim) = d_connect_to(&msgs, CALLER).unwrap();
    assert_eq!(connect_prim.chan_alloc.as_ref().unwrap().carrier, Some(SECONDARY_CARRIER));

    test.submit_message(ul_frame_to_cmce(call.carrier_num, call.ts, vec![0x33; 35]));
    test.submit_message(u_tx_ceased_msg(CALLER, call.call_id));
    test.run_stack(Some(1));
    let msgs = run_until_release(&mut test, CALLER, 200);
    assert_eq!(playback_frames(&msgs), vec![(SECONDARY_CARRIER, call.ts, vec![0x33; 35])]);
    assert_released_caller_only(&msgs, call);
}

// ─── CMCE: recording, playback, release ─────────────────────────────────────

#[test]
fn test_parrot_records_replays_exact_frames_then_releases_caller() {
    debug::setup_logging_verbose();

    let mut test = cmce_test(parrot_config());
    let (call, _) = start_parrot_call(&mut test, CALLER, PARROT);

    let frames = vec![vec![0xA5; 35], vec![0x5A; 35]];
    for frame in &frames {
        test.submit_message(ul_frame_to_cmce(call.carrier_num, call.ts, frame.clone()));
    }
    // Another slot's voice is not the caller's.
    test.submit_message(ul_frame_to_cmce(call.carrier_num, call.ts % 4 + 1, vec![0xFF; 35]));
    test.run_stack(Some(1));
    let _ = test.dump_sinks();

    test.submit_message(u_tx_ceased_msg(CALLER, call.call_id));
    test.run_stack(Some(1));
    let msgs = test.dump_sinks();
    assert!(playback_frames(&msgs).is_empty(), "playback waits for its start guard");
    assert!(d_releases_to(&msgs, CALLER).is_empty());
    let grants = d_tx_granted_to(&msgs, CALLER);
    assert_eq!(grants.len(), 1, "the caller is told the parrot has the floor");
    let (grant, grant_prim) = &grants[0];
    assert_eq!(grant.call_identifier, call.call_id);
    assert_eq!(grant.transmission_grant, TransmissionGrant::GrantedToOtherUser.into_raw() as u8);
    assert_eq!(grant.transmitting_party_address_ssi, Some(PARROT as u64));
    let chan_alloc = grant_prim.chan_alloc.as_ref().expect("D-TX GRANTED goes on the traffic channel");
    assert_eq!(chan_alloc.ul_dl_assigned, UlDlAssignment::Dl);
    assert_eq!(chan_alloc.carrier, Some(call.carrier_num));
    assert!(chan_alloc.timeslots[call.ts as usize - 1]);
    assert_eq!(
        count_control(
            &msgs,
            TetraEntity::Umac,
            |cc| matches!(cc, CallControl::RemoteFloorGranted { ts, .. } if *ts == call.ts)
        ),
        1
    );
    assert_eq!(
        count_control(&msgs, TetraEntity::Umac, |cc| matches!(
            cc,
            CallControl::FloorGranted { .. } | CallControl::FloorReleased { .. }
        )),
        0,
        "the floor never goes free and UMAC arms no UL timer for the parrot"
    );

    // Late UL voice during playback is consumed, not recorded.
    test.submit_message(ul_frame_to_cmce(call.carrier_num, call.ts, vec![0x11; 35]));

    let msgs = run_until_release(&mut test, CALLER, 200);
    let expected: Vec<_> = frames.iter().map(|f| (call.carrier_num, call.ts, f.clone())).collect();
    assert_eq!(
        playback_frames(&msgs),
        expected,
        "playback must keep the recorded frames and their order"
    );
    assert_released_caller_only(&msgs, call);
    assert!(!msgs.iter().any(|msg| msg.dest == TetraEntity::Brew));

    // The service is free again.
    let (next, _) = start_parrot_call(&mut test, OTHER, PARROT);
    assert_ne!(next.call_id, call.call_id);
}

#[test]
fn test_parrot_rf_length_recording_is_paced_and_released() {
    debug::setup_logging_verbose();

    let mut test = cmce_test(parrot_config());
    let (call, _) = start_parrot_call(&mut test, CALLER, PARROT);

    const RF_RECORDED_FRAMES: usize = 141;
    for seq in 0..RF_RECORDED_FRAMES {
        test.submit_message(ul_frame_to_cmce(call.carrier_num, call.ts, vec![seq as u8; 35]));
    }
    test.run_stack(Some(1));
    let recording_msgs = test.dump_sinks();
    assert_eq!(
        count_control(&recording_msgs, TetraEntity::Umac, |cc| matches!(
            cc,
            CallControl::FloorGranted { .. }
        )),
        0,
        "recording must not emit one FloorGranted per frame"
    );

    test.submit_message(u_tx_ceased_msg(CALLER, call.call_id));
    test.run_stack(Some(1));
    let _ = test.dump_sinks();

    test.run_stack(Some(16));
    let paced = test.dump_sinks();
    let paced_count = playback_frames(&paced).len();
    assert!(
        paced_count <= 4,
        "playback must be TDMA-paced, not a flood; got {paced_count} frames in 16 ticks"
    );

    let rest = run_until_release(&mut test, CALLER, 1000);
    let played: Vec<u8> = playback_frames(&paced)
        .into_iter()
        .chain(playback_frames(&rest))
        .map(|(_, _, data)| data[0])
        .collect();
    let expected: Vec<u8> = (0..RF_RECORDED_FRAMES).map(|seq| seq as u8).collect();
    assert_eq!(played, expected, "all frames are played back, in order");
    assert_released_caller_only(&rest, call);
}

#[test]
fn test_parrot_recording_stops_at_parrot_max_secs() {
    debug::setup_logging_verbose();

    let mut config = parrot_config();
    config.cell.parrot_max_secs = 1;
    let mut test = cmce_test(config);
    let (call, _) = start_parrot_call(&mut test, CALLER, PARROT);

    for seq in 0..40u8 {
        test.submit_message(ul_frame_to_cmce(call.carrier_num, call.ts, vec![seq; 35]));
    }
    test.submit_message(u_tx_ceased_msg(CALLER, call.call_id));
    test.run_stack(Some(1));
    let msgs = run_until_release(&mut test, CALLER, 1000);
    assert_eq!(playback_frames(&msgs).len(), 17, "1 s of TCH/S is 17 frames");
    assert_released_caller_only(&msgs, call);
}

#[test]
fn test_parrot_tx_ceased_without_speech_releases() {
    debug::setup_logging_verbose();

    let mut test = cmce_test(parrot_config());
    let (call, _) = start_parrot_call(&mut test, CALLER, PARROT);

    test.submit_message(u_tx_ceased_msg(CALLER, call.call_id));
    test.run_stack(Some(1));
    let msgs = test.dump_sinks();
    assert!(d_tx_granted_to(&msgs, CALLER).is_empty());
    assert_released_caller_only(&msgs, call);
}

#[test]
fn test_parrot_ul_inactivity_starts_playback_then_is_ignored() {
    debug::setup_logging_verbose();

    let mut test = cmce_test(parrot_config());
    let (call, _) = start_parrot_call(&mut test, CALLER, PARROT);
    test.submit_message(ul_frame_to_cmce(call.carrier_num, call.ts, vec![0x42; 35]));
    test.run_stack(Some(1));
    let _ = test.dump_sinks();

    test.submit_message(ul_inactivity_msg(call.carrier_num, call.ts));
    test.run_stack(Some(1));
    let msgs = test.dump_sinks();
    assert_eq!(
        d_tx_granted_to(&msgs, CALLER).len(),
        1,
        "a silent PTT holder hands the floor to the parrot"
    );
    assert_eq!(
        count_control(&msgs, TetraEntity::Umac, |cc| matches!(cc, CallControl::RemoteFloorGranted { .. })),
        1
    );
    assert!(d_releases_to(&msgs, CALLER).is_empty());

    // While the parrot "talks" the timer resolves to the parrot itself: nothing happens.
    test.submit_message(ul_inactivity_msg(call.carrier_num, call.ts));
    test.run_stack(Some(1));
    let msgs = test.dump_sinks();
    assert!(d_tx_granted_to(&msgs, CALLER).is_empty());
    assert!(d_releases_to(&msgs, CALLER).is_empty());

    let msgs = run_until_release(&mut test, CALLER, 200);
    assert_eq!(playback_frames(&msgs), vec![(call.carrier_num, call.ts, vec![0x42; 35])]);
    assert_released_caller_only(&msgs, call);
}

#[test]
fn test_parrot_ul_inactivity_without_speech_releases() {
    debug::setup_logging_verbose();

    let mut test = cmce_test(parrot_config());
    let (call, _) = start_parrot_call(&mut test, CALLER, PARROT);

    test.submit_message(ul_inactivity_msg(call.carrier_num, call.ts));
    test.run_stack(Some(1));
    let msgs = test.dump_sinks();
    assert_released_caller_only(&msgs, call);
}

#[test]
fn test_parrot_repeated_tx_ceased_during_playback_repeats_the_grant() {
    debug::setup_logging_verbose();

    let mut test = cmce_test(parrot_config());
    let (call, _) = start_parrot_call(&mut test, CALLER, PARROT);
    for seq in 0..10u8 {
        test.submit_message(ul_frame_to_cmce(call.carrier_num, call.ts, vec![seq; 35]));
    }
    test.submit_message(u_tx_ceased_msg(CALLER, call.call_id));
    test.run_stack(Some(1));
    let _ = test.dump_sinks();

    test.submit_message(u_tx_ceased_msg(CALLER, call.call_id));
    test.run_stack(Some(1));
    let msgs = test.dump_sinks();
    let grants = d_tx_granted_to(&msgs, CALLER);
    assert_eq!(grants.len(), 1, "a repeated U-TX CEASED is answered again");
    assert_eq!(
        grants[0].0.transmission_grant,
        TransmissionGrant::GrantedToOtherUser.into_raw() as u8
    );
    assert!(d_releases_to(&msgs, CALLER).is_empty());
    assert_eq!(
        count_control(&msgs, TetraEntity::Umac, |cc| matches!(cc, CallControl::RemoteFloorGranted { .. })),
        0
    );

    let msgs = run_until_release(&mut test, CALLER, 400);
    assert_eq!(playback_frames(&msgs).len(), 10, "the repeat does not restart or cut the playback");
}

#[test]
fn test_parrot_ignores_tx_ceased_from_another_issi() {
    debug::setup_logging_verbose();

    let mut test = cmce_test(parrot_config());
    let (call, _) = start_parrot_call(&mut test, CALLER, PARROT);
    test.submit_message(ul_frame_to_cmce(call.carrier_num, call.ts, vec![0x42; 35]));
    test.run_stack(Some(1));
    let _ = test.dump_sinks();

    test.submit_message(u_tx_ceased_msg(OTHER, call.call_id));
    test.run_stack(Some(1));
    let msgs = test.dump_sinks();
    assert!(d_tx_granted_to(&msgs, CALLER).is_empty());
    assert!(d_tx_granted_to(&msgs, OTHER).is_empty());
    assert!(d_releases_to(&msgs, CALLER).is_empty());
    assert_eq!(
        count_control(&msgs, TetraEntity::Umac, |cc| matches!(cc, CallControl::RemoteFloorGranted { .. })),
        0
    );

    // The caller's own U-TX CEASED still starts the playback.
    test.submit_message(u_tx_ceased_msg(CALLER, call.call_id));
    test.run_stack(Some(1));
    let msgs = test.dump_sinks();
    assert_eq!(d_tx_granted_to(&msgs, CALLER).len(), 1);
}

#[test]
fn test_parrot_caller_disconnect_while_recording_frees_the_service() {
    debug::setup_logging_verbose();

    let mut test = cmce_test(parrot_config());
    let (call, _) = start_parrot_call(&mut test, CALLER, PARROT);
    test.submit_message(ul_frame_to_cmce(call.carrier_num, call.ts, vec![0x42; 35]));
    test.run_stack(Some(1));
    let _ = test.dump_sinks();

    test.submit_message(u_disconnect_msg(CALLER, call.call_id));
    test.run_stack(Some(1));
    let msgs = test.dump_sinks();
    let releases = d_releases_to(&msgs, CALLER);
    assert!(!releases.is_empty());
    assert!(d_releases_to(&msgs, PARROT).is_empty());
    assert_eq!(
        count_control(
            &msgs,
            TetraEntity::Umac,
            |cc| matches!(cc, CallControl::CloseSlot { ts, .. } if *ts == call.ts)
        ),
        1
    );

    // No playback after the hang-up, and a new call is accepted.
    test.run_stack(Some(40));
    assert!(playback_frames(&test.dump_sinks()).is_empty());
    let _ = start_parrot_call(&mut test, OTHER, PARROT);
}

#[test]
fn test_parrot_session_finishes_after_being_disabled_mid_call() {
    debug::setup_logging_verbose();

    let mut test = cmce_test(parrot_config());
    let (call, _) = start_parrot_call(&mut test, CALLER, PARROT);
    test.submit_message(ul_frame_to_cmce(call.carrier_num, call.ts, vec![0x42; 35]));
    test.run_stack(Some(1));
    let _ = test.dump_sinks();

    let mut disabled = (*test.config.config()).clone();
    disabled.cell.parrot_enabled = false;
    let state = test.config.state_read().clone();
    let disabled = SharedConfig::from_parts(disabled, Some(state));
    test.router
        .get_entity(TetraEntity::Cmce)
        .expect("cmce registered")
        .set_config(disabled);

    test.submit_message(u_tx_ceased_msg(CALLER, call.call_id));
    test.run_stack(Some(1));
    let msgs = run_until_release(&mut test, CALLER, 200);
    assert_eq!(playback_frames(&msgs), vec![(call.carrier_num, call.ts, vec![0x42; 35])]);
    assert_released_caller_only(&msgs, call);

    // Disabled now: 99999 is routed as any other ISSI (no Brew here, so rejected).
    test.submit_message(u_setup_msg(OTHER, PARROT, false, false));
    test.run_stack(Some(1));
    let msgs = test.dump_sinks();
    assert!(opened_circuits(&msgs).is_empty());
    assert_eq!(d_releases_to(&msgs, OTHER).len(), 1);
}

// ─── UMAC: media path ────────────────────────────────────────────────────────

fn umac_test(config: StackConfig) -> ComponentTest {
    let mut test = ComponentTest::from_config(config, Some(TdmaTime { h: 0, m: 1, f: 1, t: 4 }));
    test.populate_entities(
        vec![TetraEntity::Umac],
        vec![TetraEntity::Cmce, TetraEntity::Lmac, TetraEntity::Brew],
    );
    test
}

fn open_parrot_circuit(test: &mut ComponentTest, ts: u8) {
    test.submit_message(SapMsg {
        sap: Sap::Control,
        src: TetraEntity::Cmce,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::CmceCallControl(CallControl::Open(Circuit {
            direction: Direction::Both,
            carrier_num: MAIN_CARRIER,
            ts,
            peer_carrier_num: None,
            peer_ts: None,
            usage: 4,
            circuit_mode: CircuitModeType::TchS,
            speech_service: Some(0),
            etee_encrypted: false,
            dl_media_source: CircuitDlMediaSource::LocalParrot,
        })),
    });
    test.submit_message(SapMsg {
        sap: Sap::Control,
        src: TetraEntity::Cmce,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::CmceCallControl(CallControl::FloorGranted {
            call_id: 99,
            source_issi: CALLER,
            dest_gssi: PARROT,
            carrier_num: MAIN_CARRIER,
            ts,
        }),
    });
    test.run_stack(Some(1));
    let _ = test.dump_sinks();
}

/// A recognisable 274-bit ACELP frame, one bit per byte as the LMAC delivers it.
fn acelp_test_bits() -> Vec<u8> {
    (0..TCH_S_BITS).map(|idx| ((idx * 7 + idx / 3) % 2) as u8).collect()
}

fn pack_bits(bits: &[u8]) -> Vec<u8> {
    bits.chunks(8)
        .map(|chunk| chunk.iter().enumerate().fold(0u8, |byte, (i, bit)| byte | (bit & 1) << (7 - i)))
        .collect()
}

/// The 274 bits of every DL TCH/S block sent for `ts`, one bit per byte.
fn dl_tch_bits(msgs: &[SapMsg], ts: u8) -> Vec<Vec<u8>> {
    msgs.iter()
        .filter_map(|msg| match &msg.msg {
            SapMsgInner::TmvUnitdataReqSlots(req) => Some(req),
            _ => None,
        })
        .flat_map(|req| req.slots.iter())
        .filter(|slot| slot.carrier_num == MAIN_CARRIER && slot.ts.t == ts)
        .flat_map(|slot| [&slot.blk1, &slot.blk2].into_iter().flatten())
        .filter(|blk| blk.logical_channel == LogicalChannel::TchS)
        .map(|blk| {
            (0..TCH_S_BITS)
                .map(|i| blk.mac_block.peek_bits_startoffset(i, 1).unwrap_or(0) as u8)
                .collect()
        })
        .collect()
}

fn ul_voice_from_lmac(ts: u8, data: Vec<u8>) -> SapMsg {
    SapMsg {
        sap: Sap::TmdSap,
        src: TetraEntity::Lmac,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::TmdCircuitDataInd(TmdCircuitDataInd {
            carrier_num: MAIN_CARRIER,
            ts,
            data,
        }),
    }
}

fn tmd_inds_to(msgs: &[SapMsg], dest: TetraEntity) -> Vec<&TmdCircuitDataInd> {
    msgs.iter()
        .filter_map(|msg| match &msg.msg {
            SapMsgInner::TmdCircuitDataInd(ind) if msg.dest == dest => Some(ind),
            _ => None,
        })
        .collect()
}

#[test]
fn test_local_parrot_ul_goes_packed_to_cmce_without_loopback() {
    debug::setup_logging_verbose();

    let mut test = umac_test(ComponentTest::get_default_test_config(StackMode::Bs));
    open_parrot_circuit(&mut test, 2);

    let ul_bits = acelp_test_bits();
    test.submit_message(ul_voice_from_lmac(2, ul_bits.clone()));
    test.run_stack(Some(12));
    let msgs = test.dump_sinks();

    let to_cmce = tmd_inds_to(&msgs, TetraEntity::Cmce);
    assert_eq!(to_cmce.len(), 1);
    assert_eq!((to_cmce[0].carrier_num, to_cmce[0].ts), (MAIN_CARRIER, 2));
    assert_eq!(to_cmce[0].data, pack_bits(&ul_bits), "CMCE gets the frame packed, ready for the DL");
    assert_eq!(to_cmce[0].data.len(), 35);
    assert!(
        !dl_tch_bits(&msgs, 2).contains(&ul_bits),
        "LocalParrot must not loop the caller's speech straight back to the DL"
    );
}

#[test]
fn test_local_parrot_ul_is_not_forwarded_to_brew() {
    debug::setup_logging_verbose();

    let mut config = ComponentTest::get_default_test_config(StackMode::Bs);
    config.brew = Some(CfgBrew {
        host: "127.0.0.1".into(),
        port: 0,
        tls: false,
        username: None,
        password: None,
        reconnect_delay: std::time::Duration::from_secs(1),
        jitter_initial_latency_frames: 0,
        feature_sds_enabled: true,
        whitelisted_ssis: None,
        feature_rssi_export: false,
        pbx_gateway_issis: None,
    });
    let mut test = umac_test(config);
    open_parrot_circuit(&mut test, 2);

    test.submit_message(ul_voice_from_lmac(2, acelp_test_bits()));
    test.run_stack(Some(12));
    let msgs = test.dump_sinks();

    assert_eq!(tmd_inds_to(&msgs, TetraEntity::Cmce).len(), 1);
    assert!(tmd_inds_to(&msgs, TetraEntity::Brew).is_empty(), "parrot voice never leaves the BS");
}

#[test]
fn test_local_parrot_playback_frame_reaches_the_dl_intact() {
    debug::setup_logging_verbose();

    let mut test = umac_test(ComponentTest::get_default_test_config(StackMode::Bs));
    open_parrot_circuit(&mut test, 2);

    let bits = acelp_test_bits();
    test.submit_message(SapMsg {
        sap: Sap::TmdSap,
        src: TetraEntity::Cmce,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::TmdCircuitDataReq(TmdCircuitDataReq {
            carrier_num: MAIN_CARRIER,
            ts: 2,
            data: pack_bits(&bits),
        }),
    });
    test.run_stack(Some(12));
    let msgs = test.dump_sinks();

    assert!(
        dl_tch_bits(&msgs, 2).contains(&bits),
        "a parrot playback frame must go out as the complete ACELP TCH/S block"
    );
}
