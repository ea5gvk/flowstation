// SPDX-FileCopyrightText: Historical upstream contributors
// SPDX-FileCopyrightText: 2026 Chris YO3TCO / Nexus-BS Project
// SPDX-License-Identifier: Apache-2.0 AND PolyForm-Noncommercial-1.0.0
// SPDX-FileComment: Modified by Nexus-BS Project; see CHANGES-NEXUS.md for change notices.
// SPDX-FileComment: Parrot tests adapted for flowstation-miura (carrier_num, configurable ISSI, packed TCH/S) by EA5GVK.

mod common;

use tetra_config::bluestation::{CfgBrew, StackConfig, StackMode};
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{Direction, Sap, TdmaTime, debug};
use tetra_saps::control::call_control::{CallControl, Circuit, CircuitDlMediaSource};
use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;
use tetra_saps::sapmsg::{SapMsg, SapMsgInner};
use tetra_saps::tmd::{TmdCircuitDataInd, TmdCircuitDataReq};
use tetra_saps::tmv::enums::logical_chans::LogicalChannel;

use crate::common::ComponentTest;

const CALLER: u32 = 1000001;
const PARROT: u32 = 99_999;
const MAIN_CARRIER: u16 = 1521;
const TCH_S_BITS: usize = 274;

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
