//! `[packet_data]`: the SNDCP bearer between the radios and the WAP gateway, tested with the real
//! LLC, MLE and SNDCP entities.

mod common;

use common::ComponentTest;
use tetra_config::bluestation::{StackConfig, StackMode};
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{BitBuffer, Sap, SsiType, TdmaTime, TetraAddress};
use tetra_pdus::mle::enums::mle_protocol_discriminator::MleProtocolDiscriminator;
use tetra_saps::ltpd::LtpdBearer;
use tetra_saps::sapmsg::{SapMsg, SapMsgInner};
use tetra_saps::tla::{TlaTlDataIndBl, TlaTlUnitdataIndBl};
use tetra_saps::tma::TmaUnitdataInd;

const MAIN_CARRIER: u16 = 1521;
const ISSI: u32 = 2_260_618;

fn config(packet_data: bool, wap: bool) -> StackConfig {
    let mut cfg = ComponentTest::get_default_test_config(StackMode::Bs);
    cfg.cell.sndcp_service = true;
    cfg.packet_data.enabled = packet_data;
    cfg.wap.enabled = wap;
    cfg
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
        let mut test = ComponentTest::from_config(config(packet_data, false), Some(TdmaTime::default()));
        test.populate_entities(
            vec![TetraEntity::Llc, TetraEntity::Mle, TetraEntity::Sndcp],
            vec![TetraEntity::Umac, TetraEntity::Mm, TetraEntity::Cmce],
        );
        // AL-SETUP (LLC PDU type 8) and AL-DATA (type 9).
        test.submit_message(tma_ind(ISSI, BitBuffer::from_bitstr("1000000000000000000000000000"), 1));
        test.submit_message(tma_ind(ISSI, BitBuffer::from_bitstr("1001000000000000000000000000"), 1));
        test.run_stack(Some(4));
        assert!(test.dump_sinks().is_empty(), "packet_data {packet_data}");
    }
}
