// SPDX-FileCopyrightText: Historical upstream contributors
// SPDX-FileCopyrightText: 2026 Chris YO3TCO / Nexus-BS Project
// SPDX-License-Identifier: Apache-2.0 AND PolyForm-Noncommercial-1.0.0
// SPDX-FileComment: Modified by Nexus-BS Project; see CHANGES-NEXUS.md for change notices.
// SPDX-FileComment: Packet-data tests adapted from Nexus-BS test_mle_bs.rs, test_sndcp_bs.rs and test_llc_bs.rs for flowstation-miura (no LTPD report / configure primitives, SNDCP answers straight to the LLC, [packet_data] instead of cell_info wap_ip, advanced link TL-DATA primitives instead of non-zero link ids) by EA5GVK.

mod common;

use common::ComponentTest;
use tetra_config::bluestation::StackMode;
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{BitBuffer, Sap, SsiType, TdmaTime, TetraAddress, TxReporter, TxState, debug};
use tetra_entities::llc::components::fcs;
use tetra_entities::sndcp::ip::{bitbuffer_npdu_octets, build_ipv4_udp_npdu, parse_ipv4_packet, parse_udp_datagram};
use tetra_entities::sndcp::transfer::{
    SN_PDU_TYPE_DATA, SN_PDU_TYPE_END_OF_DATA, SndcpDataTransmitRequest, SndcpDataTransmitResponseResult, SndcpEndOfData,
    SndcpNotSupported, SndcpPacketDataResourceRequest, SndcpPhaseModulationResourceRequest, SndcpReconnect, SndcpTransferControl,
    decode_data_transmit_response, decode_end_of_data, decode_transfer_control_pdu, encode_data_transmit_request, encode_end_of_data,
    encode_not_supported, encode_reconnect,
};
use tetra_entities::sndcp::unitdata::{
    NetworkPduKind, SndcpEncodeError, SndcpUnitdataError, decode_sn_data_pdu, decode_sn_unitdata_pdu, decode_sn_user_data_pdu,
    encode_sn_unitdata,
};
use tetra_pdus::llc::consts::timers::{T251_SENDER_RETRY_TIMER, T252_ACK_WAITING_TIMER, T271_RECEIVER_NOT_READY_FOR_TX_TIMER};
use tetra_pdus::llc::enums::llc_pdu_type::LlcPduType;
use tetra_pdus::llc::pdus::al_ack::AlAck;
use tetra_pdus::llc::pdus::al_data::AlData;
use tetra_pdus::llc::pdus::al_setup::AlSetup;
use tetra_pdus::mle::enums::mle_protocol_discriminator::MleProtocolDiscriminator;
use tetra_saps::ltpd::{LtpdBearer, LtpdMleUnitdataInd};
use tetra_saps::sapmsg::{SapMsg, SapMsgInner};
use tetra_saps::tla::{TlDataIndAl, TlDataReqAl, TlaTlDataIndBl};
use tetra_saps::tma::TmaUnitdataInd;

const TEST_ISSI: u32 = 1_000_001;
const TEST_BITS: &str = "10101100";

fn issi_addr() -> TetraAddress {
    TetraAddress {
        ssi: TEST_ISSI,
        ssi_type: SsiType::Issi,
    }
}

fn build_tl_data_ind(discriminator: MleProtocolDiscriminator, addr: TetraAddress, link_id: u32, endpoint_id: u32) -> SapMsg {
    let mut sdu = BitBuffer::new(3 + TEST_BITS.len());
    sdu.write_bits(discriminator.into_raw(), 3);
    sdu.copy_bits(&mut BitBuffer::from_bitstr(TEST_BITS), TEST_BITS.len());
    sdu.seek(0);

    SapMsg {
        sap: Sap::TlaSap,
        src: TetraEntity::Llc,
        dest: TetraEntity::Mle,
        msg: SapMsgInner::TlaTlDataIndBl(TlaTlDataIndBl {
            main_address: addr,
            link_id,
            endpoint_id,
            new_endpoint_id: None,
            css_endpoint_id: None,
            tl_sdu: Some(sdu),
            scrambling_code: 0,
            fcs_flag: false,
            air_interface_encryption: 0,
            chan_change_resp_req: false,
            chan_change_handle: None,
            chan_info: None,
            req_handle: 23,
        }),
    }
}

/// Nexus-BS test_mle_bs.rs `test_sndcp_prefixed_tl_data_ind_routes_to_tlpd_sap`; miura adds the
/// bearer the PDU came in on.
#[test]
fn test_sndcp_prefixed_tl_data_ind_routes_to_tlpd_sap() {
    let mut test = ComponentTest::new(StackMode::Bs, None);
    test.populate_entities(vec![TetraEntity::Mle], vec![TetraEntity::Sndcp]);

    test.submit_message(build_tl_data_ind(MleProtocolDiscriminator::Sndcp, issi_addr(), 9, 4));
    test.deliver_all_messages();
    let sink_msgs = test.dump_sinks();

    assert_eq!(sink_msgs.len(), 1);
    assert_eq!(sink_msgs[0].sap, Sap::TlpdSap);
    assert_eq!(sink_msgs[0].dest, TetraEntity::Sndcp);
    let SapMsgInner::LtpdMleUnitdataInd(prim) = &sink_msgs[0].msg else {
        panic!("expected SNDCP MLE-UNITDATA indication");
    };
    assert_eq!(prim.received_tetra_address, issi_addr());
    assert_eq!(prim.link_id, 9);
    assert_eq!(prim.endpoint_id, 4);
    assert_eq!(prim.bearer, LtpdBearer::BasicAck);
    assert_eq!(
        prim.sdu.peek_bits(TEST_BITS.len()),
        Some(u64::from_str_radix(TEST_BITS, 2).unwrap())
    );
}

fn build_sn_unitdata(nsapi: u8, pcomp: u8, dcomp: u8, n_pdu: &[u8]) -> BitBuffer {
    build_sn_user_data(4, nsapi, pcomp, dcomp, n_pdu)
}

fn build_sn_data(nsapi: u8, pcomp: u8, dcomp: u8, n_pdu: &[u8]) -> BitBuffer {
    build_sn_user_data(SN_PDU_TYPE_DATA, nsapi, pcomp, dcomp, n_pdu)
}

fn build_sn_user_data(sn_pdu_type: u8, nsapi: u8, pcomp: u8, dcomp: u8, n_pdu: &[u8]) -> BitBuffer {
    let mut sdu = BitBuffer::new(16 + n_pdu.len() * 8);
    sdu.write_bits(sn_pdu_type as u64, 4);
    sdu.write_bits(nsapi as u64, 4);
    sdu.write_bits(pcomp as u64, 4);
    sdu.write_bits(dcomp as u64, 4);
    for byte in n_pdu {
        sdu.write_bits(*byte as u64, 8);
    }
    sdu.seek(0);
    sdu
}

fn build_sn_pdu(sn_pdu_type: u8) -> BitBuffer {
    let mut sdu = BitBuffer::new(8);
    sdu.write_bits(sn_pdu_type as u64, 4);
    sdu.write_bits(0, 4);
    sdu.seek(0);
    sdu
}

/// Nexus-BS `sndcp_encode_sn_unitdata_no_compression_round_trips_decoder`.
#[test]
fn sndcp_encode_sn_unitdata_no_compression_round_trips_decoder() {
    // EN 300 392-2 clause 28.4.4.14/table 28.43 defines SN-UNITDATA as
    // SN PDU type, NSAPI, PCOMP, DCOMP and a lower-layer-length N-PDU with no
    // trailing O-bit.
    let mut n_pdu = BitBuffer::new(32);
    for byte in [0x45, 0x00, 0x00, 0x14] {
        n_pdu.write_bits(byte, 8);
    }
    n_pdu.seek(0);

    let encoded = encode_sn_unitdata(3, 0, 0, &n_pdu).expect("SN-UNITDATA encode should succeed");
    let unitdata = decode_sn_unitdata_pdu(&encoded).expect("expected encoded SN-UNITDATA to decode");

    assert_eq!(unitdata.nsapi, 3);
    assert_eq!(unitdata.pcomp, 0);
    assert_eq!(unitdata.dcomp, 0);
    assert_eq!(unitdata.network_pdu_kind, NetworkPduKind::Ipv4);
    assert_eq!(unitdata.n_pdu.to_bitstr(), n_pdu.to_bitstr());

    assert_eq!(
        encode_sn_unitdata(0, 0, 0, &n_pdu).map(|_| ()),
        Err(SndcpEncodeError::UnsupportedNsapi(0))
    );
    assert_eq!(
        encode_sn_unitdata(15, 0, 0, &n_pdu).map(|_| ()),
        Err(SndcpEncodeError::UnsupportedNsapi(15))
    );
    assert_eq!(
        encode_sn_unitdata(3, 1, 0, &n_pdu).map(|_| ()),
        Err(SndcpEncodeError::UnsupportedCompression { pcomp: 1, dcomp: 0 })
    );
    assert_eq!(
        encode_sn_unitdata(3, 0, 0, &BitBuffer::new(0)).map(|_| ()),
        Err(SndcpEncodeError::EmptyNPdu)
    );
}

/// Nexus-BS `sndcp_decode_ltpd_sdu_accepts_mle_demux_cursor`: the MLE consumes the 3-bit
/// discriminator before handing the SDU over, so the SNDCP PDU starts at its cursor (bit 3).
#[test]
fn sndcp_decode_ltpd_sdu_accepts_mle_demux_cursor() {
    let sndcp_sdu = build_sn_unitdata(2, 0, 0, &[0x45, 0x00, 0x00, 0x14]);
    let mut tl_sdu = BitBuffer::new(3 + sndcp_sdu.get_len());
    tl_sdu.write_bits(MleProtocolDiscriminator::Sndcp.into_raw(), 3);
    let mut copy = BitBuffer::from_bitbuffer(&sndcp_sdu);
    let len = copy.get_len();
    tl_sdu.copy_bits(&mut copy, len);
    tl_sdu.seek(0);

    let mut msg = build_tl_data_ind(MleProtocolDiscriminator::Sndcp, issi_addr(), 1, 0);
    if let SapMsgInner::TlaTlDataIndBl(prim) = &mut msg.msg {
        prim.tl_sdu = Some(tl_sdu);
    }
    let mut test = ComponentTest::new(StackMode::Bs, None);
    test.populate_entities(vec![TetraEntity::Mle], vec![TetraEntity::Sndcp]);
    test.submit_message(msg);
    test.deliver_all_messages();
    let sink_msgs = test.dump_sinks();
    let SapMsgInner::LtpdMleUnitdataInd(prim) = &sink_msgs[0].msg else {
        panic!("expected SNDCP MLE-UNITDATA indication");
    };
    assert_eq!(prim.sdu.get_pos(), 3, "cursor after the MLE discriminator");
    let unitdata = decode_sn_unitdata_pdu(&BitBuffer::from_bitbuffer_pos(&prim.sdu)).expect("cursor-relative SN-UNITDATA");
    assert_eq!(unitdata.nsapi, 2);
    assert_eq!(unitdata.n_pdu.get_len(), 32);
}

/// Nexus-BS `sndcp_decode_sn_unitdata_no_compression_ipv4_npdu`.
#[test]
fn sndcp_decode_sn_unitdata_no_compression_ipv4_npdu() {
    let sdu = build_sn_unitdata(3, 0, 0, &[0x45, 0x00, 0x00, 0x14]);
    let unitdata = decode_sn_unitdata_pdu(&sdu).expect("expected decoded SN-UNITDATA");

    assert_eq!(unitdata.nsapi, 3);
    assert_eq!(unitdata.pcomp, 0);
    assert_eq!(unitdata.dcomp, 0);
    assert_eq!(unitdata.network_pdu_kind, NetworkPduKind::Ipv4);
    assert_eq!(unitdata.n_pdu.get_len(), 32);

    let mut n_pdu = BitBuffer::from_bitbuffer(&unitdata.n_pdu);
    assert_eq!(n_pdu.read_bits(8), Some(0x45));
}

/// Nexus-BS `sndcp_decode_sn_data_no_compression_ipv4_npdu`.
#[test]
fn sndcp_decode_sn_data_no_compression_ipv4_npdu() {
    let sdu = build_sn_data(3, 0, 0, &[0x45, 0x00, 0x00, 0x14]);
    let unitdata = decode_sn_data_pdu(&sdu).expect("expected decoded SN-DATA");

    assert_eq!(unitdata.nsapi, 3);
    assert_eq!(unitdata.pcomp, 0);
    assert_eq!(unitdata.dcomp, 0);
    assert_eq!(unitdata.network_pdu_kind, NetworkPduKind::Ipv4);
    assert_eq!(unitdata.n_pdu.get_len(), 32);
}

/// Nexus-BS `sndcp_decode_distinguishes_unsupported_packet_data_cases`.
#[test]
fn sndcp_decode_distinguishes_unsupported_packet_data_cases() {
    assert_eq!(
        decode_sn_user_data_pdu(&build_sn_pdu(14)).map(|_| ()),
        Err(SndcpUnitdataError::UnsupportedPduType(14))
    );
    assert_eq!(
        decode_sn_unitdata_pdu(&build_sn_unitdata(15, 0, 0, &[0x45])).map(|_| ()),
        Err(SndcpUnitdataError::UnsupportedNsapi(15))
    );
    assert_eq!(
        decode_sn_unitdata_pdu(&build_sn_unitdata(3, 1, 0, &[0x45])).map(|_| ()),
        Err(SndcpUnitdataError::UnsupportedCompression { pcomp: 1, dcomp: 0 })
    );
}

/// Nexus-BS `sndcp_decode_transfer_control_pdus_without_runtime_handoff`.
#[test]
fn sndcp_decode_transfer_control_pdus() {
    let request = encode_data_transmit_request(&SndcpDataTransmitRequest {
        nsapi: 2,
        logical_link_status: false,
        resource_request: SndcpPacketDataResourceRequest::None,
    })
    .expect("SN-DATA TRANSMIT REQUEST should encode");
    let Ok(SndcpTransferControl::DataTransmitRequest(decoded_request)) = decode_transfer_control_pdu(&request) else {
        panic!("expected decoded SN-DATA TRANSMIT REQUEST");
    };
    assert_eq!(decoded_request.nsapi, 2);

    let end = encode_end_of_data(&SndcpEndOfData {
        immediate_service_change: true,
    })
    .expect("SN-END OF DATA should encode");
    let Ok(SndcpTransferControl::EndOfData(decoded_end)) = decode_transfer_control_pdu(&end) else {
        panic!("expected decoded SN-END OF DATA");
    };
    assert!(decoded_end.immediate_service_change);

    let not_supported = encode_not_supported(&SndcpNotSupported {
        not_supported_pdu_type: SN_PDU_TYPE_END_OF_DATA,
    })
    .expect("SN-NOT SUPPORTED should encode");
    let Ok(SndcpTransferControl::NotSupported(decoded_not_supported)) = decode_transfer_control_pdu(&not_supported) else {
        panic!("expected decoded SN-NOT SUPPORTED");
    };
    assert_eq!(decoded_not_supported.not_supported_pdu_type, SN_PDU_TYPE_END_OF_DATA);
}

// ---------------------------------------------------------------------------------------------
// Runtime (Nexus-BS test_sndcp_bs.rs, adapted: SNDCP answers straight to the LLC, the PDP context
// is kept by the miura runtime, B1 assigns no channel)
// ---------------------------------------------------------------------------------------------

/// The SNDCP entity alone, answers collected at the LLC.
fn sndcp_test(packet_data: bool) -> ComponentTest {
    let mut config = ComponentTest::get_default_test_config(StackMode::Bs);
    config.cell.sndcp_service = true;
    config.packet_data.enabled = packet_data;
    config.wap.enabled = packet_data;
    let mut test = ComponentTest::from_config(config, None);
    test.populate_entities(
        vec![TetraEntity::Sndcp],
        vec![TetraEntity::Llc, TetraEntity::Mle, TetraEntity::Cmce],
    );
    test
}

/// LTPD-UNITDATA indication of `sn` (an SN-PDU) as the MLE delivers it: with the discriminator in
/// front and the cursor after it.
fn build_ltpd_ind(sap: Sap, sn: BitBuffer) -> SapMsg {
    let mut sn = BitBuffer::from_bitbuffer(&sn);
    let len = sn.get_len();
    let mut sdu = BitBuffer::new(3 + len);
    sdu.write_bits(MleProtocolDiscriminator::Sndcp.into_raw(), 3);
    sdu.copy_bits(&mut sn, len);
    sdu.seek(3);
    SapMsg {
        sap,
        src: TetraEntity::Mle,
        dest: TetraEntity::Sndcp,
        msg: SapMsgInner::LtpdMleUnitdataInd(LtpdMleUnitdataInd {
            sdu,
            endpoint_id: 1,
            link_id: 1,
            received_tetra_address: issi_addr(),
            chan_change_resp_req: false,
            chan_change_handle: None,
            bearer: LtpdBearer::BasicAck,
        }),
    }
}

/// SN-ACTIVATE PDP CONTEXT DEMAND, dynamic IPv4 (table 28.24), for `ms_type` (0 = A, 1 = B, 2 = C).
fn build_dynamic_ipv4_activation_demand_with_ms_type(nsapi: u8, ms_type: u8) -> BitBuffer {
    BitBuffer::from_bitstr(&format!("00000001{nsapi:04b}001{ms_type:04b}000000000"))
}

fn build_dynamic_ipv4_activation_demand(nsapi: u8) -> BitBuffer {
    build_dynamic_ipv4_activation_demand_with_ms_type(nsapi, 0)
}

fn build_mxp600_data_transmit_request(nsapi: u8, slots: u8, unspecified: bool) -> BitBuffer {
    encode_data_transmit_request(&SndcpDataTransmitRequest {
        nsapi,
        logical_link_status: false,
        resource_request: SndcpPacketDataResourceRequest::PhaseModulation(SndcpPhaseModulationResourceRequest {
            uplink_timeslots: slots,
            downlink_timeslots: slots,
            full_phase_modulation_capability_timeslots: slots,
            unspecified_phase_modulation_resource: unspecified,
        }),
    })
    .expect("MXP600-style SN-DATA TRANSMIT REQUEST should encode")
}

/// Everything SNDCP sent to the LLC: (acknowledged service, SN-PDU without the discriminator,
/// channel allocation present, link id).
fn take_llc_reqs(test: &mut ComponentTest) -> Vec<(bool, BitBuffer, bool, u32)> {
    test.dump_sinks()
        .into_iter()
        .filter(|msg| msg.src == TetraEntity::Sndcp && msg.dest == TetraEntity::Llc)
        .filter_map(|msg| {
            let (acked, mut sdu, chan_alloc, link_id) = match msg.msg {
                SapMsgInner::TlaTlDataReqBl(req) => (true, req.tl_sdu, req.chan_alloc.is_some(), req.link_id),
                SapMsgInner::TlaTlUnitdataReqBl(req) => (false, req.tl_sdu, req.chan_alloc.is_some(), req.link_id),
                _ => return None,
            };
            assert_eq!(sdu.read_bits(3), Some(MleProtocolDiscriminator::Sndcp.into_raw()));
            Some((acked, BitBuffer::from_bitbuffer_pos(&sdu), chan_alloc, link_id))
        })
        .collect()
}

/// (NSAPI, IPv4) of an SN-ACTIVATE PDP CONTEXT ACCEPT.
fn accept_nsapi_ip(pdu: &BitBuffer) -> (u8, [u8; 4]) {
    let bits = pdu.to_bitstr();
    assert_eq!(&bits[..4], "0000", "SN-ACTIVATE PDP CONTEXT ACCEPT");
    let ip = u32::from_str_radix(&bits[26..58], 2).unwrap();
    (u8::from_str_radix(&bits[4..8], 2).unwrap(), ip.to_be_bytes())
}

fn wtp_get(tid: u16, uri: &str) -> Vec<u8> {
    let mut payload = vec![0x0a];
    payload.extend_from_slice(&(tid & 0x7fff).to_be_bytes());
    payload.extend_from_slice(&[0x12, 0x40, uri.len() as u8]);
    payload.extend_from_slice(uri.as_bytes());
    payload
}

/// Nexus-BS `sndcp_wap_ip_mvp_answers_activation_ready_and_wml_unitdata_when_enabled`, with a WTP
/// GET to the real gateway.
#[test]
fn sndcp_wap_ip_mvp_answers_activation_ready_and_wml_unitdata_when_enabled() {
    let mut test = sndcp_test(true);
    test.submit_message(build_ltpd_ind(Sap::TlpdSap, build_dynamic_ipv4_activation_demand(2)));
    test.submit_message(build_ltpd_ind(
        Sap::TlpdSap,
        encode_data_transmit_request(&SndcpDataTransmitRequest {
            nsapi: 2,
            logical_link_status: false,
            resource_request: SndcpPacketDataResourceRequest::None,
        })
        .expect("SN-DATA TRANSMIT REQUEST should encode"),
    ));
    let n_pdu = build_ipv4_udp_npdu(
        [10, 0, 0, 2],
        [10, 0, 0, 1],
        49_152,
        9201,
        &wtp_get(0x2260, "/status.wml"),
        0x2260,
        32,
    )
    .unwrap();
    test.submit_message(build_ltpd_ind(Sap::TlpdSap, build_sn_unitdata(2, 0, 0, &n_pdu)));
    // The gateway answers on the next tick.
    test.run_stack(Some(2));

    let mut reqs = take_llc_reqs(&mut test);
    assert_eq!(reqs.len(), 3);

    assert_eq!(accept_nsapi_ip(&reqs[0].1), (2, [10, 0, 0, 2]));
    assert!(reqs[0].0, "ACCEPT on the acknowledged basic link");

    let ready = decode_data_transmit_response(&reqs[1].1).expect("ready response should decode");
    assert_eq!(ready.nsapi, 2);
    assert_eq!(ready.result, SndcpDataTransmitResponseResult::Accepted);
    assert!(reqs[1].0);
    assert!(!reqs[1].2, "B1: no channel assignment, the data stays on the MCCH");

    let (acked, pdu, chan_alloc, link_id) = reqs.remove(2);
    assert!(
        !acked && !chan_alloc && link_id == 0,
        "SN-UNITDATA on the unacknowledged basic link, MCCH"
    );
    let unitdata = decode_sn_user_data_pdu(&pdu).expect("WAP response SN user data should decode");
    let response_octets = bitbuffer_npdu_octets(&unitdata.n_pdu).expect("response N-PDU should be byte aligned");
    let response_ip = parse_ipv4_packet(&response_octets).expect("response IPv4 should parse");
    let response_udp = parse_udp_datagram(response_ip.payload).expect("response UDP should parse");
    assert_eq!(response_ip.source, [10, 0, 0, 1]);
    assert_eq!(response_ip.destination, [10, 0, 0, 2]);
    assert_eq!(response_udp.source_port, 9201);
    assert_eq!(response_udp.destination_port, 49_152);
    assert!(response_octets.len() <= 320, "basic-link datagram: {} bytes", response_octets.len());
    let page = String::from_utf8_lossy(response_udp.payload);
    assert!(page.contains("<wml>"), "page={page:?}");
}

/// Nexus-BS `sndcp_wap_ip_deregister_clears_stale_pdp_context_before_reactivation`: in miura the
/// registration lives in the subscriber registry, checked once a second.
#[test]
fn sndcp_wap_ip_deregister_clears_stale_pdp_context_before_reactivation() {
    let mut test = sndcp_test(true);
    test.config.state_write().subscribers.register(TEST_ISSI);
    test.submit_message(build_ltpd_ind(
        Sap::TlpdSap,
        build_dynamic_ipv4_activation_demand_with_ms_type(1, 1),
    ));
    test.run_stack(Some(80));
    test.config.state_write().subscribers.deregister(TEST_ISSI);
    test.run_stack(Some(80));
    test.submit_message(build_ltpd_ind(Sap::TlpdSap, build_mxp600_data_transmit_request(1, 1, false)));
    test.submit_message(build_ltpd_ind(
        Sap::TlpdSap,
        build_dynamic_ipv4_activation_demand_with_ms_type(1, 1),
    ));
    test.run_stack(Some(1));

    let reqs = take_llc_reqs(&mut test);
    assert_eq!(reqs.len(), 3);
    assert_eq!(accept_nsapi_ip(&reqs[0].1), (1, [10, 0, 0, 2]));
    assert!(
        matches!(
            decode_data_transmit_response(&reqs[1].1).unwrap().result,
            SndcpDataTransmitResponseResult::Rejected(_)
        ),
        "the stale context is gone"
    );
    assert_eq!(
        accept_nsapi_ip(&reqs[2].1),
        (1, [10, 0, 0, 2]),
        "reactivation gets the freed address"
    );
}

/// Nexus-BS `sndcp_wap_ip_mvp_accepts_mxp600_type_b_and_type_c_activation_when_enabled`.
#[test]
fn sndcp_wap_ip_mvp_accepts_mxp600_type_b_and_type_c_activation_when_enabled() {
    for ms_type in [1, 2] {
        let mut test = sndcp_test(true);
        test.submit_message(build_ltpd_ind(
            Sap::TlpdSap,
            build_dynamic_ipv4_activation_demand_with_ms_type(1, ms_type),
        ));
        test.deliver_all_messages();
        let reqs = take_llc_reqs(&mut test);
        assert_eq!(reqs.len(), 1, "unexpected response count for MS type {ms_type}");
        assert_eq!(accept_nsapi_ip(&reqs[0].1), (1, [10, 0, 0, 2]));
        assert!(reqs[0].0);
    }
}

/// Nexus-BS `sndcp_wap_ip_mvp_accepts_mxp600_type_b_single_slot_data_transmit_request` and the
/// four-slot ones (`..._unspecified_four_slot_resource_request`, `..._specific_four_slot_...`):
/// accepted, and in B1 without a channel.
#[test]
fn sndcp_wap_ip_mvp_accepts_mxp600_data_transmit_requests_without_channel() {
    for (slots, unspecified) in [(1, false), (4, true), (4, false)] {
        let mut test = sndcp_test(true);
        test.submit_message(build_ltpd_ind(
            Sap::TlpdSap,
            build_dynamic_ipv4_activation_demand_with_ms_type(2, 1),
        ));
        let request = build_mxp600_data_transmit_request(2, slots, unspecified);
        assert_eq!(request.get_len(), 21);
        test.submit_message(build_ltpd_ind(Sap::TlpdSap, request));
        test.deliver_all_messages();
        let mut reqs = take_llc_reqs(&mut test);
        assert_eq!(reqs.len(), 2);
        let (acked, pdu, chan_alloc, _) = reqs.remove(1);
        let ready = decode_data_transmit_response(&pdu).expect("SN-DATA TRANSMIT RESPONSE should decode");
        assert_eq!((ready.nsapi, ready.result), (2, SndcpDataTransmitResponseResult::Accepted));
        assert!(acked && !chan_alloc, "{slots} slot(s): no channel assignment in B1");
    }
}

/// Nexus-BS `sndcp_wap_ip_end_of_data_returns_common_control_after_pdch_assignment`: the radio's
/// SN-END OF DATA is answered with one (no channel to leave in B1).
#[test]
fn sndcp_wap_ip_end_of_data_is_answered() {
    let mut test = sndcp_test(true);
    test.submit_message(build_ltpd_ind(Sap::TlpdSap, build_dynamic_ipv4_activation_demand(2)));
    test.submit_message(build_ltpd_ind(Sap::TlpdSap, build_mxp600_data_transmit_request(2, 1, false)));
    test.submit_message(build_ltpd_ind(
        Sap::TlpdSap,
        encode_end_of_data(&SndcpEndOfData {
            immediate_service_change: false,
        })
        .unwrap(),
    ));
    test.deliver_all_messages();
    let reqs = take_llc_reqs(&mut test);
    assert_eq!(reqs.len(), 3);
    let end = decode_end_of_data(&reqs[2].1).expect("SN-END OF DATA");
    assert!(!end.immediate_service_change);
    assert!(reqs[2].0 && !reqs[2].2);
}

/// Nexus-BS `sndcp_wap_ip_mvp_accepts_mxp600_type_b_specific_four_slot_reconnect`.
#[test]
fn sndcp_wap_ip_mvp_accepts_mxp600_type_b_specific_four_slot_reconnect() {
    let mut test = sndcp_test(true);
    test.submit_message(build_ltpd_ind(
        Sap::TlpdSap,
        build_dynamic_ipv4_activation_demand_with_ms_type(1, 1),
    ));
    let reconnect = encode_reconnect(&SndcpReconnect {
        nsapi: Some(1),
        resource_request: SndcpPacketDataResourceRequest::PhaseModulation(SndcpPhaseModulationResourceRequest {
            uplink_timeslots: 4,
            downlink_timeslots: 4,
            full_phase_modulation_capability_timeslots: 4,
            unspecified_phase_modulation_resource: false,
        }),
    })
    .expect("MXP600-style specific four-slot SN-RECONNECT should encode");
    assert_eq!(reconnect.get_len(), 21);
    test.submit_message(build_ltpd_ind(Sap::TlpdSap, reconnect));
    test.deliver_all_messages();
    let reqs = take_llc_reqs(&mut test);
    assert_eq!(reqs.len(), 2);
    let response = decode_data_transmit_response(&reqs[1].1).expect("SN-DATA TRANSMIT RESPONSE");
    assert_eq!((response.nsapi, response.result), (1, SndcpDataTransmitResponseResult::Accepted));
    assert!(!reqs[1].2);
}

/// Nexus-BS drop tests (`sndcp_ltpd_deactivation_demand_decodes_but_drops_without_pdp_handler`,
/// `..._deactivation_accept_drops_without_pending_context`, `..._transfer_control_decodes_but_drops_...`,
/// `..._unitdata_drops_without_output_when_service_is_not_advertised`,
/// `..._unitdata_decodes_but_drops_without_sn_sap_handoff`, `..._reserved_nsapi_and_compression_drop_...`):
/// with `[packet_data]` off the stub answers only an activation DEMAND, as it always has.
#[test]
fn sndcp_with_packet_data_off_answers_only_the_activation_demand() {
    let mut test = sndcp_test(false);
    test.submit_message(build_ltpd_ind(Sap::TlpdSap, BitBuffer::from_bitstr("00100000000100100")));
    test.submit_message(build_ltpd_ind(Sap::TlpdSap, BitBuffer::from_bitstr("0001000000000")));
    test.submit_message(build_ltpd_ind(Sap::TlpdSap, build_mxp600_data_transmit_request(2, 1, false)));
    test.submit_message(build_ltpd_ind(
        Sap::TlpdSap,
        encode_end_of_data(&SndcpEndOfData {
            immediate_service_change: false,
        })
        .unwrap(),
    ));
    test.submit_message(build_ltpd_ind(Sap::TlpdSap, build_sn_unitdata(3, 0, 0, &[0x45])));
    test.submit_message(build_ltpd_ind(Sap::TlpdSap, build_sn_unitdata(15, 0, 0, &[0x45])));
    test.submit_message(build_ltpd_ind(Sap::TlpdSap, build_sn_unitdata(3, 1, 0, &[0x45])));
    test.run_stack(Some(2));
    assert!(take_llc_reqs(&mut test).is_empty());

    test.submit_message(build_ltpd_ind(Sap::TlpdSap, build_dynamic_ipv4_activation_demand(2)));
    test.deliver_all_messages();
    let reqs = take_llc_reqs(&mut test);
    assert_eq!(reqs.len(), 1);
    assert_eq!(accept_nsapi_ip(&reqs[0].1), (2, [192, 168, 1, 180]), "the stub's fixed address");
}

/// Nexus-BS `sndcp_ltpd_reserved_nsapi_and_compression_drop_without_output` and
/// `sndcp_ltpd_malformed_control_pdu_drops_without_output`, with the runtime on (a DEMAND of 8
/// bits, which the stub would still answer, is dropped).
#[test]
fn sndcp_runtime_drops_reserved_nsapi_compression_and_malformed_pdus() {
    let mut test = sndcp_test(true);
    test.submit_message(build_ltpd_ind(Sap::TlpdSap, build_sn_unitdata(15, 0, 0, &[0x45])));
    test.submit_message(build_ltpd_ind(Sap::TlpdSap, build_sn_unitdata(3, 1, 0, &[0x45])));
    test.submit_message(build_ltpd_ind(Sap::TlpdSap, build_sn_pdu(0)));
    test.run_stack(Some(2));
    assert!(take_llc_reqs(&mut test).is_empty());
}

/// Nexus-BS `sndcp_unexpected_sap_drops_without_panic`: a primitive SNDCP does not handle is
/// dropped, with the runtime on or off.
#[test]
fn sndcp_unexpected_primitive_drops_without_panic() {
    for packet_data in [false, true] {
        let mut test = sndcp_test(packet_data);
        test.submit_message(SapMsg {
            sap: Sap::LmmSap,
            src: TetraEntity::Mle,
            dest: TetraEntity::Sndcp,
            msg: build_tl_data_ind(MleProtocolDiscriminator::Sndcp, issi_addr(), 1, 0).msg,
        });
        test.run_stack(Some(2));
        assert!(take_llc_reqs(&mut test).is_empty());
    }
}

// ---------------------------------------------------------------------------------------------
// LLC advanced link (Nexus-BS test_llc_bs.rs, adapted: TL-DATA on an advanced link is
// TlaTlDataReqAl / TlaTlDataIndAl instead of a TL-DATA with a non-zero link id, MAC reports are
// TxReporter states, AL PDUs never steal, one segment at a time on the MCCH)
// ---------------------------------------------------------------------------------------------

const AL_ISSI: u32 = 2_065_022;

fn al_addr() -> TetraAddress {
    TetraAddress::new(AL_ISSI, SsiType::Issi)
}

/// The LLC alone with `[packet_data]` on, MAC and MLE as sinks.
fn llc_test() -> ComponentTest {
    let mut config = ComponentTest::get_default_test_config(StackMode::Bs);
    config.packet_data.enabled = true;
    let mut test = ComponentTest::from_config(config, Some(TdmaTime { t: 1, f: 1, m: 1, h: 0 }));
    test.populate_entities(vec![TetraEntity::Llc], vec![TetraEntity::Umac, TetraEntity::Mle]);
    test
}

fn default_al_setup() -> AlSetup {
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

fn tma_unitdata_ind(pdu: BitBuffer) -> SapMsg {
    SapMsg {
        sap: Sap::TmaSap,
        src: TetraEntity::Umac,
        dest: TetraEntity::Llc,
        msg: SapMsgInner::TmaUnitdataInd(TmaUnitdataInd {
            carrier_num: 1521,
            pdu: Some(pdu),
            main_address: al_addr(),
            scrambling_code: 0,
            link_id: 1,
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

fn build_al_setup_ind_with_setup(setup: AlSetup) -> SapMsg {
    let mut pdu = BitBuffer::new_autoexpand(32);
    setup.to_bitbuf(&mut pdu);
    pdu.seek(0);
    tma_unitdata_ind(pdu)
}

fn build_al_setup_ind() -> SapMsg {
    build_al_setup_ind_with_setup(default_al_setup())
}

/// One AL-DATA / AL-FINAL segment carrying `payload` as is.
fn build_al_segment_ind(final_segment: bool, ar: bool, ns: u8, ss: u8, payload: &BitBuffer) -> SapMsg {
    let mut pdu = BitBuffer::new_autoexpand(64);
    AlData {
        final_segment,
        acknowledgement_requested: ar,
        ns,
        ss,
    }
    .to_bitbuf(&mut pdu);
    let mut payload = BitBuffer::from_bitbuffer(payload);
    payload.seek(0);
    let len = payload.get_len();
    pdu.copy_bits(&mut payload, len);
    pdu.seek(0);
    tma_unitdata_ind(pdu)
}

/// A whole TL-SDU in one AL-FINAL-AR, FCS appended.
fn build_al_final_ar_ind(ns: u8, tl_sdu: &[u8]) -> SapMsg {
    let mut with_fcs = BitBuffer::new_autoexpand(64);
    with_fcs.copy_bits(&mut BitBuffer::from_bytes(tl_sdu), tl_sdu.len() * 8);
    let value = fcs::compute_fcs(&with_fcs, 0, with_fcs.get_len());
    with_fcs.write_bits(value as u64, 32);
    with_fcs.seek(0);
    build_al_segment_ind(true, true, ns, 0, &with_fcs)
}

fn build_al_ack_ind(ack: AlAck) -> SapMsg {
    let mut pdu = BitBuffer::new_autoexpand(32);
    ack.to_bitbuf(&mut pdu);
    pdu.seek(0);
    tma_unitdata_ind(pdu)
}

fn build_al_rnr_complete_ind(nr: u8) -> SapMsg {
    let mut rnr = AlAck::complete(nr);
    rnr.receiver_ready = false;
    build_al_ack_ind(rnr)
}

/// TL-DATA on advanced link 1, as the SNDCP runtime sends it.
fn tl_data_req_al(tl_sdu: &[u8]) -> (SapMsg, TxReporter) {
    let reporter = TxReporter::new();
    let msg = SapMsg {
        sap: Sap::TlaSap,
        src: TetraEntity::Sndcp,
        dest: TetraEntity::Llc,
        msg: SapMsgInner::TlaTlDataReqAl(TlDataReqAl {
            main_address: al_addr(),
            al_number: 0,
            tl_sdu: BitBuffer::from_bytes(tl_sdu),
            tx_reporter: Some(reporter.clone()),
        }),
    };
    (msg, reporter)
}

/// What reached the sinks; the MAC reports every TMA request transmitted when `transmit`.
fn drain(test: &mut ComponentTest, transmit: bool) -> Vec<SapMsg> {
    let msgs = test.dump_sinks();
    for msg in &msgs {
        if let SapMsgInner::TmaUnitdataReq(req) = &msg.msg {
            assert!(
                !req.stealing_permission && req.chan_alloc.is_none() && req.link_id == 0,
                "advanced link PDUs go on the MCCH, never stolen: {req:?}"
            );
            if transmit
                && let Some(r) = &req.tx_reporter
                && r.get_state() == TxState::Pending
            {
                r.mark_transmitted();
            }
        }
    }
    msgs
}

/// Run `ticks` ticks with the MAC transmitting everything; returns all the sinks got.
fn run_llc(test: &mut ComponentTest, ticks: usize) -> Vec<SapMsg> {
    let mut all = Vec::new();
    for _ in 0..ticks {
        test.run_stack(Some(1));
        all.extend(drain(test, true));
    }
    all
}

fn llc_type(msg: &SapMsg) -> Option<LlcPduType> {
    let SapMsgInner::TmaUnitdataReq(req) = &msg.msg else { return None };
    LlcPduType::try_from(req.pdu.peek_bits(4)?).ok()
}

fn pdu_of(msg: &SapMsg) -> BitBuffer {
    let SapMsgInner::TmaUnitdataReq(req) = &msg.msg else {
        panic!("TMA-UNITDATA request expected");
    };
    req.pdu.clone()
}

/// (final, AR, N(S), S(S), payload bits) of the AL-DATA / AL-FINAL segments.
fn al_segment_headers(msgs: &[SapMsg]) -> Vec<(bool, bool, u8, u8, usize)> {
    msgs.iter()
        .filter(|m| llc_type(m) == Some(LlcPduType::AlDataAlFinal))
        .map(|m| {
            let mut pdu = pdu_of(m);
            let h = AlData::from_bitbuf(&mut pdu).unwrap();
            (h.final_segment, h.acknowledgement_requested, h.ns, h.ss, pdu.get_len_remaining())
        })
        .collect()
}

fn al_setup_from(msgs: &[SapMsg]) -> Option<AlSetup> {
    msgs.iter()
        .find(|m| llc_type(m) == Some(LlcPduType::AlSetup))
        .map(|m| AlSetup::from_bitbuf(&mut pdu_of(m)).unwrap())
}

fn al_ack_from(msgs: &[SapMsg]) -> Option<AlAck> {
    msgs.iter()
        .find(|m| llc_type(m) == Some(LlcPduType::AlAckAlRnr))
        .map(|m| AlAck::from_bitbuf(&mut pdu_of(m)).unwrap())
}

fn data_ind_al(msgs: &[SapMsg]) -> Option<&TlDataIndAl> {
    msgs.iter().find_map(|m| match &m.msg {
        SapMsgInner::TlaTlDataIndAl(prim) => Some(prim),
        _ => None,
    })
}

fn establish(test: &mut ComponentTest, setup: AlSetup) {
    test.submit_message(build_al_setup_ind_with_setup(setup));
    test.deliver_all_messages();
    let msgs = drain(test, true);
    assert_eq!(al_setup_from(&msgs).map(|s| s.setup_report), Some(AlSetup::SETUP_REPORT_SUCCESS));
}

/// Nexus-BS `test_al_setup_success_response_establishes_original_acknowledged_link`.
#[test]
fn test_al_setup_success_response_establishes_original_acknowledged_link() {
    debug::setup_logging_verbose();
    let mut test = llc_test();
    test.submit_message(build_al_setup_ind());
    test.deliver_all_messages();
    let msgs = drain(&mut test, true);
    let response = al_setup_from(&msgs).expect("supported AL-SETUP should produce AL-SETUP success response");
    assert_eq!(response.setup_report, AlSetup::SETUP_REPORT_SUCCESS);
    assert!(
        msgs.iter()
            .all(|m| !matches!(&m.msg, SapMsgInner::TlaTlDataIndAl(_) | SapMsgInner::TlaTlDataIndBl(_))),
        "AL-SETUP establishes LLC link state; it must not be delivered to MLE"
    );
}

/// Nexus-BS `test_al_setup_four_slot_phase_mod_request_is_negotiated_down_before_data_transfer`.
#[test]
fn test_al_setup_four_slot_phase_mod_request_is_negotiated_down_before_data_transfer() {
    debug::setup_logging_verbose();
    let mut test = llc_test();
    let mut request = default_al_setup();
    request.connection_width = true;
    request.uplink_timeslots = Some(3);
    test.submit_message(build_al_setup_ind_with_setup(request));
    test.deliver_all_messages();
    let response = al_setup_from(&drain(&mut test, true)).expect("4-slot AL-SETUP should produce a negotiated response");
    assert_eq!(response.setup_report, AlSetup::SETUP_REPORT_SERVICE_CHANGE);
    assert_eq!(response.uplink_timeslots, Some(0), "N.264 answered with one slot, not the 4 asked");
    assert_eq!(response.throughput_code, 6);

    test.submit_message(build_al_final_ar_ind(0, &[0xA5]));
    test.deliver_all_messages();
    assert!(
        data_ind_al(&drain(&mut test, true)).is_none(),
        "AL-DATA before the MS accepts lower QoS must not be delivered"
    );

    let mut accepted = response;
    accepted.setup_report = AlSetup::SETUP_REPORT_SUCCESS;
    test.submit_message(build_al_setup_ind_with_setup(accepted));
    test.deliver_all_messages();
    assert!(drain(&mut test, true).is_empty(), "the radio's success needs no answer");

    test.submit_message(build_al_final_ar_ind(0, &[0xA5]));
    test.deliver_all_messages();
    let msgs = drain(&mut test, true);
    let ind = data_ind_al(&msgs).expect("accepted lower-QoS original AL should deliver AL-FINAL-AR");
    assert_eq!(ind.al_number, 0);
}

/// Nexus-BS `test_inbound_al_final_ar_delivers_tldata_with_link_id_and_ack` (the AL-ACK is not
/// stolen here: it waits for the MCCH).
#[test]
fn test_inbound_al_final_ar_delivers_tldata_with_link_id_and_ack() {
    debug::setup_logging_verbose();
    let mut test = llc_test();
    establish(&mut test, default_al_setup());
    test.submit_message(build_al_final_ar_ind(0, &[0xA5]));
    test.deliver_all_messages();
    let msgs = drain(&mut test, true);
    let ind = data_ind_al(&msgs).expect("complete AL-FINAL-AR should deliver TL-DATA to MLE");
    assert_eq!(ind.main_address, al_addr());
    assert_eq!((ind.al_number, ind.max_sdu_bytes, ind.link_id), (0, 2048, 1));
    assert_eq!(ind.tl_sdu.to_bitstr(), "10100101", "LLC must strip the AL FCS");
    let ack = al_ack_from(&msgs).expect("AL-FINAL-AR should be acknowledged");
    assert!(ack.receiver_ready && ack.acknowledges_complete_tl_sdu());
    assert_eq!(ack.nr, 0);
}

/// Nexus-BS `test_inbound_incomplete_al_data_ar_sends_selective_ack_not_whole_repeat`.
#[test]
fn test_inbound_incomplete_al_data_ar_sends_selective_ack_not_whole_repeat() {
    debug::setup_logging_verbose();
    let mut test = llc_test();
    establish(&mut test, default_al_setup());
    test.submit_message(build_al_segment_ind(false, true, 0, 1, &BitBuffer::from_bytes(&[0xA5])));
    test.deliver_all_messages();
    let msgs = drain(&mut test, true);
    assert!(data_ind_al(&msgs).is_none(), "incomplete TL-SDU must not be delivered");
    let ack = al_ack_from(&msgs).expect("AL-DATA-AR with a missing older segment should be selectively acknowledged");
    assert_eq!(
        (ack.nr, ack.sr, ack.acknowledgement_length, ack.acknowledgement_bitmap),
        (0, Some(0), 2, 1)
    );
    assert!(!ack.requests_repeat_entire_tl_sdu());
}

/// Nexus-BS `test_outbound_nonzero_link_tldata_uses_al_final_ar_and_completes_on_al_ack`.
#[test]
fn test_outbound_al_tldata_uses_al_final_ar_and_completes_on_al_ack() {
    debug::setup_logging_verbose();
    let mut test = llc_test();
    establish(&mut test, default_al_setup());
    let (req, reporter) = tl_data_req_al(&[0x12, 0x34]);
    test.submit_message(req);
    test.run_stack(Some(1));
    let msgs = drain(&mut test, false);
    assert!(
        msgs.iter().all(|m| llc_type(m) != Some(LlcPduType::BlData)),
        "no fall back to BL-DATA"
    );
    let segment = msgs
        .iter()
        .find(|m| llc_type(m) == Some(LlcPduType::AlDataAlFinal))
        .expect("TL-DATA on the AL should emit AL-FINAL-AR");
    let mut pdu = pdu_of(segment);
    let h = AlData::from_bitbuf(&mut pdu).unwrap();
    assert_eq!((h.final_segment, h.acknowledgement_requested, h.ns, h.ss), (true, true, 0, 0));
    assert_eq!(pdu.get_len_remaining(), 16 + 32);
    assert!(fcs::check_fcs(&pdu), "mandatory AL FCS");
    assert_eq!(reporter.get_state(), TxState::Pending);
    let SapMsgInner::TmaUnitdataReq(req) = &segment.msg else {
        unreachable!()
    };
    req.tx_reporter.as_ref().unwrap().mark_transmitted();
    run_llc(&mut test, 1);
    assert_eq!(reporter.get_state(), TxState::Transmitted, "first complete transmission");
    test.submit_message(build_al_ack_ind(AlAck::complete(0)));
    test.deliver_all_messages();
    assert_eq!(reporter.get_state(), TxState::Acknowledged);
}

/// Nexus-BS `test_same_link_al_setup_clears_pending_outbound_before_ns_reset`.
#[test]
fn test_same_link_al_setup_clears_pending_outbound_before_ns_reset() {
    debug::setup_logging_verbose();
    let mut test = llc_test();
    establish(&mut test, default_al_setup());
    let (first, first_reporter) = tl_data_req_al(&[1, 2, 3]);
    test.submit_message(first);
    let msgs = run_llc(&mut test, 1);
    assert!(al_segment_headers(&msgs).iter().any(|s| s.2 == 0));

    test.submit_message(build_al_setup_ind());
    test.deliver_all_messages();
    let reset = drain(&mut test, true);
    assert!(
        first_reporter.is_in_final_state() && first_reporter.get_state() != TxState::Acknowledged,
        "a reset fails the pending transfer: {:?}",
        first_reporter.get_state()
    );
    assert!(al_setup_from(&reset).is_some(), "same-link setup is still answered");

    let (second, second_reporter) = tl_data_req_al(&[4, 5, 6]);
    test.submit_message(second);
    let msgs = run_llc(&mut test, 2);
    assert!(al_segment_headers(&msgs).iter().any(|s| s.2 == 0), "N(S) starts again from 0");
    test.submit_message(build_al_ack_ind(AlAck::complete(0)));
    test.deliver_all_messages();
    assert_eq!(second_reporter.get_state(), TxState::Acknowledged);
}

/// Nexus-BS `test_outbound_nonzero_link_tldata_completes_on_complete_al_rnr`.
#[test]
fn test_outbound_al_tldata_completes_on_complete_al_rnr() {
    let mut test = llc_test();
    establish(&mut test, default_al_setup());
    let (req, reporter) = tl_data_req_al(&[7]);
    test.submit_message(req);
    run_llc(&mut test, 2);
    test.submit_message(build_al_rnr_complete_ind(0));
    test.deliver_all_messages();
    assert_eq!(
        reporter.get_state(),
        TxState::Acknowledged,
        "a complete AL-RNR acknowledges the TL-SDU while it stops new ones"
    );
}

/// Nexus-BS `test_outbound_al_rnr_blocks_new_tldata_until_receiver_ready` and
/// `..._until_t271_expires`.
#[test]
fn test_outbound_al_rnr_blocks_new_tldata_until_receiver_ready_or_t271() {
    let mut test = llc_test();
    establish(&mut test, default_al_setup());
    let (first, _) = tl_data_req_al(&[1]);
    test.submit_message(first);
    assert_eq!(al_segment_headers(&run_llc(&mut test, 2)).len(), 1);
    test.submit_message(build_al_rnr_complete_ind(0));
    test.deliver_all_messages();
    let (second, _) = tl_data_req_al(&[2]);
    test.submit_message(second);
    assert!(al_segment_headers(&run_llc(&mut test, 4)).is_empty(), "receiver not ready");
    test.submit_message(build_al_ack_ind(AlAck::complete(0)));
    assert_eq!(al_segment_headers(&run_llc(&mut test, 2)).len(), 1, "AL-ACK: receiver ready again");

    test.submit_message(build_al_rnr_complete_ind(1));
    test.deliver_all_messages();
    let (third, _) = tl_data_req_al(&[3]);
    test.submit_message(third);
    assert!(al_segment_headers(&run_llc(&mut test, 8)).is_empty());
    assert_eq!(
        al_segment_headers(&run_llc(&mut test, T271_RECEIVER_NOT_READY_FOR_TX_TIMER as usize)).len(),
        1,
        "T.271 expiry lets the LLC try new TL-SDUs again"
    );
}

/// Nexus-BS `test_outbound_nonzero_link_tldata_waits_t252_before_al_retransmission`.
#[test]
fn test_outbound_al_tldata_waits_t252_before_retransmission() {
    let mut test = llc_test();
    establish(&mut test, default_al_setup());
    let (req, reporter) = tl_data_req_al(&[9, 9]);
    test.submit_message(req);
    assert_eq!(al_segment_headers(&run_llc(&mut test, 2)).len(), 1);
    assert_eq!(reporter.get_state(), TxState::Transmitted);
    assert!(
        al_segment_headers(&run_llc(&mut test, T251_SENDER_RETRY_TIMER as usize + 4)).is_empty(),
        "the AL waits T.252, not T.251"
    );
    let retry = al_segment_headers(&run_llc(&mut test, T252_ACK_WAITING_TIMER as usize));
    assert_eq!(retry.len(), 1, "T.252 expiry asks again");
    assert!(retry[0].0 && retry[0].1);
}

/// Nexus-BS `test_outbound_nonzero_link_tldata_segments_large_tl_sdu_and_completes_on_al_ack`.
#[test]
fn test_outbound_al_tldata_segments_large_tl_sdu_and_completes_on_al_ack() {
    let mut test = llc_test();
    establish(&mut test, default_al_setup());
    let payload: Vec<u8> = (0..180).map(|i| i as u8).collect();
    let (req, reporter) = tl_data_req_al(&payload);
    test.submit_message(req);
    let segments = al_segment_headers(&run_llc(&mut test, 12));
    assert!(segments.len() > 1, "large TL-SDU segmented");
    for (idx, (final_segment, ar, ns, ss, bits)) in segments.iter().enumerate() {
        assert_eq!((*ns, *ss as usize), (0, idx));
        assert!(*bits <= 194, "segment payload inside one SCH/F MAC-RESOURCE");
        assert_eq!(*final_segment, idx == segments.len() - 1);
        assert_eq!(*ar, idx == segments.len() - 1 || (idx + 1) % 4 == 0);
    }
    assert_eq!(segments.iter().map(|s| s.4).sum::<usize>(), 180 * 8 + 32);
    assert_eq!(reporter.get_state(), TxState::Transmitted);
    test.submit_message(build_al_ack_ind(AlAck::complete(0)));
    test.deliver_all_messages();
    assert_eq!(reporter.get_state(), TxState::Acknowledged);
}

/// Nexus-BS `test_outbound_al_rejects_tldata_exceeding_negotiated_n271_before_ns_use`.
#[test]
fn test_outbound_al_rejects_tldata_exceeding_negotiated_n271_before_ns_use() {
    let mut test = llc_test();
    let mut setup = default_al_setup();
    setup.max_tl_sdu_len_code = 3; // 256 octets including the FCS.
    establish(&mut test, setup);
    let (req, reporter) = tl_data_req_al(&[0x81; 253]);
    test.submit_message(req);
    assert!(al_segment_headers(&run_llc(&mut test, 2)).is_empty());
    assert_eq!(reporter.get_state(), TxState::Discarded, "longer than N.271: fails at once");
    let (next, _) = tl_data_req_al(&[0x42; 20]);
    test.submit_message(next);
    assert!(
        al_segment_headers(&run_llc(&mut test, 2)).iter().any(|s| s.2 == 0),
        "the rejected TL-SDU did not use N(S) 0"
    );
}

/// Nexus-BS `test_outbound_segmented_al_requests_periodic_ack_and_retries_selective_missing_segment`.
#[test]
fn test_outbound_segmented_al_requests_periodic_ack_and_retries_selective_missing_segment() {
    let mut test = llc_test();
    establish(&mut test, default_al_setup());
    let payload: Vec<u8> = (0..560).map(|i| i as u8).collect();
    let (req, reporter) = tl_data_req_al(&payload);
    test.submit_message(req);
    let segments = al_segment_headers(&run_llc(&mut test, 30));
    assert!(segments.len() > 16);
    for (idx, (final_segment, ar, _, ss, _)) in segments.iter().enumerate() {
        assert_eq!(*ss as usize, idx);
        assert_eq!(*ar, *final_segment || (idx + 1) % 4 == 0, "periodic AR and on AL-FINAL");
    }
    test.submit_message(build_al_ack_ind(AlAck::selective(true, 0, 8, 0, 1)));
    let retry = al_segment_headers(&run_llc(&mut test, 3));
    assert_eq!(retry.iter().map(|s| s.3).collect::<Vec<_>>(), vec![8], "only the missing segment");
    assert!(retry[0].1, "the retransmission asks for an acknowledgement");
    assert_ne!(reporter.get_state(), TxState::Acknowledged, "a partial AL-ACK does not complete it");
}

/// Nexus-BS `test_outbound_segmented_al_t252_repeats_ack_request_before_full_tl_sdu_retransmit`.
#[test]
fn test_outbound_segmented_al_t252_repeats_ack_request_before_full_tl_sdu_retransmit() {
    let mut test = llc_test();
    let mut setup = default_al_setup();
    setup.max_tl_sdu_retransmissions = 1;
    establish(&mut test, setup);
    let (req, reporter) = tl_data_req_al(&[0x5a; 50]);
    test.submit_message(req);
    let first = al_segment_headers(&run_llc(&mut test, 4));
    assert_eq!(first.iter().map(|s| s.3).collect::<Vec<_>>(), vec![0, 1, 2]);
    let retry = al_segment_headers(&run_llc(&mut test, T252_ACK_WAITING_TIMER as usize + 1));
    assert_eq!(
        retry.iter().map(|s| (s.0, s.1, s.3)).collect::<Vec<_>>(),
        vec![(true, true, 2)],
        "T.252 repeats the AL-FINAL-AR, it does not restart the TL-SDU"
    );
    assert_eq!(reporter.get_state(), TxState::Transmitted, "not failed while N.274 remains");
}
