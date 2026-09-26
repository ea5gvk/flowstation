// SPDX-FileCopyrightText: Historical upstream contributors
// SPDX-FileCopyrightText: 2026 Chris YO3TCO / Nexus-BS Project
// SPDX-License-Identifier: Apache-2.0 AND PolyForm-Noncommercial-1.0.0
// SPDX-FileComment: Modified by Nexus-BS Project; see CHANGES-NEXUS.md for change notices.
// SPDX-FileComment: Packet-data tests adapted from Nexus-BS test_mle_bs.rs and test_sndcp_bs.rs for flowstation-miura (no LTPD report / configure primitives, SNDCP answers straight to the LLC, [packet_data] instead of cell_info wap_ip) by EA5GVK.

mod common;

use common::ComponentTest;
use tetra_config::bluestation::StackMode;
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{BitBuffer, Sap, SsiType, TetraAddress};
use tetra_entities::sndcp::transfer::{
    SN_PDU_TYPE_DATA, SN_PDU_TYPE_END_OF_DATA, SndcpDataTransmitRequest, SndcpEndOfData, SndcpNotSupported, SndcpPacketDataResourceRequest,
    SndcpTransferControl, decode_transfer_control_pdu, encode_data_transmit_request, encode_end_of_data, encode_not_supported,
};
use tetra_entities::sndcp::unitdata::{
    NetworkPduKind, SndcpEncodeError, SndcpUnitdataError, decode_sn_data_pdu, decode_sn_unitdata_pdu, decode_sn_user_data_pdu,
    encode_sn_unitdata,
};
use tetra_pdus::mle::enums::mle_protocol_discriminator::MleProtocolDiscriminator;
use tetra_saps::ltpd::LtpdBearer;
use tetra_saps::sapmsg::{SapMsg, SapMsgInner};
use tetra_saps::tla::TlaTlDataIndBl;

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
