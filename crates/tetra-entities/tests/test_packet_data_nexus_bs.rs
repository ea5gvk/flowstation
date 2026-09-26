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
