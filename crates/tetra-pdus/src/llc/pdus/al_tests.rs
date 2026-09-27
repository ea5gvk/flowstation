//! Bit-exact round trips of the advanced link PDUs (clause 21.2.3).

use tetra_core::BitBuffer;

use super::al_ack::{AlAck, AlAckBlock};
use super::al_data::AlData;
use super::al_disc::{AlDisc, AlDiscReport};
use super::al_reconnect::{AlReconnect, AlReconnectReport};
use super::al_setup::AlSetup;

fn bits(write: impl FnOnce(&mut BitBuffer)) -> String {
    let mut buf = BitBuffer::new_autoexpand(32);
    write(&mut buf);
    buf.seek(0);
    buf.to_bitstr()
}

/// The original acknowledged AL-SETUP a radio sends: AL 1, N.271 2048 octets, no radio resource
/// information, window 1, N.273 3, N.274 3, "service definition".
fn radio_setup() -> AlSetup {
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

#[test]
fn al_setup_bits_follow_table_21_23() {
    let setup = radio_setup();
    let expected = ["1000", "1", "00", "110", "0", "0", "110", "01", "011", "0011", "001"].concat();
    assert_eq!(bits(|b| setup.to_bitbuf(b)), expected);
    let decoded = AlSetup::from_bitbuf(&mut BitBuffer::from_bitstr(&expected)).unwrap();
    assert_eq!(decoded, setup);
    assert!(decoded.is_original_acknowledged_non_augmented());
    assert_eq!(decoded.link_id(), 1);
}

#[test]
fn al_setup_with_slots_and_augmentation_round_trips() {
    let mut setup = radio_setup();
    setup.connection_width = true;
    setup.uplink_timeslots = Some(3);
    setup.window_size_code = 0;
    setup.augmented = Some(super::al_setup::AlSetupAugmented {
        extended_advanced_link: true,
        original_window_size_code: None,
        extended_window_size_code: Some(5),
        reserved: 0,
    });
    let s = bits(|b| setup.to_bitbuf(b));
    assert_eq!(AlSetup::from_bitbuf(&mut BitBuffer::from_bitstr(&s)).unwrap(), setup);
    let lowered = setup.response_with_lower_phase_mod_timeslots(1);
    assert_eq!(lowered.uplink_timeslots, Some(0));
    assert_eq!(lowered.setup_report, AlSetup::SETUP_REPORT_SERVICE_CHANGE);
}

#[test]
fn al_data_headers_follow_tables_21_17_and_21_19() {
    let final_ar = AlData {
        final_segment: true,
        acknowledgement_requested: true,
        ns: 5,
        ss: 3,
    };
    assert_eq!(bits(|b| final_ar.to_bitbuf(b)), "10011110100000011");
    let data = AlData {
        final_segment: false,
        acknowledgement_requested: false,
        ns: 0,
        ss: 0,
    };
    let s = bits(|b| data.to_bitbuf(b));
    assert_eq!(s, "10010000000000000");
    assert_eq!(AlData::from_bitbuf(&mut BitBuffer::from_bitstr(&s)).unwrap(), data);
}

#[test]
fn al_ack_complete_and_selective_round_trip() {
    let complete = AlAck::complete(2);
    assert_eq!(bits(|b| complete.to_bitbuf(b)), ["1011", "1", "010", "000000"].concat());
    // Segment 1 missing, 2 and 4 received, 3 missing: S(R) 1, length 4, bitmap 1,0,1.
    let selective = AlAck::selective(true, 0, 1, 0b101, 4);
    let s = bits(|b| selective.to_bitbuf(b));
    assert_eq!(s, ["1011", "1", "000", "000100", "00000001", "101"].concat());
    let decoded = AlAck::from_bitbuf(&mut BitBuffer::from_bitstr(&s)).unwrap();
    assert_eq!(decoded, selective);
    assert_eq!(decoded.segment_acknowledged_in_first_block(0), Some(true));
    assert_eq!(decoded.segment_acknowledged_in_first_block(1), Some(false));
    assert_eq!(decoded.segment_acknowledged_in_first_block(2), Some(true));
    assert_eq!(decoded.segment_acknowledged_in_first_block(3), Some(false));
    assert_eq!(decoded.segment_acknowledged_in_first_block(4), Some(true));
    assert_eq!(decoded.segment_acknowledged_in_first_block(5), None);
    // AL-RNR with two blocks: TL-SDU 3 received, TL-SDU 4 to be repeated.
    let rnr = AlAck::with_blocks(false, vec![AlAckBlock::complete(3), AlAckBlock::repeat_entire(4)]);
    let s = bits(|b| rnr.to_bitbuf(b));
    let decoded = AlAck::from_bitbuf(&mut BitBuffer::from_bitstr(&s)).unwrap();
    assert!(!decoded.receiver_ready);
    assert_eq!(decoded.acknowledgement_blocks.len(), 2);
    assert!(decoded.acknowledgement_blocks[1].requests_repeat_entire_tl_sdu());
}

#[test]
fn al_disc_bits_follow_table_21_21() {
    let close = AlDisc {
        acknowledged_service: true,
        advanced_link_number: 0,
        report: AlDiscReport::Close,
    };
    assert_eq!(bits(|b| close.to_bitbuf(b)), "1111100001");
    for report in [
        AlDiscReport::Success,
        AlDiscReport::Close,
        AlDiscReport::Reject,
        AlDiscReport::ServiceNotSupported,
        AlDiscReport::ServiceTemporarilyUnavailable,
        AlDiscReport::Reserved(6),
    ] {
        let pdu = AlDisc {
            acknowledged_service: false,
            advanced_link_number: 3,
            report,
        };
        let s = bits(|b| pdu.to_bitbuf(b));
        assert_eq!(AlDisc::from_bitbuf(&mut BitBuffer::from_bitstr(&s)).unwrap(), pdu);
    }
    assert!(AlDisc::from_bitbuf(&mut BitBuffer::from_bitstr("1110100001")).is_err());
}

#[test]
fn al_reconnect_bits_follow_table_21_22() {
    let propose = AlReconnect {
        acknowledged_service: true,
        advanced_link_number: 1,
        report: AlReconnectReport::Propose,
    };
    let s = bits(|b| propose.to_bitbuf(b));
    assert_eq!(s, "110010100");
    assert_eq!(AlReconnect::from_bitbuf(&mut BitBuffer::from_bitstr(&s)).unwrap(), propose);
    let accept = AlReconnect {
        report: AlReconnectReport::Accept,
        ..propose
    };
    assert_eq!(bits(|b| accept.to_bitbuf(b)), "110010110");
    assert!(AlReconnect::from_bitbuf(&mut BitBuffer::from_bitstr("11001")).is_err());
}
