// SPDX-FileCopyrightText: Historical upstream contributors
// SPDX-FileCopyrightText: 2026 Chris YO3TCO / Nexus-BS Project
// SPDX-License-Identifier: Apache-2.0 AND PolyForm-Noncommercial-1.0.0
// SPDX-FileComment: Modified by Nexus-BS Project; see CHANGES-NEXUS.md for change notices.
// SPDX-FileComment: Adapted for flowstation-miura (multislot PDCH on the main carrier, half-duplex guard) by EA5GVK.

//! Packet-data channels of several slots (`[packet_data] pdch_max_slots` > 1) on the main
//! carrier: what the scheduler does for them besides sharing one downlink queue.
//!
//! The radios that use them (the MXP600) are frequency half duplex without fast switching: they
//! cannot receive while they transmit and need up to one slot to switch (EN 300 392-2 23.1.3.1.1,
//! 23.1.3.1.2). At the BS the uplink frame starts two slots after the downlink one (9.3.9) and the
//! uplink slot labelled u is on air while downlink slot u+2 is, so a radio holding uplink u does
//! not receive downlink u+1 (switching), u+2 (transmitting) and u+3 (switching back). On a channel
//! of two or more slots the BS should not send it anything then (23.1.3.1.1 last paragraph,
//! 23.3.1.2.2 NOTE 2, 23.5.2.2.7):
//!
//! - G1: a downlink slot of the channel its radio does not hear (an uplink slot of its channel
//!   reserved to it at d-1, d-2 or d-3, or the slot right after the one that carried its channel
//!   assignment, 23.5.4.3.1) carries nothing of the channel queue;
//! - G2: while it holds uplink slots of its channel ahead, no downlink fragmentation starts (the
//!   MS drops a partial TM-SDU after N.203 slots without a fragment, 23.4.3.1.1 iii);
//! - a random access of the radio on its channel, which the BS learns of only after the downlink
//!   slots around it went out, drops the fragmented downlink message under way (23.4.2.1.1).
//!
//! With one slot per radio none of this applies.

use super::*;

impl BsChannelScheduler {
    /// Whether the radio of the packet-data channel `ts` belongs to hears downlink slot `ts`
    /// (G1). Always true for a channel of one slot and for any other slot.
    pub(super) fn pdch_radio_hears(&self, ts: TdmaTime) -> bool {
        let Some(ssi) = self.multislot_owner(ts.t) else {
            return true;
        };
        let deaf = self.pdch_ms_deaf(ts, ssi, self.pdch_timeslots_of(ssi), self.queue_index(ts.t));
        if deaf {
            tracing::trace!("UMAC: ISSI {} does not hear ts {} of its PDCH at {}", ssi, ts.t, ts);
        }
        !deaf
    }

    /// Whether the radio `ssi` of the channel `channel` (whose queue is `q`) cannot receive
    /// downlink slot `d`: it is transmitting or switching (EN 300 392-2 9.3.9, 23.1.3.1.1,
    /// 23.3.1.2.2 NOTE 2), or `d` comes too soon after its channel assignment (23.5.4.3.1). A
    /// reservation on another slot, the MCCH's say, does not count: once on the channel the MS
    /// does not use grants of the channel it left.
    fn pdch_ms_deaf(&self, d: TdmaTime, ssi: u32, channel: [bool; 4], q: usize) -> bool {
        self.pdch_assigned_at[q].is_some_and(|a| a.add_timeslots(1) == d)
            || (1..=3).any(|k| {
                let u = d.add_timeslots(-k);
                channel[u.t as usize - 1] && self.ul_reserved_to(u, ssi)
            })
    }

    /// Whether uplink slot `u` is reserved to `ssi`.
    fn ul_reserved_to(&self, u: TdmaTime, ssi: u32) -> bool {
        let e = &self.ulsched[u.t as usize - 1][self.ul_ts_to_sched_index(&u)];
        e.ul1 == Some(ssi) || e.ul2 == Some(ssi)
    }

    /// Whether `ssi` holds uplink slots of its channel `channel` from label `d-3` on (G2). The
    /// scan stops at `d+67`: `d+68` is the schedule entry of `d-4`, cleared only once `d` is built.
    fn pdch_ul_ahead(&self, d: TdmaTime, ssi: u32, channel: [bool; 4]) -> bool {
        (-3..=67).any(|k| {
            let u = d.add_timeslots(k);
            channel[u.t as usize - 1] && self.ul_reserved_to(u, ssi)
        })
    }

    /// Whether the block of downlink slot `ts` may only take PDUs that go whole in it (G2).
    pub(super) fn pdch_whole_only(&self, ts: TdmaTime) -> bool {
        self.multislot_owner(ts.t)
            .is_some_and(|ssi| self.pdch_ul_ahead(ts, ssi, self.pdch_timeslots_of(ssi)))
    }

    /// A packet-data channel assignment to `ts_assigned` of `carrier` goes out in downlink slot
    /// `ts`: the first slot of the new channel the MS receives is the first one starting at
    /// least one slot after the end of this one (23.5.4.3.1 rule 1, NOTE 7 ii).
    pub(super) fn pdch_note_assignment(&mut self, ts: TdmaTime, carrier: u16, ts_assigned: &[bool; 4]) {
        if carrier == self.carrier_num
            && ts_assigned.iter().filter(|set| **set).count() > 1
            && let Some(lowest) = ts_assigned.iter().position(|set| *set)
        {
            self.pdch_assigned_at[lowest] = Some(ts);
        }
    }

    /// A PDU of `ssi` came in uplink slot `label` (PHY block `block`) of its channel of several
    /// slots. In a slot not reserved to it, it is a random access, which the BS learns of only
    /// once the downlink slots around it went out: the MS lost what was sent in them (23.5.1.4.12
    /// lets it skip such an access, not undo it), so the fragmented downlink message under way on
    /// the channel is dropped ("by sending no more fragments", 23.4.2.1.1) rather than sent to
    /// its end for nothing. Dropping it reports its TM-SDU discarded.
    pub fn pdch_random_access(&mut self, label: TdmaTime, block: PhyBlockNum, ssi: u32) {
        if self.multislot_owner(label.t) != Some(ssi) || self.ul_get_slot_owner(label, block) == Some(ssi) {
            return;
        }
        let q = self.queue_index(label.t);
        let before = self.dltx_queues[q].len();
        self.dltx_queues[q].retain(|e| !matches!(e, DlSchedElem::FragBuf(f) if f.is_started()));
        if self.dltx_queues[q].len() < before {
            tracing::info!(
                "UMAC: ISSI {} random access on ts {} of its PDCH: the downlink message being fragmented to it dropped",
                ssi,
                label.t
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{dl_pdus, finalize_slots, multislot_slotter};
    use super::*;

    const RADIO: u32 = 2_145_007;

    fn radio() -> TetraAddress {
        TetraAddress::issi(RADIO)
    }

    fn at(f: u8, t: u8) -> TdmaTime {
        TdmaTime { t, f, m: 1, h: 0 }
    }

    /// A MAC-RESOURCE for the radio with a TM-SDU of `bits`.
    fn resource(bits: usize) -> (MacResource, BitBuffer) {
        let sdu: String = (0..bits).map(|i| if i % 3 == 0 { '1' } else { '0' }).collect();
        (
            BsChannelScheduler::dl_make_minimal_resource(&radio(), None, false),
            BitBuffer::from_bitstr(&sdu),
        )
    }

    /// The scheduler of a channel `channel` of the radio, its next slot built (4,1).
    fn channel_sched(channel: &[u8]) -> BsChannelScheduler {
        let mut sched = multislot_slotter(RADIO, channel);
        sched.set_dl_time(at(3, 3));
        sched
    }

    /// Slots (frame, ts) of the channel `channel`, frames 4 to 7, that carried nothing for its
    /// radio while PDUs for it were always queued, with its uplink reserved at `reserved`.
    fn quiet_slots(channel: &[u8], reserved: &[(u8, u8)]) -> Vec<(u8, u8)> {
        let mut sched = channel_sched(channel);
        let labels: Vec<TdmaTime> = reserved.iter().map(|(f, t)| at(*f, *t)).collect();
        if !labels.is_empty() {
            sched.ul_reserve_grant(RADIO, labels, false, None);
        }
        for _ in 0..20 {
            let (pdu, sdu) = resource(200);
            sched.dl_enqueue_tma_for_link(u32::from(channel[0]), pdu, sdu, None);
        }
        finalize_slots(&mut sched, 16)
            .iter()
            .filter(|s| channel.contains(&s.ts.t) && !dl_pdus(s).iter().any(|p| p.1 == Some(RADIO)))
            .map(|s| (s.ts.f, s.ts.t))
            .collect()
    }

    /// EN 300 392-2 9.3.9 and 23.1.3.1.1: a radio holding uplink u does not hear downlink u+1,
    /// u+2 and u+3; of those, only the slots of its channel stay empty.
    #[test]
    fn test_half_duplex_guard_blocks_the_slots_around_the_uplink() {
        assert_eq!(quiet_slots(&[3, 4], &[]), vec![]);
        assert_eq!(quiet_slots(&[3, 4], &[(5, 3)]), vec![(5, 4)]);
        assert_eq!(quiet_slots(&[3, 4], &[(5, 4)]), vec![(6, 3)]);
        assert_eq!(quiet_slots(&[2, 3, 4], &[(5, 2)]), vec![(5, 3), (5, 4)]);
        assert_eq!(quiet_slots(&[2, 3, 4], &[(5, 3)]), vec![(5, 4), (6, 2)]);
        assert_eq!(quiet_slots(&[2, 3, 4], &[(5, 4)]), vec![(6, 2), (6, 3)]);
        assert_eq!(quiet_slots(&[4], &[(5, 4)]), vec![], "one slot: no guard");
    }

    /// A reservation of the radio on the MCCH is not one of its channel: once on the channel the
    /// MS does not use grants of the channel it left (23.5.4.3.1).
    #[test]
    fn test_the_guard_ignores_mcch_reservations() {
        assert_eq!(quiet_slots(&[3, 4], &[(5, 1)]), vec![]);
    }

    /// The first channel slot the MS receives after its assignment in (4,1) is the one starting
    /// at least a slot after it (23.5.4.3.1 rule 1): (4,3), not (4,2). With one slot nothing
    /// changes.
    #[test]
    fn test_the_slot_after_the_assignment_is_not_used() {
        use tetra_pdus::umac::fields::channel_allocation::ChanAllocElement;
        use tetra_saps::lcmc::enums::{alloc_type::ChanAllocType, ul_dl_assignment::UlDlAssignment};
        for (channel, first) in [(&[2u8, 3, 4][..], 3u8), (&[2u8][..], 2u8)] {
            let mut sched = channel_sched(channel);
            let mut ts_assigned = [false; 4];
            for ts in channel {
                ts_assigned[usize::from(*ts) - 1] = true;
            }
            let mut assignment = BsChannelScheduler::dl_make_minimal_resource(&radio(), None, false);
            assignment.chan_alloc_element = Some(ChanAllocElement {
                alloc_type: ChanAllocType::Replace,
                ts_assigned,
                ul_dl_assigned: UlDlAssignment::Both,
                clch_permission: false,
                cell_change_flag: false,
                carrier_num: sched.carrier_num(),
                ext: None,
                mon_pattern: 1,
                frame18_mon_pattern: None,
            });
            sched.dl_enqueue_tma_for_link(0, assignment, BitBuffer::from_bitstr("1011001110001111"), None);
            let (pdu, sdu) = resource(64);
            sched.dl_enqueue_tma_for_link(2, pdu, sdu, None);
            let slots = finalize_slots(&mut sched, 4);
            assert_eq!(slots[0].ts, at(4, 1));
            let carried: Vec<u8> = slots
                .iter()
                .filter(|s| s.ts.t != 1 && dl_pdus(s).iter().any(|p| p.1 == Some(RADIO)))
                .map(|s| s.ts.t)
                .collect();
            assert_eq!(carried.first(), Some(&first), "channel {channel:?}: {carried:?}");
        }
    }

    /// A datagram for the radio waits while the radio holds uplink slots of its channel ahead
    /// (from d-3): a fragmentation started in between would lose the slots it is deaf in.
    #[test]
    fn test_no_downlink_fragmentation_before_a_granted_uplink() {
        for packet_data in [false, true] {
            let mut sched = channel_sched(&[3, 4]);
            sched.ul_reserve_grant(RADIO, vec![at(6, 3)], false, None);
            let (pdu, sdu) = resource(600);
            if packet_data {
                sched.dl_enqueue_packet_data_for_link(3, pdu, sdu, None);
            } else {
                sched.dl_enqueue_tma_for_link(3, pdu, sdu, None);
            }
            let start = finalize_slots(&mut sched, 16)
                .iter()
                .find(|s| dl_pdus(s).iter().any(|p| p.0 == 0 && p.2 == 0b111111))
                .map(|s| (s.ts.f, s.ts.t));
            assert_eq!(start, Some((7, 3)), "packet data {packet_data}");
        }
    }

    /// The scan of G2 stops at d+67: the entry of d-4, still holding its old reservation while d
    /// is built, is not taken for one 68 slots ahead.
    #[test]
    fn test_the_guard_scan_does_not_wrap() {
        let mut sched = multislot_slotter(RADIO, &[3, 4]);
        // The slot built next is (6,1).
        sched.set_dl_time(at(5, 3));
        sched.ul_reserve_grant(RADIO, vec![at(5, 3)], false, None);
        let (pdu, sdu) = resource(600);
        sched.dl_enqueue_tma_for_link(3, pdu, sdu, None);
        let slots = finalize_slots(&mut sched, 3);
        assert_eq!(slots[2].ts, at(6, 3));
        assert_eq!(dl_pdus(&slots[2]).first().map(|p| (p.0, p.2)), Some((0, 0b111111)));
    }

    /// A random access of the radio on its channel drops the downlink fragmentation under way on
    /// it (its reporter says discarded); a PDU in a slot reserved to it does not.
    #[test]
    fn test_a_random_access_aborts_the_downlink_fragmentation() {
        let mut sched = channel_sched(&[3, 4]);
        let reporter = TxReporter::new();
        let (pdu, sdu) = resource(1000);
        sched.dl_enqueue_packet_data_for_link(3, pdu, sdu, Some(reporter.clone()));
        finalize_slots(&mut sched, 4);
        let started = |sched: &BsChannelScheduler| {
            sched.dltx_queues[2]
                .iter()
                .any(|e| matches!(e, DlSchedElem::FragBuf(f) if f.is_started()))
        };
        assert!(started(&sched), "the datagram is being fragmented");
        let label = sched.cur_dltime.add_timeslots(-2).forward_to_timeslot(3);
        sched.ul_reserve_grant(RADIO, vec![label], false, None);
        sched.pdch_random_access(label, PhyBlockNum::Both, RADIO);
        assert!(started(&sched), "a reserved slot is no random access");
        sched.pdch_random_access(label.add_timeslots(1), PhyBlockNum::Block1, RADIO);
        assert!(!started(&sched));
        assert_eq!(reporter.get_state(), tetra_core::TxState::Discarded);
    }
}
