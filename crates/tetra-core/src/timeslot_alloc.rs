#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeslotOwner {
    Brew,
    Cmce,
    /// A packet-data channel (PDCH) of the SNDCP bearer: only on the main carrier, and any other
    /// owner takes it when nothing else is free (voice first).
    PacketData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CarrierSlot {
    pub carrier_num: u16,
    pub ts: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeslotAllocErr {
    InvalidTimeslot(u8),
    InvalidCarrier(u16),
    InUse {
        carrier_num: u16,
        ts: u8,
        owner: TimeslotOwner,
    },
    NotAllocated {
        carrier_num: u16,
        ts: u8,
    },
    OwnerMismatch {
        carrier_num: u16,
        ts: u8,
        owner: TimeslotOwner,
        actual: TimeslotOwner,
    },
}

#[derive(Debug, Clone)]
pub struct TimeslotAllocator {
    carriers: Vec<u16>,
    // One [TS1, TS2, TS3, TS4] owner row per configured carrier.
    // The primary carrier keeps TS1 reserved for MCCH/common control; any
    // configured secondary carrier may allocate TS1 for assigned traffic.
    owners: Vec<[Option<TimeslotOwner>; 4]>,
    /// Packet-data slots another owner took, until the packet-data bearer drains them.
    preempted: Vec<CarrierSlot>,
}

impl Default for TimeslotAllocator {
    fn default() -> Self {
        Self {
            carriers: vec![0],
            owners: vec![[None, None, None, None]],
            preempted: Vec::new(),
        }
    }
}

impl TimeslotAllocator {
    fn carrier_idx(&self, carrier_num: u16) -> Result<usize, TimeslotAllocErr> {
        self.carriers
            .iter()
            .position(|carrier| *carrier == carrier_num)
            .ok_or(TimeslotAllocErr::InvalidCarrier(carrier_num))
    }

    fn slot_supported_for_carrier(&self, carrier_idx: usize, ts: u8) -> bool {
        match carrier_idx {
            0 => (2..=4).contains(&ts),
            _ => (1..=4).contains(&ts),
        }
    }

    fn slot_idx(&self, carrier_idx: usize, ts: u8) -> Result<usize, TimeslotAllocErr> {
        if self.slot_supported_for_carrier(carrier_idx, ts) {
            Ok((ts - 1) as usize)
        } else {
            Err(TimeslotAllocErr::InvalidTimeslot(ts))
        }
    }

    pub fn configure_carriers(&mut self, carriers: &[u16]) {
        let mut new_carriers = Vec::with_capacity(carriers.len().max(1));
        for carrier in carriers {
            if !new_carriers.contains(carrier) {
                new_carriers.push(*carrier);
            }
        }
        if new_carriers.is_empty() {
            new_carriers.push(0);
        }

        let mut new_owners = vec![[None, None, None, None]; new_carriers.len()];
        for (old_i, old_carrier) in self.carriers.iter().enumerate() {
            if let Some(new_i) = new_carriers.iter().position(|carrier| carrier == old_carrier) {
                new_owners[new_i] = self.owners[old_i];
            }
        }

        self.carriers = new_carriers;
        self.owners = new_owners;
    }

    pub fn carriers(&self) -> &[u16] {
        &self.carriers
    }

    pub fn allocate_any(&mut self, owner: TimeslotOwner) -> Option<u8> {
        self.allocate_any_slot(owner).map(|slot| slot.ts)
    }

    pub fn allocate_any_slot(&mut self, owner: TimeslotOwner) -> Option<CarrierSlot> {
        for (carrier_i, slots) in self.owners.iter_mut().enumerate() {
            let ts_range = if carrier_i == 0 { 2..=4 } else { 1..=4 };
            for ts in ts_range {
                let slot = &mut slots[ts as usize - 1];
                if slot.is_none() {
                    *slot = Some(owner);
                    return Some(CarrierSlot {
                        carrier_num: self.carriers[carrier_i],
                        ts,
                    });
                }
            }
        }
        // Nothing free on any carrier: a packet-data channel gives way.
        if owner != TimeslotOwner::PacketData {
            for ts in 2..=4u8 {
                let slot = &mut self.owners[0][ts as usize - 1];
                if *slot == Some(TimeslotOwner::PacketData) {
                    *slot = Some(owner);
                    let taken = CarrierSlot {
                        carrier_num: self.carriers[0],
                        ts,
                    };
                    self.preempted.push(taken);
                    return Some(taken);
                }
            }
        }
        None
    }

    /// A packet-data channel on the main carrier: the first free timeslot of `prefs` (2..=4 only).
    pub fn reserve_packet_data_slot(&mut self, prefs: &[u8]) -> Option<CarrierSlot> {
        let ts = prefs
            .iter()
            .copied()
            .find(|ts| (2..=4).contains(ts) && self.owners[0][*ts as usize - 1].is_none())?;
        self.owners[0][ts as usize - 1] = Some(TimeslotOwner::PacketData);
        Some(CarrierSlot {
            carrier_num: self.carriers[0],
            ts,
        })
    }

    /// A packet-data channel of up to `n` main-carrier timeslots: the first free ones of `prefs`
    /// (2..=4), in that order.
    pub fn reserve_packet_data_slots(&mut self, prefs: &[u8], n: usize) -> Vec<CarrierSlot> {
        (0..n).map_while(|_| self.reserve_packet_data_slot(prefs)).collect()
    }

    /// Traffic slots without an owner: (main carrier ts2..=4, every other carrier ts1..=4). For
    /// the voice headroom of a packet-data channel of several slots.
    pub fn free_traffic_slots(&self) -> (usize, usize) {
        let main = self.owners[0][1..].iter().filter(|owner| owner.is_none()).count();
        let others = self.owners[1..].iter().flatten().filter(|owner| owner.is_none()).count();
        (main, others)
    }

    /// Packet-data slots taken by another owner since the last call.
    pub fn drain_preempted_packet_data(&mut self) -> Vec<CarrierSlot> {
        std::mem::take(&mut self.preempted)
    }

    pub fn reserve(&mut self, owner: TimeslotOwner, ts: u8) -> Result<(), TimeslotAllocErr> {
        let carrier_num = self.carriers[0];
        self.reserve_slot(owner, CarrierSlot { carrier_num, ts })
    }

    pub fn reserve_slot(&mut self, owner: TimeslotOwner, slot: CarrierSlot) -> Result<(), TimeslotAllocErr> {
        let carrier_idx = self.carrier_idx(slot.carrier_num)?;
        let idx = self.slot_idx(carrier_idx, slot.ts)?;
        match self.owners[carrier_idx][idx] {
            None => {
                self.owners[carrier_idx][idx] = Some(owner);
                Ok(())
            }
            Some(existing) => Err(TimeslotAllocErr::InUse {
                carrier_num: slot.carrier_num,
                ts: slot.ts,
                owner: existing,
            }),
        }
    }

    pub fn release(&mut self, owner: TimeslotOwner, ts: u8) -> Result<(), TimeslotAllocErr> {
        let carrier_num = self.carriers[0];
        self.release_slot(owner, CarrierSlot { carrier_num, ts })
    }

    pub fn release_slot(&mut self, owner: TimeslotOwner, slot: CarrierSlot) -> Result<(), TimeslotAllocErr> {
        let carrier_idx = self.carrier_idx(slot.carrier_num)?;
        let idx = self.slot_idx(carrier_idx, slot.ts)?;
        match self.owners[carrier_idx][idx] {
            None => Err(TimeslotAllocErr::NotAllocated {
                carrier_num: slot.carrier_num,
                ts: slot.ts,
            }),
            Some(existing) if existing != owner => Err(TimeslotAllocErr::OwnerMismatch {
                carrier_num: slot.carrier_num,
                ts: slot.ts,
                owner,
                actual: existing,
            }),
            Some(_) => {
                self.owners[carrier_idx][idx] = None;
                Ok(())
            }
        }
    }

    pub fn owner(&self, ts: u8) -> Option<TimeslotOwner> {
        self.slot_owner(CarrierSlot {
            carrier_num: self.carriers[0],
            ts,
        })
    }

    pub fn slot_owner(&self, slot: CarrierSlot) -> Option<TimeslotOwner> {
        let carrier_idx = self.carrier_idx(slot.carrier_num).ok()?;
        let idx = self.slot_idx(carrier_idx, slot.ts).ok()?;
        self.owners[carrier_idx][idx]
    }

    pub fn is_free(&self, ts: u8) -> bool {
        self.owner(ts).is_none()
    }

    pub fn slot_is_free(&self, slot: CarrierSlot) -> bool {
        self.slot_owner(slot).is_none()
    }

    /// Number of traffic timeslots on the primary configured carrier a call can get: the
    /// unallocated ones and the packet-data ones, which give way.
    pub fn free_count(&self) -> usize {
        self.owners[0][1..].iter().filter(|owner| Self::yields(owner)).count()
    }

    fn yields(owner: &Option<TimeslotOwner>) -> bool {
        matches!(owner, None | Some(TimeslotOwner::PacketData))
    }

    pub fn free_slot_count(&self) -> usize {
        self.owners
            .iter()
            .enumerate()
            .flat_map(|(carrier_i, slots)| {
                let slice = if carrier_i == 0 { &slots[1..] } else { &slots[..] };
                slice.iter()
            })
            .filter(|owner| Self::yields(owner))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_carrier_compatibility_defaults_to_first_carrier() {
        let mut alloc = TimeslotAllocator::default();
        alloc.configure_carriers(&[1584]);

        let ts = alloc.allocate_any(TimeslotOwner::Cmce).expect("slot");
        assert_eq!(ts, 2);
        assert_eq!(alloc.slot_owner(CarrierSlot { carrier_num: 1584, ts }), Some(TimeslotOwner::Cmce));
        assert_eq!(alloc.owner(ts), Some(TimeslotOwner::Cmce));
    }

    #[test]
    fn dual_carrier_allows_same_timeslot_once_per_carrier() {
        let mut alloc = TimeslotAllocator::default();
        alloc.configure_carriers(&[1584, 1585]);

        alloc
            .reserve_slot(TimeslotOwner::Cmce, CarrierSlot { carrier_num: 1584, ts: 2 })
            .expect("main carrier reserve");
        alloc
            .reserve_slot(TimeslotOwner::Brew, CarrierSlot { carrier_num: 1585, ts: 2 })
            .expect("secondary carrier reserve");

        assert_eq!(alloc.free_slot_count(), 5);
    }

    #[test]
    fn secondary_ts1_is_allocatable_but_primary_ts1_is_not() {
        let mut alloc = TimeslotAllocator::default();
        alloc.configure_carriers(&[1584, 1585]);

        assert_eq!(
            alloc.reserve_slot(TimeslotOwner::Cmce, CarrierSlot { carrier_num: 1584, ts: 1 }),
            Err(TimeslotAllocErr::InvalidTimeslot(1))
        );

        alloc
            .reserve_slot(TimeslotOwner::Cmce, CarrierSlot { carrier_num: 1585, ts: 1 })
            .expect("secondary TS1 reserve");
        assert_eq!(
            alloc.slot_owner(CarrierSlot { carrier_num: 1585, ts: 1 }),
            Some(TimeslotOwner::Cmce)
        );
    }

    /// Voice takes a packet-data slot only when nothing else is free on any carrier, and the
    /// packet-data bearer learns it once.
    #[test]
    fn voice_takes_the_packet_data_slot_last() {
        let mut alloc = TimeslotAllocator::default();
        alloc.configure_carriers(&[1584, 1585]);
        let pdch = alloc.reserve_packet_data_slot(&[4, 3, 2]).expect("packet-data slot");
        assert_eq!(pdch, CarrierSlot { carrier_num: 1584, ts: 4 });
        assert_eq!(alloc.free_slot_count(), 7, "the packet-data slot counts as free");
        assert_eq!(alloc.free_count(), 3);
        let mut voice = Vec::new();
        for _ in 0..6 {
            voice.push(alloc.allocate_any_slot(TimeslotOwner::Cmce).expect("voice slot"));
        }
        assert!(!voice.contains(&pdch), "main ts2-3 and the secondary carrier first: {voice:?}");
        assert!(alloc.drain_preempted_packet_data().is_empty());
        assert_eq!(alloc.slot_owner(pdch), Some(TimeslotOwner::PacketData));
        assert_eq!(alloc.free_slot_count(), 1);
        assert_eq!(
            alloc.allocate_any_slot(TimeslotOwner::Brew),
            Some(pdch),
            "then the packet-data slot"
        );
        assert_eq!(alloc.slot_owner(pdch), Some(TimeslotOwner::Brew));
        assert_eq!(alloc.drain_preempted_packet_data(), vec![pdch]);
        assert!(alloc.drain_preempted_packet_data().is_empty(), "reported once");
        assert_eq!(alloc.allocate_any_slot(TimeslotOwner::Cmce), None);
        assert_eq!(alloc.free_slot_count(), 0);
    }

    #[test]
    fn packet_data_slot_only_on_the_main_carrier_ts2_to_4() {
        let mut alloc = TimeslotAllocator::default();
        alloc.configure_carriers(&[1584, 1585]);
        assert_eq!(alloc.reserve_packet_data_slot(&[1, 5, 0]), None, "never ts1 or out of range");
        alloc.reserve(TimeslotOwner::Cmce, 3).unwrap();
        let first = alloc.reserve_packet_data_slot(&[3, 2]).expect("the next preferred slot");
        assert_eq!(first, CarrierSlot { carrier_num: 1584, ts: 2 });
        let second = alloc.reserve_packet_data_slot(&[2, 3, 4]).expect("ts4");
        assert_eq!(second.ts, 4);
        assert_eq!(
            alloc.reserve_packet_data_slot(&[2, 3, 4]),
            None,
            "main carrier full, secondary never used"
        );
        assert_eq!(alloc.free_slot_count(), 6, "two packet-data slots and the four secondary ones");
    }

    #[test]
    fn packet_data_slots_follow_the_preferences() {
        let mut alloc = TimeslotAllocator::default();
        alloc.configure_carriers(&[1584]);
        let slots = alloc.reserve_packet_data_slots(&[4, 3, 2], 2);
        assert_eq!(slots.iter().map(|s| s.ts).collect::<Vec<_>>(), vec![4, 3]);
        assert!(slots.iter().all(|s| s.carrier_num == 1584));

        let mut alloc = TimeslotAllocator::default();
        alloc.configure_carriers(&[1584]);
        alloc.reserve(TimeslotOwner::Cmce, 3).unwrap();
        let slots = alloc.reserve_packet_data_slots(&[4, 3, 2], 2);
        assert_eq!(slots.iter().map(|s| s.ts).collect::<Vec<_>>(), vec![4, 2], "not contiguous");
        assert!(alloc.reserve_packet_data_slots(&[4, 3, 2], 3).is_empty(), "nothing left");

        let mut alloc = TimeslotAllocator::default();
        alloc.configure_carriers(&[1584]);
        alloc.reserve(TimeslotOwner::Cmce, 2).unwrap();
        alloc.reserve(TimeslotOwner::Cmce, 3).unwrap();
        assert_eq!(alloc.reserve_packet_data_slots(&[4, 3, 2], 3).len(), 1, "what is free");

        let (mut a, mut b) = (TimeslotAllocator::default(), TimeslotAllocator::default());
        a.configure_carriers(&[1584]);
        b.configure_carriers(&[1584]);
        assert_eq!(a.reserve_packet_data_slots(&[3, 4], 1), vec![b.reserve_packet_data_slot(&[3, 4]).unwrap()]);
    }

    #[test]
    fn free_traffic_slots_counts_main_and_others() {
        let mut alloc = TimeslotAllocator::default();
        alloc.configure_carriers(&[1584]);
        alloc.reserve(TimeslotOwner::Cmce, 2).unwrap();
        assert_eq!(alloc.free_traffic_slots(), (2, 0));
        alloc.reserve_packet_data_slot(&[4]).unwrap();
        assert_eq!(alloc.free_traffic_slots(), (1, 0), "a packet-data slot has an owner");

        let mut alloc = TimeslotAllocator::default();
        alloc.configure_carriers(&[1584, 1585]);
        assert_eq!(alloc.free_traffic_slots(), (3, 4));
    }

    #[test]
    fn releasing_a_packet_data_slot_voice_took_is_refused() {
        let mut alloc = TimeslotAllocator::default();
        alloc.configure_carriers(&[1584]);
        let pdch = alloc.reserve_packet_data_slot(&[2]).unwrap();
        alloc.reserve(TimeslotOwner::Cmce, 3).unwrap();
        alloc.reserve(TimeslotOwner::Cmce, 4).unwrap();
        assert_eq!(alloc.allocate_any_slot(TimeslotOwner::Cmce), Some(pdch));
        assert_eq!(
            alloc.release_slot(TimeslotOwner::PacketData, pdch),
            Err(TimeslotAllocErr::OwnerMismatch {
                carrier_num: 1584,
                ts: 2,
                owner: TimeslotOwner::PacketData,
                actual: TimeslotOwner::Cmce,
            })
        );
        alloc.release_slot(TimeslotOwner::Cmce, pdch).unwrap();
        assert!(alloc.slot_is_free(pdch));
    }

    #[test]
    fn configure_carriers_preserves_existing_owner_state() {
        let mut alloc = TimeslotAllocator::default();
        alloc.configure_carriers(&[1584, 1585]);
        alloc
            .reserve_slot(TimeslotOwner::Cmce, CarrierSlot { carrier_num: 1585, ts: 3 })
            .expect("reserve");

        alloc.configure_carriers(&[1585, 1586, 1585]);

        assert_eq!(alloc.carriers(), &[1585, 1586]);
        assert_eq!(
            alloc.slot_owner(CarrierSlot { carrier_num: 1585, ts: 3 }),
            Some(TimeslotOwner::Cmce)
        );
    }
}
