// SPDX-FileCopyrightText: Historical upstream contributors
// SPDX-FileCopyrightText: 2026 Chris YO3TCO / Nexus-BS Project
// SPDX-License-Identifier: Apache-2.0 AND PolyForm-Noncommercial-1.0.0
// SPDX-FileComment: Modified by Nexus-BS Project; see CHANGES-NEXUS.md for change notices.
// SPDX-FileComment: Adapted for flowstation-miura (carrier_num, configurable ISSI and recording limit) by EA5GVK.

//! Local Parrot/Papagal simplex test service — `parrot_issi` (default 99999).
//!
//! The service records validated UL TCH/S frames from one caller, plays the
//! exact frame payloads back after the caller releases PTT, then clears the
//! private call. Playback is paced by TDMA ticks and intentionally separate
//! from normal local P2P handling.

use std::collections::VecDeque;

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
}
