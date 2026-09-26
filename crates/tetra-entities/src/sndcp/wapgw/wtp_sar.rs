//! WTP segmentation and reassembly (WAP-224-WTP clause 7.14).
//!
//! [`OutMessage`] sends a Result as packet groups: each group ends with a GTR packet (the last
//! one with TTR) and waits for the initiator's Ack carrying that packet's PSN. A Nack gets only
//! the missing packets again; a silent timer gets the group's last packet again, and a repeated
//! Invoke before any Ack gets the whole first group again, all as retransmissions (RID set unless
//! configured otherwise); the transaction is given up after `max_retries`. The time from a
//! group's first transmission to its Ack feeds an [`Rtt`] estimate (never across a
//! retransmission).
//!
//! [`InMessage`] collects a segmented Invoke: on each GTR / TTR packet it acknowledges the group
//! or asks for the missing packets with a Nack.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::wtp::{self, GTR, TTR};

/// Packet Sequence Numbers are one octet.
pub const MAX_PACKETS: usize = 256;

/// Smoothed round trip of a terminal and its variation (RFC 6298 weights).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rtt {
    srtt: Duration,
    rttvar: Duration,
}

impl Rtt {
    pub fn new(sample: Duration) -> Self {
        Self {
            srtt: sample,
            rttvar: sample / 2,
        }
    }

    pub fn update(&mut self, sample: Duration) {
        let delta = self.srtt.abs_diff(sample);
        self.rttvar = (self.rttvar * 3 + delta) / 4;
        self.srtt = (self.srtt * 7 + sample) / 8;
    }

    /// Wait for an answer that covers the variation seen so far.
    pub fn timeout(&self) -> Duration {
        self.srtt + self.rttvar * 4
    }
}

#[derive(Debug)]
pub struct OutMessage {
    tid: u16,
    chunks: Vec<Vec<u8>>,
    group_size: usize,
    group_first: usize,
    group_last: usize,
    retries: u8,
    deadline: Instant,
    retransmit_rid: bool,
    /// First transmission of the current group and its octets, while nothing was sent again.
    sent: Option<(Instant, usize)>,
    /// Round trip of the last acknowledged group, not yet taken.
    rtt_sample: Option<(Duration, usize)>,
    /// The initiator acknowledged or Nacked something.
    heard: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AckOutcome {
    /// The last group was acknowledged: the transaction is complete.
    Done,
    /// Next group, to be sent now.
    Next(Vec<Vec<u8>>),
    Ignored,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TimerOutcome {
    Idle,
    Retransmit(Vec<u8>),
    GiveUp,
}

impl OutMessage {
    /// Split `message` into packets of at most `segment` octets (one packet when it fits).
    /// The caller keeps `message` within `MAX_PACKETS * segment`.
    pub fn new(tid: u16, message: &[u8], segment: usize, group_size: usize, now: Instant) -> Self {
        let segment = segment.max(1);
        let mut chunks: Vec<Vec<u8>> = message.chunks(segment).map(<[u8]>::to_vec).collect();
        if chunks.is_empty() {
            chunks.push(Vec::new());
        }
        chunks.truncate(MAX_PACKETS);
        let group_size = group_size.max(1);
        let group_last = (group_size - 1).min(chunks.len() - 1);
        Self {
            tid,
            chunks,
            group_size,
            group_first: 0,
            group_last,
            retries: 0,
            deadline: now,
            retransmit_rid: true,
            sent: None,
            rtt_sample: None,
            heard: false,
        }
    }

    /// Whether retransmitted packets carry RID (the default) or go out with it clear.
    pub fn with_retransmit_rid(mut self, rid: bool) -> Self {
        self.retransmit_rid = rid;
        self
    }

    pub fn packet_count(&self) -> usize {
        self.chunks.len()
    }

    /// Whether the initiator ever acknowledged or Nacked a group of this message.
    pub fn heard_back(&self) -> bool {
        self.heard
    }

    /// Round trip of the group acknowledged last and its octets, once.
    pub fn take_rtt_sample(&mut self) -> Option<(Duration, usize)> {
        self.rtt_sample.take()
    }

    fn packet(&self, psn: usize, again: bool) -> Vec<u8> {
        let flags = if psn + 1 == self.chunks.len() {
            TTR
        } else if psn == self.group_last {
            GTR
        } else {
            0
        };
        wtp::result_packet(self.tid, psn as u8, flags, again && self.retransmit_rid, &self.chunks[psn])
    }

    fn group_bytes(&self) -> usize {
        self.chunks[self.group_first..=self.group_last].iter().map(Vec::len).sum()
    }

    /// Packets of the current group, first transmission. `timer` gives the wait for the Ack from
    /// the number of octets on the air.
    pub fn send_group(&mut self, now: Instant, timer: impl Fn(usize) -> Duration) -> Vec<Vec<u8>> {
        let bytes = self.group_bytes();
        self.deadline = now + timer(bytes);
        self.sent = Some((now, bytes));
        (self.group_first..=self.group_last).map(|psn| self.packet(psn, false)).collect()
    }

    /// An Ack from the initiator. `psn` is its PSN TPI; an Ack without one acknowledges the
    /// current group.
    pub fn on_ack(&mut self, psn: Option<u8>, now: Instant, timer: impl Fn(usize) -> Duration) -> AckOutcome {
        if let Some(psn) = psn
            && (psn as usize) < self.group_last
        {
            return AckOutcome::Ignored; // stale Ack of an earlier group
        }
        self.heard = true;
        if let Some((at, bytes)) = self.sent.take() {
            self.rtt_sample = Some((now.saturating_duration_since(at), bytes));
        }
        if self.group_last + 1 == self.chunks.len() {
            return AckOutcome::Done;
        }
        self.group_first = self.group_last + 1;
        self.group_last = (self.group_first + self.group_size - 1).min(self.chunks.len() - 1);
        self.retries = 0;
        AckOutcome::Next(self.send_group(now, timer))
    }

    /// A Nack: resend the missing packets of the current group (all of it when the list is
    /// empty). `None` when the retries are exhausted.
    pub fn on_nack(&mut self, missing: &[u8], max_retries: u8, now: Instant, timer: impl Fn(usize) -> Duration) -> Option<Vec<Vec<u8>>> {
        self.heard = true;
        if self.retries >= max_retries {
            return None;
        }
        self.retries += 1;
        self.sent = None;
        let psns: Vec<usize> = if missing.is_empty() {
            (self.group_first..=self.group_last).collect()
        } else {
            missing.iter().map(|&p| p as usize).filter(|&p| p <= self.group_last).collect()
        };
        let bytes = psns.iter().map(|&p| self.chunks[p].len()).sum();
        self.deadline = now + timer(bytes);
        Some(psns.into_iter().map(|psn| self.packet(psn, true)).collect())
    }

    /// The initiator sent its Invoke again: before any Ack it did not get the Result, so the first
    /// group goes again at once (one retry). `None` once a group was acknowledged (a late copy)
    /// or the retries are exhausted.
    pub fn on_repeated_invoke(&mut self, max_retries: u8, now: Instant, timer: impl Fn(usize) -> Duration) -> Option<Vec<Vec<u8>>> {
        if self.group_first != 0 || self.retries >= max_retries {
            return None;
        }
        self.retries += 1;
        self.sent = None;
        self.deadline = now + timer(self.group_bytes());
        Some((self.group_first..=self.group_last).map(|psn| self.packet(psn, true)).collect())
    }

    /// Retransmission timer: resend the group's last packet so the initiator answers with an Ack
    /// or a Nack.
    pub fn on_timer(&mut self, max_retries: u8, now: Instant, timer: impl Fn(usize) -> Duration) -> TimerOutcome {
        if now < self.deadline {
            return TimerOutcome::Idle;
        }
        if self.retries >= max_retries {
            return TimerOutcome::GiveUp;
        }
        self.retries += 1;
        self.sent = None;
        self.deadline = now + timer(self.chunks[self.group_last].len());
        TimerOutcome::Retransmit(self.packet(self.group_last, true))
    }

    /// Start the retransmission timer afresh (the bearer held the group until now).
    pub fn restart_timer(&mut self, now: Instant, timer: impl Fn(usize) -> Duration) {
        self.sent = None;
        self.deadline = now + timer(self.group_bytes());
    }
}

#[derive(Debug)]
pub struct InMessage {
    parts: BTreeMap<u8, Vec<u8>>,
    bytes: usize,
    /// PSN and flags of the latest group end (GTR / TTR packet) received.
    end: Option<(u8, u8)>,
    pub last_activity: Instant,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reassembly {
    Incomplete,
    /// All packets up to this group's end arrived: Ack with this PSN.
    GroupAck(u8),
    /// Packets missing before a group end.
    Nack(Vec<u8>),
    Complete(Vec<u8>),
    TooLarge,
}

impl InMessage {
    pub fn new(now: Instant) -> Self {
        Self {
            parts: BTreeMap::new(),
            bytes: 0,
            end: None,
            last_activity: now,
        }
    }

    /// Add one packet. A group end reports the group (Ack or Nack); a retransmitted packet that
    /// fills the last hole before a group end already seen completes that group.
    pub fn add(&mut self, psn: u8, flags: u8, data: &[u8], max_bytes: usize, now: Instant) -> Reassembly {
        self.last_activity = now;
        if !self.parts.contains_key(&psn) {
            self.bytes += data.len();
            if self.bytes > max_bytes {
                return Reassembly::TooLarge;
            }
            self.parts.insert(psn, data.to_vec());
        }
        let group_end = flags & (GTR | TTR) != 0;
        if group_end && self.end.is_none_or(|(end, _)| psn >= end) {
            self.end = Some((psn, flags));
        }
        let Some((end, end_flags)) = self.end else {
            return Reassembly::Incomplete;
        };
        if psn > end {
            return Reassembly::Incomplete; // a packet of the next group
        }
        let missing: Vec<u8> = (0..end).filter(|p| !self.parts.contains_key(p)).collect();
        if !missing.is_empty() {
            return if group_end {
                Reassembly::Nack(missing)
            } else {
                Reassembly::Incomplete
            };
        }
        if end_flags & TTR != 0 {
            return Reassembly::Complete(self.parts.range(..=end).flat_map(|(_, d)| d.iter().copied()).collect());
        }
        Reassembly::GroupAck(end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sndcp::wapgw::wtp::{WtpPdu, parse_pdu};

    fn timer(bytes: usize) -> Duration {
        Duration::from_millis(1000 + bytes as u64)
    }

    fn psn_flags(pkt: &[u8]) -> (u8, u8, bool) {
        let ty = (pkt[0] >> 3) & 0x0f;
        let psn = if ty == 6 { pkt[3] } else { 0 };
        (psn, pkt[0] & (GTR | TTR), pkt[0] & 1 != 0)
    }

    #[test]
    fn single_packet_is_a_ttr_result() {
        let t0 = Instant::now();
        let mut m = OutMessage::new(9, b"hello", 100, 3, t0);
        let pkts = m.send_group(t0, timer);
        assert_eq!(pkts, vec![vec![0x12, 0x80, 0x09, b'h', b'e', b'l', b'l', b'o']]);
        assert_eq!(m.on_ack(None, t0, timer), AckOutcome::Done);
    }

    #[test]
    fn groups_end_with_gtr_and_message_with_ttr() {
        let t0 = Instant::now();
        let msg: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let mut m = OutMessage::new(1, &msg, 100, 4, t0);
        assert_eq!(m.packet_count(), 10);
        let g1: Vec<_> = m.send_group(t0, timer).iter().map(|p| psn_flags(p)).collect();
        assert_eq!(g1, vec![(0, 0, false), (1, 0, false), (2, 0, false), (3, GTR, false)]);
        assert_eq!(m.on_ack(Some(1), t0, timer), AckOutcome::Ignored, "stale PSN");
        let AckOutcome::Next(g2) = m.on_ack(Some(3), t0, timer) else {
            panic!()
        };
        assert_eq!(g2.iter().map(|p| psn_flags(p).0).collect::<Vec<_>>(), vec![4, 5, 6, 7]);
        let AckOutcome::Next(g3) = m.on_ack(Some(7), t0, timer) else {
            panic!()
        };
        let g3: Vec<_> = g3.iter().map(|p| psn_flags(p)).collect();
        assert_eq!(g3, vec![(8, 0, false), (9, TTR, false)]);
        assert_eq!(m.on_ack(Some(9), t0, timer), AckOutcome::Done);
    }

    #[test]
    fn nack_resends_listed_packets_with_rid() {
        let t0 = Instant::now();
        let mut m = OutMessage::new(1, &[7u8; 450], 100, 5, t0);
        m.send_group(t0, timer);
        let again = m.on_nack(&[1, 3], 4, t0, timer).unwrap();
        assert_eq!(
            again.iter().map(|p| psn_flags(p)).collect::<Vec<_>>(),
            vec![(1, 0, true), (3, 0, true)]
        );
        let all = m.on_nack(&[], 4, t0, timer).unwrap();
        assert_eq!(all.len(), 5, "an empty Nack asks for the whole group");
    }

    #[test]
    fn timer_resends_the_group_end_then_gives_up() {
        let t0 = Instant::now();
        let mut m = OutMessage::new(1, &[0u8; 250], 100, 3, t0);
        m.send_group(t0, timer);
        assert_eq!(m.on_timer(2, t0, timer), TimerOutcome::Idle);
        let t1 = t0 + Duration::from_secs(5);
        let TimerOutcome::Retransmit(p) = m.on_timer(2, t1, timer) else {
            panic!()
        };
        assert_eq!(psn_flags(&p), (2, TTR, true));
        let t2 = t1 + Duration::from_secs(5);
        assert!(matches!(m.on_timer(2, t2, timer), TimerOutcome::Retransmit(_)));
        assert_eq!(m.on_timer(2, t2 + Duration::from_secs(5), timer), TimerOutcome::GiveUp);
    }

    #[test]
    fn repeated_invoke_resends_the_first_group_only_before_any_ack() {
        let t0 = Instant::now();
        let mut m = OutMessage::new(1, &[5u8; 450], 100, 3, t0);
        m.send_group(t0, timer);
        let again = m.on_repeated_invoke(2, t0, timer).unwrap();
        assert_eq!(
            again.iter().map(|p| psn_flags(p)).collect::<Vec<_>>(),
            vec![(0, 0, true), (1, 0, true), (2, GTR, true)]
        );
        assert!(m.on_repeated_invoke(2, t0, timer).is_some());
        assert!(m.on_repeated_invoke(2, t0, timer).is_none(), "counted as retries");
        let mut m = OutMessage::new(1, &[5u8; 450], 100, 3, t0);
        m.send_group(t0, timer);
        assert!(matches!(m.on_ack(Some(2), t0, timer), AckOutcome::Next(_)));
        assert!(m.on_repeated_invoke(4, t0, timer).is_none(), "late copy after an Ack");
    }

    #[test]
    fn retransmissions_can_leave_rid_clear() {
        let t0 = Instant::now();
        let mut m = OutMessage::new(1, &[0u8; 250], 100, 3, t0).with_retransmit_rid(false);
        m.send_group(t0, timer);
        let TimerOutcome::Retransmit(p) = m.on_timer(2, t0 + Duration::from_secs(5), timer) else {
            panic!()
        };
        assert_eq!(psn_flags(&p), (2, TTR, false));
        assert!(m.on_nack(&[0], 2, t0, timer).unwrap().iter().all(|p| !psn_flags(p).2));
    }

    #[test]
    fn rtt_is_sampled_only_without_retransmission() {
        let t0 = Instant::now();
        let mut m = OutMessage::new(1, &[0u8; 250], 100, 3, t0);
        m.send_group(t0, timer);
        assert!(!m.heard_back());
        assert_eq!(m.on_ack(None, t0 + Duration::from_millis(1500), timer), AckOutcome::Done);
        assert!(m.heard_back());
        assert_eq!(m.take_rtt_sample(), Some((Duration::from_millis(1500), 250)));
        assert_eq!(m.take_rtt_sample(), None);
        let mut m = OutMessage::new(1, &[0u8; 250], 100, 3, t0);
        m.send_group(t0, timer);
        assert!(matches!(
            m.on_timer(2, t0 + Duration::from_secs(5), timer),
            TimerOutcome::Retransmit(_)
        ));
        m.on_ack(None, t0 + Duration::from_secs(6), timer);
        assert_eq!(m.take_rtt_sample(), None, "Karn: no sample across a retransmission");
    }

    #[test]
    fn rtt_estimate_follows_samples() {
        let mut rtt = Rtt::new(Duration::from_millis(800));
        assert_eq!(rtt.timeout(), Duration::from_millis(800 + 4 * 400));
        rtt.update(Duration::from_millis(800));
        assert_eq!(rtt.timeout(), Duration::from_millis(800 + 4 * 300));
        rtt.update(Duration::from_millis(8800));
        assert_eq!(rtt.timeout(), Duration::from_millis(1800 + 4 * 2225));
    }

    #[test]
    fn restarted_timer_waits_again() {
        let t0 = Instant::now();
        let mut m = OutMessage::new(1, &[0u8; 250], 100, 3, t0);
        m.send_group(t0, timer);
        let t1 = t0 + Duration::from_secs(30);
        m.restart_timer(t1, timer);
        assert_eq!(m.on_timer(2, t1 + Duration::from_millis(1100), timer), TimerOutcome::Idle);
        assert!(matches!(
            m.on_timer(2, t1 + Duration::from_millis(1300), timer),
            TimerOutcome::Retransmit(_)
        ));
    }

    #[test]
    fn reassembly_acks_groups_and_nacks_holes() {
        let t0 = Instant::now();
        let mut m = InMessage::new(t0);
        assert_eq!(m.add(0, 0, b"ab", 100, t0), Reassembly::Incomplete);
        assert_eq!(m.add(2, GTR, b"ef", 100, t0), Reassembly::Nack(vec![1]));
        assert_eq!(
            m.add(1, 0, b"cd", 100, t0),
            Reassembly::GroupAck(2),
            "the retransmission fills the hole"
        );
        assert_eq!(m.add(2, GTR, b"ef", 100, t0), Reassembly::GroupAck(2), "retransmitted group end");
        assert_eq!(m.add(3, TTR, b"g", 100, t0), Reassembly::Complete(b"abcdefg".to_vec()));
        let mut big = InMessage::new(t0);
        assert_eq!(big.add(0, 0, &[0; 60], 100, t0), Reassembly::Incomplete);
        assert_eq!(big.add(1, TTR, &[0; 60], 100, t0), Reassembly::TooLarge);
    }

    #[test]
    fn packets_parse_back_as_results() {
        let t0 = Instant::now();
        let mut m = OutMessage::new(0x13cc, &[1u8; 30], 10, 2, t0);
        let pkts = m.send_group(t0, timer);
        assert!(matches!(parse_pdu(&pkts[0]), Ok(WtpPdu::Unexpected { pdu_type: 2, tid: 0x13cc })));
        assert!(matches!(parse_pdu(&pkts[1]), Ok(WtpPdu::Unexpected { pdu_type: 6, tid: 0x13cc })));
    }
}
