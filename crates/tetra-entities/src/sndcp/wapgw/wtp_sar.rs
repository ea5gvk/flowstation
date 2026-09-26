//! WTP segmentation and reassembly (WAP-224-WTP clause 7.14).
//!
//! [`OutMessage`] sends a Result as packet groups: each group ends with a GTR packet (the last
//! one with TTR) and waits for the initiator's Ack carrying that packet's PSN. A Nack gets only
//! the missing packets again; a silent timer gets the group's last packet again, both with RID
//! set, and the transaction is given up after `max_retries`.
//!
//! [`InMessage`] collects a segmented Invoke: on each GTR / TTR packet it acknowledges the group
//! or asks for the missing packets with a Nack.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::wtp::{self, GTR, TTR};

/// Packet Sequence Numbers are one octet.
pub const MAX_PACKETS: usize = 256;

#[derive(Debug)]
pub struct OutMessage {
    tid: u16,
    chunks: Vec<Vec<u8>>,
    group_size: usize,
    group_first: usize,
    group_last: usize,
    retries: u8,
    deadline: Instant,
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
        }
    }

    pub fn packet_count(&self) -> usize {
        self.chunks.len()
    }

    fn packet(&self, psn: usize, rid: bool) -> Vec<u8> {
        let flags = if psn + 1 == self.chunks.len() {
            TTR
        } else if psn == self.group_last {
            GTR
        } else {
            0
        };
        wtp::result_packet(self.tid, psn as u8, flags, rid, &self.chunks[psn])
    }

    fn group_bytes(&self) -> usize {
        self.chunks[self.group_first..=self.group_last].iter().map(Vec::len).sum()
    }

    /// Packets of the current group, first transmission. `timer` gives the wait for the Ack from
    /// the number of octets on the air.
    pub fn send_group(&mut self, now: Instant, timer: impl Fn(usize) -> Duration) -> Vec<Vec<u8>> {
        self.deadline = now + timer(self.group_bytes());
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
        if self.retries >= max_retries {
            return None;
        }
        self.retries += 1;
        let psns: Vec<usize> = if missing.is_empty() {
            (self.group_first..=self.group_last).collect()
        } else {
            missing.iter().map(|&p| p as usize).filter(|&p| p <= self.group_last).collect()
        };
        let bytes = psns.iter().map(|&p| self.chunks[p].len()).sum();
        self.deadline = now + timer(bytes);
        Some(psns.into_iter().map(|psn| self.packet(psn, true)).collect())
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
        self.deadline = now + timer(self.chunks[self.group_last].len());
        TimerOutcome::Retransmit(self.packet(self.group_last, true))
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
