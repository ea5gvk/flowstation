//! Common things used by both modulator and demodulator.

use super::dsp_types::*;

/// RRC channel filter taps, designed using design_channel_filter.py
pub const CHANNEL_FILTER_TAPS: [RealSample; 16] = [
    0.264_971_8,
    0.20002119,
    0.10064187,
    0.00998249,
    -0.04014123,
    -0.04405674,
    -0.01982716,
    0.00642452,
    0.01744363,
    0.01213436,
    0.00071221,
    -0.00609533,
    -0.00488494,
    0.00028619,
    0.00345407,
    0.00220812,
];

/// Of the sample counts `slot_begin + k * wrap` (`wrap` = one full cycle of the TDMA time), return
/// the one nearest `near` (the current sample count).
///
/// Slot times come from `TdmaTime::to_int`, which wraps to 0 together with the hyperframe number
/// every 65536 hyperframes (~46.4 days), while the sample counter keeps counting. Without this the
/// first slot after the wrap lay ~46 days in the past, and the modulator stopped transmitting and
/// the demodulator stopped demodulating for good (TS 100 392-2 7.3.2: the counters run
/// continuously). Until the first wrap `k` is 0, so nothing changes before it.
pub fn unwrap_slot_begin(slot_begin: SampleCount, near: SampleCount, samples_slot: SampleCount) -> SampleCount {
    let wrap = tetra_core::tdma_time::TIME_INT_WRAP as SampleCount * samples_slot;
    slot_begin + (near - slot_begin + wrap / 2).div_euclid(wrap) * wrap
}

#[cfg(test)]
mod tests {
    use super::*;
    use tetra_core::TdmaTime;

    #[test]
    fn slot_begin_stays_continuous_across_the_hyperframe_wrap() {
        const S: SampleCount = 1020;
        let last = TdmaTime {
            h: 65535,
            m: 60,
            f: 18,
            t: 4,
        };
        let first = last.add_timeslots(1);
        assert_eq!(first, TdmaTime { h: 0, m: 1, f: 1, t: 1 });

        // Just before the wrap, ~46 days of samples into the run: unchanged.
        let now = last.to_int() as SampleCount * S;
        assert_eq!(unwrap_slot_begin(last.to_int() as SampleCount * S, now, S), now);
        // The slot after the wrap begins one slot later, not 46 days earlier.
        assert_eq!(unwrap_slot_begin(first.to_int() as SampleCount * S, now, S), now + S);
        // Right after start-up nothing moves.
        assert_eq!(unwrap_slot_begin(3 * S, 0, S), 3 * S);
    }
}
