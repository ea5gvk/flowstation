use core::fmt;

use tetra_core::BitBuffer;
use tetra_core::pdu_parse_error::*;
use tetra_core::{expect_value, let_field};

/// Report of an AL-DISC PDU (table 21.21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlDiscReport {
    Success,
    Close,
    Reject,
    ServiceNotSupported,
    ServiceTemporarilyUnavailable,
    Reserved(u8),
}

impl AlDiscReport {
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => Self::Success,
            1 => Self::Close,
            2 => Self::Reject,
            3 => Self::ServiceNotSupported,
            4 => Self::ServiceTemporarilyUnavailable,
            v => Self::Reserved(v & 0b111),
        }
    }

    pub fn into_raw(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Close => 1,
            Self::Reject => 2,
            Self::ServiceNotSupported => 3,
            Self::ServiceTemporarilyUnavailable => 4,
            Self::Reserved(v) => v & 0b111,
        }
    }
}

/// Clause 21.2.3.4 AL-DISC: disconnection of an advanced link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlDisc {
    pub acknowledged_service: bool,
    /// Over-air advanced link number: 0..3 means advanced link 1..4.
    pub advanced_link_number: u8,
    pub report: AlDiscReport,
}

impl AlDisc {
    pub fn from_bitbuf(buf: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let_field!(buf, llc_pdu_type, 4);
        expect_value!(llc_pdu_type, 15)?;
        let_field!(buf, advanced_link_service, 1);
        let_field!(buf, advanced_link_number, 2);
        let_field!(buf, report, 3);
        Ok(Self {
            acknowledged_service: advanced_link_service != 0,
            advanced_link_number: advanced_link_number as u8,
            report: AlDiscReport::from_raw(report as u8),
        })
    }

    pub fn to_bitbuf(&self, buf: &mut BitBuffer) {
        buf.write_bits(15, 4);
        buf.write_bits(self.acknowledged_service as u64, 1);
        buf.write_bits((self.advanced_link_number & 0b11) as u64, 2);
        buf.write_bits(self.report.into_raw() as u64, 3);
    }
}

impl fmt::Display for AlDisc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "al_disc {{ ack: {}, al: {}, report: {:?} }}",
            self.acknowledged_service,
            self.advanced_link_number + 1,
            self.report
        )
    }
}
