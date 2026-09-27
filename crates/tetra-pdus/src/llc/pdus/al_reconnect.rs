use core::fmt;

use tetra_core::BitBuffer;
use tetra_core::pdu_parse_error::*;
use tetra_core::{expect_value, let_field};

/// Reconnect report of an AL-RECONNECT PDU (table 21.22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlReconnectReport {
    Propose,
    Reject,
    Accept,
    Reserved,
}

impl AlReconnectReport {
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => Self::Propose,
            1 => Self::Reject,
            2 => Self::Accept,
            _ => Self::Reserved,
        }
    }

    pub fn into_raw(self) -> u8 {
        match self {
            Self::Propose => 0,
            Self::Reject => 1,
            Self::Accept => 2,
            Self::Reserved => 3,
        }
    }
}

/// Clause 21.2.3.4a AL-RECONNECT: an MS asks to keep an advanced link it used on its previous
/// cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlReconnect {
    pub acknowledged_service: bool,
    /// Over-air advanced link number: 0..3 means advanced link 1..4.
    pub advanced_link_number: u8,
    pub report: AlReconnectReport,
}

impl AlReconnect {
    pub fn from_bitbuf(buf: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let_field!(buf, llc_pdu_type, 4);
        expect_value!(llc_pdu_type, 12)?;
        let_field!(buf, advanced_link_service, 1);
        let_field!(buf, advanced_link_number, 2);
        let_field!(buf, report, 2);
        Ok(Self {
            acknowledged_service: advanced_link_service != 0,
            advanced_link_number: advanced_link_number as u8,
            report: AlReconnectReport::from_raw(report as u8),
        })
    }

    pub fn to_bitbuf(&self, buf: &mut BitBuffer) {
        buf.write_bits(12, 4);
        buf.write_bits(self.acknowledged_service as u64, 1);
        buf.write_bits((self.advanced_link_number & 0b11) as u64, 2);
        buf.write_bits(self.report.into_raw() as u64, 2);
    }
}

impl fmt::Display for AlReconnect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "al_reconnect {{ ack: {}, al: {}, report: {:?} }}",
            self.acknowledged_service,
            self.advanced_link_number + 1,
            self.report
        )
    }
}
