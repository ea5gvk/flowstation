/// ETSI EN 300 392-7 clause A.8.6, Table A.40 "Authentication sub-type".
/// Bits: 2
///
/// Identifies the specific PDU when the MM PDU type is 0000 (uplink, U-AUTHENTICATION) or
/// 0001 (downlink, D-AUTHENTICATION). Both directions use the same encoding.
///
/// NOTE ON ORDERING: the encoding is DEMAND / RESPONSE / RESULT / REJECT — REJECT is 11, not 01.
/// An earlier version of this file guessed the order and had REJECT=01, which silently produced
/// PDUs a real terminal could not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthenticationSubtype {
    Demand = 0,
    Response = 1,
    Result = 2,
    Reject = 3,
}

impl std::convert::TryFrom<u64> for AuthenticationSubtype {
    type Error = ();
    fn try_from(x: u64) -> Result<Self, Self::Error> {
        match x {
            0 => Ok(AuthenticationSubtype::Demand),
            1 => Ok(AuthenticationSubtype::Response),
            2 => Ok(AuthenticationSubtype::Result),
            3 => Ok(AuthenticationSubtype::Reject),
            _ => Err(()),
        }
    }
}

impl AuthenticationSubtype {
    pub fn into_raw(self) -> u64 {
        self as u64
    }
}

impl From<AuthenticationSubtype> for u64 {
    fn from(e: AuthenticationSubtype) -> Self {
        e.into_raw()
    }
}

impl core::fmt::Display for AuthenticationSubtype {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuthenticationSubtype::Demand => write!(f, "Demand"),
            AuthenticationSubtype::Response => write!(f, "Response"),
            AuthenticationSubtype::Result => write!(f, "Result"),
            AuthenticationSubtype::Reject => write!(f, "Reject"),
        }
    }
}

/// ETSI EN 300 392-7 clause A.8.4, Table A.38 "Authentication reject reason". Bits: 3.
/// Only 000 is defined; all other values are reserved.
pub const AUTH_REJECT_NOT_SUPPORTED: u8 = 0b000;

#[cfg(test)]
mod tests {
    use super::*;

    /// Guard the exact Table A.40 encoding — this is what a real terminal decodes against.
    #[test]
    fn subtype_values_match_table_a40() {
        assert_eq!(AuthenticationSubtype::Demand.into_raw(), 0b00);
        assert_eq!(AuthenticationSubtype::Response.into_raw(), 0b01);
        assert_eq!(AuthenticationSubtype::Result.into_raw(), 0b10);
        assert_eq!(AuthenticationSubtype::Reject.into_raw(), 0b11);

        for raw in 0u64..4 {
            let st = AuthenticationSubtype::try_from(raw).expect("all 4 values are defined");
            assert_eq!(st.into_raw(), raw, "round-trip must be exact");
        }
        assert!(AuthenticationSubtype::try_from(4).is_err());
    }
}
