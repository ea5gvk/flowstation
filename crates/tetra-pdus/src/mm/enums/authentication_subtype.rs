/// ETSI EN 300 392-7 clause A.8.6 "Authentication sub-type".
/// Bits: 2
///
/// Selects which of the four authentication PDUs (demand / reject / response / result) a
/// D-AUTHENTICATION or U-AUTHENTICATION PDU actually carries. Both directions share the same
/// four-way split and the same bit encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthenticationSubtype {
    Demand = 0,
    Reject = 1,
    Response = 2,
    Result = 3,
}

impl std::convert::TryFrom<u64> for AuthenticationSubtype {
    type Error = ();
    fn try_from(x: u64) -> Result<Self, Self::Error> {
        match x {
            0 => Ok(AuthenticationSubtype::Demand),
            1 => Ok(AuthenticationSubtype::Reject),
            2 => Ok(AuthenticationSubtype::Response),
            3 => Ok(AuthenticationSubtype::Result),
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
            AuthenticationSubtype::Reject => write!(f, "Reject"),
            AuthenticationSubtype::Response => write!(f, "Response"),
            AuthenticationSubtype::Result => write!(f, "Result"),
        }
    }
}
