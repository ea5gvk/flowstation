use core::fmt;

use tetra_core::expect_pdu_type;
use tetra_core::typed_pdu_fields::*;
use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

use crate::mm::enums::authentication_subtype::AuthenticationSubtype;
use crate::mm::enums::mm_pdu_type_ul::MmPduTypeUl;
use crate::mm::enums::type34_elem_id_ul::MmType34ElemIdUl;

/// Representation of the U-AUTHENTICATION PDU (ETSI EN 300 392-7, Annex A.1.5-A.1.8).
/// The MS uses this single PDU type, discriminated by `sub_type`, to carry all four
/// authentication messages the MS can send back to the SwMI: demand (the MS challenging the
/// SwMI with RAND2, for MS-initiated authentication of the infrastructure), reject, response
/// (the MS's answer RES1 to the SwMI's D-AUTHENTICATION demand), and result.
/// Response expected: D-AUTHENTICATION (subtype-dependent) / -
/// Response to: D-AUTHENTICATION demand (for `Response`) / -
///
/// NOTE ON FIELD WIDTHS: see the equivalent note on `DAuthentication` — RAND2 is modelled as 80
/// bits and RES1 as 32 bits based on common TETRA reference material, not yet checked bit-for-bit
/// against the Annex A.8 element tables in EN 300 392-7. Not yet validated on air.
#[derive(Debug)]
pub struct UAuthentication {
    /// Type1, 2 bits, which of the four authentication messages this is
    pub sub_type: AuthenticationSubtype,

    // --- Demand (sub_type == Demand): MS challenges the SwMI ---
    /// Type1, 80 bits, Random challenge RAND2 (present for Demand only)
    pub rand2: Option<u128>,

    // --- Reject (sub_type == Reject) ---
    /// Type1, 3 bits, reason the MS is rejecting the authentication exchange (Reject only)
    pub reject_reason: Option<u8>,

    // --- Response (sub_type == Response): MS answers the SwMI's D-AUTHENTICATION demand ---
    /// Type1, 32 bits, MS's response RES1 to the SwMI's RAND1 (Response only)
    pub res1: Option<u64>,

    // --- Result (sub_type == Result) ---
    /// Type1, 1 bit, TRUE if the MS accepts the SwMI as authenticated (Result only)
    pub result: Option<bool>,

    // --- Trailing optional elements, common to all sub-types ---
    /// Type2, 24 bits, MNI of the MS
    pub address_extension: Option<u64>,
    /// Type3, Authentication uplink — carries a piggybacked mutual challenge RAND2 alongside a
    /// Response, matching the flow already referenced (as an opaque Type3FieldGeneric) from
    /// U-LOCATION-UPDATE-DEMAND. Left generic here too until the element's internal layout is
    /// modelled explicitly.
    pub authentication_uplink: Option<Type3FieldGeneric>,
    /// Type3, Proprietary
    pub proprietary: Option<Type3FieldGeneric>,
}

/// Read an 80-bit field as u128 (BitBuffer::read_field tops out at 64 bits).
fn read_field_80(buffer: &mut BitBuffer, field_name: &'static str) -> Result<u128, PduParseErr> {
    let hi = buffer.read_field(16, field_name)? as u128;
    let lo = buffer.read_field(64, field_name)? as u128;
    Ok((hi << 64) | lo)
}

/// Write an 80-bit field from a u128 (only the low 80 bits are used).
fn write_field_80(buffer: &mut BitBuffer, value: u128) {
    let hi = ((value >> 64) & 0xFFFF) as u64;
    let lo = (value & 0xFFFF_FFFF_FFFF_FFFF) as u64;
    buffer.write_bits(hi, 16);
    buffer.write_bits(lo, 64);
}

impl UAuthentication {
    /// Parse from BitBuffer
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, MmPduTypeUl::UAuthentication)?;

        let sub_type_raw = buffer.read_field(2, "authentication_sub_type")?;
        let sub_type = AuthenticationSubtype::try_from(sub_type_raw).map_err(|_| PduParseErr::BufferEnded {
            field: Some("authentication_sub_type"),
        })?;

        let mut s = UAuthentication {
            sub_type,
            rand2: None,
            reject_reason: None,
            res1: None,
            result: None,
            address_extension: None,
            authentication_uplink: None,
            proprietary: None,
        };

        match sub_type {
            AuthenticationSubtype::Demand => {
                s.rand2 = Some(read_field_80(buffer, "rand2")?);
            }
            AuthenticationSubtype::Reject => {
                s.reject_reason = Some(buffer.read_field(3, "reject_reason")? as u8);
            }
            AuthenticationSubtype::Response => {
                s.res1 = Some(buffer.read_field(32, "res1")?);
            }
            AuthenticationSubtype::Result => {
                s.result = Some(buffer.read_field(1, "result")? != 0);
            }
        }

        // obit designates presence of any further type2, type3 or type4 fields
        let obit = delimiters::read_obit(buffer)?;

        // Type2
        s.address_extension = typed::parse_type2_generic(obit, buffer, 24, "address_extension")?;

        // Type3
        s.authentication_uplink = typed::parse_type3_generic(obit, buffer, MmType34ElemIdUl::AuthenticationUplink)?;

        // Type3
        s.proprietary = typed::parse_type3_generic(obit, buffer, MmType34ElemIdUl::Proprietary)?;

        // Read trailing mbit (if not previously encountered)
        let trailing_obit = if obit { buffer.read_field(1, "trailing_obit")? == 1 } else { obit };
        if trailing_obit {
            return Err(PduParseErr::InvalidTrailingMbitValue);
        }

        Ok(s)
    }

    /// Serialize this PDU into the given BitBuffer.
    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        // PDU Type
        buffer.write_bits(MmPduTypeUl::UAuthentication.into_raw(), 4);
        // Authentication sub-type
        buffer.write_bits(self.sub_type.into_raw(), 2);

        match self.sub_type {
            AuthenticationSubtype::Demand => {
                write_field_80(buffer, self.rand2.unwrap_or(0));
            }
            AuthenticationSubtype::Reject => {
                buffer.write_bits(self.reject_reason.unwrap_or(0) as u64, 3);
            }
            AuthenticationSubtype::Response => {
                buffer.write_bits(self.res1.unwrap_or(0), 32);
            }
            AuthenticationSubtype::Result => {
                buffer.write_bits(self.result.unwrap_or(false) as u64, 1);
            }
        }

        // Check if any optional field present and place o-bit
        let obit = self.address_extension.is_some() || self.authentication_uplink.is_some() || self.proprietary.is_some();
        delimiters::write_obit(buffer, obit as u8);
        if !obit {
            return Ok(());
        }

        // Type2
        typed::write_type2_generic(obit, buffer, self.address_extension, 24);

        // Type3
        typed::write_type3_generic(obit, buffer, &self.authentication_uplink, MmType34ElemIdUl::AuthenticationUplink)?;

        // Type3
        typed::write_type3_generic(obit, buffer, &self.proprietary, MmType34ElemIdUl::Proprietary)?;

        // Write terminating m-bit
        delimiters::write_mbit(buffer, 0);
        Ok(())
    }
}

impl fmt::Display for UAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "UAuthentication {{ sub_type: {} rand2: {:?} reject_reason: {:?} res1: {:?} result: {:?} address_extension: {:?} authentication_uplink: {:?} proprietary: {:?} }}",
            self.sub_type,
            self.rand2,
            self.reject_reason,
            self.res1,
            self.result,
            self.address_extension,
            self.authentication_uplink,
            self.proprietary,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a Demand PDU (MS challenging the SwMI).
    #[test]
    fn test_u_authentication_demand_roundtrip() {
        let pdu = UAuthentication {
            sub_type: AuthenticationSubtype::Demand,
            rand2: Some(0x0F0F_0F0F_0F0F_0F0F_0F0Fu128),
            reject_reason: None,
            res1: None,
            result: None,
            address_extension: None,
            authentication_uplink: None,
            proprietary: None,
        };

        let mut buf_out = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf_out).unwrap();

        let mut buf_in = BitBuffer::from_bitstr(&buf_out.to_bitstr());
        let parsed = UAuthentication::from_bitbuf(&mut buf_in).expect("Failed parsing");

        assert_eq!(parsed.sub_type, AuthenticationSubtype::Demand);
        assert_eq!(parsed.rand2, pdu.rand2);
    }

    /// Round-trip a Response PDU (MS answering the SwMI's challenge).
    #[test]
    fn test_u_authentication_response_roundtrip() {
        let pdu = UAuthentication {
            sub_type: AuthenticationSubtype::Response,
            rand2: None,
            reject_reason: None,
            res1: Some(0xDEAD_BEEF),
            result: None,
            address_extension: None,
            authentication_uplink: None,
            proprietary: None,
        };

        let mut buf_out = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf_out).unwrap();

        let mut buf_in = BitBuffer::from_bitstr(&buf_out.to_bitstr());
        let parsed = UAuthentication::from_bitbuf(&mut buf_in).expect("Failed parsing");

        assert_eq!(parsed.sub_type, AuthenticationSubtype::Response);
        assert_eq!(parsed.res1, Some(0xDEAD_BEEF));
    }
}
