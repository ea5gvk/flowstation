use core::fmt;

use tetra_core::expect_pdu_type;
use tetra_core::typed_pdu_fields::*;
use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

use crate::mm::enums::authentication_subtype::AuthenticationSubtype;
use crate::mm::enums::mm_pdu_type_dl::MmPduTypeDl;
use crate::mm::enums::type34_elem_id_dl::MmType34ElemIdDl;

/// Representation of the D-AUTHENTICATION PDU (ETSI EN 300 392-7, Annex A.1.1-A.1.4).
/// The infrastructure uses this single PDU type, discriminated by `sub_type`, to carry all
/// four authentication messages the SwMI can send: demand (challenge the MS with RAND1/RS),
/// reject, response (SwMI's answer RES2 to an MS-initiated mutual challenge), and result
/// (final pass/fail of the exchange).
/// Response expected: U-AUTHENTICATION (subtype-dependent) / -
/// Response to: U-AUTHENTICATION demand (for `Response`) / registration or explicit auth trigger (for `Demand`)
///
/// NOTE ON FIELD WIDTHS: RAND1/RAND2/RS are modelled as 80 bits and RES1/RES2 as 32 bits, matching
/// the widths used throughout published TETRA research and third-party implementations. The exact
/// bit-for-bit layout (and the reject-reason / result flag widths) should be checked against the
/// Annex A.8 element tables in EN 300 392-7 before this is relied on against real hardware — this
/// PDU has not yet been validated on air.
#[derive(Debug)]
pub struct DAuthentication {
    /// Type1, 2 bits, which of the four authentication messages this is
    pub sub_type: AuthenticationSubtype,

    // --- Demand (sub_type == Demand) ---
    /// Type1, 80 bits, Random challenge RAND1 (present for Demand only)
    pub rand1: Option<u128>,
    /// Type1, 80 bits, Random seed RS (present for Demand only)
    pub rs: Option<u128>,
    /// Type1, 1 bit, request the MS to also challenge the SwMI (mutual authentication) (Demand only)
    pub mutual_authentication_flag: Option<bool>,

    // --- Reject (sub_type == Reject) ---
    /// Type1, 3 bits, reason the SwMI is rejecting the authentication exchange (Reject only)
    pub reject_reason: Option<u8>,

    // --- Response (sub_type == Response) ---
    /// Type1, 32 bits, SwMI's response RES2 to the MS's mutual challenge RAND2 (Response only)
    pub res2: Option<u64>,

    // --- Result (sub_type == Result) ---
    /// Type1, 1 bit, TRUE if the SwMI accepts the MS as authenticated (Result only)
    pub result: Option<bool>,

    // --- Trailing optional elements, common to all sub-types ---
    /// Type2, 24 bits, MNI of the MS
    pub address_extension: Option<u64>,
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

impl DAuthentication {
    /// Parse from BitBuffer
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, MmPduTypeDl::DAuthentication)?;

        let sub_type_raw = buffer.read_field(2, "authentication_sub_type")?;
        let sub_type = AuthenticationSubtype::try_from(sub_type_raw).map_err(|_| PduParseErr::BufferEnded {
            field: Some("authentication_sub_type"),
        })?;

        let mut s = DAuthentication {
            sub_type,
            rand1: None,
            rs: None,
            mutual_authentication_flag: None,
            reject_reason: None,
            res2: None,
            result: None,
            address_extension: None,
            proprietary: None,
        };

        match sub_type {
            AuthenticationSubtype::Demand => {
                s.rand1 = Some(read_field_80(buffer, "rand1")?);
                s.rs = Some(read_field_80(buffer, "rs")?);
                s.mutual_authentication_flag = Some(buffer.read_field(1, "mutual_authentication_flag")? != 0);
            }
            AuthenticationSubtype::Reject => {
                s.reject_reason = Some(buffer.read_field(3, "reject_reason")? as u8);
            }
            AuthenticationSubtype::Response => {
                s.res2 = Some(buffer.read_field(32, "res2")?);
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
        s.proprietary = typed::parse_type3_generic(obit, buffer, MmType34ElemIdDl::Proprietary)?;

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
        buffer.write_bits(MmPduTypeDl::DAuthentication.into_raw(), 4);
        // Authentication sub-type
        buffer.write_bits(self.sub_type.into_raw(), 2);

        match self.sub_type {
            AuthenticationSubtype::Demand => {
                write_field_80(buffer, self.rand1.unwrap_or(0));
                write_field_80(buffer, self.rs.unwrap_or(0));
                buffer.write_bits(self.mutual_authentication_flag.unwrap_or(false) as u64, 1);
            }
            AuthenticationSubtype::Reject => {
                buffer.write_bits(self.reject_reason.unwrap_or(0) as u64, 3);
            }
            AuthenticationSubtype::Response => {
                buffer.write_bits(self.res2.unwrap_or(0), 32);
            }
            AuthenticationSubtype::Result => {
                buffer.write_bits(self.result.unwrap_or(false) as u64, 1);
            }
        }

        // Check if any optional field present and place o-bit
        let obit = self.address_extension.is_some() || self.proprietary.is_some();
        delimiters::write_obit(buffer, obit as u8);
        if !obit {
            return Ok(());
        }

        // Type2
        typed::write_type2_generic(obit, buffer, self.address_extension, 24);

        // Type3
        typed::write_type3_generic(obit, buffer, &self.proprietary, MmType34ElemIdDl::Proprietary)?;

        // Write terminating m-bit
        delimiters::write_mbit(buffer, 0);
        Ok(())
    }
}

impl fmt::Display for DAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "DAuthentication {{ sub_type: {} rand1: {:?} rs: {:?} mutual_authentication_flag: {:?} reject_reason: {:?} res2: {:?} result: {:?} address_extension: {:?} proprietary: {:?} }}",
            self.sub_type,
            self.rand1,
            self.rs,
            self.mutual_authentication_flag,
            self.reject_reason,
            self.res2,
            self.result,
            self.address_extension,
            self.proprietary,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a Demand PDU (the case with the widest fields) through encode/decode.
    #[test]
    fn test_d_authentication_demand_roundtrip() {
        let pdu = DAuthentication {
            sub_type: AuthenticationSubtype::Demand,
            rand1: Some(0x1234_5678_9ABC_DEF0_1122u128),
            rs: Some(0xAAAA_BBBB_CCCC_DDDD_EEEEu128),
            mutual_authentication_flag: Some(true),
            reject_reason: None,
            res2: None,
            result: None,
            address_extension: None,
            proprietary: None,
        };

        let mut buf_out = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf_out).unwrap();

        let mut buf_in = BitBuffer::from_bitstr(&buf_out.to_bitstr());
        let parsed = DAuthentication::from_bitbuf(&mut buf_in).expect("Failed parsing");

        assert_eq!(parsed.sub_type, AuthenticationSubtype::Demand);
        assert_eq!(parsed.rand1, pdu.rand1);
        assert_eq!(parsed.rs, pdu.rs);
        assert_eq!(parsed.mutual_authentication_flag, pdu.mutual_authentication_flag);
    }

    /// Round-trip a Result PDU (the minimal case: a single flag bit).
    #[test]
    fn test_d_authentication_result_roundtrip() {
        let pdu = DAuthentication {
            sub_type: AuthenticationSubtype::Result,
            rand1: None,
            rs: None,
            mutual_authentication_flag: None,
            reject_reason: None,
            res2: None,
            result: Some(true),
            address_extension: None,
            proprietary: None,
        };

        let mut buf_out = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf_out).unwrap();

        let mut buf_in = BitBuffer::from_bitstr(&buf_out.to_bitstr());
        let parsed = DAuthentication::from_bitbuf(&mut buf_in).expect("Failed parsing");

        assert_eq!(parsed.sub_type, AuthenticationSubtype::Result);
        assert_eq!(parsed.result, Some(true));
    }
}
