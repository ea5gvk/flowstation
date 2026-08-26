use core::fmt;

use tetra_core::expect_pdu_type;
use tetra_core::typed_pdu_fields::*;
use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

use crate::mm::enums::authentication_subtype::AuthenticationSubtype;
use crate::mm::enums::mm_pdu_type_dl::MmPduTypeDl;
use crate::mm::enums::type34_elem_id_dl::MmType34ElemIdDl;

/// D-AUTHENTICATION PDU (ETSI EN 300 392-7, Tables A.1 to A.4).
///
/// One PDU type discriminated by `sub_type`, carrying all four messages the SwMI can send.
/// Layouts, verbatim from the standard:
///
/// - DEMAND (A.1):   PDU type(4) sub-type(2) RAND1(80) RS(80) [proprietary T3]
/// - REJECT (A.2):   PDU type(4) sub-type(2) reject_reason(3) [proprietary T3]
/// - RESPONSE (A.3): PDU type(4) sub-type(2) RS(80) RES2(32) mutual_flag(1)
///                   RAND1(80 — only if mutual_flag = 1) [proprietary T3]
/// - RESULT (A.4):   PDU type(4) sub-type(2) R1(1) mutual_flag(1)
///                   RES2(32 — only if mutual_flag = 1) [proprietary T3]
///
/// The mutual authentication flag exists ONLY in RESPONSE and RESULT — there is no such field in
/// DEMAND, and no address extension element in any of the four.
#[derive(Debug)]
pub struct DAuthentication {
    /// Type1, 2 bits, which of the four authentication messages this is
    pub sub_type: AuthenticationSubtype,

    // --- DEMAND ---
    /// Type1, 80 bits, random challenge RAND1 (DEMAND; also RESPONSE when mutual_flag = 1)
    pub rand1: Option<u128>,
    /// Type1, 80 bits, random seed RS (DEMAND and RESPONSE)
    pub rs: Option<u128>,

    // --- REJECT ---
    /// Type1, 3 bits, authentication reject reason (REJECT only). 000 = not supported.
    pub reject_reason: Option<u8>,

    // --- RESPONSE / RESULT ---
    /// Type1, 32 bits, RES2 (RESPONSE; also RESULT when mutual_flag = 1)
    pub res2: Option<u64>,
    /// Type1, 1 bit, authentication result R1 (RESULT only). false = failed.
    pub result: Option<bool>,
    /// Type1, 1 bit, mutual authentication flag (RESPONSE and RESULT only). Governs whether the
    /// conditional RAND1/RES2 element is present.
    pub mutual_authentication_flag: Option<bool>,

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
    /// Build a DEMAND PDU (Table A.1).
    pub fn demand(rand1: u128, rs: u128) -> Self {
        DAuthentication {
            sub_type: AuthenticationSubtype::Demand,
            rand1: Some(rand1),
            rs: Some(rs),
            reject_reason: None,
            res2: None,
            result: None,
            mutual_authentication_flag: None,
            proprietary: None,
        }
    }

    /// Build a RESULT PDU (Table A.4) for a non-mutual exchange.
    pub fn result(success: bool) -> Self {
        DAuthentication {
            sub_type: AuthenticationSubtype::Result,
            rand1: None,
            rs: None,
            reject_reason: None,
            res2: None,
            result: Some(success),
            mutual_authentication_flag: Some(false),
            proprietary: None,
        }
    }

    /// Build a REJECT PDU (Table A.2).
    pub fn reject(reason: u8) -> Self {
        DAuthentication {
            sub_type: AuthenticationSubtype::Reject,
            rand1: None,
            rs: None,
            reject_reason: Some(reason),
            res2: None,
            result: None,
            mutual_authentication_flag: None,
            proprietary: None,
        }
    }

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
            reject_reason: None,
            res2: None,
            result: None,
            mutual_authentication_flag: None,
            proprietary: None,
        };

        match sub_type {
            AuthenticationSubtype::Demand => {
                s.rand1 = Some(read_field_80(buffer, "rand1")?);
                s.rs = Some(read_field_80(buffer, "rs")?);
            }
            AuthenticationSubtype::Reject => {
                s.reject_reason = Some(buffer.read_field(3, "reject_reason")? as u8);
            }
            AuthenticationSubtype::Response => {
                s.rs = Some(read_field_80(buffer, "rs")?);
                s.res2 = Some(buffer.read_field(32, "res2")?);
                let mutual = buffer.read_field(1, "mutual_authentication_flag")? != 0;
                s.mutual_authentication_flag = Some(mutual);
                if mutual {
                    s.rand1 = Some(read_field_80(buffer, "rand1")?);
                }
            }
            AuthenticationSubtype::Result => {
                s.result = Some(buffer.read_field(1, "authentication_result")? != 0);
                let mutual = buffer.read_field(1, "mutual_authentication_flag")? != 0;
                s.mutual_authentication_flag = Some(mutual);
                if mutual {
                    s.res2 = Some(buffer.read_field(32, "res2")?);
                }
            }
        }

        // obit designates presence of any further type2, type3 or type4 fields
        let obit = delimiters::read_obit(buffer)?;

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
        buffer.write_bits(MmPduTypeDl::DAuthentication.into_raw(), 4);
        buffer.write_bits(self.sub_type.into_raw(), 2);

        match self.sub_type {
            AuthenticationSubtype::Demand => {
                write_field_80(buffer, self.rand1.unwrap_or(0));
                write_field_80(buffer, self.rs.unwrap_or(0));
            }
            AuthenticationSubtype::Reject => {
                buffer.write_bits(self.reject_reason.unwrap_or(0) as u64, 3);
            }
            AuthenticationSubtype::Response => {
                write_field_80(buffer, self.rs.unwrap_or(0));
                buffer.write_bits(self.res2.unwrap_or(0), 32);
                let mutual = self.mutual_authentication_flag.unwrap_or(false);
                buffer.write_bits(mutual as u64, 1);
                if mutual {
                    write_field_80(buffer, self.rand1.unwrap_or(0));
                }
            }
            AuthenticationSubtype::Result => {
                buffer.write_bits(self.result.unwrap_or(false) as u64, 1);
                let mutual = self.mutual_authentication_flag.unwrap_or(false);
                buffer.write_bits(mutual as u64, 1);
                if mutual {
                    buffer.write_bits(self.res2.unwrap_or(0), 32);
                }
            }
        }

        let obit = self.proprietary.is_some();
        delimiters::write_obit(buffer, obit as u8);
        if !obit {
            return Ok(());
        }

        typed::write_type3_generic(obit, buffer, &self.proprietary, MmType34ElemIdDl::Proprietary)?;
        delimiters::write_mbit(buffer, 0);
        Ok(())
    }
}

impl fmt::Display for DAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "DAuthentication {{ sub_type: {} rand1: {:?} rs: {:?} reject_reason: {:?} res2: {:?} result: {:?} mutual: {:?} proprietary: {:?} }}",
            self.sub_type, self.rand1, self.rs, self.reject_reason, self.res2, self.result, self.mutual_authentication_flag, self.proprietary,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAND1: u128 = 0x1234_5678_9ABC_DEF0_1122u128;
    const RS: u128 = 0xAAAA_BBBB_CCCC_DDDD_EEEEu128;

    /// Table A.1: 4 + 2 + 80 + 80 = 166 bits, plus the trailing o-bit = 167. Getting this wrong
    /// by even one bit is what made real terminals silently drop the PDU.
    #[test]
    fn demand_is_exactly_167_bits_and_matches_table_a1() {
        let pdu = DAuthentication::demand(RAND1, RS);
        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();

        assert_eq!(bits.len(), 167, "DEMAND must be 4+2+80+80 mandatory bits plus the o-bit");
        assert_eq!(&bits[0..4], "0001", "PDU type must be D-AUTHENTICATION (0001)");
        assert_eq!(&bits[4..6], "00", "sub-type must be DEMAND (00)");
        assert_eq!(&bits[166..167], "0", "o-bit must be 0 when no proprietary element");

        // RAND1 occupies bits 6..86 and RS bits 86..166, in that order per Table A.1.
        let rand1_bits = &bits[6..86];
        let rs_bits = &bits[86..166];
        assert_eq!(u128::from_str_radix(rand1_bits, 2).unwrap(), RAND1);
        assert_eq!(u128::from_str_radix(rs_bits, 2).unwrap(), RS);
    }

    #[test]
    fn demand_roundtrip() {
        let pdu = DAuthentication::demand(RAND1, RS);
        let mut out = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut out).unwrap();
        let mut inb = BitBuffer::from_bitstr(&out.to_bitstr());
        let parsed = DAuthentication::from_bitbuf(&mut inb).unwrap();

        assert_eq!(parsed.sub_type, AuthenticationSubtype::Demand);
        assert_eq!(parsed.rand1, Some(RAND1));
        assert_eq!(parsed.rs, Some(RS));
        assert_eq!(parsed.mutual_authentication_flag, None, "DEMAND has no mutual flag (Table A.1)");
    }

    /// Table A.4: R1(1) + mutual(1), and RES2 only when mutual = 1.
    #[test]
    fn result_layout_and_conditional_res2() {
        let pdu = DAuthentication::result(true);
        let mut buf = BitBuffer::new_autoexpand(8);
        pdu.to_bitbuf(&mut buf).unwrap();
        let bits = buf.to_bitstr();
        assert_eq!(bits.len(), 4 + 2 + 1 + 1 + 1, "non-mutual RESULT: type+subtype+R1+flag+obit");
        assert_eq!(&bits[4..6], "10", "sub-type must be RESULT (10)");
        assert_eq!(&bits[6..7], "1", "R1 = 1 means success");
        assert_eq!(&bits[7..8], "0", "mutual flag 0 -> no RES2 follows");

        // With mutual = 1, RES2 must be present and round-trip.
        let mut pdu = DAuthentication::result(true);
        pdu.mutual_authentication_flag = Some(true);
        pdu.res2 = Some(0xDEAD_BEEF);
        let mut out = BitBuffer::new_autoexpand(16);
        pdu.to_bitbuf(&mut out).unwrap();
        assert_eq!(out.to_bitstr().len(), 4 + 2 + 1 + 1 + 32 + 1);

        let mut inb = BitBuffer::from_bitstr(&out.to_bitstr());
        let parsed = DAuthentication::from_bitbuf(&mut inb).unwrap();
        assert_eq!(parsed.res2, Some(0xDEAD_BEEF));
        assert_eq!(parsed.result, Some(true));
    }

    /// Table A.3: RS(80) then RES2(32) then mutual(1), with RAND1 conditional.
    #[test]
    fn response_layout_and_conditional_rand1() {
        let mut pdu = DAuthentication {
            sub_type: AuthenticationSubtype::Response,
            rand1: None,
            rs: Some(RS),
            reject_reason: None,
            res2: Some(0x1234_5678),
            result: None,
            mutual_authentication_flag: Some(false),
            proprietary: None,
        };
        let mut out = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut out).unwrap();
        assert_eq!(out.to_bitstr().len(), 4 + 2 + 80 + 32 + 1 + 1);
        assert_eq!(&out.to_bitstr()[4..6], "01", "sub-type must be RESPONSE (01)");

        pdu.mutual_authentication_flag = Some(true);
        pdu.rand1 = Some(RAND1);
        let mut out2 = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut out2).unwrap();
        assert_eq!(out2.to_bitstr().len(), 4 + 2 + 80 + 32 + 1 + 80 + 1);

        let mut inb = BitBuffer::from_bitstr(&out2.to_bitstr());
        let parsed = DAuthentication::from_bitbuf(&mut inb).unwrap();
        assert_eq!(parsed.rs, Some(RS));
        assert_eq!(parsed.res2, Some(0x1234_5678));
        assert_eq!(parsed.rand1, Some(RAND1));
    }

    /// Table A.2 + Table A.38.
    #[test]
    fn reject_layout() {
        let pdu = DAuthentication::reject(0b000);
        let mut out = BitBuffer::new_autoexpand(8);
        pdu.to_bitbuf(&mut out).unwrap();
        let bits = out.to_bitstr();
        assert_eq!(bits.len(), 4 + 2 + 3 + 1);
        assert_eq!(&bits[4..6], "11", "sub-type must be REJECT (11)");
        assert_eq!(&bits[6..9], "000", "reason 000 = authentication not supported");

        let mut inb = BitBuffer::from_bitstr(&bits);
        let parsed = DAuthentication::from_bitbuf(&mut inb).unwrap();
        assert_eq!(parsed.sub_type, AuthenticationSubtype::Reject);
        assert_eq!(parsed.reject_reason, Some(0));
    }
}
