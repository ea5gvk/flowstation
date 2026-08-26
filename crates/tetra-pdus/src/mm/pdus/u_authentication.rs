use core::fmt;

use tetra_core::expect_pdu_type;
use tetra_core::typed_pdu_fields::*;
use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

use crate::mm::enums::authentication_subtype::AuthenticationSubtype;
use crate::mm::enums::mm_pdu_type_ul::MmPduTypeUl;
use crate::mm::enums::type34_elem_id_ul::MmType34ElemIdUl;

/// U-AUTHENTICATION PDU (ETSI EN 300 392-7, Tables A.5 to A.8).
///
/// Layouts, verbatim from the standard:
///
/// - DEMAND (A.5):   PDU type(4) sub-type(2) RAND2(80) [proprietary T3]
/// - REJECT (A.6):   PDU type(4) sub-type(2) reject_reason(3) [proprietary T3]
/// - RESPONSE (A.7): PDU type(4) sub-type(2) RES1(32) mutual_flag(1)
///                   RAND2(80 — only if mutual_flag = 1) [proprietary T3]
/// - RESULT (A.8):   PDU type(4) sub-type(2) R2(1) mutual_flag(1)
///                   RES1(32 — only if mutual_flag = 1) [proprietary T3]
///
/// The mutual authentication flag is MANDATORY in RESPONSE and RESULT. Parsing a RESPONSE
/// without consuming it misreads everything after RES1.
#[derive(Debug)]
pub struct UAuthentication {
    /// Type1, 2 bits, which of the four authentication messages this is
    pub sub_type: AuthenticationSubtype,

    /// Type1, 80 bits, random challenge RAND2 (DEMAND; also RESPONSE when mutual_flag = 1)
    pub rand2: Option<u128>,
    /// Type1, 3 bits, authentication reject reason (REJECT only)
    pub reject_reason: Option<u8>,
    /// Type1, 32 bits, RES1 (RESPONSE; also RESULT when mutual_flag = 1)
    pub res1: Option<u64>,
    /// Type1, 1 bit, authentication result R2 (RESULT only). false = failed.
    pub result: Option<bool>,
    /// Type1, 1 bit, mutual authentication flag (RESPONSE and RESULT only)
    pub mutual_authentication_flag: Option<bool>,

    /// Type3, Proprietary
    pub proprietary: Option<Type3FieldGeneric>,
}

fn read_field_80(buffer: &mut BitBuffer, field_name: &'static str) -> Result<u128, PduParseErr> {
    let hi = buffer.read_field(16, field_name)? as u128;
    let lo = buffer.read_field(64, field_name)? as u128;
    Ok((hi << 64) | lo)
}

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
            mutual_authentication_flag: None,
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
                let mutual = buffer.read_field(1, "mutual_authentication_flag")? != 0;
                s.mutual_authentication_flag = Some(mutual);
                if mutual {
                    s.rand2 = Some(read_field_80(buffer, "rand2")?);
                }
            }
            AuthenticationSubtype::Result => {
                s.result = Some(buffer.read_field(1, "authentication_result")? != 0);
                let mutual = buffer.read_field(1, "mutual_authentication_flag")? != 0;
                s.mutual_authentication_flag = Some(mutual);
                if mutual {
                    s.res1 = Some(buffer.read_field(32, "res1")?);
                }
            }
        }

        let obit = delimiters::read_obit(buffer)?;
        s.proprietary = typed::parse_type3_generic(obit, buffer, MmType34ElemIdUl::Proprietary)?;

        let trailing_obit = if obit { buffer.read_field(1, "trailing_obit")? == 1 } else { obit };
        if trailing_obit {
            return Err(PduParseErr::InvalidTrailingMbitValue);
        }

        Ok(s)
    }

    /// Serialize this PDU into the given BitBuffer.
    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(MmPduTypeUl::UAuthentication.into_raw(), 4);
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
                let mutual = self.mutual_authentication_flag.unwrap_or(false);
                buffer.write_bits(mutual as u64, 1);
                if mutual {
                    write_field_80(buffer, self.rand2.unwrap_or(0));
                }
            }
            AuthenticationSubtype::Result => {
                buffer.write_bits(self.result.unwrap_or(false) as u64, 1);
                let mutual = self.mutual_authentication_flag.unwrap_or(false);
                buffer.write_bits(mutual as u64, 1);
                if mutual {
                    buffer.write_bits(self.res1.unwrap_or(0), 32);
                }
            }
        }

        let obit = self.proprietary.is_some();
        delimiters::write_obit(buffer, obit as u8);
        if !obit {
            return Ok(());
        }

        typed::write_type3_generic(obit, buffer, &self.proprietary, MmType34ElemIdUl::Proprietary)?;
        delimiters::write_mbit(buffer, 0);
        Ok(())
    }
}

impl fmt::Display for UAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "UAuthentication {{ sub_type: {} rand2: {:?} reject_reason: {:?} res1: {:?} result: {:?} mutual: {:?} proprietary: {:?} }}",
            self.sub_type, self.rand2, self.reject_reason, self.res1, self.result, self.mutual_authentication_flag, self.proprietary,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAND2: u128 = 0x0F0F_0F0F_0F0F_0F0F_0F0Fu128;

    /// Table A.7 — the PDU the SwMI is actually waiting for after a DEMAND. RES1 then the
    /// mandatory mutual flag; RAND2 only if that flag is set.
    #[test]
    fn response_layout_matches_table_a7() {
        let pdu = UAuthentication {
            sub_type: AuthenticationSubtype::Response,
            rand2: None,
            reject_reason: None,
            res1: Some(0xDEAD_BEEF),
            result: None,
            mutual_authentication_flag: Some(false),
            proprietary: None,
        };
        let mut out = BitBuffer::new_autoexpand(16);
        pdu.to_bitbuf(&mut out).unwrap();
        let bits = out.to_bitstr();

        assert_eq!(bits.len(), 4 + 2 + 32 + 1 + 1, "non-mutual RESPONSE length");
        assert_eq!(&bits[0..4], "0000", "PDU type must be U-AUTHENTICATION (0000)");
        assert_eq!(&bits[4..6], "01", "sub-type must be RESPONSE (01)");
        assert_eq!(u64::from_str_radix(&bits[6..38], 2).unwrap(), 0xDEAD_BEEF);
        assert_eq!(&bits[38..39], "0", "mutual flag");

        let mut inb = BitBuffer::from_bitstr(&bits);
        let parsed = UAuthentication::from_bitbuf(&mut inb).unwrap();
        assert_eq!(parsed.res1, Some(0xDEAD_BEEF));
        assert_eq!(parsed.mutual_authentication_flag, Some(false));
        assert_eq!(parsed.rand2, None, "RAND2 must be absent when mutual flag = 0");
    }

    #[test]
    fn response_with_mutual_flag_carries_rand2() {
        let pdu = UAuthentication {
            sub_type: AuthenticationSubtype::Response,
            rand2: Some(RAND2),
            reject_reason: None,
            res1: Some(0x1111_2222),
            result: None,
            mutual_authentication_flag: Some(true),
            proprietary: None,
        };
        let mut out = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut out).unwrap();
        assert_eq!(out.to_bitstr().len(), 4 + 2 + 32 + 1 + 80 + 1);

        let mut inb = BitBuffer::from_bitstr(&out.to_bitstr());
        let parsed = UAuthentication::from_bitbuf(&mut inb).unwrap();
        assert_eq!(parsed.res1, Some(0x1111_2222));
        assert_eq!(parsed.rand2, Some(RAND2), "RAND2 must be present when mutual flag = 1");
    }

    /// Table A.5
    #[test]
    fn demand_layout_matches_table_a5() {
        let pdu = UAuthentication {
            sub_type: AuthenticationSubtype::Demand,
            rand2: Some(RAND2),
            reject_reason: None,
            res1: None,
            result: None,
            mutual_authentication_flag: None,
            proprietary: None,
        };
        let mut out = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut out).unwrap();
        let bits = out.to_bitstr();
        assert_eq!(bits.len(), 4 + 2 + 80 + 1);
        assert_eq!(&bits[4..6], "00", "sub-type must be DEMAND (00)");

        let mut inb = BitBuffer::from_bitstr(&bits);
        let parsed = UAuthentication::from_bitbuf(&mut inb).unwrap();
        assert_eq!(parsed.rand2, Some(RAND2));
    }

    /// Table A.8
    #[test]
    fn result_layout_matches_table_a8() {
        let pdu = UAuthentication {
            sub_type: AuthenticationSubtype::Result,
            rand2: None,
            reject_reason: None,
            res1: None,
            result: Some(true),
            mutual_authentication_flag: Some(false),
            proprietary: None,
        };
        let mut out = BitBuffer::new_autoexpand(8);
        pdu.to_bitbuf(&mut out).unwrap();
        let bits = out.to_bitstr();
        assert_eq!(bits.len(), 4 + 2 + 1 + 1 + 1);
        assert_eq!(&bits[4..6], "10", "sub-type must be RESULT (10)");

        let mut inb = BitBuffer::from_bitstr(&bits);
        let parsed = UAuthentication::from_bitbuf(&mut inb).unwrap();
        assert_eq!(parsed.result, Some(true));
    }

    /// Table A.6
    #[test]
    fn reject_layout_matches_table_a6() {
        let pdu = UAuthentication {
            sub_type: AuthenticationSubtype::Reject,
            rand2: None,
            reject_reason: Some(0b000),
            res1: None,
            result: None,
            mutual_authentication_flag: None,
            proprietary: None,
        };
        let mut out = BitBuffer::new_autoexpand(8);
        pdu.to_bitbuf(&mut out).unwrap();
        let bits = out.to_bitstr();
        assert_eq!(bits.len(), 4 + 2 + 3 + 1);
        assert_eq!(&bits[4..6], "11", "sub-type must be REJECT (11)");

        let mut inb = BitBuffer::from_bitstr(&bits);
        let parsed = UAuthentication::from_bitbuf(&mut inb).unwrap();
        assert_eq!(parsed.reject_reason, Some(0));
    }
}
