//! WTP PDU codec (WAP-224-WTP, clause 9): the Invoke in the three transaction classes, the
//! Segmented Invoke, Ack (with the Packet Sequence Number TPI), Nack and Abort that a responder
//! receives, and the Result, Segmented Result, Ack, Nack and Abort that it sends.
//!
//! The WTP fixed header starts with CON(1) PDU-type(4) and then, for Invoke / Result and their
//! segmented forms, GTR(1) TTR(1) RID(1). The initiator sends TIDs with the top bit clear; the
//! responder answers with the same TID and the top bit set.

use crate::sndcp::wap_ip::{
    WTP_CON_FLAG, WTP_PDU_ABORT, WTP_PDU_ACK, WTP_PDU_INVOKE, WTP_PDU_RESULT, WTP_RID_FLAG, WTP_TID_RESPONSE_FLAG, WTP_TID_VALUE_MASK,
    parse_wtp_variable_header_end,
};

pub const PDU_SEGMENTED_INVOKE: u8 = 5;
pub const PDU_SEGMENTED_RESULT: u8 = 6;
pub const PDU_NACK: u8 = 7;

/// Last packet of a packet group.
pub const GTR: u8 = 0x04;
/// Last packet of the message.
pub const TTR: u8 = 0x02;
/// TID verification (Tve / Tok) flag of an Ack.
const TVE_TOK: u8 = 0x04;
/// TPI identity of the Packet Sequence Number TPI.
const TPI_PSN: u8 = 0x03;

pub const ABORT_PROVIDER: u8 = 0;
pub const ABORT_USER: u8 = 1;
pub const ABORT_REASON_PROTOERR: u8 = 1;
pub const ABORT_REASON_NOTIMPLEMENTEDSAR: u8 = 4;
pub const ABORT_REASON_WTPVERSIONONE: u8 = 6;
pub const ABORT_REASON_NORESPONSE: u8 = 8;
pub const ABORT_REASON_MESSAGETOOLARGE: u8 = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invoke<'a> {
    pub tid: u16,
    pub rid: bool,
    pub gtr: bool,
    pub ttr: bool,
    /// The initiator restarted its TID sequence: forget its cached TIDs.
    pub tid_new: bool,
    /// U/P: the initiator wants the acknowledgement from the WTP user, not the provider.
    pub user_ack: bool,
    pub class: u8,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WtpPdu<'a> {
    Invoke(Invoke<'a>),
    SegmentedInvoke {
        tid: u16,
        rid: bool,
        gtr: bool,
        ttr: bool,
        psn: u8,
        data: &'a [u8],
    },
    Ack {
        tid: u16,
        rid: bool,
        tve_tok: bool,
        psn: Option<u8>,
    },
    Nack {
        tid: u16,
        rid: bool,
        missing: Vec<u8>,
    },
    Abort {
        tid: u16,
        abort_type: u8,
        reason: u8,
    },
    /// A PDU a responder never receives (Result, Segmented Result).
    Unexpected {
        pdu_type: u8,
        tid: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WtpError {
    TooShort,
    /// PDU type 0 outside a concatenation, or a malformed concatenation.
    BadType,
    /// Invoke with reserved bits set or class 3.
    BadInvokeHeader,
    /// Invoke of a WTP version other than 0 (answered with Abort WTPVERSIONONE).
    UnsupportedVersion {
        tid: u16,
    },
    BadTpi,
}

/// Split a datagram into its WTP PDUs. A first octet of 0 marks a concatenation (clause 9.4):
/// each PDU is then preceded by a 1-octet length (top bit clear) or a 2-octet length (top bit set).
pub fn parse_datagram(datagram: &[u8]) -> Result<Vec<WtpPdu<'_>>, WtpError> {
    let Some(&first) = datagram.first() else {
        return Err(WtpError::TooShort);
    };
    if first != 0 {
        return Ok(vec![parse_pdu(datagram)?]);
    }
    let mut pdus = Vec::new();
    let mut rest = &datagram[1..];
    while !rest.is_empty() {
        let (len, hdr) = if rest[0] & 0x80 == 0 {
            (rest[0] as usize, 1)
        } else {
            let lo = *rest.get(1).ok_or(WtpError::BadType)?;
            ((((rest[0] & 0x7f) as usize) << 8) | lo as usize, 2)
        };
        let pdu = rest.get(hdr..hdr + len).ok_or(WtpError::BadType)?;
        pdus.push(parse_pdu(pdu)?);
        rest = &rest[hdr + len..];
    }
    Ok(pdus)
}

pub fn parse_pdu(pdu: &[u8]) -> Result<WtpPdu<'_>, WtpError> {
    if pdu.len() < 3 {
        return Err(WtpError::TooShort);
    }
    let b0 = pdu[0];
    let pdu_type = (b0 >> 3) & 0x0f;
    let tid = u16::from_be_bytes([pdu[1], pdu[2]]) & WTP_TID_VALUE_MASK;
    let rid = b0 & WTP_RID_FLAG != 0;
    let con = b0 & WTP_CON_FLAG != 0;
    match pdu_type {
        WTP_PDU_INVOKE => {
            let b3 = *pdu.get(3).ok_or(WtpError::TooShort)?;
            let class = b3 & 0x03;
            if b3 & 0x0c != 0 || class == 3 {
                return Err(WtpError::BadInvokeHeader);
            }
            if b3 >> 6 != 0 {
                return Err(WtpError::UnsupportedVersion { tid });
            }
            let data_start = if con {
                parse_wtp_variable_header_end(pdu, 4).map_err(|_| WtpError::BadTpi)?
            } else {
                4
            };
            Ok(WtpPdu::Invoke(Invoke {
                tid,
                rid,
                gtr: b0 & GTR != 0,
                ttr: b0 & TTR != 0,
                tid_new: b3 & 0x20 != 0,
                user_ack: b3 & 0x10 != 0,
                class,
                data: &pdu[data_start..],
            }))
        }
        PDU_SEGMENTED_INVOKE => {
            let psn = *pdu.get(3).ok_or(WtpError::TooShort)?;
            let data_start = if con {
                parse_wtp_variable_header_end(pdu, 4).map_err(|_| WtpError::BadTpi)?
            } else {
                4
            };
            Ok(WtpPdu::SegmentedInvoke {
                tid,
                rid,
                gtr: b0 & GTR != 0,
                ttr: b0 & TTR != 0,
                psn,
                data: &pdu[data_start..],
            })
        }
        WTP_PDU_ACK => {
            let psn = if con { tpi_psn(pdu, 3)? } else { None };
            Ok(WtpPdu::Ack {
                tid,
                rid,
                tve_tok: b0 & TVE_TOK != 0,
                psn,
            })
        }
        PDU_NACK => {
            let count = *pdu.get(3).ok_or(WtpError::TooShort)? as usize;
            let missing = pdu.get(4..4 + count).ok_or(WtpError::TooShort)?.to_vec();
            Ok(WtpPdu::Nack { tid, rid, missing })
        }
        WTP_PDU_ABORT => Ok(WtpPdu::Abort {
            tid,
            abort_type: b0 & 0x07,
            reason: *pdu.get(3).ok_or(WtpError::TooShort)?,
        }),
        WTP_PDU_RESULT | PDU_SEGMENTED_RESULT => Ok(WtpPdu::Unexpected { pdu_type, tid }),
        _ => Err(WtpError::BadType),
    }
}

/// Walk the TPIs from `offset` and return the Packet Sequence Number TPI's value, if any.
fn tpi_psn(pdu: &[u8], mut offset: usize) -> Result<Option<u8>, WtpError> {
    let mut psn = None;
    loop {
        let hdr = *pdu.get(offset).ok_or(WtpError::BadTpi)?;
        let (len, value_start) = if hdr & 0x04 != 0 {
            (*pdu.get(offset + 1).ok_or(WtpError::BadTpi)? as usize, offset + 2)
        } else {
            ((hdr & 0x03) as usize, offset + 1)
        };
        let value = pdu.get(value_start..value_start + len).ok_or(WtpError::BadTpi)?;
        if (hdr >> 3) & 0x0f == TPI_PSN && len == 1 {
            psn = Some(value[0]);
        }
        offset = value_start + len;
        if hdr & WTP_CON_FLAG == 0 {
            return Ok(psn);
        }
    }
}

fn response_tid(tid: u16) -> [u8; 2] {
    ((tid & WTP_TID_VALUE_MASK) | WTP_TID_RESPONSE_FLAG).to_be_bytes()
}

/// One packet of a Result: PSN 0 is the Result PDU, the others are Segmented Results.
/// `flags` is GTR, TTR or 0.
pub fn result_packet(tid: u16, psn: u8, flags: u8, rid: bool, data: &[u8]) -> Vec<u8> {
    let rid = if rid { WTP_RID_FLAG } else { 0 };
    let mut out = Vec::with_capacity(4 + data.len());
    if psn == 0 {
        out.push((WTP_PDU_RESULT << 3) | flags | rid);
        out.extend_from_slice(&response_tid(tid));
    } else {
        out.push((PDU_SEGMENTED_RESULT << 3) | flags | rid);
        out.extend_from_slice(&response_tid(tid));
        out.push(psn);
    }
    out.extend_from_slice(data);
    out
}

/// Responder Ack: a hold-on Ack (no PSN) or the acknowledgement of a segmented Invoke's group.
pub fn ack(tid: u16, psn: Option<u8>, rid: bool) -> Vec<u8> {
    let rid = if rid { WTP_RID_FLAG } else { 0 };
    let tid = response_tid(tid);
    match psn {
        None => vec![(WTP_PDU_ACK << 3) | rid, tid[0], tid[1]],
        Some(psn) => vec![WTP_CON_FLAG | (WTP_PDU_ACK << 3) | rid, tid[0], tid[1], (TPI_PSN << 3) | 1, psn],
    }
}

pub fn nack(tid: u16, missing: &[u8]) -> Vec<u8> {
    let tid = response_tid(tid);
    let missing = &missing[..missing.len().min(255)];
    let mut out = vec![PDU_NACK << 3, tid[0], tid[1], missing.len() as u8];
    out.extend_from_slice(missing);
    out
}

pub fn abort(tid: u16, abort_type: u8, reason: u8) -> Vec<u8> {
    let tid = response_tid(tid);
    vec![(WTP_PDU_ABORT << 3) | (abort_type & 0x07), tid[0], tid[1], reason]
}

/// Initiator-side builders, for the simulated terminal in the tests.
#[cfg(test)]
pub(crate) mod initiator {
    use super::*;

    pub fn invoke(tid: u16, class: u8, flags: u8, rid: bool, tid_new: bool, data: &[u8]) -> Vec<u8> {
        let rid = if rid { WTP_RID_FLAG } else { 0 };
        let b3 = 0x10 | if tid_new { 0x20 } else { 0 } | (class & 0x03);
        let mut out = vec![(WTP_PDU_INVOKE << 3) | flags | rid];
        out.extend_from_slice(&(tid & WTP_TID_VALUE_MASK).to_be_bytes());
        out.push(b3);
        out.extend_from_slice(data);
        out
    }

    pub fn segmented_invoke(tid: u16, psn: u8, flags: u8, rid: bool, data: &[u8]) -> Vec<u8> {
        let rid = if rid { WTP_RID_FLAG } else { 0 };
        let mut out = vec![(PDU_SEGMENTED_INVOKE << 3) | flags | rid];
        out.extend_from_slice(&(tid & WTP_TID_VALUE_MASK).to_be_bytes());
        out.push(psn);
        out.extend_from_slice(data);
        out
    }

    pub fn ack(tid: u16, psn: Option<u8>) -> Vec<u8> {
        let tid = (tid & WTP_TID_VALUE_MASK).to_be_bytes();
        match psn {
            None => vec![WTP_PDU_ACK << 3, tid[0], tid[1]],
            Some(psn) => vec![WTP_CON_FLAG | (WTP_PDU_ACK << 3), tid[0], tid[1], (TPI_PSN << 3) | 1, psn],
        }
    }

    pub fn nack(tid: u16, missing: &[u8]) -> Vec<u8> {
        let tid = (tid & WTP_TID_VALUE_MASK).to_be_bytes();
        let mut out = vec![PDU_NACK << 3, tid[0], tid[1], missing.len() as u8];
        out.extend_from_slice(missing);
        out
    }

    pub fn abort(tid: u16, abort_type: u8, reason: u8) -> Vec<u8> {
        let tid = (tid & WTP_TID_VALUE_MASK).to_be_bytes();
        vec![(WTP_PDU_ABORT << 3) | abort_type, tid[0], tid[1], reason]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mxp600_invoke_header_is_class2_with_user_ack() {
        // Header of the MXP600's captured WSP Connect (Docs/wap-port-spec.md 7.4): RID=1,
        // TID 0x13cc, octet 4 = 0x12 (version 0, U/P=1, class 2).
        let pdu = [0x0b, 0x13, 0xcc, 0x12, 0x01, 0x10, 0x00, 0x00];
        let WtpPdu::Invoke(inv) = parse_pdu(&pdu).unwrap() else {
            panic!("not an invoke")
        };
        assert_eq!(inv.tid, 0x13cc);
        assert!(inv.rid && inv.ttr && !inv.gtr && !inv.tid_new && inv.user_ack);
        assert_eq!(inv.class, 2);
        assert_eq!(inv.data, &[0x01, 0x10, 0x00, 0x00]);
    }

    #[test]
    fn class0_and_tidnew_are_parsed() {
        let pdu = initiator::invoke(7, 0, TTR, false, true, &[0x05, 0x01]);
        let WtpPdu::Invoke(inv) = parse_pdu(&pdu).unwrap() else {
            panic!("not an invoke")
        };
        assert_eq!((inv.class, inv.tid_new), (0, true));
        assert_eq!(parse_pdu(&[0x0a, 0, 1, 0x13]), Err(WtpError::BadInvokeHeader), "class 3 is invalid");
        assert_eq!(
            parse_pdu(&[0x0a, 0, 1, 0x52]),
            Err(WtpError::UnsupportedVersion { tid: 1 }),
            "version 1 is not WTP 1.x"
        );
        assert_eq!(parse_pdu(&[0x0a, 0, 1, 0x56]), Err(WtpError::BadInvokeHeader), "reserved bits too");
    }

    #[test]
    fn spec_ack_and_abort_vectors() {
        assert_eq!(
            parse_pdu(&[0x18, 0x13, 0xcc]).unwrap(),
            WtpPdu::Ack {
                tid: 0x13cc,
                rid: false,
                tve_tok: false,
                psn: None
            }
        );
        assert_eq!(
            parse_pdu(&[0x20, 0x13, 0xcc, 0x01]).unwrap(),
            WtpPdu::Abort {
                tid: 0x13cc,
                abort_type: 0,
                reason: 1
            }
        );
    }

    #[test]
    fn ack_psn_tpi_round_trip() {
        let WtpPdu::Ack { psn, .. } = parse_pdu(&initiator::ack(0x1234, Some(5))).unwrap() else {
            panic!()
        };
        assert_eq!(psn, Some(5));
        // A long-form TPI before the PSN TPI is skipped.
        let pdu = [0x98, 0x12, 0x34, 0x84, 0x02, 0xaa, 0xbb, 0x19, 0x07];
        let WtpPdu::Ack { psn, .. } = parse_pdu(&pdu).unwrap() else {
            panic!()
        };
        assert_eq!(psn, Some(7));
        assert_eq!(parse_pdu(&[0x98, 0x12, 0x34, 0x19]), Err(WtpError::BadTpi));
    }

    #[test]
    fn responder_pdus_set_the_tid_response_bit() {
        assert_eq!(result_packet(0x13cc, 0, TTR, false, &[0x04]), vec![0x12, 0x93, 0xcc, 0x04]);
        assert_eq!(result_packet(0x0001, 3, GTR, true, &[0xaa]), vec![0x35, 0x80, 0x01, 0x03, 0xaa]);
        assert_eq!(ack(0x13cc, None, false), vec![0x18, 0x93, 0xcc]);
        assert_eq!(ack(0x13cc, Some(2), false), vec![0x98, 0x93, 0xcc, 0x19, 0x02]);
        assert_eq!(nack(0x0001, &[1, 2]), vec![0x38, 0x80, 0x01, 0x02, 0x01, 0x02]);
        assert_eq!(abort(0x13cc, ABORT_PROVIDER, ABORT_REASON_NORESPONSE), vec![0x20, 0x93, 0xcc, 0x08]);
    }

    #[test]
    fn concatenated_datagram_splits() {
        let ack = initiator::ack(1, Some(2));
        let inv = initiator::invoke(2, 2, TTR, false, false, &[0x40, 0x01, b'/']);
        let mut dgram = vec![0x00, ack.len() as u8];
        dgram.extend_from_slice(&ack);
        dgram.push(inv.len() as u8);
        dgram.extend_from_slice(&inv);
        let pdus = parse_datagram(&dgram).unwrap();
        assert_eq!(pdus.len(), 2);
        assert!(matches!(pdus[0], WtpPdu::Ack { tid: 1, psn: Some(2), .. }));
        assert!(matches!(pdus[1], WtpPdu::Invoke(Invoke { tid: 2, .. })));
        assert_eq!(parse_datagram(&[0x00, 0x05, 0x18]), Err(WtpError::BadType));
    }
}
