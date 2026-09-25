#[derive(Debug, PartialEq, Eq)]
pub struct Type4FieldGeneric {
    pub field_id: u64,
    pub len: usize,
    pub elems: usize,
    /// Up to 64 bits of data (later bits are discarded)
    pub data: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Type3FieldGeneric {
    pub field_id: u64,
    pub len: usize,
    /// Up to 128 bits of data (later bits are discarded).
    /// Sized to fit External Subscriber Number (up to 96 bits = 24 BCD digits)
    /// and any future long IEs without further refactor.
    pub data: u128,
}

/// Helper functions for dealing with type2, type3 and type4 fields for MLE, CMCE, MM and SNDCP PDUs.
pub mod delimiters {
    use crate::{bitbuffer::BitBuffer, pdu_parse_error::PduParseErr};

    /// Read the o-bit between type1 and type2/type3 elements
    pub fn read_obit(buffer: &mut BitBuffer) -> Result<bool, PduParseErr> {
        Ok(buffer.read_field(1, "obit")? == 1)
    }

    /// Write the o-bit between type1 and type2/type3 elements
    pub fn write_obit(buffer: &mut BitBuffer, val: u8) {
        buffer.write_bit(val);
    }

    /// Read a p-bit preceding a type2 element
    pub fn read_pbit(buffer: &mut BitBuffer) -> Result<bool, PduParseErr> {
        Ok(buffer.read_field(1, "pbit")? == 1)
    }

    /// Write the p-bit preceding a type2 element
    pub fn write_pbit(buffer: &mut BitBuffer, val: u8) {
        buffer.write_bit(val);
    }

    /// Read an m-bit found before a type3 or type4 element, and trailing the message
    pub fn read_mbit(buffer: &mut BitBuffer) -> Result<bool, PduParseErr> {
        Ok(buffer.read_field(1, "mbit")? == 1)
    }

    /// Write the m-bit before a type3 or type4 element, and trailing the message
    pub fn write_mbit(buffer: &mut BitBuffer, val: u8) {
        buffer.write_bit(val);
    }
}

pub mod typed {
    use crate::{
        bitbuffer::BitBuffer,
        pdu_parse_error::PduParseErr,
        typed_pdu_fields::{Type3FieldGeneric, Type4FieldGeneric, delimiters},
    };

    pub fn parse_type2_generic(
        obit: bool,
        buffer: &mut BitBuffer,
        num_bits: usize,
        field_name: &'static str,
    ) -> Result<Option<u64>, PduParseErr> {
        if !obit {
            return Ok(None);
        }
        match delimiters::read_pbit(buffer) {
            Ok(true) => {
                // Field present
                tracing::trace!("parse_type2_generic field_present {:20}: {}", field_name, buffer.dump_bin());
                match buffer.read_field(num_bits, field_name) {
                    Ok(v) => Ok(Some(v)),
                    Err(e) => Err(e),
                }
            }
            Ok(false) => {
                // Field not present
                tracing::trace!("parse_type2_generic no_field      {:20}: {}", field_name, buffer.dump_bin());
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Parse a Type-2 element into a struct that implements `from_bitbuf`.
    pub fn parse_type2_struct<T, F>(obit: bool, buffer: &mut BitBuffer, parser: F) -> Result<Option<T>, PduParseErr>
    where
        F: FnOnce(&mut BitBuffer) -> Result<T, PduParseErr>,
    {
        if !obit {
            return Ok(None);
        }

        match delimiters::read_pbit(buffer) {
            Ok(true) => {
                // Field present
                tracing::trace!("parse_type2_struct field_present: {}", buffer.dump_bin());
                let value = parser(buffer)?;
                Ok(Some(value))
            }
            Ok(false) => {
                // Field not present
                tracing::trace!("parse_type2_struct no_field      : {}", buffer.dump_bin());
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Write one Type-2 element.
    /// If `value` is `Some(v)`, writes P-bit=1 then `len` bits of `v`. If `None`, writes P-bit=0.
    pub fn write_type2_generic(obit: bool, buffer: &mut BitBuffer, value: Option<u64>, len: usize) {
        // No optional elements
        if !obit {
            assert!(value.is_none(), "Type2 element cannot be present when obit is false");
            return;
        }

        match value {
            Some(v) => {
                tracing::trace!("write_type2_generic field_present {}", buffer.dump_bin());
                delimiters::write_pbit(buffer, 1);
                buffer.write_bits(v, len);
            }
            None => {
                tracing::trace!("write_type2_generic no_field {}", buffer.dump_bin());
                delimiters::write_pbit(buffer, 0);
            }
        }
    }

    /// Write a Type-2 element from a struct that implements `to_bitbuf`.
    pub fn write_type2_struct<T, F>(obit: bool, buffer: &mut BitBuffer, value: &Option<T>, writer: F) -> Result<(), PduParseErr>
    where
        F: Fn(&T, &mut BitBuffer) -> Result<(), PduParseErr>,
    {
        // No optional elements
        if !obit {
            assert!(value.is_none(), "Type2 element cannot be present when obit is false");
            return Ok(());
        }
        match value {
            Some(v) => {
                tracing::trace!("write_type2_struct field_present {}", buffer.dump_bin());
                delimiters::write_pbit(buffer, 1);
                writer(v, buffer)?;
                Ok(())
            }
            None => {
                tracing::trace!("write_type2_struct no_field {}", buffer.dump_bin());
                delimiters::write_pbit(buffer, 0);
                Ok(())
            }
        }
    }

    /// Read the m-bit for a type3 or type4 element without advancing the buffer pos
    /// If set, reads the type3/4 field identifier and compares to expected id.
    /// Return true if present, false if not present, or PduParseErr on error
    fn peek_type34_mbit_and_id(buffer: &BitBuffer, expected_id: u64) -> Result<bool, PduParseErr> {
        let mbit = buffer.peek_bits(1);
        match mbit {
            Some(0) => {
                // Field not present
                Ok(false)
            }
            Some(1) => {
                // Some field is present, read and compare id
                let id_bits = buffer.peek_bits_posoffset(1, 4);
                match id_bits {
                    Some(id) if id == expected_id => {
                        // The expected is here; the field exists
                        Ok(true)
                    }
                    Some(_) => {
                        // Some different field is here
                        Ok(false)
                    }
                    None => {
                        // Read failed
                        Err(PduParseErr::BufferEnded {
                            field: Some("peek_type34_mbit_and_id id_bits"),
                        })
                    }
                }
            }
            None => Err(PduParseErr::BufferEnded {
                field: Some("peek_type34_mbit_and_id mbit"),
            }),
            _ => panic!(), // Never happens
        }
    }

    /// Consume the trailing M-bit of a PDU's optional part, skipping every type 3/4 element that
    /// follows it and that the parser did not decode (a repeated Facility, an element newer than
    /// this parser, one it does not list). TS 100 392-2 Annex E.1.1 NOTE 6: the decoder can pass
    /// unknown type 3/4 elements because their length is in the PDU. Failing the whole PDU on them
    /// dropped a valid U-SETUP, U-TX DEMAND or U-DISCONNECT without any answer.
    pub fn skip_remaining_type34(obit: bool, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        if !obit {
            return Ok(());
        }
        while buffer.read_field(1, "trailing_mbit")? == 1 {
            let id = buffer.read_field(4, "type34_element_id")?;
            let len_bits = buffer.read_field(11, "type34_length_indicator")? as usize;
            if len_bits > buffer.get_len_remaining() {
                return Err(PduParseErr::BufferEnded {
                    field: Some("skip_remaining_type34 data"),
                });
            }
            tracing::debug!(
                "skipping type 3/4 element id {} ({} bits) this parser does not decode",
                id,
                len_bits
            );
            buffer.seek_rel(len_bits as isize);
        }
        Ok(())
    }

    /// Parse type3 field into a placeholder struct, pending implementation.
    /// Checks whether a given type3 field identifier is present. If not, returns None without advancing
    /// the bitbuffer position. If present, reads the element and returns it as a u64, advancing the buffer position.
    /// to the end of the element.
    pub fn parse_type3_generic<E>(obit: bool, buffer: &mut BitBuffer, expected_id: E) -> Result<Option<Type3FieldGeneric>, PduParseErr>
    where
        E: Into<u64>,
    {
        // If the obit is set to false, the element cannot be present
        if !obit {
            return Ok(None);
        }

        // Obit is present, check if mbit present, and check if the elementid is the expected one
        let id = expected_id.into();
        let field_present = peek_type34_mbit_and_id(buffer, id)?;
        if !field_present {
            return Ok(None);
        }

        // Target field is present. Advance buffer position and read field contents
        buffer.seek_rel(5);
        let len_bits = match buffer.read_bits(11) {
            Some(x) => x as usize,
            None => {
                return Err(PduParseErr::BufferEnded {
                    field: Some("parse_type3_generic len_bits"),
                });
            }
        };

        // The length indicator is attacker-controlled: if it claims more bits than the SDU
        // actually holds, bail out here. Otherwise the skip-forward below would seek past the
        // window end and panic the entity.
        if len_bits > buffer.get_len_remaining() {
            return Err(PduParseErr::BufferEnded {
                field: Some("parse_type3_generic data"),
            });
        }

        // Read up to 128 bits of payload. BitBuffer::read_bits is u64-only, so for
        // lengths over 64 we split into two reads (high half first, then low half).
        let read_bits = if len_bits > 128 { 128 } else { len_bits };
        let data: u128 = if read_bits <= 64 {
            let v = match buffer.read_bits(read_bits) {
                Some(x) => x,
                None => {
                    return Err(PduParseErr::BufferEnded {
                        field: Some("parse_type3_generic data"),
                    });
                }
            };
            v as u128
        } else {
            let hi_bits = read_bits - 64;
            let hi = match buffer.read_bits(hi_bits) {
                Some(x) => x,
                None => {
                    return Err(PduParseErr::BufferEnded {
                        field: Some("parse_type3_generic data (high)"),
                    });
                }
            };
            let lo = match buffer.read_bits(64) {
                Some(x) => x,
                None => {
                    return Err(PduParseErr::BufferEnded {
                        field: Some("parse_type3_generic data (low)"),
                    });
                }
            };
            ((hi as u128) << 64) | (lo as u128)
        };

        // Seek forward past any bits beyond what we stored (>128 bits).
        if len_bits > 128 {
            tracing::warn!("Type3 element {} length {} exceeds 128 bits, data truncated", id, len_bits);
            if buffer.try_seek_rel(len_bits as isize - 128).is_none() {
                return Err(PduParseErr::BufferEnded {
                    field: Some("parse_type3_generic skip"),
                });
            }
        }

        Ok(Some(Type3FieldGeneric {
            field_id: id,
            len: len_bits,
            data,
        }))
    }

    /// Parse a Type-3 element into a struct that implements `from_bitbuf`.
    /// Validates the m-bit and element ID, then calls the parser function directly on the buffer if present.
    pub fn parse_type3_struct<E, T, F>(obit: bool, buffer: &mut BitBuffer, expected_id: E, parser: F) -> Result<Option<T>, PduParseErr>
    where
        E: Into<u64>,
        F: FnOnce(&mut BitBuffer) -> Result<T, PduParseErr>,
    {
        // If the obit is set to false, the element cannot be present
        if !obit {
            return Ok(None);
        }

        // Obit is present, peek if mbit present, and peek if the elementid is the expected one
        let id = expected_id.into();
        let field_present = peek_type34_mbit_and_id(buffer, id)?;
        if !field_present {
            tracing::trace!("parse_type3_struct no_field {}: {}", id, buffer.dump_bin());
            return Ok(None);
        }
        // Target field is present. Advance buffer past m-bit (1) + id (4) + length (11)
        buffer.seek_rel(5); // m-bit + id

        tracing::trace!("parse_type3_struct got header for {:2}: {}", id, buffer.dump_bin());

        let len_bits = match buffer.read_bits(11) {
            Some(x) => x as usize,
            None => {
                return Err(PduParseErr::BufferEnded {
                    field: Some("parse_type3_struct len_bits"),
                });
            }
        };

        tracing::trace!("parse_type3_struct got len {:4}:      {}", len_bits, buffer.dump_bin());

        // Store current position to check parsed length for discrepancies. Then, read length
        let start_pos = buffer.get_pos();

        // Now buffer is positioned at the data. Parse the struct directly. The parser is responsible for reading exactly len_bits
        let result = parser(buffer)?;

        tracing::trace!("parse_type3_struct done parsing:      {}", buffer.dump_bin());

        // If read out length does not match expectation, something went very wrong
        if start_pos + len_bits != buffer.get_pos() {
            tracing::warn!(
                "Type3 element {} parsed length mismatch: expected {}, parsed {}",
                id,
                len_bits,
                buffer.get_pos() - start_pos
            );
            return Err(PduParseErr::InconsistentLength {
                expected: len_bits,
                found: (buffer.get_pos() - start_pos),
            });
        };

        // Parsed and expected length matches, return result
        Ok(Some(result))
    }

    /// Write the type4 header start (1-bit mbit + 4-bit field type)
    pub fn write_type34_header_generic(buffer: &mut BitBuffer, field_type: u64) {
        delimiters::write_mbit(buffer, 1);
        buffer.write_bits(field_type, 4);
    }

    /// Write an optional Type-3 element using a `to_bitbuf` function.
    pub fn write_type3_struct<E, T, F>(
        obit: bool,
        buffer: &mut BitBuffer,
        value: &Option<T>,
        field_id: E,
        writer: F,
    ) -> Result<(), PduParseErr>
    where
        E: Into<u64>,
        F: Fn(&T, &mut BitBuffer) -> Result<(), PduParseErr>,
    {
        // Sanity check
        let id = field_id.into();
        if !obit && value.is_some() {
            return Err(PduParseErr::InvalidValue {
                field: "write_type3_struct",
                value: id,
            });
        }

        if let Some(elem) = value {
            tracing::trace!("write_type3_struct writing field {:2} {}", id, buffer.dump_bin());

            // Write mbit and 4-bit field ID, then length field, then write the element itself
            write_type34_header_generic(buffer, id);
            let pos_len_field = buffer.get_raw_pos();
            buffer.write_bits(0, 11); // Write instead of seek to autoexpand

            tracing::trace!("write_type3_struct header           {}", buffer.dump_bin());

            writer(elem, buffer)?;

            tracing::trace!("write_type3_struct payload          {}", buffer.dump_bin());

            // Calculate actual length and backfill
            let pos_end = buffer.get_raw_pos();
            let len_bits = (pos_end - pos_len_field - 11) as u64;
            buffer.set_raw_pos(pos_len_field);
            buffer.write_bits(len_bits, 11);

            tracing::trace!("write_type3_struct len {:2}:          {}", len_bits, buffer.dump_bin());
            buffer.set_raw_pos(pos_end);
        } else {
            // Don't write anything (no mbit)
            tracing::trace!("write_type3_struct no_field          {}", buffer.dump_bin());
        }
        Ok(())
    }

    /// Write an optional Type-3 element using a `to_bitbuf` function.
    pub fn write_type3_generic<E>(
        obit: bool,
        buffer: &mut BitBuffer,
        value: &Option<Type3FieldGeneric>,
        field_id: E,
    ) -> Result<(), PduParseErr>
    where
        E: Into<u64>,
    {
        // Sanity check
        let id = field_id.into();
        if !obit && value.is_some() {
            return Err(PduParseErr::InvalidValue {
                field: "write_type3_generic",
                value: id,
            });
        }

        if let Some(elem) = value {
            tracing::trace!("write_type3_generic field_present {}", buffer.dump_bin());
            // Write mbit and 4-bit field ID, then write length, then the element itself
            write_type34_header_generic(buffer, id);
            buffer.write_bits(elem.len as u64, 11);
            // BitBuffer::write_bits accepts u64. For payloads up to 64 bits we cast
            // directly; for longer payloads we split into high-half + low-half writes.
            if elem.len <= 64 {
                buffer.write_bits(elem.data as u64, elem.len);
            } else {
                let hi_bits = elem.len - 64;
                let hi = (elem.data >> 64) as u64;
                let lo = elem.data as u64;
                buffer.write_bits(hi, hi_bits);
                buffer.write_bits(lo, 64);
            }
        } else {
            // Don't write anything (no mbit)
            tracing::trace!("write_type3_generic no_field {}", buffer.dump_bin());
        }
        Ok(())
    }

    fn parse_type4_header(buffer: &mut BitBuffer, expected_id: u64) -> Result<Option<(usize, usize)>, PduParseErr> {
        // Check whether the element is present
        let id = expected_id;
        let field_present = peek_type34_mbit_and_id(buffer, id)?;
        if !field_present {
            return Ok(None);
        }

        // Target field is present. Advance buffer position and read field contents
        buffer.seek_rel(5);
        let len_bits = match buffer.read_bits(11) {
            Some(x) => x as usize,
            None => {
                return Err(PduParseErr::BufferEnded {
                    field: Some("parse_type4_header len_bits"),
                });
            }
        };
        // tracing::debug!("MmType4FieldUl: len_bits: {}", len_bits);
        let num_elems = match buffer.read_bits(6) {
            Some(x) => x as usize,
            None => {
                return Err(PduParseErr::BufferEnded {
                    field: Some("parse_type4_header num_elems"),
                });
            }
        };

        tracing::trace!(
            "parse_type4_header got header for {:2}, len {}, count {}: {}",
            id,
            len_bits,
            num_elems,
            buffer.dump_bin()
        );

        // The wire length covers the 6-bit element counter plus the payload. Anything below 6 is
        // malformed and would underflow the subtraction (panic on overflow-checked builds, huge
        // value otherwise, feeding the seek in parse_type4_generic).
        let payload_bits = len_bits.checked_sub(6).ok_or(PduParseErr::InconsistentLength {
            expected: 6,
            found: len_bits,
        })?;

        // Attacker-controlled length: reject anything longer than the SDU actually holds, so
        // callers can never seek or read past the window end.
        if payload_bits > buffer.get_len_remaining() {
            return Err(PduParseErr::BufferEnded {
                field: Some("parse_type4_header payload"),
            });
        }

        Ok(Some((num_elems, payload_bits)))
    }

    /// Parse a Type-4 element into a Vec of structs that implement `from_bitbuf`.
    pub fn parse_type4_struct<E, T, F>(obit: bool, buffer: &mut BitBuffer, expected_id: E, parser: F) -> Result<Option<Vec<T>>, PduParseErr>
    where
        E: Into<u64>,
        F: Fn(&mut BitBuffer) -> Result<T, PduParseErr>,
    {
        // If the obit is set to false, the element cannot be present
        if !obit {
            return Ok(None);
        }

        // Obit is present, check if mbit present, and check if the elementid is the expected one
        let id = expected_id.into();
        match parse_type4_header(buffer, id)? {
            None => {
                // Field not present
                Ok(None)
            }
            Some((num_elems, len_bits)) => {
                // Field is present, and we've gout our total lenght and number of elements
                let mut elems = Vec::with_capacity(num_elems);
                let start_pos = buffer.get_pos();

                // Parse all elements into array structs
                for _ in 0..num_elems {
                    let elem = parser(buffer)?;
                    elems.push(elem);
                }

                // If read out length does not match expectation, something went very wrong
                if start_pos + len_bits != buffer.get_pos() {
                    tracing::warn!(
                        "Type4 element {} parsed length mismatch: expected {}, parsed {}",
                        id,
                        len_bits,
                        buffer.get_pos() - start_pos
                    );
                    return Err(PduParseErr::InconsistentLength {
                        expected: len_bits,
                        found: (buffer.get_pos() - start_pos),
                    });
                };

                // Parsed and expected length matches, return result
                Ok(Some(elems))
            }
        }
    }

    /// Parse a Type-4 element into a placeholder struct type, pending proper implementation.
    /// Imperfect as we cannot know individual element sizes, besides issues with overflowing the 64-bit read
    pub fn parse_type4_generic<E>(obit: bool, buffer: &mut BitBuffer, expected_id: E) -> Result<Option<Type4FieldGeneric>, PduParseErr>
    where
        E: Into<u64>,
    {
        // If the obit is set to false, the element cannot be present
        if !obit {
            return Ok(None);
        }

        // Obit is present, check if mbit present, and check if the elementid is the expected one
        let id = expected_id.into();
        match parse_type4_header(buffer, id)? {
            None => {
                // Field not present
                Ok(None)
            }
            Some((num_elems, len_bits)) => {
                // Field is present, and we've got our total lenght and number of elements
                let read_bits = if len_bits > 64 { 64 } else { len_bits };
                let val = buffer.read_field(read_bits, "parse_type4_header")?;

                // Build placeholder return struct
                let ret = Type4FieldGeneric {
                    field_id: id,
                    len: len_bits,
                    elems: num_elems,
                    data: val,
                };

                // Seek forward to end of element, if larger than 64 bits
                if len_bits > 64 {
                    tracing::warn!("Type4 element {} length {} exceeds 64 bits, data truncated", id, len_bits);
                    if buffer.try_seek_rel(len_bits as isize - 64).is_none() {
                        return Err(PduParseErr::BufferEnded {
                            field: Some("parse_type4_generic skip"),
                        });
                    }
                }

                // Parsed and expected length matches, return result
                Ok(Some(ret))
            }
        }
    }

    /// Write a Type-4 element from a Vec of structs using a `to_bitbuf` function.
    pub fn write_type4_struct<E, T, F>(
        obit: bool,
        buffer: &mut BitBuffer,
        value: &Option<Vec<T>>,
        field_id: E,
        writer: F,
    ) -> Result<(), PduParseErr>
    where
        E: Into<u64>,
        F: Fn(&T, &mut BitBuffer) -> Result<(), PduParseErr>,
    {
        // Sanity check
        let id = field_id.into();
        if !obit && value.is_some() {
            return Err(PduParseErr::InvalidValue {
                field: "write_type4_struct",
                value: id,
            });
        }

        if let Some(elems) = value {
            if elems.is_empty() {
                // todo fixme we need to check the standards docs for knowing what to do here
                tracing::warn!("write_type4_struct called with empty elems vec. Check standard to see what is proper behavior");
            }

            // Write m-bit and field ID
            write_type34_header_generic(buffer, id);

            // Reserve space for length (11 bits) + num_elems (6 bits)
            let pos_len_field = buffer.get_raw_pos();
            buffer.write_bits(0, 11 + 6); // Write instead of space to autoexpand

            // Write all elements
            for elem in elems {
                writer(elem, buffer)?;
            }

            // Calculate actual length and backfill
            let pos_end = buffer.get_raw_pos();
            let len_bits = (pos_end - pos_len_field - 11) as u64;
            let num_elems = elems.len() as u64;

            // tracing::debug!("Wrote {} elements for Type4 field {}, total len {}, buf now: {}", elems.len(), id, len_bits, buffer.dump_bin());

            buffer.set_raw_pos(pos_len_field);
            buffer.write_bits(len_bits, 11);
            buffer.write_bits(num_elems, 6);
            buffer.set_raw_pos(pos_end);
        }
        // If None, don't write anything (no m-bit)
        Ok(())
    }

    /// Write a Type-4 element from a Vec of structs using a `to_bitbuf` function.
    pub fn write_type4_todo<E>(
        obit: bool,
        _buffer: &mut BitBuffer,
        value: &Option<Type4FieldGeneric>,
        field_id: E,
    ) -> Result<(), PduParseErr>
    where
        E: Into<u64>,
    {
        // Sanity check
        let id = field_id.into();
        if !obit && value.is_some() {
            return Err(PduParseErr::InvalidValue {
                field: "write_type4_todo",
                value: id,
            });
        }

        if let Some(_elem) = value {
            unimplemented!("can't generically write a type4 field");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::typed::{parse_type3_generic, parse_type4_generic, skip_remaining_type34};
    use super::{Type3FieldGeneric, Type4FieldGeneric};
    use crate::{bitbuffer::BitBuffer, pdu_parse_error::PduParseErr};

    /// Elements a parser does not decode - here a type 3 (id 7, 5 bits) and a type 4 (id 3, one
    /// 4-bit element: LI = 6-bit count + 4) - are skipped up to the final M-bit 0.
    #[test]
    fn test_skip_remaining_type34_passes_unknown_elements() {
        let mut buf = BitBuffer::from_bitstr(&format!(
            concat!(
                "1{:04b}{:011b}10110",      // type 3
                "1{:04b}{:011b}{:06b}1001", // type 4
                "0",                        // no more elements
                "1",                        // next field
            ),
            7, 5, 3, 10, 1
        ));
        assert_eq!(skip_remaining_type34(true, &mut buf), Ok(()));
        assert_eq!(buf.get_len_remaining(), 1);
        // Without optional elements there is nothing to consume.
        let mut empty = BitBuffer::from_bitstr("1");
        assert_eq!(skip_remaining_type34(false, &mut empty), Ok(()));
        assert_eq!(empty.get_len_remaining(), 1);
        // A length running past the PDU is an error, not a panic.
        let mut short = BitBuffer::from_bitstr(&format!("1{:04b}{:011b}10", 7, 40));
        assert!(skip_remaining_type34(true, &mut short).is_err());
    }

    /// Build a Type-3 element on the wire: m-bit + 4-bit id + 11-bit length + payload
    fn type3_elem(id: u64, len_bits: usize, payload: &str) -> BitBuffer {
        BitBuffer::from_bitstr(&format!("1{:04b}{:011b}{}", id, len_bits, payload))
    }

    /// Build a Type-4 element on the wire: m-bit + 4-bit id + 11-bit length + 6-bit count + payload
    fn type4_elem(id: u64, len_bits: usize, num_elems: usize, payload: &str) -> BitBuffer {
        BitBuffer::from_bitstr(&format!("1{:04b}{:011b}{:06b}{}", id, len_bits, num_elems, payload))
    }

    #[test]
    fn test_type3_length_exceeds_buffer_errors() {
        // 128 payload bits present, wire claims 129: must error, not panic on the skip-forward
        let mut buf = type3_elem(1, 129, &"0".repeat(128));
        assert_eq!(
            parse_type3_generic(true, &mut buf, 1u64),
            Err(PduParseErr::BufferEnded {
                field: Some("parse_type3_generic data")
            })
        );
    }

    #[test]
    fn test_type3_long_length_exceeds_buffer_errors() {
        // Same, but on the >128 bit truncation path: 130 bits present, 160 claimed
        let mut buf = type3_elem(1, 160, &"1".repeat(130));
        assert_eq!(
            parse_type3_generic(true, &mut buf, 1u64),
            Err(PduParseErr::BufferEnded {
                field: Some("parse_type3_generic data")
            })
        );
    }

    #[test]
    fn test_type3_length_exactly_remaining_parses() {
        // Short element, length exactly matches what is present
        let mut buf = type3_elem(1, 8, "10101010");
        assert_eq!(
            parse_type3_generic(true, &mut buf, 1u64),
            Ok(Some(Type3FieldGeneric {
                field_id: 1,
                len: 8,
                data: 0xAA,
            }))
        );
        assert_eq!(buf.get_len_remaining(), 0);

        // Boundary of the two-read path: exactly 128 bits present and claimed
        let mut buf = type3_elem(2, 128, &format!("{}1", "0".repeat(127)));
        assert_eq!(
            parse_type3_generic(true, &mut buf, 2u64),
            Ok(Some(Type3FieldGeneric {
                field_id: 2,
                len: 128,
                data: 1,
            }))
        );
        assert_eq!(buf.get_len_remaining(), 0);
    }

    #[test]
    fn test_type3_over_128_bits_truncates_and_skips() {
        // 160 bits present and claimed: keep the first 128, skip the rest
        let mut buf = type3_elem(3, 160, &"1".repeat(160));
        assert_eq!(
            parse_type3_generic(true, &mut buf, 3u64),
            Ok(Some(Type3FieldGeneric {
                field_id: 3,
                len: 160,
                data: u128::MAX,
            }))
        );
        assert_eq!(buf.get_len_remaining(), 0);
    }

    #[test]
    fn test_type4_length_below_header_errors() {
        // Length under 6 used to underflow `len_bits - 6`
        for len_bits in 0..6 {
            let mut buf = type4_elem(2, len_bits, 1, &"0".repeat(64));
            assert_eq!(
                parse_type4_generic(true, &mut buf, 2u64),
                Err(PduParseErr::InconsistentLength {
                    expected: 6,
                    found: len_bits
                })
            );
        }
    }

    #[test]
    fn test_type4_length_exceeds_buffer_errors() {
        // Claims 80 payload bits, only 40 present: must error, not seek past the window end
        let mut buf = type4_elem(2, 6 + 80, 1, &"1".repeat(40));
        assert_eq!(
            parse_type4_generic(true, &mut buf, 2u64),
            Err(PduParseErr::BufferEnded {
                field: Some("parse_type4_header payload")
            })
        );
    }

    #[test]
    fn test_type4_length_exactly_remaining_parses() {
        let mut buf = type4_elem(2, 6 + 8, 2, "11110000");
        assert_eq!(
            parse_type4_generic(true, &mut buf, 2u64),
            Ok(Some(Type4FieldGeneric {
                field_id: 2,
                len: 8,
                elems: 2,
                data: 0xF0,
            }))
        );
        assert_eq!(buf.get_len_remaining(), 0);

        // Boundary of the truncation path: 80 bits present and claimed
        let mut buf = type4_elem(3, 6 + 80, 1, &"1".repeat(80));
        assert_eq!(
            parse_type4_generic(true, &mut buf, 3u64),
            Ok(Some(Type4FieldGeneric {
                field_id: 3,
                len: 80,
                elems: 1,
                data: u64::MAX,
            }))
        );
        assert_eq!(buf.get_len_remaining(), 0);
    }
}
