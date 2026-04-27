use crate::err;

use super::{
    icmpv6_len_error, u16_at, Mldv2MulticastAddressRecordSlice,
    Mldv2MulticastAddressRecordsIterator,
};

const MLDV2_REPORT_MIN_LEN: usize = crate::Icmpv6Header::MIN_LEN;

/// Borrowed MLDv2 Multicast Listener Report message
/// ([RFC 3810, Section 5.2](https://datatracker.ietf.org/doc/html/rfc3810)).
///
/// The full packet layout is:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Type = 143   |    Reserved   |           Checksum            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Reserved            |Nr of Mcast Address Records (M)|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// .                                                               .
/// .                  Multicast Address Record [1]                 .
/// .                                                               .
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// .                                                               .
/// .                  Multicast Address Record [2]                 .
/// .                                                               .
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                               .                               |
/// .                               .                               .
/// |                               .                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// .                                                               .
/// .                  Multicast Address Record [M]                 .
/// .                                                               .
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mldv2ReportSlice<'a> {
    slice: &'a [u8],
    records_len: usize,
}

impl<'a> Mldv2ReportSlice<'a> {
    /// Decode an MLDv2 report from bytes containing a full ICMPv6 message.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, err::LenError> {
        if slice.len() < MLDV2_REPORT_MIN_LEN {
            return Err(icmpv6_len_error(MLDV2_REPORT_MIN_LEN, slice.len()));
        }

        let mut offset = 8;
        let mut rest = &slice[offset..];
        for _ in 0..u16_at(slice, 6) {
            let record = Mldv2MulticastAddressRecordSlice::from_slice(rest)
                .map_err(|err| err.add_offset(offset))?;
            offset += record.slice().len();
            rest = &slice[offset..];
        }

        Ok(Self {
            slice,
            records_len: offset - 8,
        })
    }

    /// Returns the complete ICMPv6/MLD report message bytes.
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Reserved field.
    pub fn reserved(&self) -> u16 {
        u16_at(self.slice, 4)
    }

    /// Number of multicast address records.
    pub fn number_of_multicast_address_records(&self) -> u16 {
        u16_at(self.slice, 6)
    }

    /// Serialized multicast address record bytes.
    pub fn multicast_address_records(&self) -> &'a [u8] {
        &self.slice[8..8 + self.records_len]
    }

    /// Iterator over multicast address records.
    pub fn multicast_address_records_iterator(&self) -> Mldv2MulticastAddressRecordsIterator<'a> {
        Mldv2MulticastAddressRecordsIterator::from_slice(self.multicast_address_records())
    }

    /// Additional data after the advertised records.
    pub fn additional_data(&self) -> &'a [u8] {
        &self.slice[8 + self.records_len..]
    }
}
