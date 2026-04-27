use crate::err;
use core::net::Ipv6Addr;

use super::{
    icmpv6_len_error, ipv6_addr_at, u16_at, MldSourceAddressesIterator,
    Mldv2MulticastAddressRecordType,
};

const MLDV2_MULTICAST_ADDRESS_RECORD_FIXED_LEN: usize = 20;

/// Borrowed MLDv2 Multicast Address Record
/// ([RFC 3810, Section 5.2.4](https://datatracker.ietf.org/doc/html/rfc3810)).
///
/// The record layout is:
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// *                                                               *
/// |                                                               |
/// *                       Multicast Address                       *
/// |                                                               |
/// *                                                               *
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// *                                                               *
/// |                                                               |
/// *                       Source Address [1]                      *
/// |                                                               |
/// *                                                               *
/// |                                                               |
/// +-                                                             -+
/// |                                                               |
/// *                                                               *
/// |                                                               |
/// *                       Source Address [2]                      *
/// |                                                               |
/// *                                                               *
/// |                                                               |
/// +-                                                             -+
/// .                               .                               .
/// .                               .                               .
/// .                               .                               .
/// +-                                                             -+
/// |                                                               |
/// *                                                               *
/// |                                                               |
/// *                       Source Address [N]                      *
/// |                                                               |
/// *                                                               *
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// .                                                               .
/// .                         Auxiliary Data                        .
/// .                                                               .
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mldv2MulticastAddressRecordSlice<'a> {
    slice: &'a [u8],
}

impl<'a> Mldv2MulticastAddressRecordSlice<'a> {
    /// Decode a multicast address record from bytes.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, err::LenError> {
        if slice.len() < MLDV2_MULTICAST_ADDRESS_RECORD_FIXED_LEN {
            return Err(icmpv6_len_error(
                MLDV2_MULTICAST_ADDRESS_RECORD_FIXED_LEN,
                slice.len(),
            ));
        }

        let required_len = MLDV2_MULTICAST_ADDRESS_RECORD_FIXED_LEN
            + usize::from(u16_at(slice, 2)) * 16
            + usize::from(slice[1]) * 4;
        if slice.len() < required_len {
            return Err(icmpv6_len_error(required_len, slice.len()));
        }

        Ok(Self {
            slice: &slice[..required_len],
        })
    }

    /// Returns the complete record bytes.
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Record type.
    pub fn record_type(&self) -> Mldv2MulticastAddressRecordType {
        Mldv2MulticastAddressRecordType(self.slice[0])
    }

    /// Auxiliary data length in 32-bit words.
    pub fn aux_data_len(&self) -> u8 {
        self.slice[1]
    }

    /// Number of source addresses.
    pub fn number_of_sources(&self) -> u16 {
        u16_at(self.slice, 2)
    }

    /// Multicast address this record pertains to.
    pub fn multicast_address(&self) -> Ipv6Addr {
        ipv6_addr_at(self.slice, 4)
    }

    /// Source address bytes.
    pub fn source_addresses(&self) -> &'a [u8] {
        let len = usize::from(self.number_of_sources()) * 16;
        &self.slice[20..20 + len]
    }

    /// Iterator over source addresses.
    pub fn source_addresses_iterator(&self) -> MldSourceAddressesIterator<'a> {
        MldSourceAddressesIterator::from_aligned_slice(self.source_addresses())
    }

    /// Auxiliary data bytes.
    pub fn auxiliary_data(&self) -> &'a [u8] {
        let start = 20 + usize::from(self.number_of_sources()) * 16;
        &self.slice[start..]
    }
}
