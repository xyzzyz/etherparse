use crate::err;
use core::net::Ipv6Addr;

use super::{icmpv6_len_error, ipv6_addr_at, u16_at, MldSourceAddressesIterator};

const MLDV2_QUERY_MIN_LEN: usize = crate::Icmpv6Header::MIN_LEN + MLDV2_QUERY_FIXED_PAYLOAD_LEN;
const MLDV2_QUERY_FIXED_PAYLOAD_LEN: usize = 20;

/// Borrowed MLDv2 Multicast Listener Query message
/// ([RFC 3810, Section 5.1](https://datatracker.ietf.org/doc/html/rfc3810)).
///
/// The full packet layout is:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Type = 130   |      Code     |           Checksum            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Maximum Response Code      |           Reserved            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// *                                                               *
/// |                                                               |
/// *                       Multicast Address                       *
/// |                                                               |
/// *                                                               *
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
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
/// +-                              .                              -+
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
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mldv2QuerySlice<'a> {
    slice: &'a [u8],
}

impl<'a> Mldv2QuerySlice<'a> {
    /// Mask for the Suppress Router-Side Processing flag.
    pub const SUPPRESS_ROUTER_SIDE_PROCESSING_MASK: u8 = 0b0000_1000;

    /// Mask for the QRV field.
    pub const QRV_MASK: u8 = 0b0000_0111;

    /// Decode an MLDv2 query from bytes containing a full ICMPv6 message.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, err::LenError> {
        if slice.len() < MLDV2_QUERY_MIN_LEN {
            return Err(icmpv6_len_error(MLDV2_QUERY_MIN_LEN, slice.len()));
        }

        let required_len = MLDV2_QUERY_MIN_LEN + usize::from(u16_at(slice, 26)) * 16;
        if slice.len() < required_len {
            return Err(icmpv6_len_error(required_len, slice.len()));
        }

        Ok(Self { slice })
    }

    /// Returns the complete ICMPv6/MLD query message bytes.
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Maximum response code.
    pub fn maximum_response_code(&self) -> u16 {
        u16_at(self.slice, 4)
    }

    /// Reserved field after the maximum response code.
    pub fn reserved(&self) -> u16 {
        u16_at(self.slice, 6)
    }

    /// Multicast address being queried, or `::` for a general query.
    pub fn multicast_address(&self) -> Ipv6Addr {
        ipv6_addr_at(self.slice, 8)
    }

    /// Raw byte containing the reserved bits, S flag, and QRV field.
    pub fn resv_s_qrv(&self) -> u8 {
        self.slice[24]
    }

    /// Suppress Router-Side Processing flag.
    pub fn suppress_router_side_processing(&self) -> bool {
        0 != self.resv_s_qrv() & Self::SUPPRESS_ROUTER_SIDE_PROCESSING_MASK
    }

    /// Querier's Robustness Variable.
    pub fn querier_robustness_variable(&self) -> u8 {
        self.resv_s_qrv() & Self::QRV_MASK
    }

    /// Querier's Query Interval Code.
    pub fn querier_query_interval_code(&self) -> u8 {
        self.slice[25]
    }

    /// Number of source addresses in this query.
    pub fn number_of_sources(&self) -> u16 {
        u16_at(self.slice, 26)
    }

    /// Source address bytes.
    pub fn source_addresses(&self) -> &'a [u8] {
        let len = usize::from(self.number_of_sources()) * 16;
        &self.slice[28..28 + len]
    }

    /// Iterator over source addresses.
    pub fn source_addresses_iterator(&self) -> MldSourceAddressesIterator<'a> {
        MldSourceAddressesIterator::from_aligned_slice(self.source_addresses())
    }

    /// Additional data after the source address vector.
    pub fn additional_data(&self) -> &'a [u8] {
        let start = 28 + usize::from(self.number_of_sources()) * 16;
        &self.slice[start..]
    }
}
