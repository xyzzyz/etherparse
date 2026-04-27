#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::net::Ipv6Addr;

#[cfg(feature = "std")]
use crate::IoWriter;
#[cfg(feature = "alloc")]
use crate::VecWriter;
use crate::{CoreWrite, Icmpv6Header, Icmpv6Type, SliceCoreWrite};

#[cfg(feature = "std")]
use super::MldIoWriteError;
use super::{mld_source_address_count, MldBuildError, Mldv2QuerySlice};

/// Borrowed fields of an MLDv2 Multicast Listener Query message
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
///
/// In this crate, `Type`, `Code`, and the ICMPv6 `Checksum` are represented
/// by [`crate::Icmpv6Header`]. The `Number of Sources` field is derived from
/// [`Mldv2Query::source_addresses`] when writing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Mldv2Query<'a> {
    /// Maximum response code.
    pub maximum_response_code: u16,
    /// Multicast address being queried, or `::` for a general query.
    pub multicast_address: Ipv6Addr,
    /// Suppress Router-Side Processing flag.
    pub suppress_router_side_processing: bool,
    /// Querier's Robustness Variable. Only the low three bits are encoded.
    pub querier_robustness_variable: u8,
    /// Querier's Query Interval Code.
    pub querier_query_interval_code: u8,
    /// Source addresses following the fixed query bytes.
    pub source_addresses: &'a [Ipv6Addr],
}

impl<'a> Mldv2Query<'a> {
    /// Minimum complete MLDv2 query length including the first 8 ICMPv6 bytes.
    pub const MIN_LEN: usize = Icmpv6Header::MIN_LEN + Self::FIXED_PAYLOAD_LEN;

    /// Fixed payload length after the first 8 ICMPv6 bytes.
    pub const FIXED_PAYLOAD_LEN: usize = 20;

    /// Returns the ICMPv6 type representation used by this crate.
    pub fn icmpv6_type(&self) -> Icmpv6Type {
        Icmpv6Type::multicast_listener_query(self.maximum_response_code)
    }

    /// Returns the payload length after the first 8 ICMPv6 bytes.
    pub fn payload_len(&self) -> Result<usize, MldBuildError> {
        mld_source_address_count(self.source_addresses.len())?;

        let source_addresses_len = self
            .source_addresses
            .len()
            .checked_mul(16)
            .ok_or(MldBuildError::PayloadLenTooBig)?;
        Self::FIXED_PAYLOAD_LEN
            .checked_add(source_addresses_len)
            .ok_or(MldBuildError::PayloadLenTooBig)
    }

    /// Write the MLDv2 query payload to a byte slice.
    ///
    /// Returns the number of bytes written.
    pub fn write_to_slice(&self, slice: &mut [u8]) -> Result<usize, MldBuildError> {
        let required_len = self.payload_len()?;
        let slice_len = slice.len();
        let target = slice
            .get_mut(..required_len)
            .ok_or_else(|| MldBuildError::slice_write_space(required_len, slice_len))?;

        let mut writer = SliceCoreWrite::new(target);
        self.write_payload_unchecked(&mut writer)
            .map_err(|err| MldBuildError::slice_write_space(err.required_len, err.len))?;
        Ok(required_len)
    }

    /// Write the MLDv2 query payload to a [`Vec<u8>`].
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn write_to_vec(&self, buffer: &mut Vec<u8>) -> Result<(), MldBuildError> {
        self.payload_len()?;
        let mut writer = VecWriter(buffer);
        match self.write_payload_unchecked(&mut writer) {
            Ok(()) => Ok(()),
            Err(value) => match value {},
        }
    }

    /// Write the MLDv2 query payload to an IO writer.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn write<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), MldIoWriteError> {
        self.payload_len()?;
        let mut writer = IoWriter(writer);
        self.write_payload_unchecked(&mut writer)?;
        Ok(())
    }

    fn write_payload_unchecked<W: CoreWrite>(&self, writer: &mut W) -> Result<(), W::Error> {
        writer.write_all(&self.fixed_payload_bytes_unchecked())?;
        for source in self.source_addresses {
            writer.write_all(&source.octets())?;
        }
        Ok(())
    }

    fn fixed_payload_bytes_unchecked(&self) -> [u8; 20] {
        let mut result = [0u8; Self::FIXED_PAYLOAD_LEN];
        result[..16].copy_from_slice(&self.multicast_address.octets());
        result[16] = (if self.suppress_router_side_processing {
            Mldv2QuerySlice::SUPPRESS_ROUTER_SIDE_PROCESSING_MASK
        } else {
            0
        }) | (self.querier_robustness_variable & Mldv2QuerySlice::QRV_MASK);
        result[17] = self.querier_query_interval_code;
        result[18..20].copy_from_slice(&(self.source_addresses.len() as u16).to_be_bytes());
        result
    }
}
