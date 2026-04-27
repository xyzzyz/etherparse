#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::net::Ipv6Addr;

#[cfg(feature = "std")]
use crate::IoWriter;
#[cfg(feature = "alloc")]
use crate::VecWriter;
use crate::{CoreWrite, SliceCoreWrite};

#[cfg(feature = "std")]
use super::MldIoWriteError;
use super::{
    mld_auxiliary_data_len, mld_source_address_count, MldBuildError,
    Mldv2MulticastAddressRecordType,
};

/// Borrowed MLDv2 Multicast Address Record fields plus variable data
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
///
/// `Aux Data Len` and `Number of Sources` are derived from
/// [`Mldv2MulticastAddressRecord::auxiliary_data`] and
/// [`Mldv2MulticastAddressRecord::source_addresses`] when writing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Mldv2MulticastAddressRecord<'a> {
    /// Record type.
    pub record_type: Mldv2MulticastAddressRecordType,
    /// Multicast address this record pertains to.
    pub multicast_address: Ipv6Addr,
    /// Source addresses following the fixed record bytes.
    pub source_addresses: &'a [Ipv6Addr],
    /// Auxiliary data following the source addresses.
    pub auxiliary_data: &'a [u8],
}

impl<'a> Mldv2MulticastAddressRecord<'a> {
    /// Fixed record length before source addresses and auxiliary data.
    pub const FIXED_LEN: usize = 20;

    /// Returns the record length in bytes.
    pub fn record_len(&self) -> Result<usize, MldBuildError> {
        mld_source_address_count(self.source_addresses.len())?;
        mld_auxiliary_data_len(self.auxiliary_data.len())?;

        let source_addresses_len = self
            .source_addresses
            .len()
            .checked_mul(16)
            .ok_or(MldBuildError::PayloadLenTooBig)?;
        Self::FIXED_LEN
            .checked_add(source_addresses_len)
            .and_then(|len| len.checked_add(self.auxiliary_data.len()))
            .ok_or(MldBuildError::PayloadLenTooBig)
    }

    /// Write this multicast address record to a byte slice.
    ///
    /// Returns the number of bytes written.
    pub fn write_to_slice(&self, slice: &mut [u8]) -> Result<usize, MldBuildError> {
        let required_len = self.record_len()?;
        let slice_len = slice.len();
        let target = slice
            .get_mut(..required_len)
            .ok_or_else(|| MldBuildError::slice_write_space(required_len, slice_len))?;

        let mut writer = SliceCoreWrite::new(target);
        self.write_record_unchecked(&mut writer)
            .map_err(|err| MldBuildError::slice_write_space(err.required_len, err.len))?;
        Ok(required_len)
    }

    /// Write this multicast address record to a [`Vec<u8>`].
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn write_to_vec(&self, buffer: &mut Vec<u8>) -> Result<(), MldBuildError> {
        self.record_len()?;
        let mut writer = VecWriter(buffer);
        match self.write_record_unchecked(&mut writer) {
            Ok(()) => Ok(()),
            Err(value) => match value {},
        }
    }

    /// Write this multicast address record to an IO writer.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn write<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), MldIoWriteError> {
        self.record_len()?;
        let mut writer = IoWriter(writer);
        self.write_record_unchecked(&mut writer)?;
        Ok(())
    }

    pub(super) fn write_record_unchecked<W: CoreWrite>(
        &self,
        writer: &mut W,
    ) -> Result<(), W::Error> {
        writer.write_all(&self.fixed_record_bytes_unchecked())?;
        for source in self.source_addresses {
            writer.write_all(&source.octets())?;
        }
        writer.write_all(self.auxiliary_data)?;
        Ok(())
    }

    fn fixed_record_bytes_unchecked(&self) -> [u8; 20] {
        let mut result = [0u8; Self::FIXED_LEN];
        result[0] = self.record_type.0;
        result[1] = (self.auxiliary_data.len() / 4) as u8;
        result[2..4].copy_from_slice(&(self.source_addresses.len() as u16).to_be_bytes());
        result[4..20].copy_from_slice(&self.multicast_address.octets());
        result
    }
}
