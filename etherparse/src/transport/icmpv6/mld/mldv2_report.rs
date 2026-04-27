#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use crate::IoWriter;
#[cfg(feature = "alloc")]
use crate::VecWriter;
use crate::{CoreWrite, Icmpv6Header, Icmpv6Type, SliceCoreWrite};

#[cfg(feature = "std")]
use super::MldIoWriteError;
use super::{mld_multicast_address_record_count, MldBuildError, Mldv2MulticastAddressRecord};

/// Borrowed MLDv2 Multicast Listener Report fields plus records
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
///
/// In this crate, `Type`, `Code`, and the ICMPv6 `Checksum` are represented
/// by [`crate::Icmpv6Header`]. `Nr of Mcast Address Records` is derived from
/// [`Mldv2Report::multicast_address_records`] when writing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Mldv2Report<'a> {
    /// Multicast address records following the first 8 ICMPv6 bytes.
    pub multicast_address_records: &'a [Mldv2MulticastAddressRecord<'a>],
}

impl<'a> Mldv2Report<'a> {
    /// Minimum complete MLDv2 report length including the first 8 ICMPv6 bytes.
    pub const MIN_LEN: usize = Icmpv6Header::MIN_LEN;

    /// Returns the ICMPv6 type representation used by this crate.
    pub fn icmpv6_type(&self) -> Result<Icmpv6Type, MldBuildError> {
        Ok(Icmpv6Type::multicast_listener_report_v2(
            mld_multicast_address_record_count(self.multicast_address_records.len())?,
        ))
    }

    /// Returns the payload length after the first 8 ICMPv6 bytes.
    pub fn payload_len(&self) -> Result<usize, MldBuildError> {
        mld_multicast_address_record_count(self.multicast_address_records.len())?;

        let mut len = 0usize;
        for record in self.multicast_address_records {
            len = len
                .checked_add(record.record_len()?)
                .ok_or(MldBuildError::PayloadLenTooBig)?;
        }
        Ok(len)
    }

    /// Write the MLDv2 report payload to a byte slice.
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

    /// Write the MLDv2 report payload to a [`Vec<u8>`].
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

    /// Write the MLDv2 report payload to an IO writer.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn write<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), MldIoWriteError> {
        self.payload_len()?;
        let mut writer = IoWriter(writer);
        self.write_payload_unchecked(&mut writer)?;
        Ok(())
    }

    fn write_payload_unchecked<W: CoreWrite>(&self, writer: &mut W) -> Result<(), W::Error> {
        for record in self.multicast_address_records {
            record.write_record_unchecked(writer)?;
        }
        Ok(())
    }
}
