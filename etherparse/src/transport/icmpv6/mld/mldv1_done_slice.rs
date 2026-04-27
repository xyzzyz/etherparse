use crate::err;
use core::net::Ipv6Addr;

use super::{icmpv6_len_error, ipv6_addr_at, Mldv1Done, Mldv1Query};

/// Borrowed MLDv1 Multicast Listener Done message
/// ([RFC 2710, Section 3](https://datatracker.ietf.org/doc/html/rfc2710)).
///
/// The full packet layout is:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Maximum Response Delay    |          Reserved             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                       Multicast Address                       +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mldv1DoneSlice<'a> {
    slice: &'a [u8],
}

impl<'a> Mldv1DoneSlice<'a> {
    /// Decode an MLDv1 done message from bytes containing a full ICMPv6 message.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, err::LenError> {
        if slice.len() < Mldv1Query::LEN {
            Err(icmpv6_len_error(Mldv1Query::LEN, slice.len()))
        } else {
            Ok(Self { slice })
        }
    }

    /// Returns the complete ICMPv6/MLD done message bytes.
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Reserved field.
    pub fn reserved(&self) -> u32 {
        u32::from_be_bytes([self.slice[4], self.slice[5], self.slice[6], self.slice[7]])
    }

    /// Multicast address no longer being listened to.
    pub fn multicast_address(&self) -> Ipv6Addr {
        ipv6_addr_at(self.slice, 8)
    }

    /// Additional data after the MLDv1 fields.
    pub fn additional_data(&self) -> &'a [u8] {
        &self.slice[Mldv1Query::LEN..]
    }

    /// Convert to owned fixed fields.
    pub fn to_done(&self) -> Mldv1Done {
        Mldv1Done {
            multicast_address: self.multicast_address(),
        }
    }
}
