use core::net::Ipv6Addr;

use super::{ipv6_addr_at, u16_at, Mldv1Query};

/// Borrowed MLDv1 Multicast Listener Query message
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
pub struct Mldv1QuerySlice<'a> {
    pub(super) slice: &'a [u8],
}

impl<'a> Mldv1QuerySlice<'a> {
    /// Returns the complete ICMPv6/MLD query message bytes.
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Maximum response delay in milliseconds.
    pub fn maximum_response_delay(&self) -> u16 {
        u16_at(self.slice, 4)
    }

    /// Reserved field after the maximum response delay.
    pub fn reserved(&self) -> u16 {
        u16_at(self.slice, 6)
    }

    /// Multicast address being queried, or `::` for a general query.
    pub fn multicast_address(&self) -> Ipv6Addr {
        ipv6_addr_at(self.slice, 8)
    }

    /// Convert to owned fixed fields.
    pub fn to_query(&self) -> Mldv1Query {
        Mldv1Query {
            maximum_response_delay: self.maximum_response_delay(),
            multicast_address: self.multicast_address(),
        }
    }
}
