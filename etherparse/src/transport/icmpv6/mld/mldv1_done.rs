use crate::Icmpv6Type;
use core::net::Ipv6Addr;

/// Owned fixed fields of an MLDv1 Multicast Listener Done message
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
///
/// In this crate, `Type`, `Code`, and the ICMPv6 `Checksum` are represented
/// by [`crate::Icmpv6Header`]. This struct stores the `Multicast Address`
/// field. The `Maximum Response Delay` and `Reserved` fields are written as
/// zero by [`Mldv1Done::icmpv6_type`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Mldv1Done {
    /// Multicast address no longer being listened to.
    pub multicast_address: Ipv6Addr,
}

impl Mldv1Done {
    /// Payload length after the first 8 ICMPv6 bytes.
    pub const PAYLOAD_LEN: usize = 16;

    /// Returns the ICMPv6 type representation used by this crate.
    pub fn icmpv6_type(&self) -> Icmpv6Type {
        Icmpv6Type::multicast_listener_done_v1()
    }

    /// Returns the bytes represented by this struct.
    pub fn to_bytes(&self) -> [u8; Self::PAYLOAD_LEN] {
        self.multicast_address.octets()
    }
}
