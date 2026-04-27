use crate::err;
use core::net::Ipv6Addr;

use super::{icmpv6_len_error, Mldv1Query, Mldv1QuerySlice, Mldv2QuerySlice};

const MLDV1_QUERY_LEN: usize = Mldv1Query::LEN;
const MLDV2_QUERY_MIN_LEN: usize = crate::Icmpv6Header::MIN_LEN + 20;

/// Multicast Listener Query message slice.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MldQuerySlice<'a> {
    /// MLDv1 query (24 octets total).
    Version1(Mldv1QuerySlice<'a>),
    /// MLDv2 query (28 or more octets total).
    Version2(Mldv2QuerySlice<'a>),
}

impl<'a> MldQuerySlice<'a> {
    /// Decode an MLD query from bytes containing a full ICMPv6 message.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, err::LenError> {
        let len = slice.len();
        if len < MLDV1_QUERY_LEN {
            return Err(icmpv6_len_error(MLDV1_QUERY_LEN, len));
        }

        if len == MLDV1_QUERY_LEN {
            return Ok(MldQuerySlice::Version1(Mldv1QuerySlice { slice }));
        }

        if len < MLDV2_QUERY_MIN_LEN {
            return Err(icmpv6_len_error(MLDV2_QUERY_MIN_LEN, len));
        }

        Ok(MldQuerySlice::Version2(Mldv2QuerySlice::from_slice(slice)?))
    }

    /// Returns the complete ICMPv6/MLD query message bytes.
    pub fn slice(&self) -> &'a [u8] {
        match self {
            MldQuerySlice::Version1(value) => value.slice(),
            MldQuerySlice::Version2(value) => value.slice(),
        }
    }

    /// Maximum Response Delay/Code field.
    pub fn maximum_response_code(&self) -> u16 {
        match self {
            MldQuerySlice::Version1(value) => value.maximum_response_delay(),
            MldQuerySlice::Version2(value) => value.maximum_response_code(),
        }
    }

    /// Multicast address field.
    pub fn multicast_address(&self) -> Ipv6Addr {
        match self {
            MldQuerySlice::Version1(value) => value.multicast_address(),
            MldQuerySlice::Version2(value) => value.multicast_address(),
        }
    }
}
