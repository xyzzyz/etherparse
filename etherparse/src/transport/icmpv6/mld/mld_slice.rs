use crate::{icmpv6, Icmpv6Slice};

use super::{MldQuerySlice, MldSliceError, Mldv1DoneSlice, Mldv1ReportSlice, Mldv2ReportSlice};

/// Multicast Listener Discovery (MLD) message slice.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MldSlice<'a> {
    /// Multicast Listener Query message.
    Query(MldQuerySlice<'a>),
    /// Version 1 Multicast Listener Report message.
    ListenerReportV1(Mldv1ReportSlice<'a>),
    /// Version 1 Multicast Listener Done message.
    ListenerDoneV1(Mldv1DoneSlice<'a>),
    /// Version 2 Multicast Listener Report message.
    ListenerReportV2(Mldv2ReportSlice<'a>),
}

impl<'a> MldSlice<'a> {
    /// Returns true if the given ICMPv6 type value is an MLD message type.
    #[inline]
    pub fn is_mld_type_u8(type_u8: u8) -> bool {
        use icmpv6::*;

        matches!(
            type_u8,
            TYPE_MULTICAST_LISTENER_QUERY
                | TYPE_MULTICAST_LISTENER_REPORT
                | TYPE_MULTICAST_LISTENER_REDUCTION
                | TYPE_MULTICAST_LISTENER_REPORT_V2
        )
    }

    /// Decode an MLD message from an ICMPv6 slice.
    pub fn from_icmpv6_slice(slice: &Icmpv6Slice<'a>) -> Result<Self, MldSliceError> {
        use icmpv6::*;

        let mld = match slice.type_u8() {
            TYPE_MULTICAST_LISTENER_QUERY => {
                MldSlice::Query(MldQuerySlice::from_slice(slice.slice())?)
            }
            TYPE_MULTICAST_LISTENER_REPORT => {
                MldSlice::ListenerReportV1(Mldv1ReportSlice::from_slice(slice.slice())?)
            }
            TYPE_MULTICAST_LISTENER_REDUCTION => {
                MldSlice::ListenerDoneV1(Mldv1DoneSlice::from_slice(slice.slice())?)
            }
            TYPE_MULTICAST_LISTENER_REPORT_V2 => {
                MldSlice::ListenerReportV2(Mldv2ReportSlice::from_slice(slice.slice())?)
            }
            type_u8 => return Err(MldSliceError::UnexpectedIcmpv6Type { type_u8 }),
        };

        Ok(mld)
    }

    /// Decode an MLD message from bytes containing a full ICMPv6 message.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, MldSliceError> {
        let icmpv6 = Icmpv6Slice::from_slice(slice)?;
        MldSlice::from_icmpv6_slice(&icmpv6)
    }

    /// Returns the complete ICMPv6/MLD message bytes.
    pub fn slice(&self) -> &'a [u8] {
        match self {
            MldSlice::Query(value) => value.slice(),
            MldSlice::ListenerReportV1(value) => value.slice(),
            MldSlice::ListenerDoneV1(value) => value.slice(),
            MldSlice::ListenerReportV2(value) => value.slice(),
        }
    }
}
