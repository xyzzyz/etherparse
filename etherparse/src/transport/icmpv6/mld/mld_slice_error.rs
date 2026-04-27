use crate::err;

/// Error when decoding an MLD message slice.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum MldSliceError {
    /// Length error while decoding the ICMPv6/MLD bytes.
    Len(err::LenError),
    /// The ICMPv6 type is not an MLD message type.
    UnexpectedIcmpv6Type {
        /// Actual ICMPv6 type value.
        type_u8: u8,
    },
}

impl MldSliceError {
    /// Returns the length error if this is a [`MldSliceError::Len`].
    #[inline]
    pub fn len(&self) -> Option<&err::LenError> {
        match self {
            MldSliceError::Len(value) => Some(value),
            MldSliceError::UnexpectedIcmpv6Type { .. } => None,
        }
    }

    /// Returns the unexpected ICMPv6 type value if this is a
    /// [`MldSliceError::UnexpectedIcmpv6Type`].
    #[inline]
    pub fn unexpected_icmpv6_type(&self) -> Option<u8> {
        match self {
            MldSliceError::Len(_) => None,
            MldSliceError::UnexpectedIcmpv6Type { type_u8 } => Some(*type_u8),
        }
    }
}

impl From<err::LenError> for MldSliceError {
    #[inline]
    fn from(value: err::LenError) -> Self {
        MldSliceError::Len(value)
    }
}

impl core::fmt::Display for MldSliceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MldSliceError::Len(value) => value.fmt(f),
            MldSliceError::UnexpectedIcmpv6Type { type_u8 } => write!(
                f,
                "MLD Slice Error: Unexpected ICMPv6 type '{type_u8}' (expected 130, 131, 132, or 143)."
            ),
        }
    }
}

impl core::error::Error for MldSliceError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            MldSliceError::Len(value) => Some(value),
            MldSliceError::UnexpectedIcmpv6Type { .. } => None,
        }
    }
}
