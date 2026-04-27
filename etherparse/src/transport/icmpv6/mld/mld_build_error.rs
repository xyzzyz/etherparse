use crate::err;

/// Error while building serialized MLD payload bytes.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum MldBuildError {
    /// Number of source addresses can not be represented in the MLD field.
    SourceAddressCountTooBig {
        /// Actual number of source addresses.
        actual: usize,
    },

    /// Number of multicast address records can not be represented in the MLD field.
    MulticastAddressRecordCountTooBig {
        /// Actual number of multicast address records.
        actual: usize,
    },

    /// Auxiliary data is too large to be represented by the auxiliary data length field.
    AuxiliaryDataLenTooBig {
        /// Actual auxiliary data length in bytes.
        actual: usize,
    },

    /// Auxiliary data length is not a multiple of 4 bytes.
    AuxiliaryDataLenUnaligned {
        /// Actual auxiliary data length in bytes.
        actual: usize,
    },

    /// Total MLD payload length is too large to be represented on this platform.
    PayloadLenTooBig,

    /// Not enough space was available in the output slice.
    SliceWriteSpace(err::SliceWriteSpaceError),
}

impl MldBuildError {
    pub(super) fn slice_write_space(required_len: usize, len: usize) -> Self {
        MldBuildError::SliceWriteSpace(err::SliceWriteSpaceError {
            required_len,
            len,
            layer: err::Layer::Icmpv6,
            layer_start_offset: 0,
        })
    }

    /// Returns the slice write space error if this error is
    /// [`MldBuildError::SliceWriteSpace`].
    pub fn slice_write_space_error(&self) -> Option<&err::SliceWriteSpaceError> {
        match self {
            MldBuildError::SliceWriteSpace(value) => Some(value),
            _ => None,
        }
    }
}

impl core::fmt::Display for MldBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use MldBuildError::*;
        match self {
            SourceAddressCountTooBig { actual } => write!(
                f,
                "MLD build error: {actual} source addresses can not be represented by a 16-bit source address count field."
            ),
            MulticastAddressRecordCountTooBig { actual } => write!(
                f,
                "MLD build error: {actual} multicast address records can not be represented by a 16-bit record count field."
            ),
            AuxiliaryDataLenTooBig { actual } => write!(
                f,
                "MLD build error: {actual} bytes of auxiliary data can not be represented by an 8-bit auxiliary data length field."
            ),
            AuxiliaryDataLenUnaligned { actual } => write!(
                f,
                "MLD build error: auxiliary data length of {actual} bytes is not a multiple of 4."
            ),
            PayloadLenTooBig => write!(
                f,
                "MLD build error: payload length is too large to be represented on this platform."
            ),
            SliceWriteSpace(value) => value.fmt(f),
        }
    }
}

impl core::error::Error for MldBuildError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            MldBuildError::SliceWriteSpace(value) => Some(value),
            _ => None,
        }
    }
}

/// Error while writing MLD payload bytes to an IO writer.
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[derive(Debug)]
pub enum MldIoWriteError {
    /// IO error while writing.
    Io(std::io::Error),

    /// Error while building the MLD payload.
    Build(MldBuildError),
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl MldIoWriteError {
    /// Returns the [`std::io::Error`] value if this is an [`MldIoWriteError::Io`].
    pub fn io(&self) -> Option<&std::io::Error> {
        match self {
            MldIoWriteError::Io(value) => Some(value),
            MldIoWriteError::Build(_) => None,
        }
    }

    /// Returns the [`MldBuildError`] value if this is an [`MldIoWriteError::Build`].
    pub fn build(&self) -> Option<&MldBuildError> {
        match self {
            MldIoWriteError::Io(_) => None,
            MldIoWriteError::Build(value) => Some(value),
        }
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for MldIoWriteError {
    fn from(value: std::io::Error) -> Self {
        MldIoWriteError::Io(value)
    }
}

#[cfg(feature = "std")]
impl From<MldBuildError> for MldIoWriteError {
    fn from(value: MldBuildError) -> Self {
        MldIoWriteError::Build(value)
    }
}

#[cfg(feature = "std")]
impl core::fmt::Display for MldIoWriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MldIoWriteError::Io(value) => value.fmt(f),
            MldIoWriteError::Build(value) => value.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl core::error::Error for MldIoWriteError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            MldIoWriteError::Io(value) => Some(value),
            MldIoWriteError::Build(value) => Some(value),
        }
    }
}
