/// MLDv2 Multicast Address Record Type value.
#[derive(PartialEq, Eq, Clone, Copy, Hash, Ord, PartialOrd)]
pub struct Mldv2MulticastAddressRecordType(pub u8);

impl Mldv2MulticastAddressRecordType {
    /// MODE_IS_INCLUDE record type.
    pub const MODE_IS_INCLUDE: Self = Self(1);
    /// MODE_IS_EXCLUDE record type.
    pub const MODE_IS_EXCLUDE: Self = Self(2);
    /// CHANGE_TO_INCLUDE_MODE record type.
    pub const CHANGE_TO_INCLUDE_MODE: Self = Self(3);
    /// CHANGE_TO_EXCLUDE_MODE record type.
    pub const CHANGE_TO_EXCLUDE_MODE: Self = Self(4);
    /// ALLOW_NEW_SOURCES record type.
    pub const ALLOW_NEW_SOURCES: Self = Self(5);
    /// BLOCK_OLD_SOURCES record type.
    pub const BLOCK_OLD_SOURCES: Self = Self(6);

    /// Human-readable name for known record types.
    pub const fn keyword_str(self) -> Option<&'static str> {
        match self.0 {
            1 => Some("MODE_IS_INCLUDE"),
            2 => Some("MODE_IS_EXCLUDE"),
            3 => Some("CHANGE_TO_INCLUDE_MODE"),
            4 => Some("CHANGE_TO_EXCLUDE_MODE"),
            5 => Some("ALLOW_NEW_SOURCES"),
            6 => Some("BLOCK_OLD_SOURCES"),
            _ => None,
        }
    }
}

impl From<u8> for Mldv2MulticastAddressRecordType {
    #[inline]
    fn from(val: u8) -> Self {
        Self(val)
    }
}

impl From<Mldv2MulticastAddressRecordType> for u8 {
    #[inline]
    fn from(val: Mldv2MulticastAddressRecordType) -> Self {
        val.0
    }
}

impl core::fmt::Debug for Mldv2MulticastAddressRecordType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(keyword) = self.keyword_str() {
            write!(f, "{} ({})", self.0, keyword)
        } else {
            write!(f, "{}", self.0)
        }
    }
}
