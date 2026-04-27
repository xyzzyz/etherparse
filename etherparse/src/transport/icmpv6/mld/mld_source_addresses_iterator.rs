use crate::err;
use core::net::Ipv6Addr;

use super::icmpv6_len_error;

/// Iterator over MLD source addresses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MldSourceAddressesIterator<'a> {
    bytes: &'a [u8],
}

impl<'a> MldSourceAddressesIterator<'a> {
    /// Creates an iterator over MLD source address bytes.
    pub fn from_slice(bytes: &'a [u8]) -> Result<Self, err::LenError> {
        if 0 != bytes.len() % 16 {
            Err(icmpv6_len_error(
                next_multiple_of_16(bytes.len()),
                bytes.len(),
            ))
        } else {
            Ok(Self::from_aligned_slice(bytes))
        }
    }

    pub(super) fn from_aligned_slice(bytes: &'a [u8]) -> Self {
        debug_assert_eq!(0, bytes.len() % 16);
        Self { bytes }
    }
}

impl Iterator for MldSourceAddressesIterator<'_> {
    type Item = Ipv6Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }

        let (addr, rest) = self.bytes.split_at_checked(16)?;
        self.bytes = rest;

        let mut bytes = [0; 16];
        bytes.copy_from_slice(addr);
        Some(Ipv6Addr::from(bytes))
    }
}

fn next_multiple_of_16(value: usize) -> usize {
    value.saturating_add(16 - value % 16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn from_slice() {
        let bytes = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x20, 0x01, 0x0d, 0xb8, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ];

        assert_eq!(
            alloc::vec![
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            ],
            MldSourceAddressesIterator::from_slice(&bytes)
                .unwrap()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn from_slice_len_error() {
        assert_eq!(
            Err(icmpv6_len_error(16, 1)),
            MldSourceAddressesIterator::from_slice(&[0; 1])
        );
        assert_eq!(
            Err(icmpv6_len_error(32, 17)),
            MldSourceAddressesIterator::from_slice(&[0; 17])
        );
    }
}
