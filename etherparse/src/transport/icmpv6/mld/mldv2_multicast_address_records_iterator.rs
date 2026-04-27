use super::Mldv2MulticastAddressRecordSlice;

/// Iterator over MLDv2 multicast address records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mldv2MulticastAddressRecordsIterator<'a> {
    pub(super) records: &'a [u8],
}

impl<'a> Mldv2MulticastAddressRecordsIterator<'a> {
    pub(crate) fn from_slice(records: &'a [u8]) -> Self {
        Self { records }
    }
}

impl<'a> Iterator for Mldv2MulticastAddressRecordsIterator<'a> {
    type Item = Mldv2MulticastAddressRecordSlice<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.records.is_empty() {
            return None;
        }

        let record = Mldv2MulticastAddressRecordSlice::from_slice(self.records).unwrap();
        self.records = &self.records[record.slice().len()..];
        Some(record)
    }
}
