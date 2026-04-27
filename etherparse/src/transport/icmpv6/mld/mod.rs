mod mld_build_error;
pub use mld_build_error::*;

mod mld_query_slice;
pub use mld_query_slice::*;

mod mld_slice;
pub use mld_slice::*;

mod mld_slice_error;
pub use mld_slice_error::*;

mod mld_source_addresses_iterator;
pub use mld_source_addresses_iterator::*;

mod mldv1_done;
pub use mldv1_done::*;

mod mldv1_done_slice;
pub use mldv1_done_slice::*;

mod mldv1_query;
pub use mldv1_query::*;

mod mldv1_query_slice;
pub use mldv1_query_slice::*;

mod mldv1_report;
pub use mldv1_report::*;

mod mldv1_report_slice;
pub use mldv1_report_slice::*;

mod mldv2_multicast_address_record;
pub use mldv2_multicast_address_record::*;

mod mldv2_multicast_address_record_slice;
pub use mldv2_multicast_address_record_slice::*;

mod mldv2_multicast_address_record_type;
pub use mldv2_multicast_address_record_type::*;

mod mldv2_multicast_address_records_iterator;
pub use mldv2_multicast_address_records_iterator::*;

mod mldv2_query;
pub use mldv2_query::*;

mod mldv2_query_slice;
pub use mldv2_query_slice::*;

mod mldv2_report;
pub use mldv2_report::*;

mod mldv2_report_slice;
pub use mldv2_report_slice::*;

use crate::{err, get_unchecked_be_u16, LenSource};
use core::net::Ipv6Addr;

const MLD_MAX_U16_COUNT: usize = u16::MAX as usize;
const MLD_MAX_AUXILIARY_DATA_LEN: usize = u8::MAX as usize * 4;

pub(super) fn icmpv6_len_error(required_len: usize, len: usize) -> err::LenError {
    err::LenError {
        required_len,
        len,
        len_source: LenSource::Slice,
        layer: err::Layer::Icmpv6,
        layer_start_offset: 0,
    }
}

pub(super) fn u16_at(slice: &[u8], offset: usize) -> u16 {
    // SAFETY: Callers only request offsets after the slice length has been checked.
    unsafe { get_unchecked_be_u16(slice.as_ptr().add(offset)) }
}

pub(super) fn ipv6_addr_at(slice: &[u8], offset: usize) -> Ipv6Addr {
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&slice[offset..offset + 16]);
    Ipv6Addr::from(addr)
}

pub(super) fn mld_source_address_count(len: usize) -> Result<u16, MldBuildError> {
    if len > MLD_MAX_U16_COUNT {
        Err(MldBuildError::SourceAddressCountTooBig { actual: len })
    } else {
        Ok(len as u16)
    }
}

pub(super) fn mld_multicast_address_record_count(len: usize) -> Result<u16, MldBuildError> {
    if len > MLD_MAX_U16_COUNT {
        Err(MldBuildError::MulticastAddressRecordCountTooBig { actual: len })
    } else {
        Ok(len as u16)
    }
}

pub(super) fn mld_auxiliary_data_len(len: usize) -> Result<u8, MldBuildError> {
    if len > MLD_MAX_AUXILIARY_DATA_LEN {
        Err(MldBuildError::AuxiliaryDataLenTooBig { actual: len })
    } else if 0 != len % 4 {
        Err(MldBuildError::AuxiliaryDataLenUnaligned { actual: len })
    } else {
        Ok((len / 4) as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{icmpv6, Icmpv6Header, Icmpv6Slice, Icmpv6Type};
    use alloc::vec::Vec;
    use core::net::Ipv6Addr;

    const GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    const SOURCE_1: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    const SOURCE_2: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

    #[test]
    fn mldv1_query_parse_and_write() {
        let query = Mldv1Query {
            maximum_response_delay: 1234,
            multicast_address: GROUP,
        };
        let mut packet = Vec::new();
        packet.extend_from_slice(&Icmpv6Header::new(query.icmpv6_type()).to_bytes());
        packet.extend_from_slice(&query.to_bytes());

        let icmp = Icmpv6Slice::from_slice(&packet).unwrap();
        assert_eq!(
            icmp.icmp_type(),
            Icmpv6Type::Unknown {
                type_u8: icmpv6::TYPE_MULTICAST_LISTENER_QUERY,
                code_u8: 0,
                bytes5to8: [0x04, 0xd2, 0, 0],
            }
        );

        assert!(icmp.is_mld());
        let mld = icmp.mld_slice().unwrap();
        let query = match mld {
            MldSlice::Query(MldQuerySlice::Version1(value)) => value,
            _ => panic!("expected mldv1 query"),
        };
        assert_eq!(1234, query.maximum_response_delay());
        assert_eq!(0, query.reserved());
        assert_eq!(GROUP, query.multicast_address());
        assert_eq!(GROUP.octets(), query.to_query().to_bytes());
    }

    #[test]
    fn mld_query_versions_and_lengths() {
        assert_eq!(
            Err(icmpv6_len_error(Mldv1Query::LEN, 23)),
            MldQuerySlice::from_slice(&[0; 23])
        );
        assert_eq!(
            Err(icmpv6_len_error(Mldv2Query::MIN_LEN, 26)),
            MldQuerySlice::from_slice(&[0; 26])
        );

        let mut v2 = [0u8; Mldv2Query::MIN_LEN];
        v2[0] = icmpv6::TYPE_MULTICAST_LISTENER_QUERY;
        assert!(matches!(
            MldQuerySlice::from_slice(&v2).unwrap(),
            MldQuerySlice::Version2(_)
        ));
    }

    #[test]
    fn mldv2_query_parse_and_write() {
        let query = Mldv2Query {
            maximum_response_code: 0x8123,
            multicast_address: GROUP,
            suppress_router_side_processing: true,
            querier_robustness_variable: 5,
            querier_query_interval_code: 0x80,
            source_addresses: &[SOURCE_1, SOURCE_2],
        };
        let mut payload = Vec::new();
        query.write_to_vec(&mut payload).unwrap();
        payload.extend_from_slice(&[9, 8, 7]);

        let mut packet = Vec::new();
        packet.extend_from_slice(&Icmpv6Header::new(query.icmpv6_type()).to_bytes());
        packet.extend_from_slice(&payload);

        let mld = MldSlice::from_slice(&packet).unwrap();
        let query = match mld {
            MldSlice::Query(MldQuerySlice::Version2(value)) => value,
            _ => panic!("expected mldv2 query"),
        };

        assert_eq!(0x8123, query.maximum_response_code());
        assert_eq!(GROUP, query.multicast_address());
        assert!(query.suppress_router_side_processing());
        assert_eq!(5, query.querier_robustness_variable());
        assert_eq!(0x80, query.querier_query_interval_code());
        assert_eq!(2, query.number_of_sources());
        assert_eq!(
            alloc::vec![SOURCE_1, SOURCE_2],
            query.source_addresses_iterator().collect::<Vec<_>>()
        );
        assert_eq!(&[9, 8, 7], query.additional_data());
    }

    #[test]
    fn mldv1_report_and_done() {
        for (type_u8, expected) in [
            (icmpv6::TYPE_MULTICAST_LISTENER_REPORT, "report"),
            (icmpv6::TYPE_MULTICAST_LISTENER_DONE, "done"),
        ] {
            let mut packet = Vec::new();
            packet.extend_from_slice(
                &Icmpv6Header::new(Icmpv6Type::Unknown {
                    type_u8,
                    code_u8: 0,
                    bytes5to8: [0; 4],
                })
                .to_bytes(),
            );
            packet.extend_from_slice(&GROUP.octets());
            packet.extend_from_slice(&[1, 2, 3]);

            match MldSlice::from_slice(&packet).unwrap() {
                MldSlice::ListenerReportV1(value) => {
                    assert_eq!("report", expected);
                    assert_eq!(GROUP, value.multicast_address());
                    assert_eq!(&[1, 2, 3], value.additional_data());
                }
                MldSlice::ListenerDoneV1(value) => {
                    assert_eq!("done", expected);
                    assert_eq!(GROUP, value.multicast_address());
                    assert_eq!(&[1, 2, 3], value.additional_data());
                }
                _ => panic!("expected mldv1 report/done"),
            }
        }
    }

    #[test]
    fn mldv2_report_records() {
        let record = Mldv2MulticastAddressRecord {
            record_type: Mldv2MulticastAddressRecordType::ALLOW_NEW_SOURCES,
            multicast_address: GROUP,
            source_addresses: &[SOURCE_1, SOURCE_2],
            auxiliary_data: &[1, 2, 3, 4],
        };
        let records = [record];
        let report = Mldv2Report {
            multicast_address_records: &records,
        };
        let mut payload = Vec::new();
        report.write_to_vec(&mut payload).unwrap();
        payload.extend_from_slice(&[5, 6]);

        let mut packet = Vec::new();
        packet.extend_from_slice(&Icmpv6Header::new(report.icmpv6_type().unwrap()).to_bytes());
        packet.extend_from_slice(&payload);

        let report = match MldSlice::from_slice(&packet).unwrap() {
            MldSlice::ListenerReportV2(value) => value,
            _ => panic!("expected mldv2 report"),
        };
        assert_eq!(1, report.number_of_multicast_address_records());
        assert_eq!(&[5, 6], report.additional_data());

        let records = report
            .multicast_address_records_iterator()
            .collect::<Vec<_>>();
        assert_eq!(1, records.len());
        assert_eq!(
            Mldv2MulticastAddressRecordType::ALLOW_NEW_SOURCES,
            records[0].record_type()
        );
        assert_eq!(GROUP, records[0].multicast_address());
        assert_eq!(
            alloc::vec![SOURCE_1, SOURCE_2],
            records[0].source_addresses_iterator().collect::<Vec<_>>()
        );
        assert_eq!(&[1, 2, 3, 4], records[0].auxiliary_data());
    }

    #[test]
    fn mldv2_query_write_to_slice() {
        let query = Mldv2Query {
            maximum_response_code: 0x1234,
            multicast_address: GROUP,
            suppress_router_side_processing: true,
            querier_robustness_variable: 3,
            querier_query_interval_code: 0x7f,
            source_addresses: &[SOURCE_1, SOURCE_2],
        };

        let mut payload = [0u8; Mldv2Query::FIXED_PAYLOAD_LEN + 2 * 16];
        let len = query.write_to_slice(&mut payload).unwrap();
        assert_eq!(payload.len(), len);
        assert_eq!(payload.len(), query.payload_len().unwrap());

        let mut packet = Vec::new();
        packet.extend_from_slice(&Icmpv6Header::new(query.icmpv6_type()).to_bytes());
        packet.extend_from_slice(&payload);

        let parsed = match MldSlice::from_slice(&packet).unwrap() {
            MldSlice::Query(MldQuerySlice::Version2(value)) => value,
            _ => panic!("expected mldv2 query"),
        };
        assert_eq!(0x1234, parsed.maximum_response_code());
        assert_eq!(GROUP, parsed.multicast_address());
        assert!(parsed.suppress_router_side_processing());
        assert_eq!(3, parsed.querier_robustness_variable());
        assert_eq!(0x7f, parsed.querier_query_interval_code());
        assert_eq!(2, parsed.number_of_sources());
        assert_eq!(
            alloc::vec![SOURCE_1, SOURCE_2],
            parsed.source_addresses_iterator().collect::<Vec<_>>()
        );
    }

    #[test]
    fn mldv2_query_write_to_vec() {
        let query = Mldv2Query {
            maximum_response_code: 10,
            multicast_address: GROUP,
            suppress_router_side_processing: false,
            querier_robustness_variable: 1,
            querier_query_interval_code: 2,
            source_addresses: &[SOURCE_1],
        };

        let mut payload = Vec::new();
        query.write_to_vec(&mut payload).unwrap();
        assert_eq!(Mldv2Query::FIXED_PAYLOAD_LEN + 16, payload.len());
    }

    #[test]
    fn mldv2_report_write_to_slice() {
        let record = Mldv2MulticastAddressRecord {
            record_type: Mldv2MulticastAddressRecordType::BLOCK_OLD_SOURCES,
            multicast_address: GROUP,
            source_addresses: &[SOURCE_1, SOURCE_2],
            auxiliary_data: &[1, 2, 3, 4],
        };
        let records = [record];
        let report = Mldv2Report {
            multicast_address_records: &records,
        };

        let mut payload = [0u8; Mldv2MulticastAddressRecord::FIXED_LEN + 2 * 16 + 4];
        let len = report.write_to_slice(&mut payload).unwrap();
        assert_eq!(payload.len(), len);
        assert_eq!(payload.len(), report.payload_len().unwrap());

        let mut packet = Vec::new();
        packet.extend_from_slice(&Icmpv6Header::new(report.icmpv6_type().unwrap()).to_bytes());
        packet.extend_from_slice(&payload);

        let report = match MldSlice::from_slice(&packet).unwrap() {
            MldSlice::ListenerReportV2(value) => value,
            _ => panic!("expected mldv2 report"),
        };
        assert_eq!(1, report.number_of_multicast_address_records());

        let records = report
            .multicast_address_records_iterator()
            .collect::<Vec<_>>();
        assert_eq!(1, records.len());
        assert_eq!(
            Mldv2MulticastAddressRecordType::BLOCK_OLD_SOURCES,
            records[0].record_type()
        );
        assert_eq!(GROUP, records[0].multicast_address());
        assert_eq!(
            alloc::vec![SOURCE_1, SOURCE_2],
            records[0].source_addresses_iterator().collect::<Vec<_>>()
        );
        assert_eq!(&[1, 2, 3, 4], records[0].auxiliary_data());
    }

    #[test]
    fn mldv2_report_write_to_vec() {
        let record = Mldv2MulticastAddressRecord {
            record_type: Mldv2MulticastAddressRecordType::CHANGE_TO_INCLUDE_MODE,
            multicast_address: GROUP,
            source_addresses: &[SOURCE_1],
            auxiliary_data: &[],
        };
        let records = [record];
        let report = Mldv2Report {
            multicast_address_records: &records,
        };

        let mut payload = Vec::new();
        report.write_to_vec(&mut payload).unwrap();
        assert_eq!(Mldv2MulticastAddressRecord::FIXED_LEN + 16, payload.len());
    }

    #[cfg(feature = "std")]
    #[test]
    fn mldv2_query_write_io() {
        let query = Mldv2Query {
            maximum_response_code: 10,
            multicast_address: GROUP,
            suppress_router_side_processing: false,
            querier_robustness_variable: 1,
            querier_query_interval_code: 2,
            source_addresses: &[SOURCE_1],
        };

        let mut payload = Vec::new();
        query.write(&mut payload).unwrap();
        assert_eq!(Mldv2Query::FIXED_PAYLOAD_LEN + 16, payload.len());
    }

    #[test]
    fn mldv2_writer_errors() {
        let query = Mldv2Query {
            maximum_response_code: 10,
            multicast_address: GROUP,
            suppress_router_side_processing: false,
            querier_robustness_variable: 1,
            querier_query_interval_code: 2,
            source_addresses: &[SOURCE_1],
        };

        assert!(matches!(
            query
                .write_to_slice(&mut [0; Mldv2Query::FIXED_PAYLOAD_LEN])
                .unwrap_err(),
            MldBuildError::SliceWriteSpace(_)
        ));

        let record = Mldv2MulticastAddressRecord {
            record_type: Mldv2MulticastAddressRecordType::ALLOW_NEW_SOURCES,
            multicast_address: GROUP,
            source_addresses: &[],
            auxiliary_data: &[1, 2, 3],
        };
        assert_eq!(
            Err(MldBuildError::AuxiliaryDataLenUnaligned { actual: 3 }),
            record.record_len()
        );

        let too_many_sources = alloc::vec![SOURCE_1; usize::from(u16::MAX) + 1];
        let query = Mldv2Query {
            maximum_response_code: 10,
            multicast_address: GROUP,
            suppress_router_side_processing: false,
            querier_robustness_variable: 1,
            querier_query_interval_code: 2,
            source_addresses: &too_many_sources,
        };
        assert_eq!(
            Err(MldBuildError::SourceAddressCountTooBig {
                actual: usize::from(u16::MAX) + 1
            }),
            query.payload_len()
        );
    }

    #[test]
    fn mldv2_report_record_length_errors() {
        assert_eq!(
            Err(icmpv6_len_error(Mldv2MulticastAddressRecord::FIXED_LEN, 19)),
            Mldv2MulticastAddressRecordSlice::from_slice(&[0; 19])
        );

        let mut record = [0u8; Mldv2MulticastAddressRecord::FIXED_LEN];
        record[3] = 1;
        assert_eq!(
            Err(icmpv6_len_error(36, 20)),
            Mldv2MulticastAddressRecordSlice::from_slice(&record)
        );
    }

    #[test]
    fn mldv1_writer_checksum() {
        let query = Mldv1Query {
            maximum_response_delay: 1000,
            multicast_address: GROUP,
        };
        let payload = query.to_bytes();
        let header = Icmpv6Header::with_checksum(
            query.icmpv6_type(),
            Ipv6Addr::LOCALHOST.octets(),
            GROUP.octets(),
            &payload,
        )
        .unwrap();

        let mut packet = Vec::new();
        packet.extend_from_slice(&header.to_bytes());
        packet.extend_from_slice(&payload);

        assert!(Icmpv6Slice::from_slice(&packet)
            .unwrap()
            .is_checksum_valid(Ipv6Addr::LOCALHOST.octets(), GROUP.octets()));
    }

    #[test]
    fn mld_detection_and_unexpected_type_error() {
        assert!(MldSlice::is_mld_type_u8(
            icmpv6::TYPE_MULTICAST_LISTENER_QUERY
        ));
        assert!(MldSlice::is_mld_type_u8(
            icmpv6::TYPE_MULTICAST_LISTENER_REPORT
        ));
        assert!(MldSlice::is_mld_type_u8(
            icmpv6::TYPE_MULTICAST_LISTENER_DONE
        ));
        assert!(MldSlice::is_mld_type_u8(
            icmpv6::TYPE_MULTICAST_LISTENER_REPORT_V2
        ));
        assert!(!MldSlice::is_mld_type_u8(icmpv6::TYPE_ECHO_REQUEST));

        let header = Icmpv6Header::new(Icmpv6Type::EchoRequest(crate::IcmpEchoHeader {
            id: 1,
            seq: 2,
        }));
        let packet = header.to_bytes();
        let icmp = Icmpv6Slice::from_slice(&packet).unwrap();

        assert!(!icmp.is_mld());
        assert_eq!(
            Err(MldSliceError::UnexpectedIcmpv6Type {
                type_u8: icmpv6::TYPE_ECHO_REQUEST,
            }),
            icmp.mld_slice()
        );
    }
}
