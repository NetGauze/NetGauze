use crate::{serde::tests::BGP_MARKER, BGPMessage};
use netgauze_parse_utils::test_helpers::{combine, test_parsed_completely};

#[test]
fn test_keep_alive() {
    let good_wire = combine(vec![&BGP_MARKER, &[0x00, 0x13, 0x04]]);

    let good = BGPMessage::KeepAlive;

    test_parsed_completely(&good_wire[..], &good);
}
