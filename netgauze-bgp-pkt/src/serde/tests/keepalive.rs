use crate::{
    serde::{serializer::BGPMessageWritingError, tests::BGP_MARKER},
    BGPMessage,
};
use netgauze_parse_utils::test_helpers::{combine, test_parsed_completely, test_write};

#[test]
fn test_keep_alive() -> Result<(), BGPMessageWritingError> {
    let good_wire = combine(vec![&BGP_MARKER, &[0x00, 0x13, 0x04]]);

    let good = BGPMessage::KeepAlive;

    test_parsed_completely(&good_wire[..], &good);

    test_write(&good, &good_wire[..])?;
    Ok(())
}
