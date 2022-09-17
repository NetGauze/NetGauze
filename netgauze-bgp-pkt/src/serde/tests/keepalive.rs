use crate::{
    serde::{serializer::BGPMessageWritingError, tests::BGP_MARKER},
    BGPMessage,
};
use netgauze_parse_utils::test_helpers::{
    combine, test_parsed_completely_with_one_input, test_write,
};

#[test]
fn test_keep_alive() -> Result<(), BGPMessageWritingError> {
    let good_wire = combine(vec![&BGP_MARKER, &[0x00, 0x13, 0x04]]);

    let good = BGPMessage::KeepAlive;

    test_parsed_completely_with_one_input(&good_wire[..], false, &good);
    test_parsed_completely_with_one_input(&good_wire[..], true, &good);

    test_write(&good, &good_wire[..])?;
    Ok(())
}
