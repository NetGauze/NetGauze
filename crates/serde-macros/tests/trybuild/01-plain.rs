#[allow(unused_imports)]
#[allow(unused_variables)]

use netgauze_serde_macros::LocatedError;
use netgauze_parse_utils::Span;
use netgauze_parse_utils::LocatedParsingError;


#[derive(LocatedError, Eq, PartialEq, Debug, Clone)]
pub enum TestError {
    A,
    B,
}

fn main() {
    let span = Span::new(&[]);
    let error = TestError::A;
    let located = LocatedTestError::new(span, error.clone());
    assert_eq!(located.span(), &span);
    assert_eq!(located.error(), &error);
}