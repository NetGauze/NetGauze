#[allow(unused_imports)]
#[allow(unused_variables)]

use netgauze_serde_macros::LocatedError;
use netgauze_parse_utils::Span;

use nom::{
    error::ErrorKind,
    number::complete::be_u8,
    IResult,
};


#[derive(LocatedError, Eq, PartialEq, Debug, Clone)]
pub enum TestError {
    NomError(#[from_nom] ErrorKind),
    A(AError),
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub enum AError {
    A
}

fn parse(buf: Span<'_>, ) -> IResult<Span<'_>, u8, LocatedTestError> {
    let (buf, ret) = nom::combinator::map_res(be_u8, |_| Err(AError::A))(buf)?;
    Ok((buf, ret))
}

fn main() {
    let span = Span::new(&[1]);
    let parsed = parse(span);
    assert_eq!(parsed, Err(nom::Err::Error(LocatedTestError::new(span, TestError::A(AError::A)))))
}