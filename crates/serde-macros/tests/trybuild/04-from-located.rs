#[allow(unused_imports)]
#[allow(unused_variables)]

use netgauze_serde_macros::LocatedError;
use netgauze_parse_utils::Span;

use nom::{
    error::ErrorKind,
    IResult,
};


#[derive(LocatedError, Eq, PartialEq, Debug, Clone)]
pub enum TestError {
    NomError(#[from_nom] ErrorKind),
    A(#[from_located(module = "self")] AError),
}

#[derive(LocatedError, Eq, PartialEq, Debug, Clone)]
pub enum AError {
    A
}

fn parse_a(buf: Span<'_>) -> IResult<Span<'_>, u8, LocatedAError<'_>> {
    Err(nom::Err::Error(LocatedAError::new(buf, AError::A)))
}

fn parse(buf: Span<'_>) -> IResult<Span<'_>, u8, LocatedTestError<'_>> {
    match parse_a(buf) {
        Ok((buf, ret)) => Ok((buf, ret)),
        Err(err) => match err {
            nom::Err::Incomplete(needed) => Err(nom::Err::Incomplete(needed)),
            nom::Err::Error(error) => Err(nom::Err::Error(error.into())),
            nom::Err::Failure(failure) => Err(nom::Err::Failure(failure.into())),
        }
    }
}

fn main() {
    let span = Span::new(&[1]);
    let parsed = parse(span);
    assert_eq!(parsed, Err(nom::Err::Error(LocatedTestError::new(span, TestError::A(AError::A)))))
}