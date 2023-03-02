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
    NomErrorA(#[from_nom] ErrorKind),
    NomErrorB(#[from_nom] ErrorKind),
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub enum AError {
    A
}

fn parse(buf: Span<'_>, ) -> IResult<Span<'_>, u8, LocatedTestError> {
    let (buf, ret) = be_u8(buf)?;
    Ok((buf, ret))
}

fn main() {}