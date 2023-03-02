#[allow(unused_imports)]
#[allow(unused_variables)]

use netgauze_serde_macros::WritingError;


#[derive(WritingError, Eq, PartialEq, Debug, Clone)]
pub enum TestError {
    A,
    B,
}

fn main() {}