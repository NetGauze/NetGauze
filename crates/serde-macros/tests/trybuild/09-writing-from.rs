#[allow(unused_imports)]
#[allow(unused_variables)]

use netgauze_serde_macros::WritingError;


#[derive(WritingError, Eq, PartialEq, Debug, Clone)]
pub enum TestError {
    A(#[from_std_io_error] String),
    B(#[from] BError),
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub enum BError {
    B,
}

fn main() {
    let b_error = BError::B;
    let test_error: TestError = b_error.into();
    assert_eq!(test_error, TestError::B(BError::B));
}