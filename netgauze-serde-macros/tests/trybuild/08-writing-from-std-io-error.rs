#[allow(unused_imports)]
#[allow(unused_variables)]

use netgauze_serde_macros::WritingError;


#[derive(WritingError, Eq, PartialEq, Debug, Clone)]
pub enum TestError {
    A(#[from_std_io_error] String),
    B,
}

fn main() {
    let std_error = std::io::Error::last_os_error();
    let msg = std_error.to_string();
    let test_error: TestError = std_error.into();
    assert_eq!(test_error, TestError::A(msg));
}