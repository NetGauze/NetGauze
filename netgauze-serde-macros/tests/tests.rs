#[test]
fn macro_tests() {
    let test_cases = trybuild::TestCases::new();
    test_cases.pass("tests/trybuild/01-plain.rs");
    test_cases.pass("tests/trybuild/02-from-external.rs");
    test_cases.compile_fail("tests/trybuild/03-from-external-not-defined.rs");
    test_cases.pass("tests/trybuild/04-from-located.rs");
    test_cases.compile_fail("tests/trybuild/05-from-located-no-module.rs");
    test_cases.compile_fail("tests/trybuild/06-from-nom-multiple.rs");
    test_cases.pass("tests/trybuild/07-writing-plain.rs");
    test_cases.pass("tests/trybuild/08-writing-from-std-io-error.rs");
    test_cases.pass("tests/trybuild/09-writing-from.rs");
}
