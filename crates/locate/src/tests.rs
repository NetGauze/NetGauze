use super::BinarySpan;
use nom::{
    bytes::complete::take, Compare, CompareResult, FindSubstring, FindToken, InputIter, Offset,
    Slice,
};

type StrSpan<'a> = BinarySpan<&'a str>;
type BytesSpan<'a> = BinarySpan<&'a [u8]>;

#[test]
fn new_sould_be_the_same_as_new_extra() {
    let byteinput = &b"foobar"[..];
    assert_eq!(BytesSpan::new(byteinput), BinarySpan::new_extra(byteinput));
    let strinput = "foobar";
    assert_eq!(StrSpan::new(strinput), BinarySpan::new_extra(strinput));
}

#[test]
fn it_should_call_new_for_u8_successfully() {
    let input = &b"foobar"[..];
    let output = BytesSpan {
        offset: 0,
        fragment: input,
    };

    assert_eq!(BytesSpan::new(input), output);
}

#[test]
fn it_should_convert_from_u8_successfully() {
    let input = &b"foobar"[..];
    assert_eq!(BytesSpan::new(input), input.into());
}

#[test]
fn it_should_call_new_for_str_successfully() {
    let input = "foobar";
    let output = StrSpan {
        offset: 0,
        fragment: input,
    };

    assert_eq!(StrSpan::new(input), output);
}

#[test]
fn it_should_convert_from_str_successfully() {
    let input = "foobar";
    assert_eq!(StrSpan::new(input), input.into());
}

#[test]
fn it_should_iterate_indices() {
    let str_slice = StrSpan::new("foobar");
    assert_eq!(
        str_slice.iter_indices().collect::<Vec<(usize, char)>>(),
        vec![(0, 'f'), (1, 'o'), (2, 'o'), (3, 'b'), (4, 'a'), (5, 'r')]
    );
    assert_eq!(
        StrSpan::new("")
            .iter_indices()
            .collect::<Vec<(usize, char)>>(),
        vec![]
    );
}

#[test]
fn it_should_iterate_elements() {
    let str_slice = StrSpan::new("foobar");
    assert_eq!(
        str_slice.iter_elements().collect::<Vec<char>>(),
        vec!['f', 'o', 'o', 'b', 'a', 'r']
    );
    assert_eq!(
        StrSpan::new("").iter_elements().collect::<Vec<char>>(),
        vec![]
    );
}

#[test]
fn it_should_position_char() {
    let str_slice = StrSpan::new("foobar");
    assert_eq!(str_slice.position(|x| x == 'a'), Some(4));
    assert_eq!(str_slice.position(|x| x == 'c'), None);
}

#[test]
fn it_should_compare_elements() {
    assert_eq!(StrSpan::new("foobar").compare("foo"), CompareResult::Ok);
    assert_eq!(StrSpan::new("foobar").compare("bar"), CompareResult::Error);
    assert_eq!(StrSpan::new("foobar").compare("foobar"), CompareResult::Ok);
    assert_eq!(
        StrSpan::new("foobar").compare_no_case("fooBar"),
        CompareResult::Ok
    );
    assert_eq!(
        StrSpan::new("foobar").compare("foobarbaz"),
        CompareResult::Incomplete
    );
    assert_eq!(
        BytesSpan::new(b"foobar").compare(b"foo" as &[u8]),
        CompareResult::Ok
    );
}

#[test]
#[allow(unused_parens, clippy::double_parens)]
fn it_should_find_token() {
    assert!(StrSpan::new("foobar").find_token('a'));
    assert!(StrSpan::new("foobar").find_token(b'a'));
    assert!(StrSpan::new("foobar").find_token(&(b'a')));
    assert!(!StrSpan::new("foobar").find_token('c'));
    assert!(!StrSpan::new("foobar").find_token(b'c'));
    assert!(!StrSpan::new("foobar").find_token((&b'c')));

    assert!(BytesSpan::new(b"foobar").find_token(b'a'));
    assert!(BytesSpan::new(b"foobar").find_token(&(b'a')));
    assert!(!BytesSpan::new(b"foobar").find_token(b'c'));
    assert!(!BytesSpan::new(b"foobar").find_token((&b'c')));
}

#[test]
fn it_should_find_substring() {
    assert_eq!(StrSpan::new("foobar").find_substring("bar"), Some(3));
    assert_eq!(StrSpan::new("foobar").find_substring("baz"), None);
    assert_eq!(BytesSpan::new(b"foobar").find_substring("bar"), Some(3));
    assert_eq!(BytesSpan::new(b"foobar").find_substring("baz"), None);
    assert_eq!(
        BytesSpan::new(b"foobar").find_substring(b"bar" as &[u8]),
        Some(3)
    );
    assert_eq!(
        BytesSpan::new(b"foobar").find_substring(b"baz" as &[u8]),
        None
    );
}

// https://github.com/Geal/nom/blob/eee82832fafdfdd0505546d224caa466f7d39a15/src/util.rs#L710-L720
#[test]
fn it_should_calculate_offset_for_u8() {
    let s = b"abcd123";
    let a = &s[..];
    let b = &a[2..];
    let c = &a[..4];
    let d = &a[3..5];
    assert_eq!(a.offset(b), 2);
    assert_eq!(a.offset(c), 0);
    assert_eq!(a.offset(d), 3);
}

// https://github.com/Geal/nom/blob/eee82832fafdfdd0505546d224caa466f7d39a15/src/util.rs#L722-L732
#[test]
fn it_should_calculate_offset_for_str() {
    let s = StrSpan::new("abcřèÂßÇd123");
    let a = s.slice(..);
    let b = a.slice(7..);
    let c = a.slice(..5);
    let d = a.slice(5..9);
    assert_eq!(a.offset(&b), 7);
    assert_eq!(a.offset(&c), 0);
    assert_eq!(a.offset(&d), 5);
}

#[test]
fn it_should_capture_position() {
    use nom::{bytes::complete::tag, IResult};

    fn parser(s: BytesSpan<'_>) -> IResult<BytesSpan<'_>, (BytesSpan<'_>, &[u8])> {
        let (s, _) = take(2usize)(s)?;
        let (s, t) = tag([3u8])(s)?;
        Ok((s, (s, t.fragment())))
    }

    let s = BytesSpan::new(&[1, 2, 3, 4, 5]);
    let (_, (s, t)) = parser(s).unwrap();
    assert_eq!(s.offset, 3);
    assert_eq!(t, [3]);
}
