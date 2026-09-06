use std::fmt::Write as _;

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

#[test]
fn digest_bytes_are_encoded_as_lowercase_hex() {
    assert_eq!(encode_hex(&[0x00, 0x0f, 0x10, 0xff]), "000f10ff");
}
