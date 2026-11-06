// SPDX-License-Identifier: Apache-2.0

//! The kernel's one string encoder: every replacement a splice writes into a body goes through it.
//! Its bytes equal `serde_json::to_string`'s for every string, so the independent oracle checks it
//! byte for byte.

use crate::error::{ErrorKind, JsonError};

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Appends `s` to `out` as a quoted JSON string literal.
///
/// `"` and `\` are escaped; U+0008, U+000C, U+000A, U+000D and U+0009 become `\b \f \n \r \t`;
/// the other characters below U+0020 become `\u00xx` in lowercase hex. Everything else, `/`,
/// U+007F, U+2028 and non-ASCII included, is written as it is.
///
/// # Errors
///
/// [`ErrorKind::OutOfMemory`] when `out` cannot grow by the encoded length, which is reserved
/// before anything is written; `out` is then unchanged.
pub fn encode_str(s: &str, out: &mut Vec<u8>) -> Result<(), JsonError> {
    let bytes = s.as_bytes();
    let escaped: usize = bytes
        .iter()
        .map(|&byte| match byte {
            b'"' | b'\\' | 0x08 | 0x0C | b'\n' | b'\r' | b'\t' => 1,
            0x00..=0x1F => 5,
            _ => 0,
        })
        .sum();
    out.try_reserve(bytes.len() + escaped + 2)
        .map_err(|_| JsonError::new(ErrorKind::OutOfMemory, 0))?;
    out.push(b'"');
    let mut copied = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        let short: &[u8] = match byte {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            0x08 => b"\\b",
            0x0C => b"\\f",
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            b'\t' => b"\\t",
            0x00..=0x1F => b"",
            _ => continue,
        };
        out.extend_from_slice(bytes.get(copied..i).unwrap_or_default());
        if short.is_empty() {
            let high = HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'0');
            let low = HEX.get(usize::from(byte & 0x0F)).copied().unwrap_or(b'0');
            out.extend_from_slice(&[b'\\', b'u', b'0', b'0', high, low]);
        } else {
            out.extend_from_slice(short);
        }
        copied = i + 1;
    }
    out.extend_from_slice(bytes.get(copied..).unwrap_or_default());
    out.push(b'"');
    Ok(())
}
