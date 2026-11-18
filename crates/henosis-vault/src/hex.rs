//! Strict lowercase hexadecimal encoding and decoding without extra crates.

use std::fmt;

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    OddLength,
    WrongLength { expected: usize, actual: usize },
    InvalidByte,
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OddLength => f.write_str("hex string must have an even number of digits"),
            Self::WrongLength { expected, actual } => {
                write!(f, "expected {expected} decoded bytes, got {actual}")
            }
            Self::InvalidByte => f.write_str("hex string must use lowercase ASCII hex digits"),
        }
    }
}

impl std::error::Error for HexError {}

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX_LOWER[(byte >> 4) as usize] as char);
        out.push(HEX_LOWER[(byte & 0x0f) as usize] as char);
    }
    out
}

fn nibble(byte: u8) -> Result<u8, HexError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(HexError::InvalidByte),
    }
}

/// Decode strict lowercase ASCII hex into bytes.
pub fn decode(text: &str) -> Result<Vec<u8>, HexError> {
    if !text.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    let raw = text.as_bytes();
    let mut out = Vec::with_capacity(raw.len() / 2);
    let mut idx = 0;
    while idx < raw.len() {
        let hi = nibble(raw[idx])?;
        let lo = nibble(raw[idx + 1])?;
        out.push((hi << 4) | lo);
        idx += 2;
    }
    Ok(out)
}

/// Decode strict lowercase ASCII hex into a fixed-length array.
pub fn decode_array<const N: usize>(text: &str) -> Result<[u8; N], HexError> {
    if !text.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    if text.len() != N * 2 {
        return Err(HexError::WrongLength {
            expected: N,
            actual: text.len() / 2,
        });
    }
    let mut out = [0u8; N];
    let raw = text.as_bytes();
    for (slot, pair) in out.iter_mut().zip(raw.array_chunks::<2>()) {
        *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_uppercase_or_wrong_lengths() {
        let input = [0x00, 0x0f, 0xa5, 0xff];
        let encoded = encode(&input);
        assert_eq!(encoded, "000fa5ff");
        assert_eq!(decode(&encoded).unwrap(), input);
        assert_eq!(decode_array::<4>(&encoded).unwrap(), input);
        assert_eq!(decode("00F").unwrap_err(), HexError::OddLength);
        assert_eq!(decode("00AF").unwrap_err(), HexError::InvalidByte);
        assert_eq!(
            decode_array::<2>(&encoded).unwrap_err(),
            HexError::WrongLength {
                expected: 2,
                actual: 4
            }
        );
    }
}
