//! EUI-48 MAC address type.
//!
//! This replaces the `advmac` crate, which does not compile on targets where
//! `c_char` is `u8` (aarch64, arm, riscv64, s390x): it unconditionally defines
//! both `TryFrom<&[u8]>` and `TryFrom<&[c_char]>`, and those collide there.
//! The bug is still present on advmac `master`, so there is nothing to upgrade
//! to.
//!
//! Not a verbatim copy of advmac, but derived from it: this was written
//! against advmac 1.0.3's source, and the accepted string formats, the
//! canonical output format and the `ParseMacError` variants intentionally
//! mirror it so existing reservation files and emitted events are unchanged.
//! `Display`, `Debug` and serde all produce the canonical uppercase dash form
//! `AA-BB-CC-DD-EE-FF`; parsing accepts dash, colon, dot, bare hex, and
//! `0x`-prefixed hex. Dropped from advmac's API: everything unused here, plus
//! the `c_char` conversions that caused the build failure.
//!
//! advmac is MIT licensed, Copyright (c) the advmac authors
//! <https://github.com/GamePad64/advmac>. The MIT terms in LICENSE-MIT apply
//! to the parts of this file derived from it.

use std::{
    fmt::{self, Debug, Display, Formatter},
    str::FromStr,
};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// MAC address, represented as EUI-48.
#[repr(transparent)]
#[derive(Default, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct MacAddr6([u8; 6]);

impl MacAddr6 {
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    /// Returns the octets of this MAC address, consuming it.
    // only the tests build raw wire bytes from a MacAddr6 today
    #[cfg_attr(not(test), allow(dead_code))]
    pub const fn to_array(self) -> [u8; 6] {
        self.0
    }

    /// Parse a MAC address in dash, colon, dot, bare hex or `0x` hex notation.
    pub fn parse_str(s: &str) -> Result<Self, ParseMacError> {
        let s = s.as_bytes();
        match s.len() {
            // AABBCCDDEEFF
            12 => from_hex(s),
            // 0xAABBCCDDEEFF
            14 if s[0] == b'0' && s[1] == b'x' => from_hex(&s[2..]),
            // AABB.CCDD.EEFF
            14 => from_separated(s, b'.', 4),
            // AA-BB-CC-DD-EE-FF or AA:BB:CC:DD:EE:FF
            17 => match s[2] {
                sep @ (b'-' | b':') => from_separated(s, sep, 2),
                _ => Err(ParseMacError::InvalidMac),
            },
            length => Err(ParseMacError::InvalidLength { length }),
        }
    }
}

/// Parse `2 * 6` hex digits.
fn from_hex(s: &[u8]) -> Result<MacAddr6, ParseMacError> {
    debug_assert_eq!(s.len(), 12);
    let mut octets = [0u8; 6];
    for (i, octet) in octets.iter_mut().enumerate() {
        *octet = (nibble(s[2 * i])? << 4) | nibble(s[2 * i + 1])?;
    }
    Ok(MacAddr6(octets))
}

/// Strip `sep` between every `group_len` hex digits, then parse what is left.
/// The caller has already checked that `s` has the length this grouping implies.
fn from_separated(s: &[u8], sep: u8, group_len: usize) -> Result<MacAddr6, ParseMacError> {
    let mut hex = [0u8; 12];
    let mut out = 0;
    for (i, &c) in s.iter().enumerate() {
        if (i + 1) % (group_len + 1) == 0 {
            if c != sep {
                return Err(ParseMacError::InvalidMac);
            }
        } else {
            hex[out] = c;
            out += 1;
        }
    }
    from_hex(&hex)
}

fn nibble(c: u8) -> Result<u8, ParseMacError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ParseMacError::InvalidMac),
    }
}

impl Display for MacAddr6 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02X}-{b:02X}-{c:02X}-{d:02X}-{e:02X}-{g:02X}")
    }
}

impl Debug for MacAddr6 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl From<[u8; 6]> for MacAddr6 {
    fn from(octets: [u8; 6]) -> Self {
        Self(octets)
    }
}

impl TryFrom<&[u8]> for MacAddr6 {
    type Error = ParseMacError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value
            .try_into()
            .map(Self)
            .map_err(|_| ParseMacError::InvalidLength {
                length: value.len(),
            })
    }
}

impl FromStr for MacAddr6 {
    type Err = ParseMacError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_str(s)
    }
}

impl Serialize for MacAddr6 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MacAddr6 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct MacVisitor;

        impl de::Visitor<'_> for MacVisitor {
            type Value = MacAddr6;

            fn expecting(&self, f: &mut Formatter<'_>) -> fmt::Result {
                f.write_str("a MAC address string")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                MacAddr6::parse_str(v).map_err(de::Error::custom)
            }
        }

        d.deserialize_str(MacVisitor)
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub enum ParseMacError {
    InvalidMac,
    InvalidLength { length: usize },
}

impl Display for ParseMacError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMac => write!(f, "invalid MAC address"),
            Self::InvalidLength { length } => write!(f, "invalid length: {length}"),
        }
    }
}

impl std::error::Error for ParseMacError {}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: MacAddr6 = MacAddr6::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    #[test]
    fn parses_every_accepted_notation() {
        for s in [
            "AA-BB-CC-DD-EE-FF",
            "aa-bb-cc-dd-ee-ff",
            "AA:BB:CC:DD:EE:FF",
            "AABB.CCDD.EEFF",
            "AABBCCDDEEFF",
            "0xAABBCCDDEEFF",
        ] {
            assert_eq!(MacAddr6::from_str(s).unwrap(), MAC, "failed to parse {s}");
        }
    }

    #[test]
    fn displays_canonical_dash_notation() {
        assert_eq!(MAC.to_string(), "AA-BB-CC-DD-EE-FF");
        assert_eq!(format!("{MAC:?}"), "AA-BB-CC-DD-EE-FF");
        assert_eq!(
            MacAddr6::new([0, 0x11, 0x22, 0x33, 0x44, 0x55]).to_string(),
            "00-11-22-33-44-55"
        );
    }

    #[test]
    fn rejects_malformed_strings() {
        for s in [
            "",
            "AA-BB-CC-DD-EE",       // too short
            "AA-BB-CC-DD-EE-FF-00", // too long
            "AA-BB-CC-DD-EE-GG",    // non-hex digit
            "AA-BB:CC-DD-EE-FF",    // mixed separators
            "AA.BB.CC.DD.EE.FF",    // wrong separator for its length
            "AABB-CCDD-EEFF",       // wrong grouping
            "0yAABBCCDDEEFF",       // bad prefix
            "AABBCCDDEEF",          // odd length
        ] {
            assert!(MacAddr6::from_str(s).is_err(), "wrongly parsed {s:?}");
        }
    }

    #[test]
    fn converts_from_byte_slices_of_exactly_six() {
        let bytes = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(MacAddr6::try_from(&bytes[..]).unwrap(), MAC);
        assert_eq!(MAC.to_array(), bytes);
        assert!(MacAddr6::try_from(&bytes[..5]).is_err());
        assert!(MacAddr6::try_from(&[0u8; 16][..]).is_err());
    }

    #[test]
    fn serde_round_trips_through_canonical_form() {
        let json = serde_json::to_string(&MAC).unwrap();
        assert_eq!(json, r#""AA-BB-CC-DD-EE-FF""#);
        assert_eq!(serde_json::from_str::<MacAddr6>(&json).unwrap(), MAC);
        // deserialization stays lenient about notation
        assert_eq!(
            serde_json::from_str::<MacAddr6>(r#""aabbccddeeff""#).unwrap(),
            MAC
        );
        assert!(serde_json::from_str::<MacAddr6>(r#""nope""#).is_err());
    }
}
