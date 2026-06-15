//! `did:crdt` identifier type.
//!
//! A DID has the form `did:crdt:<blake3-hex>` where the hex is the BLAKE3-256
//! hash of the serialised creation delta.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::core::Error;

const METHOD: &str = "crdt";
const PREFIX: &str = "did:crdt:";

/// A `did:crdt` identifier.
///
/// The inner string is always a well-formed `did:crdt:<64-hex-chars>` value;
/// the invariant is enforced at construction and on deserialisation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Did(String);

impl Did {
    /// Construct a DID from the BLAKE3 hash of the creation delta bytes.
    pub fn from_creation_hash(hash: &blake3::Hash) -> Self {
        Self(format!("{PREFIX}{}", hash.to_hex()))
    }

    /// Return the method name (`"crdt"`).
    #[inline]
    pub fn method() -> &'static str {
        METHOD
    }

    /// Return the method-specific identifier (the 64-character hex portion).
    pub fn method_specific_id(&self) -> &str {
        self.0.strip_prefix(PREFIX).expect("invariant: valid did:crdt prefix")
    }

    /// Return the full DID string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ── Display ───────────────────────────────────────────────────────────────────

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── FromStr ───────────────────────────────────────────────────────────────────

impl FromStr for Did {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let id = s.strip_prefix(PREFIX).ok_or_else(|| Error::InvalidDid(s.to_owned()))?;
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::InvalidDid(s.to_owned()));
        }
        Ok(Self(s.to_owned()))
    }
}

// ── Serde ─────────────────────────────────────────────────────────────────────
//
// Serialise as a plain string; deserialise through `FromStr` so that the
// validation invariant is always enforced — no malformed DID can sneak in via
// untrusted input.

impl Serialize for Did {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse::<Did>().map_err(serde::de::Error::custom)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_hex() -> String {
        "a".repeat(64)
    }

    fn valid_did_str() -> String {
        format!("{PREFIX}{}", valid_hex())
    }

    // -- construction ---------------------------------------------------------

    #[test]
    fn from_creation_hash_roundtrip() {
        let hash = blake3::hash(b"genesis");
        let did = Did::from_creation_hash(&hash);
        assert_eq!(did.as_str(), format!("did:crdt:{}", hash.to_hex()));
        assert_eq!(did.method_specific_id(), hash.to_hex().as_str());
    }

    // -- display / as_str -----------------------------------------------------

    #[test]
    fn display_matches_as_str() {
        let did: Did = valid_did_str().parse().unwrap();
        assert_eq!(did.to_string(), did.as_str());
    }

    // -- FromStr happy paths --------------------------------------------------

    #[test]
    fn parse_valid_lowercase_hex() {
        let s = format!("{PREFIX}{}", "deadbeef".repeat(8));
        let did: Did = s.parse().expect("should parse");
        assert_eq!(did.as_str(), s);
    }

    #[test]
    fn parse_valid_uppercase_hex() {
        let s = format!("{PREFIX}{}", "DEADBEEF".repeat(8));
        let did: Did = s.parse().expect("uppercase hex should parse");
        assert_eq!(did.as_str(), s);
    }

    // -- FromStr error paths --------------------------------------------------

    #[test]
    fn parse_wrong_method_fails() {
        assert!("did:key:abc".parse::<Did>().is_err());
    }

    #[test]
    fn parse_missing_prefix_fails() {
        assert!(valid_hex().parse::<Did>().is_err());
    }

    #[test]
    fn parse_short_hash_fails() {
        let s = format!("{PREFIX}{}", "aa".repeat(31)); // 62 hex chars, not 64
        assert!(s.parse::<Did>().is_err());
    }

    #[test]
    fn parse_long_hash_fails() {
        let s = format!("{PREFIX}{}", "aa".repeat(33)); // 66 hex chars
        assert!(s.parse::<Did>().is_err());
    }

    #[test]
    fn parse_non_hex_chars_fails() {
        let s = format!("{PREFIX}{}zz", "aa".repeat(31)); // contains 'z'
        assert!(s.parse::<Did>().is_err());
    }

    #[test]
    fn parse_empty_id_fails() {
        assert!(format!("{PREFIX}").parse::<Did>().is_err());
    }

    // -- Serde ----------------------------------------------------------------

    #[test]
    fn serialize_as_plain_string() {
        let did: Did = valid_did_str().parse().unwrap();
        let json = serde_json::to_string(&did).unwrap();
        assert_eq!(json, format!("\"{}\"", valid_did_str()));
    }

    #[test]
    fn deserialize_valid_did() {
        let json = format!("\"{}\"", valid_did_str());
        let did: Did = serde_json::from_str(&json).unwrap();
        assert_eq!(did.as_str(), valid_did_str());
    }

    #[test]
    fn deserialize_invalid_did_returns_error() {
        let json = "\"did:key:invalidkey\"";
        assert!(serde_json::from_str::<Did>(json).is_err());
    }

    #[test]
    fn serde_roundtrip() {
        let original: Did = valid_did_str().parse().unwrap();
        let json = serde_json::to_string(&original).unwrap();
        let recovered: Did = serde_json::from_str(&json).unwrap();
        assert_eq!(original, recovered);
    }
}
