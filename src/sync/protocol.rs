//! Wire message types for the did-crdt sync protocol (CON-004).
//!
//! Three message variants are exchanged between peers via iroh-gossip:
//!
//! | Variant                    | Meaning                                          |
//! |----------------------------|--------------------------------------------------|
//! | [`SyncMessage::Announce`]  | "I have this DID at this state"                  |
//! | [`SyncMessage::Request`]   | "Send me deltas for this DID"                    |
//! | [`SyncMessage::Deltas`]    | "Here are signed deltas for this DID"            |
//!
//! Every cross-peer payload travels as authenticated [`SignedDelta`]s
//! (`DELTAS`); there is deliberately **no** wire message that ships a whole
//! materialised `Document`. State-based convergence ([`Document::merge_state`])
//! is a local/trusted-domain primitive and is intentionally not reachable from
//! the untrusted network — an untrusted peer can only extend a DID via signed
//! deltas, which are admitted through the full authorisation path.
//!
//! Messages are serialised with `serde` (JSON / CBOR / MessagePack) before
//! being handed to iroh-gossip for propagation.
//!
//! # Protocol flow (CON-004)
//!
//! 1. On connection: exchange `ANNOUNCE` for all locally-known DIDs.
//! 2. On receiving `ANNOUNCE` with unknown hash: send `REQUEST` (frontier).
//! 3. On receiving `REQUEST`: respond with `DELTAS` above the peer's frontier.
//! 4. On local delta creation: broadcast `ANNOUNCE` to all peers.
//! 5. Deduplication: track seen `(did, hash)` pairs; skip known states.

use serde::{Deserialize, Serialize};

use crate::core::delta::{DeltaHash, SignedDelta};
use crate::core::did::Did;
use crate::core::hlc::HlcTimestamp;

/// A BLAKE3-256 content hash encoded as 32 raw bytes.
pub type Blake3Hash = [u8; 32];

/// Messages exchanged between did-crdt peers via iroh-gossip (CON-004).
///
/// Serialised with a `"msg"` tag field whose value is the variant name in
/// `SCREAMING_SNAKE_CASE` (e.g. `{"msg":"ANNOUNCE", ...}`).
// No `PartialEq`: the `Deltas` variant carries `SignedDelta`, which is not
// `PartialEq`. Tests compare messages by their canonical serialisation instead.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SyncMessage {
    /// "I have this DID at this state."
    ///
    /// Broadcast on connection establishment (for all locally-known DIDs) and
    /// whenever a new local delta is applied.
    Announce {
        /// The DID whose state is being announced.
        did: Did,
        /// BLAKE3 hash of the current serialised [`Document`] state.
        hash: Blake3Hash,
        /// HLC clock value at the time of the announcement.
        clock: HlcTimestamp,
    },

    /// "Send me the deltas I lack for this DID, given my current frontier."
    ///
    /// Sent on receipt of an [`SyncMessage::Announce`] whose `hash` is not
    /// locally known. Frontier exchange (SPEC-036 REQ-366): the responder replies
    /// with exactly the deltas above this frontier — cost proportional to the
    /// divergence, not the history.
    Request {
        /// The DID whose deltas are being requested.
        did: Did,
        /// The requester's delta-DAG frontier (the hashes of its current heads).
        /// Empty requests the full history (a fresh or cold-start replica).
        frontier: Vec<DeltaHash>,
    },

    /// "Here are signed deltas for this DID."
    ///
    /// Sent in response to a [`SyncMessage::Request`] when the responder holds
    /// individual deltas for the requested DID.
    Deltas {
        /// The DID these deltas belong to.
        did: Did,
        /// Ordered list of signed deltas (ascending HLC order preferred).
        deltas: Vec<SignedDelta>,
    },
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::delta::{DeltaOp, SignedDelta};
    use crate::core::hlc::HlcTimestamp;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn sample_did() -> Did {
        format!("did:crdt:{}", "a".repeat(64)).parse().unwrap()
    }

    fn sample_ts() -> HlcTimestamp {
        HlcTimestamp { wall_ms: 1_000, logical: 0, node_id: 1 }
    }

    fn roundtrip(msg: &SyncMessage) -> SyncMessage {
        let json = serde_json::to_string(msg).expect("serialise");
        serde_json::from_str(&json).expect("deserialise")
    }

    fn msg_tag(msg: &SyncMessage) -> String {
        let v: serde_json::Value = serde_json::to_value(msg).unwrap();
        v["msg"].as_str().unwrap().to_owned()
    }

    // ── ANNOUNCE ──────────────────────────────────────────────────────────────

    #[test]
    fn announce_tag_is_screaming_snake_case() {
        let msg = SyncMessage::Announce {
            did: sample_did(),
            hash: [0u8; 32],
            clock: sample_ts(),
        };
        assert_eq!(msg_tag(&msg), "ANNOUNCE");
    }

    #[test]
    fn announce_roundtrip() {
        let msg = SyncMessage::Announce {
            did: sample_did(),
            hash: [1u8; 32],
            clock: sample_ts(),
        };
        assert_eq!(
            serde_json::to_string(&roundtrip(&msg)).unwrap(),
            serde_json::to_string(&msg).unwrap()
        );
    }

    #[test]
    fn announce_serialises_hash_as_array() {
        let hash = [42u8; 32];
        let msg = SyncMessage::Announce {
            did: sample_did(),
            hash,
            clock: sample_ts(),
        };
        let v: serde_json::Value = serde_json::to_value(&msg).unwrap();
        let arr = v["hash"].as_array().expect("hash must be a JSON array");
        assert_eq!(arr.len(), 32);
        assert!(arr.iter().all(|b| b.as_u64() == Some(42)));
    }

    // ── REQUEST ───────────────────────────────────────────────────────────────

    #[test]
    fn request_tag_is_screaming_snake_case() {
        let msg = SyncMessage::Request { did: sample_did(), frontier: vec![] };
        assert_eq!(msg_tag(&msg), "REQUEST");
    }

    #[test]
    fn request_roundtrip_empty_frontier() {
        let msg = SyncMessage::Request { did: sample_did(), frontier: vec![] };
        assert_eq!(
            serde_json::to_string(&roundtrip(&msg)).unwrap(),
            serde_json::to_string(&msg).unwrap()
        );
    }

    #[test]
    fn request_roundtrip_with_frontier() {
        let msg = SyncMessage::Request {
            did: sample_did(),
            frontier: vec![DeltaHash("a".repeat(64)), DeltaHash("b".repeat(64))],
        };
        assert_eq!(
            serde_json::to_string(&roundtrip(&msg)).unwrap(),
            serde_json::to_string(&msg).unwrap()
        );
    }

    #[test]
    fn request_empty_frontier_serialises_as_array() {
        let msg = SyncMessage::Request { did: sample_did(), frontier: vec![] };
        let v: serde_json::Value = serde_json::to_value(&msg).unwrap();
        assert!(v["frontier"].as_array().is_some_and(|a| a.is_empty()));
    }

    // ── DELTAS ────────────────────────────────────────────────────────────────

    #[test]
    fn deltas_tag_is_screaming_snake_case() {
        let msg = SyncMessage::Deltas { did: sample_did(), deltas: vec![] };
        assert_eq!(msg_tag(&msg), "DELTAS");
    }

    #[test]
    fn deltas_roundtrip_empty() {
        let msg = SyncMessage::Deltas { did: sample_did(), deltas: vec![] };
        assert_eq!(
            serde_json::to_string(&roundtrip(&msg)).unwrap(),
            serde_json::to_string(&msg).unwrap()
        );
    }

    #[test]
    fn deltas_roundtrip_with_payload() {
        let did = sample_did();
        let delta = SignedDelta::unsigned(
            did.clone(),
            DeltaOp::Deactivate,
            sample_ts(),
            format!("{}#key-0", did),
        );
        let msg = SyncMessage::Deltas { did: did.clone(), deltas: vec![delta] };
        let rt = roundtrip(&msg);
        // Structural equality via re-serialisation (SignedDelta doesn't derive PartialEq).
        assert_eq!(
            serde_json::to_string(&msg).unwrap(),
            serde_json::to_string(&rt).unwrap()
        );
    }

    // ── discriminant stability ────────────────────────────────────────────────

    #[test]
    fn all_three_tags_are_distinct() {
        let messages = [
            msg_tag(&SyncMessage::Announce {
                did: sample_did(),
                hash: [0u8; 32],
                clock: sample_ts(),
            }),
            msg_tag(&SyncMessage::Request { did: sample_did(), frontier: vec![] }),
            msg_tag(&SyncMessage::Deltas { did: sample_did(), deltas: vec![] }),
        ];
        let unique: std::collections::HashSet<_> = messages.iter().collect();
        assert_eq!(unique.len(), 3, "each variant must have a unique tag");
    }

    #[test]
    fn unknown_tag_deserialises_as_error() {
        let json = r#"{"msg":"UNKNOWN","did":"did:crdt:aaaa"}"#;
        let result: Result<SyncMessage, _> = serde_json::from_str(json);
        assert!(result.is_err(), "unknown tag must fail deserialisation");
    }
}
