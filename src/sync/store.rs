//! iroh-blobs persistence layer for `Document` state.
//!
//! Stores serialised CRDT state as content-addressed blobs and pins snapshot
//! hashes so that GC does not evict live documents.
//!
//! # Design
//!
//! Each [`BlobStore::save`] call:
//!
//! 1. Serialises the `Document` to compact JSON bytes.
//! 2. Imports those bytes into the blobs store as a raw blob — iroh-blobs
//!    computes the BLAKE3-256 hash of the content automatically.
//! 3. Persists a named tag `did:<method-specific-id>` that points at the
//!    latest `(hash, Raw)` pair.  The tag keeps the blob alive through GC
//!    cycles; updating it to a newer hash automatically releases the pin on
//!    older snapshots so they can be collected.
//!
//! [`BlobStore::load`] looks up a blob by its BLAKE3 hash and deserialises
//! the bytes back into a `Document`.
//!
//! [`BlobStore::latest_hash`] resolves the named tag for a DID to its current
//! snapshot hash without deserialising the full document.
//!
//! # Generics
//!
//! `BlobStore<S>` is generic over any type that implements
//! `iroh_blobs::store::Store`.  Call [`BlobStore::new_in_memory`] for a
//! self-contained ephemeral store, or [`BlobStore::new`] to wrap an existing
//! store (e.g. the persistent `iroh_blobs::store::fs::Store`).

use bytes::Bytes;
use iroh_blobs::{
    store::{mem::Store as MemStore, MapEntry, Store as IrohStore},
    BlobFormat, Hash, HashAndFormat, Tag,
};
use iroh_io::AsyncSliceReaderExt as _;

use crate::core::{did::Did, document::Document};

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors produced by the blob-store layer.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// JSON serialisation / deserialisation failure.
    #[error("serialisation error: {0}")]
    Serialisation(#[from] serde_json::Error),

    /// I/O error from the underlying iroh-blobs store.
    #[error("store i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// Pure-core error (delta/document serialisation or validation).
    #[error("core error: {0}")]
    Core(#[from] crate::core::Error),
}

/// Result alias for the blob-store layer.
pub type Result<T> = std::result::Result<T, StoreError>;

// ── BlobStore ─────────────────────────────────────────────────────────────────

/// Content-addressed store for `Document` CRDT snapshots backed by iroh-blobs.
///
/// See the [module-level documentation](self) for the design overview.
pub struct BlobStore<S> {
    inner: S,
}

// ── Constructor for the default in-memory store ───────────────────────────────

impl BlobStore<MemStore> {
    /// Create a `BlobStore` backed by an ephemeral in-memory blobs store.
    ///
    /// Suitable for unit tests and short-lived processes.  All blobs are lost
    /// when the store is dropped.
    pub fn new_in_memory() -> Self {
        Self {
            inner: MemStore::new(),
        }
    }
}

// ── Generic constructor ───────────────────────────────────────────────────────

impl<S: IrohStore> BlobStore<S> {
    /// Wrap an existing iroh-blobs store.
    pub fn new(store: S) -> Self {
        Self { inner: store }
    }

    // ── write path ───────────────────────────────────────────────────────────

    /// Persist a `Document` snapshot in the blobs store.
    ///
    /// The document is serialised to compact JSON and imported as a raw blob.
    /// A named tag is created (or updated) so that the snapshot is pinned
    /// against GC: `did:<method-specific-id>` → `(hash, Raw)`.
    ///
    /// # Returns
    ///
    /// The [`Hash`] of the persisted blob (BLAKE3 over the serialised bytes,
    /// which include the delta log so the DAG can be rebuilt on load). For a
    /// log-independent state identity, use [`Document::content_hash`].
    pub async fn save(&self, doc: &Document) -> Result<Hash> {
        let bytes = Bytes::from(doc.to_bytes()?);

        // Import into the blobs store; iroh-blobs derives the BLAKE3 hash.
        let temp_tag = self.inner.import_bytes(bytes, BlobFormat::Raw).await?;
        let hash = *temp_tag.hash();

        // Pin under a stable tag so GC cannot evict this snapshot.
        let tag = did_tag(doc.did.as_str());
        self.inner
            .set_tag(
                tag,
                Some(HashAndFormat {
                    hash,
                    format: BlobFormat::Raw,
                }),
            )
            .await?;

        Ok(hash)
    }

    // ── read path ────────────────────────────────────────────────────────────

    /// Retrieve a `Document` by its BLAKE3 snapshot hash.
    ///
    /// Returns `None` if no blob with the given hash is present in the store.
    pub async fn load(&self, hash: Hash) -> Result<Option<Document>> {
        let Some(entry) = self.inner.get(&hash).await? else {
            return Ok(None);
        };

        let mut reader = entry.data_reader().await?;
        let bytes = reader.read_to_end().await?;
        let doc = Document::from_bytes(&bytes)?;

        Ok(Some(doc))
    }

    /// Look up the hash of the most-recently-saved snapshot for a DID.
    ///
    /// Returns `None` if no snapshot for `did` has been pinned in this store.
    /// Does not deserialise the document bytes; useful for cheap divergence
    /// checks (compare with a remote peer's announced hash before deciding
    /// whether to fetch).
    pub async fn latest_hash(&self, did: &Did) -> Result<Option<Hash>> {
        let target = did_tag(did.as_str());
        let tags = self.inner.tags().await?;
        for item in tags {
            let (tag, hf) = item?;
            if tag == target {
                return Ok(Some(hf.hash));
            }
        }
        Ok(None)
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Build the GC-pin tag name for a DID's latest snapshot.
///
/// The tag name is the full DID string, e.g. `did:crdt:<64-hex-chars>`.
/// iroh-blobs tags are free-form byte strings, so any valid DID is a legal
/// tag name.
fn did_tag(did_str: &str) -> Tag {
    Tag::from(did_str)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::document::Document;

    fn make_store() -> BlobStore<MemStore> {
        BlobStore::new_in_memory()
    }

    fn make_doc() -> Document {
        let (doc, _) = Document::new("zTestKey").expect("new() must succeed");
        doc
    }

    // ── save / load round-trip ────────────────────────────────────────────────

    #[tokio::test]
    async fn save_returns_hash_and_load_recovers_document() {
        let store = make_store();
        let doc = make_doc();
        let did = doc.did.clone();

        let hash = store.save(&doc).await.expect("save must succeed");
        let loaded = store.load(hash).await.expect("load must succeed");
        let loaded = loaded.expect("document must be present");

        assert_eq!(loaded.did, did);
        assert_eq!(
            loaded.verification_methods.entries(),
            doc.verification_methods.entries()
        );
    }

    #[tokio::test]
    async fn save_is_deterministic_for_same_state() {
        let store = make_store();
        let doc = make_doc();

        let h1 = store.save(&doc).await.unwrap();
        let h2 = store.save(&doc).await.unwrap();
        assert_eq!(h1, h2, "same document state must produce the same hash");
    }

    #[tokio::test]
    async fn load_returns_none_for_unknown_hash() {
        let store = make_store();
        // A hash with all-zero bytes is extremely unlikely to collide with
        // any real blob content.
        let absent_hash = Hash::from_bytes([0u8; 32]);
        let result = store.load(absent_hash).await.unwrap();
        assert!(result.is_none(), "absent hash must yield None");
    }

    // ── hash matches document content_hash ───────────────────────────────────

    #[tokio::test]
    async fn save_hash_differs_from_content_hash_and_is_stable() {
        let store = make_store();
        let doc = make_doc();

        let iroh_hash = store.save(&doc).await.unwrap();
        let core_hash = doc.content_hash().unwrap();

        // The blob hash is BLAKE3 over `to_bytes()` (which carries the delta log);
        // `content_hash()` is BLAKE3 over the CRDT-state tuple. They are different
        // by construction (see store::save docs) and MUST NOT be equated.
        assert_ne!(
            iroh_hash.as_bytes(),
            core_hash.as_bytes(),
            "blob hash (over to_bytes incl. log) differs from content_hash (state tuple)"
        );
        // The blob hash is deterministic for the same serialised document.
        let iroh_hash_again = store.save(&doc).await.unwrap();
        assert_eq!(
            iroh_hash.as_bytes(),
            iroh_hash_again.as_bytes(),
            "blob hash is stable"
        );
    }

    // ── tag pinning / latest_hash ─────────────────────────────────────────────

    #[tokio::test]
    async fn latest_hash_returns_none_before_any_save() {
        let store = make_store();
        let doc = make_doc();
        let result = store.latest_hash(&doc.did).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn latest_hash_returns_correct_hash_after_save() {
        let store = make_store();
        let doc = make_doc();

        let saved_hash = store.save(&doc).await.unwrap();
        let pinned_hash = store.latest_hash(&doc.did).await.unwrap();
        assert_eq!(pinned_hash, Some(saved_hash));
    }

    #[tokio::test]
    async fn latest_hash_updates_after_second_save() {
        use crate::core::{delta::DeltaOp, delta::SignedDelta, hlc::HlcTimestamp};

        let store = make_store();
        let mut doc = make_doc();

        let hash_v1 = store.save(&doc).await.unwrap();

        // Mutate the document so a second save produces a different hash.
        let signer = doc.verification_methods.entries()[0].id.clone();
        let ts = HlcTimestamp {
            wall_ms: 100,
            logical: 0,
            node_id: 1,
        };
        let mut delta = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "cred-001".to_owned(),
            },
            ts,
            signer,
        );
        delta.parents = doc.frontier();
        doc.merge(delta).unwrap();

        let hash_v2 = store.save(&doc).await.unwrap();
        assert_ne!(
            hash_v1, hash_v2,
            "mutated document must produce different hash"
        );

        // The tag should now point at the newer hash.
        let pinned = store.latest_hash(&doc.did).await.unwrap();
        assert_eq!(pinned, Some(hash_v2));
    }

    // ── different DIDs get different tags ─────────────────────────────────────

    #[tokio::test]
    async fn two_documents_have_independent_tags() {
        let store = make_store();
        let (doc_a, _) = Document::new("zKeyA").unwrap();
        let (doc_b, _) = Document::new("zKeyB").unwrap();

        let ha = store.save(&doc_a).await.unwrap();
        let hb = store.save(&doc_b).await.unwrap();
        assert_ne!(ha, hb);

        assert_eq!(store.latest_hash(&doc_a.did).await.unwrap(), Some(ha));
        assert_eq!(store.latest_hash(&doc_b.did).await.unwrap(), Some(hb));
    }
}
