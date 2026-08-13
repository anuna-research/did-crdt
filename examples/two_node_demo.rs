//! Demo: two did-crdt service instances converging via DHT discovery.
//!
//! Spins up two in-process HTTP servers.  Node A creates the DID and
//! publishes its address to a shared in-process pkarr relay stub (standing
//! in for the real DHT).  Node B starts with an empty DocStore and *no*
//! knowledge of node A's address; when asked to resolve the DID it performs
//! a DHT lookup, discovers node A, connects, and bootstraps the full delta
//! history automatically (CON-006 cold-start resolution).  A signed delta is
//! then submitted to node A; on the next GET node B detects the new
//! versionId and converges.
//!
//! Run with:
//!   cargo run --example two_node_demo --features service,sync

use std::collections::HashMap;
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64ct::{Base64UrlUnpadded, Encoding as _};
use did_crdt::core::delta::{DeltaOp, SignedDelta, SigningKey};
use did_crdt::core::hlc::HlcTimestamp;
use did_crdt::core::validate::node_id_from_pubkey;
use did_crdt::service::metrics::Metrics;
use did_crdt::service::server::{build_router, AppState};
use did_crdt::sync::dht::DhtNode;
use did_crdt::sync::live::{topic_for, LiveNode};
use did_crdt::Document;
use pkarr::SignedPacket;
use serde_json::Value;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let sep = "═".repeat(55);
    println!("\n{sep}");
    println!("  did-crdt two-node DHT discovery demo");
    println!("{sep}");
    println!("  Node B discovers node A via DHT — no manual peering.");
    println!("{sep}\n");

    // ── [1/6] Keypair + DID ───────────────────────────────────────────────────
    println!("[1/6] Generating Ed25519 keypair …");
    let raw = [0x42u8; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&raw);
    let pk_mb = format!(
        "u{}",
        Base64UrlUnpadded::encode_string(sk.verifying_key().as_bytes())
    );
    let (doc_template, genesis_delta) = Document::new(&pk_mb)?;
    let did = doc_template.did.clone();
    let did_str = did.to_string();
    let genesis_hash = genesis_delta.content_hash()?;
    println!("      DID: {did_str}\n");

    // ── Shared in-process DHT stores ─────────────────────────────────────────
    // Both nodes share these Arcs so publish on A is immediately visible to
    // lookup on B — a stand-in for the real pkarr relay network.
    let pkarr_store: Arc<Mutex<HashMap<[u8; 32], SignedPacket>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let addr_store: Arc<Mutex<HashMap<[u8; 32], iroh::net::NodeAddr>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // ── [2/6] Node A ──────────────────────────────────────────────────────────
    println!("[2/6] Starting node A (with DHT) …");
    let topic = topic_for(b"did-crdt/two-node-demo");
    let docs_a = did_crdt::DocStore::new();
    let dht_a = Arc::new(DhtNode::new_in_process(
        pkarr_store.clone(),
        addr_store.clone(),
        Duration::from_secs(5),
    ));
    let node_a = LiveNode::bind(topic, docs_a.clone(), Some(dht_a.clone()), false).await?;
    let _task_a = node_a.spawn();
    node_a.seed().await?;
    let a_node_id = node_a.node_id();
    println!("      iroh node id: {a_node_id}");

    let state_a = AppState {
        docs: docs_a.clone(),
        live_node: Some(Arc::new(node_a)),
        dht: Some(dht_a),
        metrics: Arc::new(Metrics::new()),
        resolve_timeout: Duration::from_secs(10),
    };
    let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr_a = listener_a.local_addr()?;
    tokio::spawn(async move {
        axum::serve(listener_a, build_router(state_a))
            .await
            .unwrap()
    });
    println!("      HTTP: http://{addr_a}\n");

    // ── [3/6] Node B ──────────────────────────────────────────────────────────
    // Node B has *no* knowledge of node A's address — it will discover it
    // via DHT lookup when it first tries to resolve an unknown DID.
    println!("[3/6] Starting node B (empty DocStore, no manual peering) …");
    let docs_b = did_crdt::DocStore::new();
    let dht_b = Arc::new(DhtNode::new_in_process(
        pkarr_store.clone(),
        addr_store.clone(),
        Duration::from_secs(5),
    ));
    let node_b = LiveNode::bind(topic, docs_b.clone(), Some(dht_b.clone()), false).await?;
    let _task_b = node_b.spawn();
    node_b.seed().await?;
    let b_node_id = node_b.node_id();
    println!("      iroh node id: {b_node_id}");

    let state_b = AppState {
        docs: docs_b.clone(),
        live_node: Some(Arc::new(node_b)),
        dht: Some(dht_b),
        metrics: Arc::new(Metrics::new()),
        resolve_timeout: Duration::from_secs(15),
    };
    let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr_b = listener_b.local_addr()?;
    tokio::spawn(async move {
        axum::serve(listener_b, build_router(state_b))
            .await
            .unwrap()
    });
    println!("      HTTP: http://{addr_b}\n");

    // ── [4/6] Create DID on node A ────────────────────────────────────────────
    // POST /dids triggers DHT publish: node A's full NodeAddr (including its
    // iroh UDP socket) is stored in the shared addr_store.  Node B can now
    // find it via DhtNode::lookup() without any out-of-band coordination.
    println!("[4/6] Creating DID on node A (publishes to DHT) …");
    let client = reqwest::Client::new();
    let body = serde_json::json!({ "publicKeyMultibase": pk_mb });

    let resp_a: Value = client
        .post(format!("http://{addr_a}/dids"))
        .json(&body)
        .send()
        .await?
        .json()
        .await?;
    let version_genesis = resp_a["document"]["didDocumentMetadata"]["versionId"]
        .as_str()
        .unwrap_or("?")
        .to_owned();
    println!("      A: created DID, version={version_genesis}");
    println!("      DHT record published — node B can now discover node A\n");

    // ── [5/6] Submit a signed delta to node A ────────────────────────────────
    println!("[5/6] Submitting signed delta to node A (revoking credential) …");
    let nid = node_id_from_pubkey(sk.verifying_key().as_bytes());
    let ts = HlcTimestamp {
        wall_ms: 1_000,
        logical: 0,
        node_id: nid,
    };
    let signer_id = format!("{did}#key-0");
    let signing_key = SigningKey::Ed25519(sk);
    let delta = SignedDelta::new_with_parents(
        did.clone(),
        DeltaOp::RevokeCredential {
            credential_id: "demo-credential-001".to_owned(),
        },
        ts,
        vec![genesis_hash],
        signer_id,
        &signing_key,
    )?;

    let resp = client
        .post(format!("http://{addr_a}/dids/{did_str}/deltas"))
        .json(&delta)
        .send()
        .await?;
    assert_eq!(
        resp.status().as_u16(),
        202,
        "delta must be accepted by node A"
    );

    let after_a: Value = client
        .get(format!("http://{addr_a}/{did_str}"))
        .send()
        .await?
        .json()
        .await?;
    let version_after = after_a["didDocumentMetadata"]["versionId"]
        .as_str()
        .unwrap_or("?")
        .to_owned();
    println!("      delta accepted — A version: {version_genesis} → {version_after}\n");

    // ── [6/6] Resolve DID on node B via DHT cold-start ───────────────────────
    // Node B has never seen this DID and has no connection to node A.
    // GET /:did triggers cold_start_bootstrap:
    //   1. DHT lookup  → finds node A's NodeAddr in the shared stub
    //   2. Connect     → iroh gossip join with node A as bootstrap peer
    //   3. REQUEST {}  → node A responds with full DELTAS (genesis + delta)
    //   4. Bootstrap   → genesis_bootstrap inserts doc; delta is applied
    //   5. Resolve     → returns 200 with the fully converged DID document
    println!("[6/6] Resolving DID on node B (DHT cold-start) …");
    println!("      Node B has no prior knowledge of this DID or node A's address.");
    print!("      ");
    std::io::stdout().flush()?;
    let start = Instant::now();
    let deadline = start + Duration::from_secs(20);
    loop {
        let resp = client
            .get(format!("http://{addr_b}/{did_str}"))
            .send()
            .await?;
        if resp.status().is_success() {
            let body: Value = resp.json().await?;
            if body["didDocumentMetadata"]["versionId"].as_str() == Some(&version_after) {
                println!();
                println!(
                    "\n      B converged via DHT cold-start!  version={version_after}  (elapsed: {:?})",
                    start.elapsed()
                );
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "node B did not converge within 20 s"
        );
        print!(".");
        std::io::stdout().flush()?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    println!("\n{sep}");
    println!("  Demo complete — DHT discovery and cold-start bootstrap working.");
    println!("{sep}\n");
    Ok(())
}
