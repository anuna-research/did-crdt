//! axum HTTP server setup and router.
//!
//! Entry point: [`Server::run`] — binds the listener, attaches all routes,
//! and drives the server until the process is stopped.
//!
//! # Routes
//!
//! | Method | Path                  | Handler                        |
//! |--------|-----------------------|--------------------------------|
//! | POST   | /dids                 | create a new DID               |
//! | GET    | /:did                 | resolve a DID to a DID doc     |
//! | POST   | /dids/:did/deltas     | submit a signed delta          |
//! | GET    | /metrics              | prometheus metrics             |
//! | GET    | /health               | liveness + storage/sync status |

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    routing::{get, post},
    Router,
};

use super::handlers;
use super::metrics::Metrics;

// ── ServerConfig ──────────────────────────────────────────────────────────────

/// Configuration for the did-crdt HTTP service.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// TCP address and port to listen on (e.g. `"127.0.0.1:8080"`).
    pub listen_addr: SocketAddr,

    /// iroh-gossip peer addresses for P2P delta propagation.
    ///
    /// Each entry must be a `<NodeId>@<ip>:<port>` string. The address
    /// component must be a numeric IP — DNS hostnames are not resolved.
    /// Leave empty to run as a standalone (non-peered) node.
    pub peers: Vec<String>,

    /// Filesystem path for persistent CRDT state (iroh-blobs store).
    ///
    /// `None` means an ephemeral in-memory store is used.
    pub storage_path: Option<std::path::PathBuf>,

    /// URL of the pkarr HTTP relay for DHT peer discovery.
    /// Env: `DHT_RELAY_URL`, default: `https://relay.pkarr.org`.
    pub dht_relay_url: String,

    /// When `true`, skip all DHT publication and lookup.
    /// Env: `DISABLE_DHT_PUBLISH=true`.
    pub disable_dht_publish: bool,

    /// Total timeout for cold-start DID resolution (DHT lookup + bootstrap).
    /// Env: `RESOLVE_TIMEOUT_MS`, default: `1_500`.
    ///
    /// THE DEFAULT IS SET BY THE CALLER'S DEADLINE, NOT BY OUR PATIENCE.
    /// Selfsame's resolver client — the one client `did-crdt-service-v1` is
    /// defined for — gives the whole HTTP request 3,000 ms
    /// (`selfsame-app-identity-net`, `RESOLVER_DEADLINE`). A resolution that
    /// takes longer than that is not a slow answer, it is no answer: the caller
    /// has already recorded a timeout and moved on, so every millisecond spent
    /// past its deadline is spent on nobody's behalf.
    ///
    /// 1,500 ms leaves the rest of that budget for connection setup, TLS and
    /// transfer. It is deliberately well under, rather than just under, because
    /// the deadline covers the round trip and we do not know the caller's RTT.
    pub resolve_timeout_ms: u64,

    /// DHT lookup sub-timeout in milliseconds.
    /// Env: `DHT_LOOKUP_TIMEOUT_MS`, default: `1_000`.
    ///
    /// Kept strictly below `resolve_timeout_ms` so the two are coherent: a sub-
    /// timeout longer than the total it sits inside can never be the thing that
    /// fires, which makes it a number that looks like a control and is not one.
    pub dht_lookup_timeout_ms: u64,

    /// Opt this node into bootstrapping every DID announced on the gossip
    /// mesh (full-replica mode). Off by default: ordinary nodes only
    /// bootstrap DIDs they are asked to resolve (CON-006 §admission control).
    /// Env: `REPLICATE_ALL=true`.
    pub replicate_all: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".parse().expect("default address is valid"),
            peers: Vec::new(),
            storage_path: None,
            // Mirrors crate::sync::dht::DEFAULT_RELAY, which is unavailable in
            // a service-only build (no "sync" feature).
            dht_relay_url: "https://relay.pkarr.org".to_owned(),
            disable_dht_publish: false,
            resolve_timeout_ms: 1_500,
            dht_lookup_timeout_ms: 1_000,
            replicate_all: false,
        }
    }
}

// ── AppState ──────────────────────────────────────────────────────────────────

/// Shared state injected into every axum handler via [`axum::extract::State`].
#[derive(Clone)]
pub struct AppState {
    /// Canonical CRDT document store, shared with the sync layer when enabled.
    pub docs: crate::DocStore,
    /// Live gossip node for announcing local changes to peers.
    #[cfg(feature = "sync")]
    pub live_node: Option<Arc<crate::sync::live::LiveNode>>,
    /// DHT node for peer discovery and genesis bootstrap.
    #[cfg(feature = "sync")]
    pub dht: Option<Arc<crate::sync::dht::DhtNode>>,
    /// Durable snapshot store, present only when `STORAGE_PATH` is configured.
    ///
    /// `None` means the `DocStore` is the only copy of the state and the
    /// process is ephemeral.
    #[cfg(feature = "sync")]
    pub persistence: Option<Arc<crate::sync::store::FsBlobStore>>,
    /// Prometheus metrics.
    pub metrics: Arc<Metrics>,
    /// Total timeout for cold-start DID resolution. See
    /// [`ServerConfig::resolve_timeout_ms`] for why the default is what it is.
    pub resolve_timeout: Duration,
}

impl AppState {
    /// Create a fresh, empty application state (standalone, no sync).
    pub fn new() -> Self {
        Self {
            docs: crate::DocStore::new(),
            #[cfg(feature = "sync")]
            live_node: None,
            #[cfg(feature = "sync")]
            dht: None,
            #[cfg(feature = "sync")]
            persistence: None,
            metrics: Arc::new(Metrics::new()),
            resolve_timeout: Duration::from_millis(1_500),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Build the axum [`Router`] with all routes and the given shared state.
///
/// Exported so that integration tests can construct the router directly
/// without binding a real TCP port.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        // DID creation
        .route("/dids", post(handlers::create_did))
        // DID resolution — the static routes are registered first so they take
        // precedence over the dynamic `/:did` pattern.
        .route("/metrics", get(handlers::get_metrics))
        .route("/health", get(handlers::get_health))
        .route("/:did", get(handlers::resolve_did))
        // Delta submission
        .route("/dids/:did/deltas", post(handlers::submit_delta))
        .with_state(state)
}

// ── Server ────────────────────────────────────────────────────────────────────

/// HTTP server lifecycle manager.
pub struct Server;

impl Server {
    /// Start the HTTP server and block until the process is terminated.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP listener cannot bind or if the underlying
    /// `axum::serve` encounters an I/O error.
    pub async fn run(config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
        #[allow(unused_mut)]
        let mut state = AppState::new();

        #[cfg(feature = "sync")]
        {
            use crate::sync::dht::DhtNode;
            use crate::sync::live::{topic_for, LiveNode};
            use crate::sync::store::BlobStore;
            use std::time::Duration;

            // Open the durable store and recover prior state *before* the node
            // joins the mesh, so a restarted replica announces what it already
            // holds rather than re-bootstrapping it from peers.
            if let Some(ref path) = config.storage_path {
                match BlobStore::new_fs(path).await {
                    Ok(store) => {
                        match store.load_all().await {
                            Ok(docs) => {
                                let recovered = docs.len();
                                {
                                    let mut guard = state.docs.lock();
                                    for doc in docs {
                                        guard.insert(doc.did.clone(), doc);
                                    }
                                }
                                eprintln!(
                                    "did-crdt: recovered {recovered} document(s) from {}",
                                    path.display()
                                );
                            }
                            // A listing failure is not a reason to refuse to
                            // serve; the node continues with an empty store and
                            // rebuilds from the mesh.
                            Err(e) => eprintln!(
                                "did-crdt: could not read snapshots from {}: {e}",
                                path.display()
                            ),
                        }
                        state.persistence = Some(Arc::new(store));
                    }
                    // Refuse to start rather than silently run ephemeral: an
                    // operator who set STORAGE_PATH is asking for durability,
                    // and quietly not providing it is the failure this whole
                    // change exists to remove.
                    Err(e) => {
                        return Err(format!(
                            "STORAGE_PATH {} could not be opened: {e}",
                            path.display()
                        )
                        .into());
                    }
                }
            }

            // Build the DHT node (unless opted out).
            let dht: Option<Arc<DhtNode>> = if config.disable_dht_publish {
                None
            } else {
                let lookup_timeout = Duration::from_millis(config.dht_lookup_timeout_ms);
                match DhtNode::new_http(&config.dht_relay_url, lookup_timeout) {
                    Ok(d) => Some(Arc::new(d)),
                    Err(e) => {
                        eprintln!("did-crdt: DHT init failed (running without DHT): {e}");
                        None
                    }
                }
            };

            let topic = topic_for(b"did-crdt/v1");
            let node = LiveNode::bind(
                topic,
                state.docs.clone(),
                dht.clone(),
                config.replicate_all,
                state.persistence.clone(),
            )
            .await?;
            if config.peers.is_empty() {
                node.seed().await?;
            } else {
                for peer_str in &config.peers {
                    match parse_peer_addr(peer_str) {
                        Ok(addr) => {
                            if let Err(e) = node.connect(addr).await {
                                eprintln!("did-crdt: failed to connect to peer {peer_str}: {e}");
                            }
                        }
                        Err(e) => eprintln!("did-crdt: invalid peer address {peer_str:?}: {e}"),
                    }
                }
            }

            let node_id = node.node_id();
            eprintln!("did-crdt: iroh node id: {node_id}");
            let node_addr = node.node_addr().await.unwrap_or(iroh::net::NodeAddr {
                node_id,
                info: iroh::net::AddrInfo {
                    relay_url: None,
                    direct_addresses: Default::default(),
                },
            });
            for socket in &node_addr.info.direct_addresses {
                eprintln!("did-crdt: peer string: {node_id}@{socket}");
            }

            // Startup DHT publication for all existing DIDs (trigger 2), in the
            // background so a slow or unreachable relay never delays READY.
            if let Some(ref d) = dht {
                let d2 = d.clone();
                let docs = state.docs.clone();
                let startup_addr = node_addr.clone();
                tokio::spawn(async move {
                    let dids: Vec<_> = docs.lock().keys().cloned().collect();
                    for did in dids {
                        if let Err(e) = d2.publish(&did, &startup_addr).await {
                            eprintln!("did-crdt: DHT startup publish failed for {did}: {e}");
                        }
                    }
                });
                // Spawn the periodic refresh (trigger 3); it re-resolves the
                // node address each cycle so address changes propagate.
                let _refresh = d
                    .clone()
                    .spawn_refresh_task(state.docs.clone(), node.endpoint());
            }

            state.resolve_timeout = Duration::from_millis(config.resolve_timeout_ms);

            let handle = node.spawn();
            tokio::spawn(async move {
                match handle.await {
                    Ok(()) => eprintln!("did-crdt: sync loop exited"),
                    Err(e) => eprintln!("did-crdt: sync loop panicked: {e}"),
                }
            });
            state.dht = dht;
            state.live_node = Some(Arc::new(node));
        }

        let app = build_router(state);
        let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
        let local_addr = listener.local_addr()?;
        tracing_log(&config);
        eprintln!("READY http://{local_addr}");

        // Stop accepting on SIGTERM and let in-flight requests finish. This is
        // what makes the durable store safe to restart under: the blobs store's
        // background actor flushes when the last handle drops, which cannot
        // happen if the process is killed while `serve` still owns the router.
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        Ok(())
    }

    /// Bind to a random OS-assigned port and return `(router, local_addr)`.
    ///
    /// Useful for integration tests that need a real TCP server without
    /// hardcoding a port number.
    pub async fn bind_ephemeral(
    ) -> Result<(axum::serve::Serve<Router, Router>, SocketAddr), Box<dyn std::error::Error>> {
        let state = AppState::new();
        let app = build_router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        Ok((axum::serve(listener, app), addr))
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Resolve when the process is asked to stop.
///
/// Waits on SIGTERM (how container runtimes ask) and SIGINT (Ctrl-C). If the
/// SIGTERM handler cannot be installed, this waits on Ctrl-C alone rather than
/// returning immediately — resolving early would shut the server down the
/// moment it started.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(e) => {
                eprintln!("did-crdt: cannot listen for SIGTERM ({e}); Ctrl-C only");
                ctrl_c.await;
            }
        }
    }

    #[cfg(not(unix))]
    ctrl_c.await;

    eprintln!("did-crdt: shutdown signal received, draining");
}

/// Parse a `"NodeId@ip:port"` string into an iroh [`NodeAddr`].
///
/// The address component must be a numeric IP — DNS hostnames are not resolved.
#[cfg(feature = "sync")]
fn parse_peer_addr(s: &str) -> anyhow::Result<iroh::net::NodeAddr> {
    let (node_id_str, addr_str) = s
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("expected NodeId@host:port, got {:?}", s))?;
    let node_id: iroh::net::NodeId = node_id_str.parse()?;
    let socket: std::net::SocketAddr = addr_str.parse()?;
    Ok(iroh::net::NodeAddr {
        node_id,
        info: iroh::net::AddrInfo {
            relay_url: None,
            direct_addresses: std::collections::BTreeSet::from([socket]),
        },
    })
}

fn tracing_log(config: &ServerConfig) {
    // Avoid pulling in the `tracing` crate as an unconditional dep — use
    // eprintln! as a lightweight startup banner instead.
    eprintln!(
        "did-crdt service listening on {} (peers: {}, storage: {})",
        config.listen_addr,
        if config.peers.is_empty() {
            "none".to_owned()
        } else {
            config.peers.join(", ")
        },
        config
            .storage_path
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "in-memory".to_owned()),
    );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use tower::ServiceExt as _;

    fn make_app() -> Router {
        build_router(AppState::new())
    }

    // ── Timeout defaults ──────────────────────────────────────────────────────

    /// The deadline `did-crdt-service-v1`'s only defined client gives the whole
    /// HTTP request: `selfsame-app-identity-net`'s `RESOLVER_DEADLINE`.
    const SELFSAME_RESOLVER_DEADLINE_MS: u64 = 3_000;

    /// A resolution slower than the caller's deadline is not a slow answer, it
    /// is no answer — the caller has recorded a timeout and moved on. This is
    /// asserted against the client's constant rather than against `1_500`, so
    /// the test states the invariant instead of restating the default.
    #[test]
    fn cold_start_resolution_finishes_inside_the_clients_deadline() {
        let config = ServerConfig::default();
        assert!(
            config.resolve_timeout_ms < SELFSAME_RESOLVER_DEADLINE_MS,
            "resolve_timeout_ms {} must be under the client's {} ms deadline",
            config.resolve_timeout_ms,
            SELFSAME_RESOLVER_DEADLINE_MS,
        );
        // Room for connection setup, TLS and transfer: the client's deadline
        // covers the round trip, and this service does not know the caller's
        // RTT. Half the budget is the crude, defensible split.
        assert!(
            config.resolve_timeout_ms <= SELFSAME_RESOLVER_DEADLINE_MS / 2,
            "resolve_timeout_ms {} leaves too little of the {} ms budget for the round trip",
            config.resolve_timeout_ms,
            SELFSAME_RESOLVER_DEADLINE_MS,
        );
    }

    /// A sub-timeout longer than the total it sits inside can never fire, which
    /// makes it a number that looks like a control and is not one.
    #[test]
    fn the_dht_sub_timeout_can_actually_fire() {
        let config = ServerConfig::default();
        assert!(
            config.dht_lookup_timeout_ms < config.resolve_timeout_ms,
            "dht_lookup_timeout_ms {} must be under resolve_timeout_ms {}",
            config.dht_lookup_timeout_ms,
            config.resolve_timeout_ms,
        );
    }

    /// `AppState::new()` is used by callers that never build a `ServerConfig`,
    /// so its default has to agree — they drifted apart before this test.
    #[test]
    fn the_two_defaults_agree() {
        assert_eq!(
            AppState::new().resolve_timeout,
            Duration::from_millis(ServerConfig::default().resolve_timeout_ms),
        );
    }

    // ── GET /metrics ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn metrics_endpoint_returns_200() {
        let app = make_app();
        let req = Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── GET /health ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn health_endpoint_reports_ok() {
        use axum::body::to_bytes;

        let app = make_app();
        let req = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["documents"], 0);
        // AppState::new() carries no persistence handle.
        assert_eq!(json["storage"], "ephemeral");
    }

    #[tokio::test]
    async fn health_counts_documents() {
        use axum::body::to_bytes;

        let app = make_app();
        // Create a DID, then confirm /health sees it.
        let body = serde_json::json!({ "publicKeyMultibase": "zTestPublicKey" });
        let req = Request::builder()
            .method(Method::POST)
            .uri("/dids")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::CREATED
        );

        let req = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["documents"], 1);
    }

    /// `/health` is a static route and must not be swallowed by `/:did`, which
    /// would otherwise match it and answer 400 for a malformed DID.
    #[tokio::test]
    async fn health_is_not_captured_by_the_did_route() {
        let app = make_app();
        let req = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "/health must resolve to the health handler, not the DID resolver"
        );
    }

    // ── POST /dids ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn create_did_returns_201() {
        let app = make_app();
        let body = serde_json::json!({ "publicKeyMultibase": "zTestPublicKey" });
        let req = Request::builder()
            .method(Method::POST)
            .uri("/dids")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // ── GET /:did — not found ─────────────────────────────────────────────────

    #[tokio::test]
    async fn resolve_unknown_did_returns_404() {
        let app = make_app();
        // A structurally valid but unknown DID.
        let fake_did = format!("did:crdt:{}", "a".repeat(64));
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/{fake_did}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── Full round-trip: create → resolve → submit delta ─────────────────────

    #[tokio::test]
    async fn create_resolve_submit_delta_round_trip() {
        use crate::core::{
            delta::{DeltaOp, SignedDelta, SigningKey},
            hlc::HlcTimestamp,
        };
        use axum::body::to_bytes;
        use base64ct::{Base64UrlUnpadded, Encoding as _};

        // Use a real Ed25519 keypair so verify_signature passes at the Tier 1
        // trust boundary.  The public key is encoded as multibase base64url
        // (`u` prefix, no padding) as required by the document model.
        let raw = [0xBBu8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&raw);
        let pk_mb = format!(
            "u{}",
            Base64UrlUnpadded::encode_string(sk.verifying_key().as_bytes())
        );

        let state = AppState::new();
        let app = build_router(state);

        // 1. POST /dids — create a document with the real public key.
        let create_body = serde_json::json!({ "publicKeyMultibase": pk_mb });
        let req = Request::builder()
            .method(Method::POST)
            .uri("/dids")
            .header("content-type", "application/json")
            .body(Body::from(create_body.to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let did_str = json["did"].as_str().unwrap().to_owned();

        // 2. GET /:did
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/{did_str}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // 3. POST /dids/:did/deltas — submit a *signed* delta.
        //    The handler now enforces verify_signature at the trust boundary,
        //    so unsigned deltas on active documents are rejected with 403.
        let did = did_str.parse::<crate::core::did::Did>().unwrap();
        let node_id = crate::core::validate::node_id_from_pubkey(sk.verifying_key().as_bytes());
        let ts = HlcTimestamp {
            wall_ms: 1_000,
            logical: 1,
            node_id,
        };
        let signer = format!("{did}#key-0");
        let signing_key = SigningKey::Ed25519(sk);
        // Ground the delta on the document's current frontier (SPEC-036). Genesis
        // derivation is deterministic, so a client (here, the test) can recompute
        // the genesis hash from the public key. Exposing the live frontier via the
        // API is a follow-up (SPEC-036 §1a).
        let (_ref_doc, genesis_delta) = crate::core::document::Document::new(&pk_mb).unwrap();
        let parents = vec![genesis_delta.content_hash().unwrap()];
        let delta = SignedDelta::new_with_parents(
            did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "cred-test".to_owned(),
            },
            ts,
            parents,
            signer,
            &signing_key,
        )
        .unwrap();
        let delta_body = serde_json::to_string(&delta).unwrap();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("/dids/{did_str}/deltas"))
            .header("content-type", "application/json")
            .body(Body::from(delta_body))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn submit_delta_unsigned_rejected_on_active_document() {
        // FINDING-001: unsigned deltas on active documents must be rejected 403.
        use crate::core::{
            delta::{DeltaOp, SignedDelta},
            hlc::HlcTimestamp,
        };
        use axum::body::to_bytes;
        use base64ct::{Base64UrlUnpadded, Encoding as _};

        let raw = [0xCCu8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&raw);
        let pk_mb = format!(
            "u{}",
            Base64UrlUnpadded::encode_string(sk.verifying_key().as_bytes())
        );

        let state = AppState::new();
        let app = build_router(state);

        // Create the DID.
        let create_body = serde_json::json!({ "publicKeyMultibase": pk_mb });
        let req = Request::builder()
            .method(Method::POST)
            .uri("/dids")
            .header("content-type", "application/json")
            .body(Body::from(create_body.to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let did_str = json["did"].as_str().unwrap().to_owned();

        // Submit an unsigned delta — must be rejected.
        let did = did_str.parse::<crate::core::did::Did>().unwrap();
        let ts = HlcTimestamp {
            wall_ms: 1_000,
            logical: 0,
            node_id: 1,
        };
        let signer = format!("{did}#key-0");
        let delta = SignedDelta::unsigned(
            did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "cred-evil".to_owned(),
            },
            ts,
            signer,
        );
        let delta_body = serde_json::to_string(&delta).unwrap();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("/dids/{did_str}/deltas"))
            .header("content-type", "application/json")
            .body(Body::from(delta_body))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "unsigned delta on active document must return 403 Forbidden"
        );
    }
}
