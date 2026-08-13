//! Entry point for the did-crdt HTTP service.
//!
//! Configuration via environment variables:
//!
//! | Variable               | Default                    | Description                              |
//! |------------------------|----------------------------|------------------------------------------|
//! | `LISTEN_ADDR`          | `0.0.0.0:8080`             | TCP address and port to bind             |
//! | `PEERS`                | *(empty)*                  | Comma-separated `NodeId@host:port` list  |
//! | `STORAGE_PATH`         | *(in-memory)*              | Path for persistent iroh-blobs store     |
//! | `DHT_RELAY_URL`        | `https://relay.pkarr.org`  | pkarr HTTP relay for peer discovery      |
//! | `DISABLE_DHT_PUBLISH`  | *(unset)*                  | Set to `true` to opt out of DHT          |
//! | `RESOLVE_TIMEOUT_MS`   | `10000`                    | Cold-start resolution total timeout (ms) |
//! | `DHT_LOOKUP_TIMEOUT_MS`| `5000`                     | pkarr lookup sub-timeout (ms)            |
//! | `REPLICATE_ALL`        | *(unset)*                  | Set to `true` to bootstrap every DID announced on the mesh (full-replica mode; accepts unbounded storage growth) |
//! | `RESOLVER_ID`          | *(unset)*                  | This node's stable identity in Path-B resolution metadata (e.g. `did.anuna.io`). A verifier applying a two-resolver union needs to say which node reported what; unset means the property is omitted |

use std::net::SocketAddr;

use did_crdt::service::server::{Server, ServerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listen_addr: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_owned())
        .parse()?;

    let peers = std::env::var("PEERS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();

    let storage_path = std::env::var("STORAGE_PATH").ok().map(Into::into);

    let defaults = ServerConfig::default();

    let dht_relay_url =
        std::env::var("DHT_RELAY_URL").unwrap_or_else(|_| defaults.dht_relay_url.clone());

    let disable_dht_publish = std::env::var("DISABLE_DHT_PUBLISH").ok().as_deref() == Some("true");

    let resolve_timeout_ms = std::env::var("RESOLVE_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(defaults.resolve_timeout_ms);

    let dht_lookup_timeout_ms = std::env::var("DHT_LOOKUP_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(defaults.dht_lookup_timeout_ms);

    let replicate_all = std::env::var("REPLICATE_ALL").ok().as_deref() == Some("true");

    // An empty value is treated as unset. A node whose identity is the empty
    // string has not been named, and the metadata property is better omitted
    // than carrying a blank claim.
    let resolver_id = std::env::var("RESOLVER_ID").ok().filter(|id| !id.is_empty());

    let config = ServerConfig {
        listen_addr,
        peers,
        storage_path,
        dht_relay_url,
        disable_dht_publish,
        resolve_timeout_ms,
        resolver_id,
        dht_lookup_timeout_ms,
        replicate_all,
    };

    Server::run(config).await
}
