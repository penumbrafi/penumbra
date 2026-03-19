//! peer broadcast — fan-out a message to all peer narsild instances
//!
//! fire-and-forget: we don't wait for peer responses.
//! peers process the message and contribute their own share.

use std::sync::Arc;
use serde::Serialize;

/// peer list (shared, immutable after init)
#[derive(Clone)]
pub struct PeerSet {
    peers: Arc<Vec<String>>,
    client: reqwest::Client,
}

impl PeerSet {
    pub fn new(peers: Vec<String>) -> Self {
        Self {
            peers: Arc::new(peers),
            client: reqwest::Client::new(),
        }
    }

    /// broadcast a message to all peers at the given path.
    /// fire-and-forget: spawns tasks, does not await responses.
    pub fn broadcast<T: Serialize + Send + Sync + 'static>(&self, path: &str, msg: &T) {
        let body = match serde_json::to_string(msg) {
            Ok(b) => b,
            Err(e) => { tracing::warn!("broadcast serialize error: {}", e); return; }
        };

        for peer in self.peers.iter() {
            let url = format!("{}{}", peer, path);
            let body = body.clone();
            let client = self.client.clone();
            tokio::spawn(async move {
                match client.post(&url)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .send()
                    .await
                {
                    Ok(resp) => tracing::debug!("broadcast {}: {}", url, resp.status()),
                    Err(e) => tracing::warn!("broadcast {} failed: {}", url, e),
                }
            });
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}
