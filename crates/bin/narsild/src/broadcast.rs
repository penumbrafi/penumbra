//! Peer transport.
//!
//! Two shapes, and the distinction is load-bearing:
//!
//! - [`PeerSet::broadcast`] fans a message out to every other member. Only
//!   public data goes this way — Feldman commitments, proofs of knowledge,
//!   nonce commitments, signature shares.
//! - [`PeerSet::send_to`] delivers one message to one member. DKG round 2 uses
//!   this and nothing else: each recipient gets its own sealed package and no
//!   other. The sealing already makes a misdelivered package useless
//!   (`osst::sealed` binds the recipient's static key), but not putting `n-1`
//!   packages in front of every node is the part that does not depend on the
//!   crypto being right.

use crate::auth::Authenticator;
use crate::roster::Roster;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;

/// The peers this node talks to, addressed by roster index.
#[derive(Clone)]
pub struct PeerSet {
    roster: Arc<Roster>,
    /// This node's own index — never a destination.
    self_index: u32,
    /// Signs everything that leaves this node.
    auth: Arc<Authenticator>,
    client: reqwest::Client,
}

/// How long to wait on a peer before giving up on one message.
pub const PEER_TIMEOUT: Duration = Duration::from_secs(10);

impl PeerSet {
    pub fn new(roster: Arc<Roster>, self_index: u32, auth: Arc<Authenticator>) -> Self {
        Self {
            roster,
            self_index,
            auth,
            client: reqwest::Client::builder()
                .timeout(PEER_TIMEOUT)
                .connect_timeout(PEER_TIMEOUT)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    /// Number of peers other than this node.
    pub fn peer_count(&self) -> usize {
        self.roster
            .members()
            .iter()
            .filter(|m| m.index != self.self_index)
            .count()
    }

    /// Fan a public message out to every member but this one.
    pub fn broadcast<T: Serialize>(&self, path: &str, msg: &T) {
        let body = match self.seal(path, msg) {
            Some(b) => b,
            None => return,
        };
        for member in self.roster.members() {
            if member.index == self.self_index {
                continue;
            }
            self.post(&member.url, path, body.clone());
        }
    }

    /// Deliver a message to exactly one member.
    ///
    /// Returns `false` if the index is not on the roster; the caller should
    /// treat that as a configuration error, not a transient failure.
    pub fn send_to<T: Serialize>(&self, index: u32, path: &str, msg: &T) -> bool {
        let member = match self.roster.get(index) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("cannot deliver to {}: {}", index, e);
                return false;
            }
        };
        let body = match self.seal(path, msg) {
            Some(b) => b,
            None => return false,
        };
        self.post(&member.url, path, body);
        true
    }

    /// Wrap a message in a signed envelope for `path`, ready to post.
    fn seal<T: Serialize>(&self, path: &str, msg: &T) -> Option<String> {
        match self
            .auth
            .seal(path, msg)
            .ok()
            .and_then(|e| serde_json::to_string(&e).ok())
        {
            Some(body) => Some(body),
            None => {
                tracing::warn!("could not seal an outgoing {} message", path);
                None
            }
        }
    }

    fn post(&self, base: &str, path: &str, body: String) {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let client = self.client.clone();
        tokio::spawn(async move {
            match client
                .post(&url)
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await
            {
                Ok(resp) => tracing::debug!("post {}: {}", url, resp.status()),
                Err(e) => tracing::warn!("post {} failed: {}", url, e),
            }
        });
    }
}
