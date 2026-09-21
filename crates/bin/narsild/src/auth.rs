//! Authenticated requests between roster members (M-2).
//!
//! # The problem
//!
//! Every endpoint was unauthenticated. `POST /sign/round1` then
//! `/sign/round2` is the whole coordinator flow, so anyone who could reach the
//! port — and the default bind was `0.0.0.0` — obtained an inner signature
//! share over bytes of their choosing; `POST /dkg/init` destroyed the key
//! package. "Keep the port on a private network" is not a mitigation against
//! an adversary the README names as a hostile *peer*, who is by construction
//! on that network.
//!
//! # The envelope
//!
//! Every mutating request is an [`Envelope`]: a body, plus who sent it, when,
//! with what one-time nonce, under which roster, to which path, signed with
//! the sender's ed25519 roster identity.
//!
//! ```text
//! signed bytes =
//!     "narsild/request/v1"
//!   ‖ roster_hash (32)
//!   ‖ sender_index (u32 le)
//!   ‖ timestamp (u64 le)
//!   ‖ nonce (32)
//!   ‖ len(path) (u64 le) ‖ path
//!   ‖ len(body) (u64 le) ‖ body          <- the exact bytes received
//! ```
//!
//! Each field is there for a specific substitution:
//!
//! - **roster hash** — an envelope made under one participant set does not
//!   verify under another, so a member of a retired group cannot drive a
//!   current one.
//! - **path** — without it, a `/dkg/complaint` envelope replays as a
//!   `/sign/round2`; the signature would still verify and the body would still
//!   parse as something.
//! - **nonce + timestamp** — replay. The timestamp is checked first, against a
//!   ±[`MAX_SKEW_SECS`] window, which is what keeps the seen-nonce set
//!   bounded; the nonce is then checked against that set, which is held in
//!   memory *and* appended to disk with `fsync`, so a restart does not reopen
//!   the replay window.
//! - **the raw body bytes** — the signature covers the bytes as received, not
//!   a re-serialization of the parsed value. Re-serializing a
//!   `serde_json::Value` reorders keys and rewrites numbers, and a verifier
//!   that signs its own re-encoding is verifying something the sender never
//!   saw.
//!
//! # What this is not
//!
//! It is not confidentiality: an envelope is plaintext over HTTP and anyone on
//! the path reads it. Round-2 sub-shares are sealed independently
//! (`osst::sealed`) and are the only secret on the wire. Deployments that want
//! the traffic private should run this over a private link or a TLS
//! terminator; the authentication does not depend on it.

use crate::identity::NodeIdentity;
use crate::roster::Roster;
use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::collections::{BTreeSet, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Domain separator for the signed bytes.
pub const ENVELOPE_DOMAIN: &[u8] = b"narsild/request/v1";

/// How far a request's timestamp may be from ours, in seconds, in either
/// direction. Bounds the seen-nonce set: anything older is refused on the
/// timestamp alone and never needs to be remembered.
pub const MAX_SKEW_SECS: u64 = 300;

/// File the seen nonces are appended to, inside the data directory.
pub const SEEN_FILE: &str = "seen-nonces.log";

/// A signed request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// The roster index of the sender.
    pub sender_index: u32,
    /// Unix seconds.
    pub timestamp: u64,
    /// One-time value; never accepted twice.
    #[serde(with = "crate::codec::bytes32")]
    pub nonce: [u8; 32],
    /// The sender's roster fingerprint, hex.
    pub roster_hash: String,
    /// The endpoint this envelope was made for.
    pub path: String,
    /// The request body, verbatim.
    pub body: Box<RawValue>,
    /// ed25519 signature over the bytes described in the module docs, hex.
    pub sig: String,
}

/// Why an envelope was refused.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("sender {0} is not on the roster")]
    UnknownSender(u32),
    #[error("envelope names roster {theirs}, ours is {ours}")]
    RosterMismatch { ours: String, theirs: String },
    #[error("envelope was made for path {theirs:?}, this is {ours:?}")]
    PathMismatch { ours: String, theirs: String },
    #[error("signature does not verify for roster member {0}")]
    BadSignature(u32),
    #[error("timestamp is {skew}s away from ours, the window is {max}s")]
    Skew { skew: u64, max: u64 },
    #[error("nonce has been seen before: this is a replay from member {0}")]
    Replay(u32),
    #[error("malformed envelope: {0}")]
    Malformed(&'static str),
    #[error("body does not parse as the type this endpoint takes")]
    BadBody,
    #[error("seen-nonce store: {0}")]
    Io(#[from] std::io::Error),
}

/// The bytes an envelope's signature covers.
fn signed_bytes(
    roster_hash: &[u8; 32],
    sender_index: u32,
    timestamp: u64,
    nonce: &[u8; 32],
    path: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(ENVELOPE_DOMAIN.len() + 32 + 4 + 8 + 32 + 8 + path.len() + 8 + body.len());
    out.extend_from_slice(ENVELOPE_DOMAIN);
    out.extend_from_slice(roster_hash);
    out.extend_from_slice(&sender_index.to_le_bytes());
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&(path.len() as u64).to_le_bytes());
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// The replay guard: nonces seen inside the skew window, in memory and on disk.
///
/// # The snapshot caveat
///
/// Restoring this node from a filesystem snapshot rolls the store back, and a
/// nonce accepted after the snapshot becomes acceptable again. That is the
/// same caveat the spent-session store carries
/// ([`crate::agreement::SpentSessions`]) and it has the same answer: a narsild
/// data directory must not be restored from a snapshot, because the thing that
/// actually breaks is nonce reuse in signing, not replay of a request.
struct SeenNonces {
    /// `(timestamp, sender, nonce)`, so expiry is a prefix scan.
    live: BTreeSet<(u64, u32, [u8; 32])>,
    keys: HashSet<(u32, [u8; 32])>,
    path: PathBuf,
}

impl SeenNonces {
    fn load(data_dir: &Path, now: u64) -> std::io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join(SEEN_FILE);
        let mut live = BTreeSet::new();
        let mut keys = HashSet::new();
        if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            for line in raw.lines() {
                let mut parts = line.split_whitespace();
                let (Some(ts), Some(sender), Some(nonce)) =
                    (parts.next(), parts.next(), parts.next())
                else {
                    continue;
                };
                let (Ok(ts), Ok(sender), Some(nonce)) = (
                    ts.parse::<u64>(),
                    sender.parse::<u32>(),
                    hex::decode(nonce)
                        .ok()
                        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()),
                ) else {
                    continue;
                };
                if now.saturating_sub(ts) > MAX_SKEW_SECS {
                    continue; // outside the window: the timestamp check refuses it anyway
                }
                live.insert((ts, sender, nonce));
                keys.insert((sender, nonce));
            }
        }
        Ok(Self { live, keys, path })
    }

    /// Record a nonce, durably. Returns `false` if it had been seen.
    fn record(&mut self, timestamp: u64, sender: u32, nonce: [u8; 32]) -> std::io::Result<bool> {
        if !self.keys.insert((sender, nonce)) {
            return Ok(false);
        }
        self.live.insert((timestamp, sender, nonce));

        // fsync before the request is acted on: a crash between accepting a
        // request and remembering its nonce is exactly the window a replay
        // needs.
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{} {} {}", timestamp, sender, hex::encode(nonce))?;
        f.sync_all()?;
        Ok(true)
    }

    /// Drop everything older than the window.
    fn expire(&mut self, now: u64) {
        let cutoff = now.saturating_sub(MAX_SKEW_SECS);
        let stale: Vec<_> = self
            .live
            .range(..(cutoff, 0, [0u8; 32]))
            .cloned()
            .collect();
        for entry in stale {
            self.live.remove(&entry);
            self.keys.remove(&(entry.1, entry.2));
        }
    }
}

/// Signs this node's outgoing requests and verifies incoming ones.
pub struct Authenticator {
    roster: Arc<Roster>,
    roster_hash: [u8; 32],
    roster_hash_hex: String,
    self_index: u32,
    signing_key: SigningKey,
    seen: Mutex<SeenNonces>,
}

impl Authenticator {
    pub fn new(
        roster: Arc<Roster>,
        identity: &NodeIdentity,
        self_index: u32,
        data_dir: &Path,
    ) -> std::io::Result<Self> {
        let roster_hash = roster.hash();
        Ok(Self {
            roster_hash_hex: hex::encode(roster_hash),
            roster_hash,
            roster,
            self_index,
            signing_key: identity.ed25519_signing_key(),
            seen: Mutex::new(SeenNonces::load(data_dir, now_secs())?),
        })
    }

    /// Wrap a body in a signed envelope for `path`.
    pub fn seal<T: Serialize>(&self, path: &str, body: &T) -> Result<Envelope, AuthError> {
        let body = serde_json::to_string(body).map_err(|_| AuthError::Malformed("body"))?;
        let body: Box<RawValue> =
            RawValue::from_string(body).map_err(|_| AuthError::Malformed("body"))?;
        let mut nonce = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let timestamp = now_secs();
        let sig = self.signing_key.sign(&signed_bytes(
            &self.roster_hash,
            self.self_index,
            timestamp,
            &nonce,
            path,
            body.get().as_bytes(),
        ));
        Ok(Envelope {
            sender_index: self.self_index,
            timestamp,
            nonce,
            roster_hash: self.roster_hash_hex.clone(),
            path: path.to_string(),
            body,
            sig: hex::encode(sig.to_bytes()),
        })
    }

    /// Verify an envelope for `path` and parse its body.
    ///
    /// Order matters: cheap structural checks, then the timestamp window (so
    /// an attacker cannot grow the seen set with ancient nonces), then the
    /// signature, and only then the nonce is recorded — a request whose
    /// signature does not verify must not consume a nonce, or anyone can
    /// burn a member's nonces.
    pub fn open<T: DeserializeOwned>(
        &self,
        path: &str,
        envelope: &Envelope,
    ) -> Result<(u32, T), AuthError> {
        if envelope.path != path {
            return Err(AuthError::PathMismatch {
                ours: path.to_string(),
                theirs: envelope.path.clone(),
            });
        }
        if envelope.roster_hash != self.roster_hash_hex {
            return Err(AuthError::RosterMismatch {
                ours: self.roster_hash_hex.clone(),
                theirs: envelope.roster_hash.clone(),
            });
        }

        let now = now_secs();
        let skew = now.abs_diff(envelope.timestamp);
        if skew > MAX_SKEW_SECS {
            return Err(AuthError::Skew {
                skew,
                max: MAX_SKEW_SECS,
            });
        }

        let verifying = self
            .roster
            .verifying_key(envelope.sender_index)
            .map_err(|_| AuthError::UnknownSender(envelope.sender_index))?;
        let sig_bytes: [u8; 64] = hex::decode(&envelope.sig)
            .ok()
            .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
            .ok_or(AuthError::Malformed("signature"))?;
        let signature = Signature::from_bytes(&sig_bytes);

        verifying
            .verify_strict(
                &signed_bytes(
                    &self.roster_hash,
                    envelope.sender_index,
                    envelope.timestamp,
                    &envelope.nonce,
                    &envelope.path,
                    envelope.body.get().as_bytes(),
                ),
                &signature,
            )
            .map_err(|_| AuthError::BadSignature(envelope.sender_index))?;

        {
            let mut seen = self.seen.lock().expect("seen-nonce store poisoned");
            seen.expire(now);
            if !seen.record(envelope.timestamp, envelope.sender_index, envelope.nonce)? {
                return Err(AuthError::Replay(envelope.sender_index));
            }
        }

        let value: T =
            serde_json::from_str(envelope.body.get()).map_err(|_| AuthError::BadBody)?;
        Ok((envelope.sender_index, value))
    }
}

/// Unix seconds, saturating at the epoch on a clock set before 1970.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::Peer;

    fn ident(i: u32) -> NodeIdentity {
        NodeIdentity::from_seed_for_test([i as u8; 32])
    }

    fn roster() -> Arc<Roster> {
        Arc::new(
            Roster::new(
                (1..=3u32)
                    .map(|i| Peer {
                        index: i,
                        url: format!("http://node{i}:9200"),
                        x25519_pub: ident(i).x25519_public(),
                        ed25519_pub: ident(i).ed25519_public(),
                        identity_pub: osst::curve::OsstPoint::compress(
                            &ident(i).ceremony_identity_public(),
                        )
                        .as_ref()
                        .try_into()
                        .unwrap(),
                    })
                    .collect(),
            )
            .unwrap(),
        )
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "narsild-auth-{}-{}-{}",
            std::process::id(),
            tag,
            now_secs()
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn auth(index: u32, dir: &Path) -> Authenticator {
        Authenticator::new(roster(), &ident(index), index, dir).unwrap()
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Body {
        v: u32,
    }

    #[test]
    fn a_signed_envelope_round_trips() {
        let dir = tmp("rt");
        let sender = auth(1, &dir.join("a"));
        let receiver = auth(2, &dir.join("b"));
        let env = sender.seal("/dkg/round1", &Body { v: 7 }).unwrap();
        let (who, body): (u32, Body) = receiver.open("/dkg/round1", &env).unwrap();
        assert_eq!(who, 1);
        assert_eq!(body, Body { v: 7 });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M-2: a body that is not in an envelope at all does not even parse, and
    /// one signed by a key the roster does not name is refused.
    #[test]
    fn an_unauthenticated_request_is_rejected() {
        let dir = tmp("unauth");
        let receiver = auth(2, &dir.join("b"));

        // A bare body is not an envelope.
        assert!(serde_json::from_str::<Envelope>(r#"{"v":7}"#).is_err());

        // An envelope from a key that is not on the roster.
        let outsider = NodeIdentity::from_seed_for_test([0xee; 32]);
        let stranger = Authenticator {
            roster: roster(),
            roster_hash: roster().hash(),
            roster_hash_hex: hex::encode(roster().hash()),
            self_index: 1, // claims to be member 1
            signing_key: outsider.ed25519_signing_key(),
            seen: Mutex::new(SeenNonces::load(&dir.join("x"), now_secs()).unwrap()),
        };
        let env = stranger.seal("/dkg/round1", &Body { v: 7 }).unwrap();
        assert!(matches!(
            receiver.open::<Body>("/dkg/round1", &env),
            Err(AuthError::BadSignature(1))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M-2: the same envelope twice is a replay.
    #[test]
    fn a_replayed_envelope_is_rejected() {
        let dir = tmp("replay");
        let sender = auth(1, &dir.join("a"));
        let receiver = auth(2, &dir.join("b"));
        let env = sender.seal("/dkg/round1", &Body { v: 7 }).unwrap();
        receiver.open::<Body>("/dkg/round1", &env).unwrap();
        assert!(matches!(
            receiver.open::<Body>("/dkg/round1", &env),
            Err(AuthError::Replay(1))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The seen set survives a restart: the on-disk log is the durable half.
    #[test]
    fn a_replay_is_still_rejected_after_a_restart() {
        let dir = tmp("restart");
        let sender = auth(1, &dir.join("a"));
        let receiver = auth(2, &dir.join("b"));
        let env = sender.seal("/dkg/round1", &Body { v: 7 }).unwrap();
        receiver.open::<Body>("/dkg/round1", &env).unwrap();

        let restarted = auth(2, &dir.join("b"));
        assert!(matches!(
            restarted.open::<Body>("/dkg/round1", &env),
            Err(AuthError::Replay(1))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An envelope made for one endpoint does not work on another.
    #[test]
    fn an_envelope_does_not_move_between_endpoints() {
        let dir = tmp("path");
        let sender = auth(1, &dir.join("a"));
        let receiver = auth(2, &dir.join("b"));
        let env = sender.seal("/dkg/complaint", &Body { v: 7 }).unwrap();
        assert!(matches!(
            receiver.open::<Body>("/sign/round2", &env),
            Err(AuthError::PathMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Any change to the body invalidates the signature — including one that
    /// re-serializes to the same value, since the bytes are what is signed.
    #[test]
    fn a_tampered_body_is_rejected() {
        let dir = tmp("tamper");
        let sender = auth(1, &dir.join("a"));
        let receiver = auth(2, &dir.join("b"));
        let mut env = sender.seal("/dkg/round1", &Body { v: 7 }).unwrap();
        env.body = RawValue::from_string(r#"{"v":8}"#.to_string()).unwrap();
        assert!(matches!(
            receiver.open::<Body>("/dkg/round1", &env),
            Err(AuthError::BadSignature(1))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A stale envelope is refused on the timestamp, before it can enter the
    /// seen set.
    #[test]
    fn a_stale_envelope_is_rejected_without_growing_the_seen_set() {
        let dir = tmp("skew");
        let sender = auth(1, &dir.join("a"));
        let receiver = auth(2, &dir.join("b"));
        let mut env = sender.seal("/dkg/round1", &Body { v: 7 }).unwrap();
        env.timestamp = env.timestamp.saturating_sub(MAX_SKEW_SECS + 60);
        assert!(matches!(
            receiver.open::<Body>("/dkg/round1", &env),
            Err(AuthError::Skew { .. })
        ));
        assert!(receiver
            .seen
            .lock()
            .unwrap()
            .keys
            .is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed signature check must not consume the nonce, or anyone can
    /// burn a member's envelopes by mangling them in flight.
    #[test]
    fn a_bad_signature_does_not_consume_the_nonce() {
        let dir = tmp("burn");
        let sender = auth(1, &dir.join("a"));
        let receiver = auth(2, &dir.join("b"));
        let good = sender.seal("/dkg/round1", &Body { v: 7 }).unwrap();
        let mut bad = good.clone();
        bad.sig = hex::encode([0u8; 64]);
        assert!(receiver.open::<Body>("/dkg/round1", &bad).is_err());
        assert!(receiver.open::<Body>("/dkg/round1", &good).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An envelope made under a different roster does not verify here.
    #[test]
    fn an_envelope_from_another_roster_is_rejected() {
        let dir = tmp("roster");
        let receiver = auth(2, &dir.join("b"));
        let mut other_members: Vec<Peer> = roster().members().to_vec();
        other_members[2].url = "http://attacker:9200".into();
        let other = Arc::new(Roster::new(other_members).unwrap());
        let sender = Authenticator::new(other, &ident(1), 1, &dir.join("a")).unwrap();
        let env = sender.seal("/dkg/round1", &Body { v: 7 }).unwrap();
        assert!(matches!(
            receiver.open::<Body>("/dkg/round1", &env),
            Err(AuthError::RosterMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
