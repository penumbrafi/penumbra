//! What this node is willing to sign (M-2).
//!
//! Authentication says *who* asked. It does not say whether the thing asked
//! for should happen: a roster member whose host is compromised is still a
//! roster member, and the daemon holds escrow authority. So a request to sign
//! is checked twice — once against the roster identity, once against a local
//! policy that has nothing to do with who is asking.
//!
//! # The policy this daemon ships with is "no"
//!
//! [`DenyAll`] is the default, and a node started without a policy signs
//! nothing. That is not a placeholder: a signing daemon that approves by
//! default is a signing oracle with extra steps, and the alternative — approve
//! unless someone configured a rule — fails open on the one axis where failing
//! open is unrecoverable.
//!
//! # What the real policy will be
//!
//! The bridge component. `zcash-shielded-bridge.md` states the model: "the
//! event, not any off-chain message, is the authorization". The node fetches
//! the withdrawal event from its own `pd`, reconstructs the message the event
//! implies, and approves only that. That predicate is a [`SigningPolicy`]
//! implementation and nothing else in this crate changes when it lands —
//! which is why this is a trait and not an `if`.
//!
//! [`AllowList`] exists so that tests and devnets can run an end-to-end
//! signature without either shipping a bridge or defaulting to yes. It
//! approves a fixed set of message digests read from a config file, so what a
//! node will sign is auditable by reading the file it was started with.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

/// The digest a policy keys on: SHA-256 of the application message.
///
/// The *application* message, not the signing-context bytes: the context wraps
/// it with this node's own epoch and manifest hash, which a policy author
/// cannot be expected to precompute and which the node binds anyway.
pub fn message_digest(message: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"narsild/policy/message/v1");
    h.update((message.len() as u64).to_le_bytes());
    h.update(message);
    h.finalize().into()
}

/// Whether this node will contribute a signature share over a message.
pub trait SigningPolicy: Send + Sync + 'static {
    /// Approve, or not. Called before nonces are sampled, and again before a
    /// share is produced.
    fn approve(&self, message: &[u8]) -> bool;

    /// A one-line description for the startup log, so an operator can see
    /// from the journal what the node will sign.
    fn describe(&self) -> String;
}

/// The default: sign nothing.
pub struct DenyAll;

impl SigningPolicy for DenyAll {
    fn approve(&self, _message: &[u8]) -> bool {
        false
    }
    fn describe(&self) -> String {
        "deny-all (no signing policy configured; this node will not sign)".into()
    }
}

/// Approve a fixed set of message digests. Development and test use.
pub struct AllowList {
    approved: BTreeSet<[u8; 32]>,
    source: String,
}

impl AllowList {
    /// Read one hex digest per line; `#` starts a comment, blank lines are
    /// ignored.
    pub fn from_file(path: &Path) -> std::io::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let mut approved = BTreeSet::new();
        for (n, line) in raw.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let digest: [u8; 32] = hex::decode(line)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "{}:{}: expected a 32-byte hex message digest",
                            path.display(),
                            n + 1
                        ),
                    )
                })?;
            approved.insert(digest);
        }
        Ok(Self {
            approved,
            source: path.display().to_string(),
        })
    }

    /// Build one directly — tests.
    #[cfg(test)]
    pub fn from_messages(messages: &[&[u8]]) -> Self {
        Self {
            approved: messages.iter().map(|m| message_digest(m)).collect(),
            source: "<in-process>".into(),
        }
    }
}

impl SigningPolicy for AllowList {
    fn approve(&self, message: &[u8]) -> bool {
        self.approved.contains(&message_digest(message))
    }
    fn describe(&self) -> String {
        format!(
            "allow-list of {} message digest(s) from {}",
            self.approved.len(),
            self.source
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default refuses everything, including the empty message.
    #[test]
    fn the_default_policy_signs_nothing() {
        let p = DenyAll;
        assert!(!p.approve(b""));
        assert!(!p.approve(b"release escrow 42"));
    }

    #[test]
    fn an_allow_list_approves_only_what_it_names() {
        let p = AllowList::from_messages(&[b"yes".as_slice()]);
        assert!(p.approve(b"yes"));
        assert!(!p.approve(b"no"));
        assert!(!p.approve(b"yes "));
    }

    /// The digest is length-prefixed and domain-separated, so two messages
    /// cannot collide by sharing a prefix.
    #[test]
    fn the_digest_is_unambiguous() {
        assert_ne!(message_digest(b"ab"), message_digest(b"a"));
        assert_ne!(message_digest(b""), [0u8; 32]);
    }

    #[test]
    fn an_allow_list_reads_a_config_file() {
        let dir = std::env::temp_dir().join(format!("narsild-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allow.txt");
        std::fs::write(
            &path,
            format!(
                "# the devnet message\n{}\n\n",
                hex::encode(message_digest(b"release escrow 42"))
            ),
        )
        .unwrap();
        let p = AllowList::from_file(&path).unwrap();
        assert!(p.approve(b"release escrow 42"));
        assert!(!p.approve(b"release escrow 43"));

        std::fs::write(&path, "not hex\n").unwrap();
        assert!(AllowList::from_file(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
