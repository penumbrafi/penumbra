//! The signed roster: who is in the group, and how to reach each of them.
//!
//! Every node is configured with the same index→peer map. A peer entry is
//! `(index, URL, x25519 public key, ed25519 public key)`; the roster is the
//! sorted list of them.
//!
//! # The two keys
//!
//! The X25519 key seals round-2 sub-shares to a recipient. The ed25519 key
//! authenticates that member's *requests*: every mutating endpoint takes a
//! signed envelope (see [`crate::auth`]), and the roster is where the public
//! key that envelope is checked against comes from. Both are derived from that
//! node's identity seed under distinct HKDF info strings, and both enter
//! [`Roster::hash`] — a node that disagrees about either key disagrees about
//! the manifest, and its signatures and sealed packages both stop verifying.
//!
//! # Why the roster is hashed
//!
//! `osst::sealed` binds a round-2 package to the ceremony by putting the
//! participant set, the session id and the round number in the Noise
//! prologue. Its own [`osst::sealed::SealedRoster`] carries only
//! `(index, pubkey)` — a transport is out of scope for the crate. narsild's
//! roster additionally carries the URL each index is reachable at, which is
//! exactly the datum an attacker would want to change: redirect a recipient's
//! packages to a host it controls and the sealing buys nothing if nobody
//! notices the substitution.
//!
//! So the URLs enter the prologue transitively. [`Roster::hash`] covers
//! `(index, pubkey, url)` for every member; the ceremony's session id is
//! derived from that hash and the epoch ([`Roster::session_id`]); and that
//! session id is what [`Roster::sealed_roster`] hands to osst. Two nodes that
//! disagree about any member's URL, key or index derive different session ids,
//! so their sealed packages simply do not open.
//!
//! The same hash is the `manifest_hash` of the signing context
//! (`osst::SigningContext`): the roster *is* the group's membership manifest,
//! so a signature made under one roster is not valid under another.

use ed25519_dalek::VerifyingKey;
use osst::sealed::SealedRoster;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Decode a 32-byte key from hex.
fn key32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s.trim()).ok()?.as_slice().try_into().ok()
}

/// Domain tag for [`Roster::hash`].
pub const ROSTER_DOMAIN: &[u8] = b"narsild/roster/v1";

/// Domain tag for [`Roster::session_id`].
pub const SESSION_DOMAIN: &[u8] = b"narsild/dkg-session/v1";

/// One member of the group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    /// 1-indexed holder index. Also the Shamir index.
    pub index: u32,
    /// Base URL of that node's narsild, without a trailing slash.
    pub url: String,
    /// That node's static X25519 public key — seals round-2 sub-shares to it.
    pub x25519_pub: [u8; 32],
    /// That node's ed25519 public key — verifies its signed requests.
    pub ed25519_pub: [u8; 32],
}

/// Errors from building or reading a roster.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RosterError {
    #[error("roster is empty")]
    Empty,
    #[error("holder indices are 1-indexed; index 0 is not a member")]
    ZeroIndex,
    #[error("duplicate holder index {0}")]
    DuplicateIndex(u32),
    #[error("duplicate x25519 public key for indices {0} and {1}")]
    DuplicateKey(u32, u32),
    #[error("duplicate ed25519 public key for indices {0} and {1}")]
    DuplicateSigningKey(u32, u32),
    #[error("index {0} is not on the roster")]
    Unknown(u32),
    #[error("the ed25519 key for index {0} is not a valid point")]
    BadSigningKey(u32),
    #[error(
        "malformed peer specification {0:?}: expected \
         index=url=x25519_pubkey_hex=ed25519_pubkey_hex"
    )]
    Malformed(String),
}

/// The full participant set, sorted by index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roster {
    members: Vec<Peer>,
}

impl Roster {
    /// Build a roster. Order does not matter; the result is sorted by index.
    ///
    /// Duplicate indices and duplicate static keys are both refused: two
    /// members sharing a key means one can open the other's sealed packages,
    /// which is the property round 2 exists to deny.
    pub fn new(mut members: Vec<Peer>) -> Result<Self, RosterError> {
        if members.is_empty() {
            return Err(RosterError::Empty);
        }
        members.sort_by(|a, b| a.index.cmp(&b.index));
        if members[0].index == 0 {
            return Err(RosterError::ZeroIndex);
        }
        for w in members.windows(2) {
            if w[0].index == w[1].index {
                return Err(RosterError::DuplicateIndex(w[0].index));
            }
        }
        for i in 0..members.len() {
            for j in (i + 1)..members.len() {
                if members[i].x25519_pub == members[j].x25519_pub {
                    return Err(RosterError::DuplicateKey(members[i].index, members[j].index));
                }
                if members[i].ed25519_pub == members[j].ed25519_pub {
                    return Err(RosterError::DuplicateSigningKey(
                        members[i].index,
                        members[j].index,
                    ));
                }
            }
        }
        Ok(Self { members })
    }

    /// Parse a roster from `index=url=x25519_pubkey_hex=ed25519_pubkey_hex`
    /// specifications.
    ///
    /// The two keys are peeled off the *end*, not taken as fields 3 and 4 of a
    /// left-to-right split: a URL may legitimately contain `=` (a query
    /// string), and a parser that splits from the left silently truncates it —
    /// which would put a different URL in the roster hash on different nodes.
    pub fn parse(specs: &[String]) -> Result<Self, RosterError> {
        let mut members = Vec::with_capacity(specs.len());
        for spec in specs {
            let tail: Vec<&str> = spec.rsplitn(3, '=').collect();
            if tail.len() != 3 {
                return Err(RosterError::Malformed(spec.clone()));
            }
            // rsplitn yields right-to-left.
            let ed25519_hex = tail[0];
            let x25519_hex = tail[1];
            let head = tail[2];

            let (index_str, url) = head
                .split_once('=')
                .ok_or_else(|| RosterError::Malformed(spec.clone()))?;
            let index: u32 = index_str
                .trim()
                .parse()
                .map_err(|_| RosterError::Malformed(spec.clone()))?;
            let url = url.trim().trim_end_matches('/').to_string();
            if url.is_empty() {
                return Err(RosterError::Malformed(spec.clone()));
            }
            let x25519_pub = key32(x25519_hex).ok_or_else(|| RosterError::Malformed(spec.clone()))?;
            let ed25519_pub =
                key32(ed25519_hex).ok_or_else(|| RosterError::Malformed(spec.clone()))?;
            members.push(Peer {
                index,
                url,
                x25519_pub,
                ed25519_pub,
            });
        }
        Self::new(members)
    }

    /// Members, sorted by index.
    pub fn members(&self) -> &[Peer] {
        &self.members
    }

    /// Number of members.
    pub fn len(&self) -> u32 {
        self.members.len() as u32
    }

    /// Member indices, ascending.
    pub fn indices(&self) -> Vec<u32> {
        self.members.iter().map(|m| m.index).collect()
    }

    /// Look up a member.
    pub fn get(&self, index: u32) -> Result<&Peer, RosterError> {
        self.members
            .iter()
            .find(|m| m.index == index)
            .ok_or(RosterError::Unknown(index))
    }

    /// The roster fingerprint: SHA-256 over the sorted `(index, pubkey, url)`
    /// triples, every variable-length field length-prefixed so that two
    /// different rosters cannot hash alike by rearranging characters across a
    /// field boundary.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(ROSTER_DOMAIN);
        h.update((self.members.len() as u64).to_le_bytes());
        for m in &self.members {
            h.update(m.index.to_le_bytes());
            h.update(m.x25519_pub);
            h.update(m.ed25519_pub);
            h.update((m.url.len() as u64).to_le_bytes());
            h.update(m.url.as_bytes());
        }
        h.finalize().into()
    }

    /// The ed25519 verifying key of one member, for checking its signed
    /// requests.
    pub fn verifying_key(&self, index: u32) -> Result<VerifyingKey, RosterError> {
        let peer = self.get(index)?;
        VerifyingKey::from_bytes(&peer.ed25519_pub).map_err(|_| RosterError::BadSigningKey(index))
    }

    /// The session id of one ceremony **attempt**:
    /// `H(domain ‖ roster hash ‖ epoch ‖ ceremony nonce)`.
    ///
    /// The nonce is 32 random bytes chosen by whoever starts the ceremony and
    /// echoed by every member (M-15). Without it the session id was a function
    /// of the roster and the epoch alone, so a re-run of a *failed* ceremony —
    /// which happens at the same epoch, by definition — reproduced a
    /// byte-identical session id and Noise prologue, and an attacker who
    /// recorded attempt A could replay a dealer's round-1 and round-2 messages
    /// into attempt B ahead of that dealer's own.
    ///
    /// This value is the ceremony's identity: the Noise prologue via
    /// [`Self::sealed_roster`], the echo round's binding, and what a complaint
    /// names. It is deliberately *not* the manifest hash — that stays
    /// [`Self::hash`], because the manifest is who the group is, which does
    /// not change between two attempts at the same generation.
    pub fn session_id(&self, epoch: u64, ceremony_nonce: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(SESSION_DOMAIN);
        h.update(self.hash());
        h.update(epoch.to_le_bytes());
        h.update(ceremony_nonce);
        h.finalize().into()
    }

    /// The osst view of this roster for one attempt: `(index, pubkey)` pairs
    /// under the session id derived above.
    pub fn sealed_roster(
        &self,
        epoch: u64,
        ceremony_nonce: &[u8; 32],
    ) -> Result<SealedRoster, osst::OsstError> {
        let pairs: Vec<(u32, [u8; 32])> = self
            .members
            .iter()
            .map(|m| (m.index, m.x25519_pub))
            .collect();
        SealedRoster::new(&pairs, self.session_id(epoch, ceremony_nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(index: u32, url: &str, key: u8) -> Peer {
        Peer {
            index,
            url: url.to_string(),
            x25519_pub: [key; 32],
            ed25519_pub: [key.wrapping_add(0x80); 32],
        }
    }

    fn three() -> Vec<Peer> {
        vec![
            peer(1, "http://a:9200", 1),
            peer(2, "http://b:9200", 2),
            peer(3, "http://c:9200", 3),
        ]
    }

    #[test]
    fn the_hash_does_not_depend_on_the_order_entries_arrive_in() {
        let mut shuffled = three();
        shuffled.reverse();
        assert_eq!(
            Roster::new(three()).unwrap().hash(),
            Roster::new(shuffled).unwrap().hash()
        );
    }

    #[test]
    fn the_hash_covers_the_url_as_well_as_the_key_and_index() {
        let base = Roster::new(three()).unwrap().hash();

        let mut other_url = three();
        other_url[1].url = "http://evil:9200".into();
        assert_ne!(base, Roster::new(other_url).unwrap().hash());

        let mut other_key = three();
        other_key[1].x25519_pub = [0x77; 32];
        assert_ne!(base, Roster::new(other_key).unwrap().hash());

        // The signing key is part of the manifest too: swapping who may
        // authorize a request is a roster change.
        let mut other_signing_key = three();
        other_signing_key[1].ed25519_pub = [0x66; 32];
        assert_ne!(base, Roster::new(other_signing_key).unwrap().hash());

        let mut other_index = three();
        other_index[2].index = 4;
        assert_ne!(base, Roster::new(other_index).unwrap().hash());
    }

    /// Length prefixes, not concatenation: moving a character across the
    /// index/URL boundary must not preserve the hash.
    #[test]
    fn the_hash_is_unambiguous_across_field_boundaries() {
        let a = Roster::new(vec![peer(1, "http://a:9200x", 1), peer(2, "http://b", 2)]).unwrap();
        let b = Roster::new(vec![peer(1, "http://a:9200", 1), peer(2, "xhttp://b", 2)]).unwrap();
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn the_session_id_changes_with_the_epoch_and_with_the_roster() {
        let r = Roster::new(three()).unwrap();
        let n = [7u8; 32];
        assert_ne!(r.session_id(0, &n), r.session_id(1, &n));

        let mut moved = three();
        moved[0].url = "http://a2:9200".into();
        let r2 = Roster::new(moved).unwrap();
        assert_ne!(r.session_id(7, &n), r2.session_id(7, &n));
    }

    /// M-15: two attempts at the same generation on the same roster are
    /// different ceremonies. A failed DKG is re-run at the same epoch, which
    /// is precisely the case the epoch does not separate.
    #[test]
    fn two_attempts_at_one_epoch_are_different_ceremonies() {
        let r = Roster::new(three()).unwrap();
        assert_ne!(r.session_id(7, &[1u8; 32]), r.session_id(7, &[2u8; 32]));
        assert_ne!(
            r.sealed_roster(7, &[1u8; 32]).unwrap().prologue(2),
            r.sealed_roster(7, &[2u8; 32]).unwrap().prologue(2)
        );
        // The manifest hash is not the session id and does not move with it.
        assert_eq!(r.hash(), Roster::new(three()).unwrap().hash());
    }

    /// The property the derivation exists for: a URL substitution reaches the
    /// Noise prologue, so a package sealed under the honest roster does not
    /// open under the tampered one.
    #[test]
    fn a_url_substitution_changes_the_sealed_prologue() {
        let r = Roster::new(three()).unwrap();
        let mut moved = three();
        moved[2].url = "http://attacker:9200".into();
        let r2 = Roster::new(moved).unwrap();
        assert_ne!(
            r.sealed_roster(0, &[0u8; 32]).unwrap().prologue(2),
            r2.sealed_roster(0, &[0u8; 32]).unwrap().prologue(2)
        );
    }

    #[test]
    fn malformed_rosters_are_refused() {
        assert_eq!(Roster::new(vec![]), Err(RosterError::Empty));
        assert_eq!(
            Roster::new(vec![peer(0, "http://a", 1)]),
            Err(RosterError::ZeroIndex)
        );
        assert_eq!(
            Roster::new(vec![peer(1, "http://a", 1), peer(1, "http://b", 2)]),
            Err(RosterError::DuplicateIndex(1))
        );
        assert_eq!(
            Roster::new(vec![peer(1, "http://a", 9), peer(2, "http://b", 9)]),
            Err(RosterError::DuplicateKey(1, 2))
        );

        let mut shared_signing_key = vec![peer(1, "http://a", 1), peer(2, "http://b", 2)];
        shared_signing_key[1].ed25519_pub = shared_signing_key[0].ed25519_pub;
        assert_eq!(
            Roster::new(shared_signing_key),
            Err(RosterError::DuplicateSigningKey(1, 2))
        );
    }

    #[test]
    fn peers_parse_from_index_url_two_key_specs() {
        let specs = vec![
            format!(
                "1=http://a:9200/={}={}",
                hex::encode([1u8; 32]),
                hex::encode([0x81u8; 32])
            ),
            format!(
                "2=http://b:9200={}={}",
                hex::encode([2u8; 32]),
                hex::encode([0x82u8; 32])
            ),
        ];
        let r = Roster::parse(&specs).unwrap();
        assert_eq!(r.indices(), vec![1, 2]);
        assert_eq!(r.get(1).unwrap().url, "http://a:9200");
        assert_eq!(r.get(2).unwrap().ed25519_pub, [0x82u8; 32]);

        // The old three-field form no longer parses: a roster without signing
        // keys cannot authenticate anything, and half-understanding it would
        // put a key-shaped URL fragment in the manifest.
        assert!(Roster::parse(&[format!("1=http://a={}", hex::encode([1u8; 32]))]).is_err());
        assert!(Roster::parse(&["1=http://a".to_string()]).is_err());
        assert!(Roster::parse(&["1=http://a=zz=ww".to_string()]).is_err());
    }

    /// A URL with an `=` in it survives parsing intact — the keys are peeled
    /// off the right.
    #[test]
    fn a_url_containing_an_equals_sign_is_not_truncated() {
        let spec = format!(
            "3=http://h:9200/p?a=b={}={}",
            hex::encode([3u8; 32]),
            hex::encode([0x83u8; 32])
        );
        let r = Roster::parse(&[spec]).unwrap();
        assert_eq!(r.get(3).unwrap().url, "http://h:9200/p?a=b");
    }
}
