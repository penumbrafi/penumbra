//! Agreement primitives: what the group must see identically, and what it must
//! remember.
//!
//! # Why these live in one module
//!
//! Everything here belongs upstream in osst, and osst 0.5.0 is expected to
//! ship it: the canonical round-1 digest so that every caller computes the
//! same bytes, justified complaints so that every caller adjudicates the same
//! way, and a spent-session trait so that "the type system cannot see a
//! process boundary" has an implementation to point at. Keeping them in one
//! module makes that swap a change to this file's `use` lines rather than an
//! archaeology exercise across the crate.
//!
//! Until then these are narsild's own, and they are written to the shapes the
//! upstream API is expected to take.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Domain separator for [`round1_digest`].
pub const ROUND1_DIGEST_DOMAIN: &[u8] = b"narsild/dkg/round1-set/v1";

/// One coefficient's entry in the digest: `(coeff_index, commitment points,
/// pok_r, pok_z)`, every value canonically encoded.
pub type CoefficientEntry = (u32, Vec<Vec<u8>>, Vec<u8>, Vec<u8>);

/// One dealer's round-1 contribution, in the form the digest covers.
///
/// Deliberately not the wire type: a digest over a JSON encoding is a digest
/// over whitespace and key order. These are the decoded values.
pub struct Round1Entry<'a> {
    pub dealer_index: u32,
    /// One entry per outer coefficient.
    pub coefficients: Vec<CoefficientEntry>,
    /// Borrowed lifetime marker so callers can build these from borrowed data
    /// without an allocation dance later.
    pub _marker: std::marker::PhantomData<&'a ()>,
}

/// The canonical digest of a complete round-1 set (M-5).
///
/// Every node computes this over the packages it accepted and broadcasts it;
/// a node proceeds to round 2 only when every roster member's digest equals
/// its own. That is what turns `n` independent point-to-point deliveries into
/// a reliable broadcast, and it is the thing osst's D-2 fix cannot do on its
/// own: sealing binds a sub-share to the commitment *as delivered to this
/// recipient*, and nothing binds that commitment to a single value every
/// recipient saw. A dealer that sends `C_A` to Alice and `C_B` to Bob passes
/// every per-recipient check and splits the group.
///
/// The encoding is sorted by dealer index and length-prefixed at every level,
/// so two different sets cannot digest alike by moving bytes across a
/// boundary.
pub fn round1_digest(epoch: u64, session_id: &[u8; 32], entries: &[Round1Entry<'_>]) -> [u8; 32] {
    let mut sorted: Vec<&Round1Entry<'_>> = entries.iter().collect();
    sorted.sort_by_key(|e| e.dealer_index);

    let mut h = Sha256::new();
    h.update(ROUND1_DIGEST_DOMAIN);
    h.update(epoch.to_le_bytes());
    h.update(session_id);
    h.update((sorted.len() as u64).to_le_bytes());
    for entry in sorted {
        h.update(entry.dealer_index.to_le_bytes());
        h.update((entry.coefficients.len() as u64).to_le_bytes());
        let mut coefficients = entry.coefficients.clone();
        coefficients.sort_by_key(|c| c.0);
        for (coeff_index, points, pok_r, pok_z) in &coefficients {
            h.update(coeff_index.to_le_bytes());
            h.update((points.len() as u64).to_le_bytes());
            for p in points {
                h.update((p.len() as u64).to_le_bytes());
                h.update(p);
            }
            h.update((pok_r.len() as u64).to_le_bytes());
            h.update(pok_r);
            h.update((pok_z.len() as u64).to_le_bytes());
            h.update(pok_z);
        }
    }
    h.finalize().into()
}

/// Every member's echo of the round-1 digest, and the verdict.
#[derive(Debug, Default)]
pub struct EchoSet {
    digests: BTreeMap<u32, [u8; 32]>,
}

/// What an echo set says about the group's view of round 1.
#[derive(Debug, PartialEq, Eq)]
pub enum EchoVerdict {
    /// Not every member has echoed yet.
    Pending { collected: usize, needed: usize },
    /// Every member echoed the same digest.
    Agreed,
    /// Members disagree. The indices are those whose digest differs from ours.
    Disagree { differing: Vec<u32> },
}

impl EchoSet {
    /// Record one member's digest. First echo from a member wins: a member
    /// that echoes twice with different digests is itself equivocating, and
    /// the first value is the one the rest of the group reacted to.
    pub fn insert(&mut self, index: u32, digest: [u8; 32]) {
        self.digests.entry(index).or_insert(digest);
    }

    pub fn len(&self) -> usize {
        self.digests.len()
    }

    /// Compare against our own digest, given the roster size.
    pub fn verdict(&self, ours: &[u8; 32], n: usize) -> EchoVerdict {
        let differing: Vec<u32> = self
            .digests
            .iter()
            .filter(|(_, d)| *d != ours)
            .map(|(i, _)| *i)
            .collect();
        if !differing.is_empty() {
            return EchoVerdict::Disagree { differing };
        }
        if self.digests.len() < n {
            return EchoVerdict::Pending {
                collected: self.digests.len(),
                needed: n,
            };
        }
        EchoVerdict::Agreed
    }
}

/// One member's echo of the round-1 digest. Public data; broadcast; signed by
/// the sender's roster identity like every other request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DkgEcho {
    pub sender_index: u32,
    pub epoch: u64,
    #[serde(with = "crate::codec::bytes32")]
    pub session_id: [u8; 32],
    #[serde(with = "crate::codec::bytes32")]
    pub digest: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(dealer: u32, byte: u8) -> Round1Entry<'static> {
        Round1Entry {
            dealer_index: dealer,
            coefficients: vec![(0, vec![vec![byte; 32]], vec![byte; 32], vec![byte; 32])],
            _marker: std::marker::PhantomData,
        }
    }

    /// The digest does not depend on the order packages arrived in.
    #[test]
    fn the_digest_is_order_independent() {
        let a = vec![entry(1, 1), entry(2, 2), entry(3, 3)];
        let b = vec![entry(3, 3), entry(1, 1), entry(2, 2)];
        assert_eq!(
            round1_digest(7, &[9u8; 32], &a),
            round1_digest(7, &[9u8; 32], &b)
        );
    }

    /// One dealer's package changing changes the digest — the property the
    /// echo round exists for.
    #[test]
    fn one_changed_package_changes_the_digest() {
        let honest = vec![entry(1, 1), entry(2, 2)];
        let equivocated = vec![entry(1, 1), entry(2, 0xff)];
        assert_ne!(
            round1_digest(7, &[9u8; 32], &honest),
            round1_digest(7, &[9u8; 32], &equivocated)
        );
    }

    /// The digest is bound to the ceremony, so an old set does not match a new
    /// attempt even if the packages were replayed wholesale.
    #[test]
    fn the_digest_is_bound_to_the_ceremony() {
        let set = vec![entry(1, 1)];
        assert_ne!(
            round1_digest(7, &[9u8; 32], &set),
            round1_digest(8, &[9u8; 32], &set)
        );
        assert_ne!(
            round1_digest(7, &[9u8; 32], &set),
            round1_digest(7, &[10u8; 32], &set)
        );
    }

    /// Length prefixes, not concatenation.
    #[test]
    fn the_encoding_is_unambiguous_across_boundaries() {
        let mut a = entry(1, 0);
        a.coefficients = vec![(0, vec![vec![1, 2], vec![3]], vec![4], vec![5])];
        let mut b = entry(1, 0);
        b.coefficients = vec![(0, vec![vec![1], vec![2, 3]], vec![4], vec![5])];
        assert_ne!(
            round1_digest(1, &[0u8; 32], &[a]),
            round1_digest(1, &[0u8; 32], &[b])
        );
    }

    #[test]
    fn an_echo_set_reports_agreement_only_when_everyone_has_echoed() {
        let ours = [1u8; 32];
        let mut set = EchoSet::default();
        assert_eq!(
            set.verdict(&ours, 3),
            EchoVerdict::Pending { collected: 0, needed: 3 }
        );
        set.insert(1, ours);
        set.insert(2, ours);
        assert_eq!(
            set.verdict(&ours, 3),
            EchoVerdict::Pending { collected: 2, needed: 3 }
        );
        set.insert(3, ours);
        assert_eq!(set.verdict(&ours, 3), EchoVerdict::Agreed);
    }

    #[test]
    fn an_echo_set_names_the_members_that_disagree() {
        let ours = [1u8; 32];
        let mut set = EchoSet::default();
        set.insert(1, ours);
        set.insert(2, [2u8; 32]);
        assert_eq!(
            set.verdict(&ours, 3),
            EchoVerdict::Disagree { differing: vec![2] }
        );
    }
}
