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

// ---------------------------------------------------------------------------
// Complaints (M-6)
// ---------------------------------------------------------------------------

/// Why a recipient is accusing a dealer. A closed set, not a string: the old
/// `reason: String` was unbounded attacker-controlled text logged at `error!`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplaintReason {
    /// The sealed package did not open for this ceremony.
    SealedOpenFailed,
    /// It opened, and the sub-share fails the Feldman check.
    InvalidSubShare,
    /// The dealer's proof of knowledge of its constant term does not verify.
    InvalidProofOfKnowledge,
    /// The members disagree about what round 1 was.
    Round1Disagreement,
}

/// What the accuser publishes so that everyone else can reach the same verdict.
///
/// A complaint that nobody can check is a denial-of-service primitive: the
/// only two policies available are "believe everyone", where one packet halts
/// the ceremony, and "believe nobody", where a genuinely bad dealer is
/// undetectable. Justification is what makes the third option — everyone
/// checks — possible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ComplaintEvidence {
    /// The accuser opened the package and publishes the sub-share it received,
    /// so every node re-runs the Feldman check itself and reaches the same
    /// verdict. A sub-share whose secrecy the complaint already forfeits is no
    /// additional loss.
    ///
    /// narsild cannot produce this against osst 0.4.0: `open_subshare`
    /// discards the plaintext on a failed check, and there is no lower-level
    /// open. The verification path below is written and tested against
    /// hand-built evidence so that the 0.5.0 swap is a change to the
    /// *producing* side only.
    SubShare { value_hex: String },
    /// The package did not open at all, so there is nothing to publish: the
    /// ciphertext is sealed to the accuser. Not publicly verifiable, and
    /// treated as such.
    SealedRejected {
        /// SHA-256 of the ciphertext the accuser received, so the accusation
        /// is at least pinned to one concrete message.
        ciphertext_digest: String,
    },
}

/// What a node concludes about a complaint it did not raise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The evidence checks out: the dealer is at fault and the ceremony ends.
    DealerAtFault,
    /// The evidence contradicts the accusation: the accuser is at fault, the
    /// complaint is ignored, and the accuser is flagged.
    AccuserAtFault,
    /// Nobody but the accuser can check this one.
    Unverifiable,
}

/// Adjudicate a complaint against the commitment this node recorded in round 1.
///
/// Deterministic, and a function of data every node holds — which is the
/// point: `osst::dkg::DkgState::disqualify` documents that "every participant
/// must apply the same complaints, or they derive different keys", and a
/// verdict reached by trust rather than by checking cannot be the same on
/// every node.
pub fn adjudicate<P: osst::curve::OsstPoint>(
    complainant_index: u32,
    evidence: &ComplaintEvidence,
    named_commitment_digest: &str,
    commitment: &osst::reshare::DealerCommitment<P>,
) -> Verdict {
    // The complaint must be about the commitment this node saw in round 1. A
    // complaint naming anything else is about a message this ceremony does not
    // contain.
    if named_commitment_digest != hex::encode(osst::sealed::commitment_digest(commitment)) {
        return Verdict::AccuserAtFault;
    }

    match evidence {
        ComplaintEvidence::SealedRejected { .. } => Verdict::Unverifiable,
        ComplaintEvidence::SubShare { value_hex } => {
            let Some(value) = crate::codec::scalar_from_hex_of::<P>(value_hex) else {
                return Verdict::AccuserAtFault;
            };
            if commitment.verify_subshare(complainant_index, &value) {
                // The share the accuser published is the share it should have
                // received. The accusation is false.
                Verdict::AccuserAtFault
            } else {
                Verdict::DealerAtFault
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spent sessions (M-13)
// ---------------------------------------------------------------------------

/// File the spent session ids are appended to, inside the data directory.
pub const SPENT_FILE: &str = "spent-sessions.log";

/// Session ids this node has already released a signature share for.
///
/// # Why this is durable and not a `BTreeMap`
///
/// osst's nonce discipline is sound *within one process*: `inner_sign_v2`
/// takes the nonces by value, so the pair is consumed and zeroized, and the
/// published commitment is checked against them. Across a process boundary it
/// is nothing, and osst's own doc says so — "callers that persist state across
/// restarts MUST additionally record `(session_id, holder_index)` as spent —
/// the type system cannot see a process boundary".
///
/// narsild kept nonces in an in-memory map and nothing else. A VM snapshot
/// restore, a container restarted from an image, or any rollback of the node's
/// state replays a nonce under a fresh challenge, and two responses under one
/// nonce leak the share by elementary algebra. For a daemon holding long-lived
/// escrow authority that is the failure mode most likely to actually happen:
/// snapshots are operational routine, not an attack.
///
/// # The caveat this does not remove
///
/// Restoring the data directory from a snapshot rolls this file back too. What
/// the file buys is that an *ordinary* restart — a crash, a redeploy, an OOM
/// kill — is safe. A snapshot restore is not, and cannot be made so from
/// inside the process. See the README.
pub trait SpentSessions: Send + Sync + 'static {
    /// Whether a share has already been released for this session.
    fn is_spent(&self, session_id: &[u8; 32]) -> bool;

    /// Record a session as spent, durably, *before* the share is produced.
    fn mark_spent(&self, session_id: &[u8; 32]) -> std::io::Result<()>;
}

/// The shipped implementation: an append-only log, fsync'd per entry.
pub struct FileSpentSessions {
    path: std::path::PathBuf,
    live: std::sync::Mutex<std::collections::BTreeSet<[u8; 32]>>,
}

impl FileSpentSessions {
    pub fn open(data_dir: &std::path::Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join(SPENT_FILE);
        let mut live = std::collections::BTreeSet::new();
        if path.exists() {
            for line in std::fs::read_to_string(&path)?.lines() {
                if let Some(id) = hex::decode(line.trim())
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                {
                    live.insert(id);
                }
            }
        }
        Ok(Self {
            path,
            live: std::sync::Mutex::new(live),
        })
    }
}

impl SpentSessions for FileSpentSessions {
    fn is_spent(&self, session_id: &[u8; 32]) -> bool {
        self.live
            .lock()
            .expect("spent-session store poisoned")
            .contains(session_id)
    }

    fn mark_spent(&self, session_id: &[u8; 32]) -> std::io::Result<()> {
        use std::io::Write as _;
        let mut live = self.live.lock().expect("spent-session store poisoned");
        // The disk write comes first: a crash between marking in memory and
        // marking on disk is exactly the window this exists to close.
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{}", hex::encode(session_id))?;
        f.sync_all()?;
        live.insert(*session_id);
        Ok(())
    }
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

    /// M-13: a session id is usable once, and the record survives a restart.
    #[test]
    fn a_spent_session_stays_spent_across_a_restart() {
        let dir = std::env::temp_dir().join(format!("narsild-spent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let store = FileSpentSessions::open(&dir).unwrap();
        assert!(!store.is_spent(&[1u8; 32]));
        store.mark_spent(&[1u8; 32]).unwrap();
        assert!(store.is_spent(&[1u8; 32]));
        assert!(!store.is_spent(&[2u8; 32]));

        // The restart: this is the case an in-memory map loses, and it is the
        // one that leaks a share.
        let reopened = FileSpentSessions::open(&dir).unwrap();
        assert!(reopened.is_spent(&[1u8; 32]));
        assert!(!reopened.is_spent(&[2u8; 32]));
        let _ = std::fs::remove_dir_all(&dir);
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

    /// M-6: the adjudication a justified complaint gets. Both directions are
    /// checked here because both matter: a true complaint must stop the
    /// ceremony on every node, and a false one must not stop it anywhere.
    ///
    /// The evidence is hand-built because osst 0.4.0's `open_subshare`
    /// discards the plaintext on a failed check, so narsild cannot yet produce
    /// it. This is the path the 0.5.0 swap turns on.
    #[test]
    fn a_justified_complaint_is_adjudicated_the_same_way_by_anyone() {
        use osst::curve::{OsstPoint as _, OsstScalar as _};
        use pasta_curves::pallas::{Point as P, Scalar as S};

        // f(x) = 5 + 7x, and its Feldman commitment.
        let a0 = S::from_u32(5);
        let a1 = S::from_u32(7);
        let commitment = osst::reshare::DealerCommitment::<P> {
            dealer_index: 2,
            coefficients: vec![
                P::generator().mul_scalar(&a0),
                P::generator().mul_scalar(&a1),
            ],
        };
        let digest = hex::encode(osst::sealed::commitment_digest(&commitment));

        // The share holder 1 should have received: f(1) = 12.
        let honest = S::from_u32(12);
        assert!(commitment.verify_subshare(1, &honest));

        // Accusing a dealer while publishing the share it should have sent is
        // a false accusation, and says so.
        assert_eq!(
            adjudicate::<P>(
                1,
                &ComplaintEvidence::SubShare {
                    value_hex: hex::encode(honest.to_bytes())
                },
                &digest,
                &commitment,
            ),
            Verdict::AccuserAtFault
        );

        // A share that fails the Feldman check convicts the dealer, and every
        // node reaches that verdict from public data.
        assert_eq!(
            adjudicate::<P>(
                1,
                &ComplaintEvidence::SubShare {
                    value_hex: hex::encode(S::from_u32(13).to_bytes())
                },
                &digest,
                &commitment,
            ),
            Verdict::DealerAtFault
        );

        // A complaint about a commitment this ceremony does not contain.
        assert_eq!(
            adjudicate::<P>(
                1,
                &ComplaintEvidence::SubShare {
                    value_hex: hex::encode(S::from_u32(13).to_bytes())
                },
                &hex::encode([0xaa; 32]),
                &commitment,
            ),
            Verdict::AccuserAtFault
        );

        // And one nobody can check stays uncheckable.
        assert_eq!(
            adjudicate::<P>(
                1,
                &ComplaintEvidence::SealedRejected {
                    ciphertext_digest: hex::encode([1u8; 32])
                },
                &digest,
                &commitment,
            ),
            Verdict::Unverifiable
        );
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
