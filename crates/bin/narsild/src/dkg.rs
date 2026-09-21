//! Distributed interleaved DKG for the nested FROST position.
//!
//! Each narsild node acts as one dealer in `outer_t` independent Feldman VSS
//! ceremonies — one per coefficient of the nested position's outer polynomial
//! — so the inner group ends up holding Shamir shares of each coefficient and
//! nobody learns a coefficient.
//!
//! ```text
//! round 1  broadcast  Feldman commitments + proof of knowledge of a_0
//! round 2  direct     one SEALED package per recipient, to that recipient only
//! round 3  local      open, Feldman-check, aggregate
//! ```
//!
//! # Round 2 is sealed, and there is no other kind (D-1, D-2)
//!
//! The previous implementation serialized each sub-share as a hex scalar and
//! *broadcast* the message for every recipient to every peer. A dealer's
//! polynomial has degree `t-1` and is pinned down by `t` points, so round 2
//! put `n-1` evaluations of every dealer's polynomial in front of every node:
//! for any `n > t` — 2-of-3 included — a single participant interpolates the
//! coefficients and reconstructs the group signing key. That is D-1 (Critical)
//! of SECURITY-REVIEW-2026-09.
//!
//! Two things changed, and both are needed:
//!
//! 1. **The wire type for round 2 is the sealed ciphertext.** [`SealedEntry`]
//!    carries `osst::sealed::SealedSubShare::ciphertext` and nothing else;
//!    there is no plaintext sub-share type in this crate any more, so there is
//!    no code path that can emit one. Both round-2 types are
//!    `deny_unknown_fields`, so a peer speaking the old protocol is rejected
//!    at deserialization rather than half-understood.
//! 2. **Each package goes to its recipient and to nobody else.**
//!    [`round2_messages`] returns one message per recipient and the caller
//!    delivers each with `PeerSet::send_to`. Sealing means a misdelivered
//!    package discloses nothing (D-2: the Noise `ss` mix binds the sender, the
//!    responder's static key binds the recipient, the roster-derived prologue
//!    binds the ceremony, and a digest inside the plaintext binds the dealer's
//!    Feldman commitment) — but not handing `n-1` packages to every node is
//!    the part of the fix that does not depend on the crypto being right.
//!
//! `open_subshare` runs the Feldman check itself and names the dealer on
//! failure. A failure is a [`Complaint`], and any complaint aborts the
//! ceremony: with a roster fixed by configuration there is no honest reason
//! for a member to deal a bad share, and silently continuing with a smaller
//! qualified set is how a partition turns into two groups holding different
//! keys.

use crate::codec::{point_from_hex, point_hex, scalar_hex};
use crate::keypackage::{KeyPackage, KEY_PACKAGE_FORMAT};
use crate::roster::Roster;
use osst::dkg;
use osst::reshare::DealerCommitment;
use osst::sealed::{self, SealedRoster, SealedSubShare};
use osst::OsstError;
use pasta_curves::pallas::Point as PallasPoint;
use pasta_curves::pallas::Scalar as PallasScalar;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Round number mixed into the Noise prologue for sub-share delivery.
///
/// Cross-coefficient replay does not need a separate round byte: the sealed
/// plaintext carries a digest of the dealer's Feldman commitment for *that*
/// coefficient, and `open_subshare` checks it against the commitment the
/// recipient looks up by `(coeff_index, dealer_index)` from round 1. A package
/// moved between coefficients fails as `InvalidSubShare`.
pub const ROUND_SUBSHARE: u8 = 2;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// One dealer's Feldman commitment for one outer coefficient, with the
/// Komlo–Goldberg proof of knowledge of its constant term (K-1).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DkgCommitmentMsg {
    /// Which outer polynomial coefficient (0-indexed).
    pub coeff_index: u32,
    /// Dealer's roster index (1-indexed).
    pub dealer_index: u32,
    /// `g^{c_j}` for each polynomial term, canonical compressed, hex.
    pub commitments: Vec<String>,
    /// Proof of knowledge commitment `R = g^k`, canonical compressed, hex.
    pub pok_r: String,
    /// Proof of knowledge response `z = k + e·a_0`, canonical, hex.
    pub pok_z: String,
}

/// Round 1: everything one node publishes. Public data; broadcast.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DkgRound1Broadcast {
    pub dealer_index: u32,
    /// The DKG generation this ceremony is producing. Binds the proofs of
    /// knowledge, so one ceremony's proof cannot be replayed into another.
    pub epoch: u64,
    /// The 32-byte nonce that distinguishes this *attempt* from another at the
    /// same epoch (M-15). Chosen by the initiator, echoed by every member;
    /// a broadcast carrying a different one is not part of this ceremony.
    #[serde(with = "crate::codec::bytes32")]
    pub ceremony_nonce: [u8; 32],
    /// The sender's roster fingerprint, hex. A mismatch means the two nodes
    /// disagree about the participant set and must not proceed.
    pub roster_hash: String,
    /// One entry per outer coefficient.
    pub coefficients: Vec<DkgCommitmentMsg>,
}

/// A proposal to run a DKG (M-3).
///
/// A DKG overwrites the key package, and the key package is the only thing
/// that can spend what the group holds. `POST /dkg/init {"epoch": N}` used to
/// be enough, from anyone, and a forged `/dkg/round1` auto-started a ceremony
/// on a peer-asserted epoch — the honest nodes then ran a perfectly legitimate
/// DKG among themselves and wrote over the shares. For a Zcash escrow with no
/// script recovery path, unspendable is permanent.
///
/// So a ceremony starts only when `t` roster members have signed the same
/// proposal, and a node that already holds a key package approves nothing that
/// does not say `rotate: true`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DkgProposal {
    /// The generation to produce.
    pub epoch: u64,
    /// The attempt nonce this ceremony will run under (M-15).
    #[serde(with = "crate::codec::bytes32")]
    pub ceremony_nonce: [u8; 32],
    /// Whether this proposal replaces an existing key package. A node holding
    /// one refuses to approve a proposal that does not say so.
    pub rotate: bool,
    /// The proposer's roster fingerprint, hex.
    pub roster_hash: String,
}

/// Domain separator for [`DkgProposal::digest`].
pub const PROPOSAL_DOMAIN: &[u8] = b"narsild/dkg/proposal/v1";

impl DkgProposal {
    /// What members approve: every field, length-prefixed.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(PROPOSAL_DOMAIN);
        h.update(self.epoch.to_le_bytes());
        h.update(self.ceremony_nonce);
        h.update([u8::from(self.rotate)]);
        h.update((self.roster_hash.len() as u64).to_le_bytes());
        h.update(self.roster_hash.as_bytes());
        h.finalize().into()
    }
}

/// Whether a node in the given state approves a proposal (M-3).
///
/// A pure function of the node's own state, so every member reaches its
/// verdict the same way and the rule can be read in one place. The rule that
/// matters: a node holding a key package approves nothing that does not say
/// `rotate: true`, and approves a rotation only with its operator's standing
/// consent. Everything else about a DKG is recoverable; overwriting the shares
/// that hold the escrow is not.
pub fn may_approve(
    proposal: &DkgProposal,
    our_roster_hash_hex: &str,
    current_epoch: u64,
    have_key_package: bool,
    allow_rotation: bool,
) -> Result<(), &'static str> {
    if proposal.roster_hash != our_roster_hash_hex {
        return Err("proposal is for a different roster");
    }
    if proposal.epoch <= current_epoch {
        return Err("proposal does not advance the epoch");
    }
    if have_key_package && !proposal.rotate {
        return Err("this node holds a key package and the proposal is not a rotation");
    }
    if proposal.rotate && !allow_rotation {
        return Err("this node is not configured to replace its key package");
    }
    Ok(())
}

/// One member's approval of a proposal.
///
/// The approval *is* the signed envelope that carries it: the envelope binds
/// the body to the sender's roster identity, this roster and this endpoint.
/// The body names what is being approved.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DkgApproval {
    pub approver_index: u32,
    #[serde(with = "crate::codec::bytes32")]
    pub proposal_digest: [u8; 32],
}

/// One sealed sub-share: the Noise_K message and the coefficient it belongs
/// to. The scalar is inside the ciphertext and appears nowhere else.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedEntry {
    pub coeff_index: u32,
    /// `ephemeral ‖ ciphertext ‖ tag`, hex.
    pub ciphertext: String,
}

/// Round 2: what one dealer sends to ONE recipient. Never broadcast.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DkgRound2Msg {
    pub dealer_index: u32,
    pub recipient_index: u32,
    pub epoch: u64,
    /// One sealed package per outer coefficient.
    pub sealed: Vec<SealedEntry>,
}

/// A recipient's accusation against a dealer (M-6).
///
/// Bound to the ceremony it belongs to — roster, session, epoch, round — so a
/// complaint captured from one attempt cannot be replayed into another, and
/// carried in a signed envelope so it is bound to its accuser. It names the
/// dealer's round-1 commitment it is about, and carries evidence every other
/// node adjudicates for itself (`agreement::adjudicate`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Complaint {
    pub complainant_index: u32,
    pub dealer_index: u32,
    pub coeff_index: u32,
    pub epoch: u64,
    #[serde(with = "crate::codec::bytes32")]
    pub session_id: [u8; 32],
    /// The sender's roster fingerprint, hex.
    pub roster_hash: String,
    /// Which round the accusation is about: 1 for a proof of knowledge or a
    /// round-1 disagreement, 2 for a sealed package.
    pub round: u8,
    /// Digest of the dealer's round-1 commitment this complaint is about, hex.
    pub commitment_digest: String,
    pub reason: crate::agreement::ComplaintReason,
    pub evidence: crate::agreement::ComplaintEvidence,
}

/// The ceremony's output for one node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgResult {
    pub holder_index: u32,
    pub epoch: u64,
    /// This ceremony's session id — see [`crate::roster::Roster::session_id`].
    #[serde(with = "crate::codec::bytes32")]
    pub session_id: [u8; 32],
    pub roster_hash: String,
    /// Shamir share of each outer coefficient, hex scalars.
    ///
    /// **M-1**: `skip`, not merely "do not put this in a handler". This is the
    /// group signing key in `t` pieces; `/dkg/status` used to serialize the
    /// whole struct, and the fix that survives the next handler is the one
    /// that makes the field unserializable rather than the one that remembers
    /// not to serialize it. [`crate::response::PublicDkgResult`] is the type a
    /// status page may carry.
    #[serde(skip)]
    pub coefficient_shares: Vec<String>,
    /// `g^{a_j}` for each outer coefficient, hex points. Same on every node.
    pub coeff_commitments: Vec<String>,
    /// `verification_shares[j][k-1] = g^{s_{j,k}}`: the point holder `k`'s
    /// share of coefficient `j` commits to. Public, and identical on every
    /// node.
    pub verification_shares: Vec<Vec<String>>,
    pub inner_threshold: u32,
    pub inner_n: u32,
    pub outer_threshold: u32,
}

impl DkgResult {
    /// The public half: what a status page may report.
    pub fn public_view(&self) -> crate::response::PublicDkgResult {
        let mut h = Sha256::new();
        h.update(b"narsild/verification-shares/v1");
        h.update((self.verification_shares.len() as u64).to_le_bytes());
        for coeff in &self.verification_shares {
            h.update((coeff.len() as u64).to_le_bytes());
            for point in coeff {
                h.update((point.len() as u64).to_le_bytes());
                h.update(point.as_bytes());
            }
        }
        crate::response::PublicDkgResult {
            holder_index: self.holder_index,
            epoch: self.epoch,
            roster_hash: self.roster_hash.clone(),
            coeff_commitments: self.coeff_commitments.clone(),
            verification_share_digest: hex::encode(h.finalize()),
            inner_threshold: self.inner_threshold,
            inner_n: self.inner_n,
            outer_threshold: self.outer_threshold,
        }
    }

    /// Persistable form.
    pub fn key_package(&self) -> KeyPackage {
        KeyPackage {
            format: KEY_PACKAGE_FORMAT,
            epoch: self.epoch,
            roster_hash: self.roster_hash.clone(),
            holder_index: self.holder_index,
            coefficient_shares: self.coefficient_shares.clone(),
            coeff_commitments: self.coeff_commitments.clone(),
            verification_shares: self.verification_shares.clone(),
            inner_threshold: self.inner_threshold,
            inner_n: self.inner_n,
            outer_threshold: self.outer_threshold,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum DkgError {
    #[error("osst: {0}")]
    Osst(OsstError),
    #[error("roster: {0}")]
    Roster(#[from] crate::roster::RosterError),
    #[error(
        "this DKG needs roster indices 1..={0} exactly; \
         osst::dkg::DkgState addresses dealers positionally"
    )]
    NonContiguousRoster(u32),
    #[error(
        "refusing a DKG for epoch {asked}: this node is already at epoch {current}, \
         and the key package for it is the one its peers expect"
    )]
    EpochNotAdvancing { current: u64, asked: u64 },
    #[error("peer {0} is taking part in a different attempt at this epoch")]
    CeremonyMismatch(u32),
    #[error(
        "round-1 set disagreement: members {differing:?} saw a different round 1 \
         from this node. At least one dealer sent different commitments to \
         different recipients; this ceremony cannot produce one key."
    )]
    EchoMismatch { differing: Vec<u32> },
    #[error("round 1 is not agreed yet: {collected}/{needed} members have echoed")]
    EchoIncomplete { collected: usize, needed: usize },
    #[error("dealer {0} has already submitted a round-1 package for coefficient {1}")]
    DuplicateRound1(u32, u32),
    #[error("epoch mismatch: ours is {ours}, peer {peer_index} says {theirs}")]
    EpochMismatch {
        peer_index: u32,
        ours: u64,
        theirs: u64,
    },
    #[error("roster mismatch with peer {0}: it has a different participant set")]
    RosterMismatch(u32),
    #[error("malformed round-1 message from dealer {0}: {1}")]
    MalformedRound1(u32, &'static str),
    #[error("malformed round-2 message from dealer {0}: {1}")]
    MalformedRound2(u32, &'static str),
    #[error("round-2 package addressed to {addressed}, we are {ours}")]
    NotOurs { addressed: u32, ours: u32 },
    #[error("no round-1 commitment for coefficient {coeff_index} from dealer {dealer_index}")]
    MissingCommitment { coeff_index: u32, dealer_index: u32 },
    #[error("DKG aborted by complaint against dealer {}: {:?}", .0.dealer_index, .0.reason)]
    Aborted(Box<Complaint>),
    #[error("DKG already aborted by complaint against dealer {}", .0.dealer_index)]
    AlreadyAborted(Box<Complaint>),
    #[error("round 1 is not complete: {got}/{need} dealers have committed")]
    Round1Incomplete { got: usize, need: usize },
    #[error("round 2 is not complete for coefficient {coeff_index}: {got}/{need}")]
    Round2Incomplete {
        coeff_index: u32,
        got: usize,
        need: usize,
    },
}

impl From<OsstError> for DkgError {
    fn from(e: OsstError) -> Self {
        DkgError::Osst(e)
    }
}

// ---------------------------------------------------------------------------
// Ceremony
// ---------------------------------------------------------------------------

/// One DKG ceremony, with no transport of its own.
///
/// The ceremony produces messages and consumes messages; delivering them is
/// the caller's job. That is what lets the whole protocol run in-process in a
/// test, and it is why round 2 cannot accidentally reach `broadcast`.
pub struct DkgCeremony {
    pub holder_index: u32,
    pub epoch: u64,
    pub inner_n: u32,
    pub inner_t: u32,
    pub outer_t: u32,
    /// This ceremony's session id.
    pub session_id: [u8; 32],
    /// The attempt nonce the session id is derived from.
    pub ceremony_nonce: [u8; 32],
    roster: Arc<Roster>,
    roster_hash_hex: String,
    sealed_roster: SealedRoster,
    x25519_secret: [u8; 32],
    /// Our dealers, one per outer coefficient.
    dealers: Vec<dkg::Dealer<PallasPoint>>,
    /// Round-1 state, one per outer coefficient. Verifies proofs of knowledge.
    states: Vec<dkg::DkgState<PallasPoint>>,
    /// Opened sub-shares: `subshares[coeff][dealer] = f_dealer(us)`.
    subshares: Vec<BTreeMap<u32, PallasScalar>>,
    /// The round-1 broadcasts as accepted, by dealer — what the echo digest is
    /// computed over, and the evidence a complaint is checked against.
    round1_msgs: BTreeMap<u32, DkgRound1Broadcast>,
    /// Every member's echo of the round-1 digest (M-5).
    echoes: crate::agreement::EchoSet,
    /// This node's round-1 broadcast, sampled once.
    ///
    /// `Dealer::round1_package` draws a fresh proof-of-knowledge nonce on
    /// every call, so calling it twice would make an honest node look like an
    /// equivocating dealer to the echo round.
    our_broadcast: DkgRound1Broadcast,
    /// The complaint that aborted the ceremony, if any.
    aborted: Option<Complaint>,
    /// Accusers whose complaints contradicted the evidence they carried.
    flagged: BTreeSet<u32>,
    /// Complaints nobody but the accuser can check, by dealer: a single one is
    /// not acted on, `inner_t` independent ones are.
    unverifiable: BTreeMap<u32, BTreeSet<u32>>,
    /// `(complainant, dealer, coeff)` of complaints already seen, so a
    /// re-broadcast does not loop.
    seen_complaints: BTreeSet<(u32, u32, u32)>,
    pub result: Option<DkgResult>,
}

impl DkgCeremony {
    /// Start a ceremony.
    ///
    /// `inner_t` is the inner threshold, `outer_t` the number of outer
    /// polynomial coefficients (i.e. the outer threshold). The participant set
    /// is the roster, in full: a member that does not commit stalls the
    /// ceremony rather than being dropped from it, because the roster is
    /// configuration and disagreement about who is in the group is exactly
    /// what the roster hash exists to detect.
    pub fn new(
        holder_index: u32,
        roster: Arc<Roster>,
        x25519_secret: [u8; 32],
        epoch: u64,
        ceremony_nonce: [u8; 32],
        inner_t: u32,
        outer_t: u32,
    ) -> Result<Self, DkgError> {
        let n = roster.len();
        if roster.indices() != (1..=n).collect::<Vec<u32>>() {
            return Err(DkgError::NonContiguousRoster(n));
        }
        roster.get(holder_index)?;

        let mut rng = rand_core::OsRng;
        let mut dealers = Vec::with_capacity(outer_t as usize);
        for _ in 0..outer_t {
            dealers.push(dkg::Dealer::<PallasPoint>::new(
                holder_index,
                inner_t,
                &mut rng,
            )?);
        }

        let states = (0..outer_t)
            .map(|_| dkg::DkgState::<PallasPoint>::new(epoch, inner_t, n))
            .collect();

        let mut ceremony = Self {
            holder_index,
            epoch,
            inner_n: n,
            inner_t,
            outer_t,
            session_id: roster.session_id(epoch, &ceremony_nonce),
            ceremony_nonce,
            roster_hash_hex: hex::encode(roster.hash()),
            sealed_roster: roster.sealed_roster(epoch, &ceremony_nonce)?,
            roster,
            x25519_secret,
            dealers,
            states,
            subshares: (0..outer_t).map(|_| BTreeMap::new()).collect(),
            round1_msgs: BTreeMap::new(),
            echoes: crate::agreement::EchoSet::default(),
            our_broadcast: DkgRound1Broadcast {
                dealer_index: holder_index,
                epoch,
                ceremony_nonce,
                roster_hash: String::new(),
                coefficients: Vec::new(),
            },
            aborted: None,
            flagged: BTreeSet::new(),
            unverifiable: BTreeMap::new(),
            seen_complaints: BTreeSet::new(),
            result: None,
        };
        ceremony.our_broadcast = ceremony.sample_round1_broadcast();
        Ok(ceremony)
    }

    /// The complaint that aborted this ceremony, if any.
    pub fn abort_reason(&self) -> Option<&Complaint> {
        self.aborted.as_ref()
    }

    fn check_live(&self) -> Result<(), DkgError> {
        match &self.aborted {
            Some(c) => Err(DkgError::AlreadyAborted(Box::new(c.clone()))),
            None => Ok(()),
        }
    }

    /// Round 1: our Feldman commitments and proofs of knowledge.
    ///
    /// Sampled once, in the constructor, and handed out unchanged. The proof
    /// of knowledge draws a fresh nonce per call, so a node that re-derived
    /// this would publish two different packages for one slot and be
    /// indistinguishable from an equivocating dealer.
    pub fn round1_broadcast(&self) -> DkgRound1Broadcast {
        self.our_broadcast.clone()
    }

    fn sample_round1_broadcast(&self) -> DkgRound1Broadcast {
        let mut rng = rand_core::OsRng;
        let coefficients = self
            .dealers
            .iter()
            .enumerate()
            .map(|(j, dealer)| {
                let package = dealer.round1_package(self.epoch, &mut rng);
                DkgCommitmentMsg {
                    coeff_index: j as u32,
                    dealer_index: self.holder_index,
                    commitments: package
                        .commitment
                        .coefficients
                        .iter()
                        .map(point_hex)
                        .collect(),
                    pok_r: point_hex(&package.proof_of_knowledge.r),
                    pok_z: scalar_hex(&package.proof_of_knowledge.z),
                }
            })
            .collect();

        DkgRound1Broadcast {
            dealer_index: self.holder_index,
            epoch: self.epoch,
            ceremony_nonce: self.ceremony_nonce,
            roster_hash: self.roster_hash_hex.clone(),
            coefficients,
        }
    }

    /// Accept a peer's (or our own) round-1 broadcast.
    ///
    /// The proof of knowledge is verified inside
    /// [`dkg::DkgState::submit_commitment`], before the commitment is
    /// recorded: a dealer that cannot prove knowledge of its constant term
    /// never enters the ceremony, so a rogue-key setup has nowhere to start.
    ///
    /// Returns `true` once every roster member has committed for every
    /// coefficient.
    pub fn receive_round1(&mut self, msg: &DkgRound1Broadcast) -> Result<bool, DkgError> {
        self.check_live()?;

        // M-7: one package per dealer, and a second one is an error rather
        // than a silent drop. osst's `submit_commitment` is first-write-wins
        // and returns `Ok(false)` for a taken slot, which the old code read as
        // success — so an attacker who posted under an honest dealer's index
        // first had that dealer's genuine broadcast dropped, and round 2 then
        // framed it. Authentication (main.rs) stops the squat; this stops the
        // silence.
        if self.round1_msgs.contains_key(&msg.dealer_index) {
            return Err(DkgError::DuplicateRound1(msg.dealer_index, 0));
        }

        if msg.epoch != self.epoch {
            return Err(DkgError::EpochMismatch {
                peer_index: msg.dealer_index,
                ours: self.epoch,
                theirs: msg.epoch,
            });
        }
        if msg.ceremony_nonce != self.ceremony_nonce {
            return Err(DkgError::CeremonyMismatch(msg.dealer_index));
        }
        if msg.roster_hash != self.roster_hash_hex {
            return Err(DkgError::RosterMismatch(msg.dealer_index));
        }
        self.roster.get(msg.dealer_index)?;
        if msg.coefficients.len() != self.outer_t as usize {
            return Err(DkgError::MalformedRound1(
                msg.dealer_index,
                "wrong number of coefficients",
            ));
        }

        for entry in &msg.coefficients {
            if entry.dealer_index != msg.dealer_index {
                return Err(DkgError::MalformedRound1(
                    msg.dealer_index,
                    "coefficient entry names a different dealer",
                ));
            }
            let coeff = entry.coeff_index;
            if coeff >= self.outer_t {
                return Err(DkgError::MalformedRound1(
                    msg.dealer_index,
                    "coefficient index out of range",
                ));
            }
            if entry.commitments.len() != self.inner_t as usize {
                return Err(DkgError::MalformedRound1(
                    msg.dealer_index,
                    "wrong number of commitment points",
                ));
            }

            let points = entry
                .commitments
                .iter()
                .map(|h| {
                    point_from_hex(h).ok_or(DkgError::MalformedRound1(
                        msg.dealer_index,
                        "non-canonical commitment point",
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let pok_r = point_from_hex(&entry.pok_r).ok_or(DkgError::MalformedRound1(
                msg.dealer_index,
                "non-canonical proof-of-knowledge commitment",
            ))?;
            let pok_z = crate::codec::scalar_from_hex(&entry.pok_z).ok_or(
                DkgError::MalformedRound1(
                    msg.dealer_index,
                    "non-canonical proof-of-knowledge response",
                ),
            )?;

            let package = dkg::Round1Package {
                commitment: DealerCommitment {
                    dealer_index: entry.dealer_index,
                    coefficients: points,
                },
                proof_of_knowledge: dkg::ProofOfKnowledge {
                    r: pok_r,
                    z: pok_z,
                },
            };

            // K-1: the proof is checked here, and a failure names the dealer.
            match self.states[coeff as usize].submit_commitment(package) {
                Ok(_) => {}
                Err(OsstError::InvalidProofOfKnowledge(idx)) => {
                    // Publicly verifiable by construction: the package is a
                    // broadcast, so everyone re-checks the proof themselves.
                    let complaint = self.complaint(
                        idx,
                        coeff,
                        1,
                        crate::agreement::ComplaintReason::InvalidProofOfKnowledge,
                        crate::agreement::ComplaintEvidence::SealedRejected {
                            ciphertext_digest: String::new(),
                        },
                    );
                    return Err(self.abort(complaint));
                }
                Err(e) => return Err(DkgError::Osst(e)),
            }
        }

        self.round1_msgs.insert(msg.dealer_index, msg.clone());
        Ok(self.round1_complete())
    }

    /// The canonical digest of the round-1 set this node accepted (M-5).
    ///
    /// `None` until round 1 is complete: a digest over a partial set says
    /// nothing, and echoing one would make honest nodes disagree.
    pub fn round1_digest(&self) -> Option<[u8; 32]> {
        if !self.round1_complete() {
            return None;
        }
        let entries: Vec<crate::agreement::Round1Entry<'_>> = self
            .round1_msgs
            .values()
            .map(|msg| crate::agreement::Round1Entry {
                dealer_index: msg.dealer_index,
                coefficients: msg
                    .coefficients
                    .iter()
                    .map(|c| {
                        (
                            c.coeff_index,
                            c.commitments
                                .iter()
                                .map(|h| hex::decode(h).unwrap_or_default())
                                .collect(),
                            hex::decode(&c.pok_r).unwrap_or_default(),
                            hex::decode(&c.pok_z).unwrap_or_default(),
                        )
                    })
                    .collect(),
                _marker: std::marker::PhantomData,
            })
            .collect();
        Some(crate::agreement::round1_digest(
            self.epoch,
            &self.session_id,
            &entries,
        ))
    }

    /// This node's echo of the round-1 digest, to broadcast.
    pub fn echo(&self) -> Option<crate::agreement::DkgEcho> {
        Some(crate::agreement::DkgEcho {
            sender_index: self.holder_index,
            epoch: self.epoch,
            session_id: self.session_id,
            digest: self.round1_digest()?,
        })
    }

    /// Accept a member's echo (M-5).
    ///
    /// Returns `true` once every roster member has echoed the same digest this
    /// node computed. A disagreement aborts: at least one dealer sent
    /// different commitments to different recipients, and there is no key the
    /// whole group could agree on afterwards.
    pub fn receive_echo(&mut self, echo: &crate::agreement::DkgEcho) -> Result<bool, DkgError> {
        self.check_live()?;
        if echo.epoch != self.epoch {
            return Err(DkgError::EpochMismatch {
                peer_index: echo.sender_index,
                ours: self.epoch,
                theirs: echo.epoch,
            });
        }
        if echo.session_id != self.session_id {
            return Err(DkgError::CeremonyMismatch(echo.sender_index));
        }
        self.roster.get(echo.sender_index)?;

        let ours = self
            .round1_digest()
            .ok_or(DkgError::Round1Incomplete {
                got: self.round1_msgs.len(),
                need: self.inner_n as usize,
            })?;
        self.echoes.insert(echo.sender_index, echo.digest);

        match self.echoes.verdict(&ours, self.inner_n as usize) {
            crate::agreement::EchoVerdict::Agreed => Ok(true),
            crate::agreement::EchoVerdict::Pending { .. } => Ok(false),
            crate::agreement::EchoVerdict::Disagree { differing } => {
                let complaint = self.complaint(
                    *differing.first().unwrap_or(&0),
                    0,
                    1,
                    crate::agreement::ComplaintReason::Round1Disagreement,
                    crate::agreement::ComplaintEvidence::SealedRejected {
                        ciphertext_digest: String::new(),
                    },
                );
                self.aborted = Some(complaint);
                Err(DkgError::EchoMismatch { differing })
            }
        }
    }

    /// Every member has echoed our digest.
    pub fn round1_agreed(&self) -> bool {
        match self.round1_digest() {
            Some(ours) => {
                self.echoes.verdict(&ours, self.inner_n as usize)
                    == crate::agreement::EchoVerdict::Agreed
            }
            None => false,
        }
    }

    /// Every roster member has committed for every coefficient.
    pub fn round1_complete(&self) -> bool {
        self.states
            .iter()
            .all(|s| s.commitment_count() == self.inner_n as usize)
    }

    /// Round 2: one message per recipient, each carrying only that
    /// recipient's sealed sub-shares.
    ///
    /// The message addressed to this node is included, so a node applies its
    /// own sub-shares through exactly the code path it applies everyone
    /// else's — including the Feldman check.
    pub fn round2_messages(&self) -> Result<Vec<DkgRound2Msg>, DkgError> {
        self.check_live()?;
        if !self.round1_complete() {
            return Err(DkgError::Round1Incomplete {
                got: self.states.iter().map(|s| s.commitment_count()).min().unwrap_or(0),
                need: self.inner_n as usize,
            });
        }
        // M-5: nothing leaves this node until the group agrees on what round 1
        // was. A sealed sub-share is only bound to the commitment as delivered
        // to its recipient; the echo is what binds that commitment to a single
        // value every recipient saw.
        if !self.round1_agreed() {
            return Err(DkgError::EchoIncomplete {
                collected: self.echoes.len(),
                needed: self.inner_n as usize,
            });
        }

        // seal_round2 gives us, per coefficient, one package per recipient.
        // Regroup by recipient: a recipient must receive its own packages and
        // no others.
        let mut by_recipient: BTreeMap<u32, Vec<SealedEntry>> = BTreeMap::new();
        for (j, dealer) in self.dealers.iter().enumerate() {
            let packages: Vec<SealedSubShare> = sealed::seal_round2::<PallasPoint>(
                dealer,
                &self.x25519_secret,
                &self.sealed_roster,
                ROUND_SUBSHARE,
            )?;
            for package in packages {
                by_recipient
                    .entry(package.recipient_index)
                    .or_default()
                    .push(SealedEntry {
                        coeff_index: j as u32,
                        ciphertext: hex::encode(&package.ciphertext),
                    });
            }
        }

        let mut out: Vec<DkgRound2Msg> = by_recipient
            .into_iter()
            .map(|(recipient_index, sealed)| DkgRound2Msg {
                dealer_index: self.holder_index,
                recipient_index,
                epoch: self.epoch,
                sealed,
            })
            .collect();
        out.sort_by_key(|m| m.recipient_index);
        Ok(out)
    }

    /// Open a round-2 package addressed to us.
    ///
    /// `open_subshare` does the work: it checks that the package opens under
    /// (our static key, the named dealer's static key, this ceremony's
    /// prologue), that the indices inside match the envelope, that the
    /// commitment digest inside matches the commitment we recorded in round 1,
    /// and that the sub-share satisfies the Feldman check. Any failure names
    /// the dealer and aborts the ceremony.
    ///
    /// Returns `true` once every dealer's sub-shares are in.
    pub fn receive_round2(&mut self, msg: &DkgRound2Msg) -> Result<bool, DkgError> {
        self.check_live()?;

        if msg.recipient_index != self.holder_index {
            return Err(DkgError::NotOurs {
                addressed: msg.recipient_index,
                ours: self.holder_index,
            });
        }
        if msg.epoch != self.epoch {
            return Err(DkgError::EpochMismatch {
                peer_index: msg.dealer_index,
                ours: self.epoch,
                theirs: msg.epoch,
            });
        }
        self.roster.get(msg.dealer_index)?;
        if msg.sealed.len() != self.outer_t as usize {
            return Err(DkgError::MalformedRound2(
                msg.dealer_index,
                "wrong number of sealed packages",
            ));
        }

        for entry in &msg.sealed {
            let coeff = entry.coeff_index;
            if coeff >= self.outer_t {
                return Err(DkgError::MalformedRound2(
                    msg.dealer_index,
                    "coefficient index out of range",
                ));
            }
            let ciphertext = hex::decode(&entry.ciphertext).map_err(|_| {
                DkgError::MalformedRound2(msg.dealer_index, "ciphertext is not hex")
            })?;

            let commitment = self.states[coeff as usize]
                .commitments
                .get(msg.dealer_index as usize - 1)
                .and_then(|c| c.as_ref())
                .ok_or(DkgError::MissingCommitment {
                    coeff_index: coeff,
                    dealer_index: msg.dealer_index,
                })?;

            let sealed_package = SealedSubShare {
                dealer_index: msg.dealer_index,
                recipient_index: self.holder_index,
                ciphertext,
            };

            match sealed::open_subshare::<PallasPoint>(
                &self.x25519_secret,
                self.holder_index,
                &self.sealed_roster,
                ROUND_SUBSHARE,
                &sealed_package,
                commitment,
            ) {
                Ok(subshare) => {
                    self.subshares[coeff as usize]
                        .insert(msg.dealer_index, *subshare.value());
                }
                Err(e) => {
                    // The distinction osst keeps between these two matters —
                    // one says the package was not for us, the other that the
                    // dealer's own arithmetic is wrong — and it is what drives
                    // the complaint round.
                    let reason = match e {
                        OsstError::InvalidSubShare(_) => {
                            crate::agreement::ComplaintReason::InvalidSubShare
                        }
                        _ => crate::agreement::ComplaintReason::SealedOpenFailed,
                    };
                    // osst 0.4.0's `open_subshare` discards the plaintext on a
                    // failed check, so this node cannot publish the sub-share
                    // that would make the complaint publicly verifiable. It
                    // pins the accusation to the exact ciphertext instead, and
                    // peers treat it as unverifiable: `inner_t` independent
                    // accusers against one dealer, not one packet. osst 0.5.0
                    // is expected to return the plaintext, at which point this
                    // becomes `ComplaintEvidence::SubShare` and the
                    // adjudication path in `agreement` — already written and
                    // tested — does the rest.
                    let mut h = Sha256::new();
                    h.update(b"narsild/dkg/ciphertext/v1");
                    h.update(&sealed_package.ciphertext);
                    let complaint = self.complaint(
                        msg.dealer_index,
                        coeff,
                        2,
                        reason,
                        crate::agreement::ComplaintEvidence::SealedRejected {
                            ciphertext_digest: hex::encode(h.finalize()),
                        },
                    );
                    return Err(self.abort(complaint));
                }
            }
        }

        Ok(self.round2_complete())
    }

    /// Every dealer's sub-shares are in, for every coefficient.
    pub fn round2_complete(&self) -> bool {
        self.subshares
            .iter()
            .all(|m| m.len() == self.inner_n as usize)
    }

    /// Round 3: aggregate into this node's share of each outer coefficient.
    pub fn finalize(&mut self) -> Result<DkgResult, DkgError> {
        self.check_live()?;

        let dealer_set = self.roster.indices();
        let mut coefficient_shares = Vec::with_capacity(self.outer_t as usize);
        let mut coeff_commitments = Vec::with_capacity(self.outer_t as usize);
        let mut verification_shares = Vec::with_capacity(self.outer_t as usize);

        for j in 0..self.outer_t {
            let subs = &self.subshares[j as usize];
            if subs.len() != self.inner_n as usize {
                return Err(DkgError::Round2Incomplete {
                    coeff_index: j,
                    got: subs.len(),
                    need: self.inner_n as usize,
                });
            }

            let mut agg =
                dkg::Aggregator::<PallasPoint>::new(self.holder_index, &dealer_set)?;
            for &dealer_index in &dealer_set {
                let value = subs.get(&dealer_index).ok_or(DkgError::Round2Incomplete {
                    coeff_index: j,
                    got: subs.len(),
                    need: self.inner_n as usize,
                })?;
                let commitment = self.states[j as usize]
                    .commitments
                    .get(dealer_index as usize - 1)
                    .and_then(|c| c.as_ref())
                    .ok_or(DkgError::MissingCommitment {
                        coeff_index: j,
                        dealer_index,
                    })?;
                let subshare = osst::reshare::SubShare::new(
                    dealer_index,
                    self.holder_index,
                    *value,
                )?;
                agg.add_subshare(subshare, commitment)?;
            }

            coefficient_shares.push(scalar_hex(&agg.finalize()?));
            coeff_commitments.push(point_hex(&agg.derive_group_key()?));
            verification_shares.push(
                self.states[j as usize]
                    .derive_all_verification_shares()?
                    .values()
                    .map(point_hex)
                    .collect(),
            );
        }

        let result = DkgResult {
            holder_index: self.holder_index,
            epoch: self.epoch,
            session_id: self.session_id,
            roster_hash: self.roster_hash_hex.clone(),
            coefficient_shares,
            coeff_commitments,
            verification_shares,
            inner_threshold: self.inner_t,
            inner_n: self.inner_n,
            outer_threshold: self.outer_t,
        };
        self.result = Some(result.clone());
        Ok(result)
    }

    /// Accept a complaint raised by another participant, and adjudicate it
    /// (M-6).
    ///
    /// The old behaviour was to believe any complaint from anyone: it named a
    /// dealer, and the ceremony stopped. One unauthenticated packet was a
    /// denial of service, and because the handler did not re-broadcast, a
    /// complaint delivered to one node stopped that node while the rest
    /// finalized — which is the split-group outcome the broadcast exists to
    /// prevent.
    ///
    /// Now every node reaches its own verdict from data it holds:
    ///
    /// - the complaint must belong to *this* ceremony (roster, epoch, session)
    ///   and name members of this roster;
    /// - its evidence is checked against the dealer's round-1 commitment as
    ///   this node recorded it;
    /// - a complaint whose evidence contradicts it is ignored and its accuser
    ///   flagged;
    /// - a complaint nobody but the accuser can check does not act alone:
    ///   `inner_t` independent accusers against one dealer are required.
    ///
    /// Returns whether the caller should re-broadcast it — true the first time
    /// a well-formed complaint is seen, so it reaches the whole group without
    /// looping.
    pub fn receive_complaint(&mut self, complaint: &Complaint) -> Result<bool, DkgError> {
        if complaint.epoch != self.epoch {
            return Err(DkgError::EpochMismatch {
                peer_index: complaint.complainant_index,
                ours: self.epoch,
                theirs: complaint.epoch,
            });
        }
        if complaint.session_id != self.session_id {
            return Err(DkgError::CeremonyMismatch(complaint.complainant_index));
        }
        if complaint.roster_hash != self.roster_hash_hex {
            return Err(DkgError::RosterMismatch(complaint.complainant_index));
        }
        self.roster.get(complaint.complainant_index)?;
        self.roster.get(complaint.dealer_index)?;
        if complaint.coeff_index >= self.outer_t {
            return Err(DkgError::MalformedRound1(
                complaint.complainant_index,
                "coefficient index out of range",
            ));
        }

        let key = (
            complaint.complainant_index,
            complaint.dealer_index,
            complaint.coeff_index,
        );
        if !self.seen_complaints.insert(key) {
            return Ok(false);
        }

        let commitment = self.states[complaint.coeff_index as usize]
            .commitments
            .get(complaint.dealer_index as usize - 1)
            .and_then(|c| c.as_ref());

        let verdict = match commitment {
            Some(commitment) => crate::agreement::adjudicate::<PallasPoint>(
                complaint.complainant_index,
                &complaint.evidence,
                &complaint.commitment_digest,
                commitment,
            ),
            // No round-1 commitment from that dealer here: nothing to check
            // the accusation against.
            None => crate::agreement::Verdict::Unverifiable,
        };

        match verdict {
            crate::agreement::Verdict::DealerAtFault => {
                tracing::error!(
                    "DKG aborted: member {} proved dealer {} sent a bad sub-share for \
                     coefficient {}",
                    complaint.complainant_index,
                    complaint.dealer_index,
                    complaint.coeff_index
                );
                if self.aborted.is_none() {
                    self.aborted = Some(complaint.clone());
                }
            }
            crate::agreement::Verdict::AccuserAtFault => {
                tracing::warn!(
                    "ignoring a complaint from member {} against dealer {}: its own \
                     evidence contradicts it",
                    complaint.complainant_index,
                    complaint.dealer_index
                );
                self.flagged.insert(complaint.complainant_index);
            }
            crate::agreement::Verdict::Unverifiable => {
                let accusers = self
                    .unverifiable
                    .entry(complaint.dealer_index)
                    .or_default();
                accusers.insert(complaint.complainant_index);
                let count = accusers.len();
                tracing::warn!(
                    "unverifiable complaint against dealer {} from member {} ({}/{} \
                     independent accusers)",
                    complaint.dealer_index,
                    complaint.complainant_index,
                    count,
                    self.inner_t
                );
                if count >= self.inner_t as usize && self.aborted.is_none() {
                    tracing::error!(
                        "DKG aborted: {} independent members accuse dealer {}",
                        count,
                        complaint.dealer_index
                    );
                    self.aborted = Some(complaint.clone());
                }
            }
        }
        Ok(true)
    }

    /// Build a complaint bound to this ceremony.
    fn complaint(
        &self,
        dealer_index: u32,
        coeff_index: u32,
        round: u8,
        reason: crate::agreement::ComplaintReason,
        evidence: crate::agreement::ComplaintEvidence,
    ) -> Complaint {
        Complaint {
            complainant_index: self.holder_index,
            dealer_index,
            coeff_index,
            epoch: self.epoch,
            session_id: self.session_id,
            roster_hash: self.roster_hash_hex.clone(),
            round,
            commitment_digest: self
                .commitment_digest_of(coeff_index, dealer_index)
                .unwrap_or_default(),
            reason,
            evidence,
        }
    }

    /// The digest of a dealer's round-1 commitment for one coefficient, as
    /// this node recorded it. What a complaint names, and what an adjudicator
    /// checks that name against.
    pub fn commitment_digest_of(&self, coeff_index: u32, dealer_index: u32) -> Option<String> {
        let commitment = self
            .states
            .get(coeff_index as usize)?
            .commitments
            .get(dealer_index as usize - 1)?
            .as_ref()?;
        Some(hex::encode(sealed::commitment_digest(commitment)))
    }

    /// Accusers whose complaints contradicted their own evidence.
    ///
    /// Read by the operator-facing tests and by anyone deciding whether a
    /// member should stay on the roster; the ceremony itself only needs to
    /// know that it did not act on them.
    #[allow(dead_code)]
    pub fn flagged_accusers(&self) -> &BTreeSet<u32> {
        &self.flagged
    }

    fn abort(&mut self, complaint: Complaint) -> DkgError {
        tracing::error!(
            "DKG aborted: complaint against dealer {} for coefficient {}: {:?}",
            complaint.dealer_index,
            complaint.coeff_index,
            complaint.reason
        );
        self.aborted = Some(complaint.clone());
        DkgError::Aborted(Box::new(complaint))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal(epoch: u64, rotate: bool) -> DkgProposal {
        DkgProposal {
            epoch,
            ceremony_nonce: [3u8; 32],
            rotate,
            roster_hash: hex::encode([7u8; 32]),
        }
    }

    /// M-3: a node holding a key package approves nothing that is not an
    /// explicit, operator-consented rotation.
    #[test]
    fn a_node_holding_a_key_package_only_approves_a_consented_rotation() {
        let ours = hex::encode([7u8; 32]);

        // A node with no key package: an ordinary first ceremony.
        assert!(may_approve(&proposal(1, false), &ours, 0, false, false).is_ok());

        // A node that holds one: a proposal that is not a rotation is refused,
        // and a rotation is refused without the operator's consent.
        assert!(may_approve(&proposal(2, false), &ours, 1, true, false).is_err());
        assert!(may_approve(&proposal(2, true), &ours, 1, true, false).is_err());
        assert!(may_approve(&proposal(2, true), &ours, 1, true, true).is_ok());

        // Backwards, and from another roster.
        assert!(may_approve(&proposal(1, true), &ours, 1, true, true).is_err());
        assert!(may_approve(&proposal(2, true), &hex::encode([9u8; 32]), 1, true, true).is_err());
    }

    /// The digest covers every term, so an approval of one proposal is not an
    /// approval of another.
    #[test]
    fn the_proposal_digest_covers_every_term() {
        let base = proposal(2, false).digest();
        assert_ne!(base, proposal(3, false).digest());
        assert_ne!(base, proposal(2, true).digest());

        let mut other_nonce = proposal(2, false);
        other_nonce.ceremony_nonce = [4u8; 32];
        assert_ne!(base, other_nonce.digest());

        let mut other_roster = proposal(2, false);
        other_roster.roster_hash = hex::encode([8u8; 32]);
        assert_ne!(base, other_roster.digest());
    }

    /// The round-2 wire type refuses the shape the vulnerable narsild used.
    ///
    /// This is the regression test for D-1. The old message was
    /// `{dealer_index, recipient_index, subshares:[{coeff_index, dealer_index,
    /// recipient_index, value_hex}]}` and was broadcast to every peer. There
    /// is no type in this crate that can hold it any more, and
    /// `deny_unknown_fields` means a peer still speaking it is refused at the
    /// door rather than partially understood.
    #[test]
    fn a_plaintext_round2_message_does_not_deserialize() {
        let legacy = r#"{
            "dealer_index": 1,
            "recipient_index": 2,
            "subshares": [
                {"coeff_index":0,"dealer_index":1,"recipient_index":2,
                 "value_hex":"0101010101010101010101010101010101010101010101010101010101010101"}
            ]
        }"#;
        let err = serde_json::from_str::<DkgRound2Msg>(legacy).unwrap_err();
        assert!(
            err.to_string().contains("subshares") || err.to_string().contains("missing field"),
            "unexpected error: {err}"
        );
    }

    /// Even a sealed envelope carrying an extra plaintext field is refused —
    /// there is no "sealed, but also here is the scalar" transitional shape.
    #[test]
    fn a_sealed_message_with_a_plaintext_field_is_refused() {
        let smuggled = r#"{
            "dealer_index": 1, "recipient_index": 2, "epoch": 0,
            "sealed": [{"coeff_index":0,"ciphertext":"00","value_hex":"01"}]
        }"#;
        assert!(serde_json::from_str::<DkgRound2Msg>(smuggled).is_err());
    }

    #[test]
    fn a_well_formed_sealed_message_deserializes() {
        let good = r#"{
            "dealer_index": 1, "recipient_index": 2, "epoch": 3,
            "sealed": [{"coeff_index":0,"ciphertext":"aabb"}]
        }"#;
        let msg: DkgRound2Msg = serde_json::from_str(good).unwrap();
        assert_eq!(msg.sealed.len(), 1);
        assert_eq!(msg.epoch, 3);
    }

    /// The wire type has no field that could carry a scalar, so no code path
    /// can serialize one. Belt and braces: check the serialized form of a real
    /// ceremony's round-2 message contains no `value` key.
    #[test]
    fn the_serialized_round2_message_has_no_plaintext_field() {
        let msg = DkgRound2Msg {
            dealer_index: 1,
            recipient_index: 2,
            epoch: 0,
            sealed: vec![SealedEntry {
                coeff_index: 0,
                ciphertext: "aabb".into(),
            }],
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(!json.contains("value"));
        assert!(json.contains("ciphertext"));
    }
}
