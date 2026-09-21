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
//! `open_subshare_agreed_with_evidence` runs the Feldman check itself, against
//! the *agreed* commitment, and on failure hands back the plaintext it
//! rejected. That is a [`ComplaintMsg`] every other member re-checks for
//! itself — which is what makes a round-2 failure something the group reaches
//! a verdict on rather than something one node aborts on alone.
//!
//! How far that verdict carries depends on the evidence. A forged proof of
//! knowledge is public data: one upheld complaint disqualifies its dealer. A
//! bad sub-share is not, because Noise_K authenticates the dealer to its
//! recipient and to nobody else, so a lying recipient can fabricate a scalar
//! that fails the same check — [`osst::dkg::ComplaintTally`] therefore
//! requires `t` distinct accusers before the dealer goes, and a lone complaint
//! is recorded and logged. With a roster fixed by configuration there is no
//! honest reason for a member to deal a bad share, so reaching the threshold
//! aborts rather than continuing with a smaller qualified set, which is how a
//! partition turns into two groups holding different keys.

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

/// Domain tag for this node's combined round-1 echo digest.
pub const ECHO_DOMAIN: &[u8] = b"narsild/dkg/round1-echo/v1";

/// One member's echo of the round-1 digest. Public; broadcast; signed by the
/// sender's roster identity like every other request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DkgEcho {
    pub sender_index: u32,
    pub epoch: u64,
    #[serde(with = "crate::codec::bytes32")]
    pub session_id: [u8; 32],
    /// One [`osst::dkg::EchoDigest`] per outer coefficient, hex, in
    /// coefficient order.
    ///
    /// Per coefficient, not one combined hash: each coefficient is its own
    /// Feldman ceremony with its own `DkgState`, and osst's comparison —
    /// `AgreedRound1::confirm_all` — is defined over one agreed set. Sending
    /// the digests separately is what lets that function be the comparison,
    /// rather than something this crate re-implements beside it.
    pub digests: Vec<String>,
}

/// The wire form of [`osst::dkg::Complaint`] (M-6).
///
/// osst 0.5.1 owns the complaint: the value, the `(epoch, session_id, round)`
/// binding, the Schnorr signature under the accuser's roster identity key, and
/// the adjudication. It does not own the wire, because it does not own the
/// roster or the transport — so this is the encoding, and nothing more. Every
/// field is decoded back into the osst type before anything looks at it.
///
/// # Two kinds of evidence, and how far each one carries
///
/// [`ComplaintEvidenceMsg::ForgedProofOfKnowledge`] is fully transferable: the
/// round-1 package is public, so any third party re-runs
/// `Round1Package::verify` and reaches the same verdict with no trust in the
/// accuser. One upheld complaint of this kind disqualifies its dealer.
///
/// [`ComplaintEvidenceMsg::BadSubShare`] is checkable but **not**
/// attributable. Every node recomputes the Feldman equation against the
/// dealer's commitment in its *own* agreed round-1 set and learns that the
/// scalar is not a valid sub-share for it — but Noise_K authenticates the
/// dealer to the recipient and to nobody else, so a lying recipient can
/// fabricate a scalar that fails the same check. `Upheld` therefore does not
/// distinguish a cheated node from a lying one, and
/// [`osst::dkg::ComplaintTally`] gates disqualification on `t` distinct
/// accusers. See [`DkgCeremony::receive_complaint`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ComplaintMsg {
    pub epoch: u64,
    #[serde(with = "crate::codec::bytes32")]
    pub session_id: [u8; 32],
    pub round: u8,
    pub accuser_index: u32,
    pub accused_index: u32,
    pub evidence: ComplaintEvidenceMsg,
    /// Schnorr signature by the accuser's ceremony identity key.
    pub sig_r: String,
    pub sig_s: String,
}

/// The evidence half of a [`ComplaintMsg`].
///
/// The fields osst's `BadSubShareEvidence` repeats from the complaint itself —
/// dealer index, recipient index, session id, round — are **not** on the wire.
/// They are reconstructed at decode from the complaint's own fields, and osst
/// then insists the two agree, so there is no encoding in which they can drift
/// apart. Tampering with the complaint's copy breaks the signature, which
/// covers the evidence in full.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ComplaintEvidenceMsg {
    /// A round-1 package whose proof of knowledge does not verify.
    ForgedProofOfKnowledge {
        /// The accused dealer's round-1 commitment, hex.
        commitment: String,
        pok_r: String,
        pok_z: String,
    },
    /// A scalar the accuser decrypted from the dealer's sealed round-2
    /// package, which fails the Feldman check against the agreed commitment.
    BadSubShare {
        /// The decrypted sub-share scalar, hex.
        ///
        /// Secret-ish, and published deliberately: an `Upheld` verdict is
        /// itself the proof that this value is *not* a point on the agreed
        /// polynomial, so it discloses nothing about the agreed commitments,
        /// the group key, or the accuser's real share. An `Unfounded` verdict
        /// means the accuser burned one of its own share components to make a
        /// false accusation — a cost to the accuser, and one point of a
        /// degree-`t-1` polynomial.
        subshare: String,
        /// `osst::dkg::commitment_digest` of the dealer's commitment in the
        /// agreed round-1 set — which coefficient's ceremony it belongs to is
        /// found by matching this against the node's own agreed sets, so a
        /// complaint cannot point a verifier at the wrong one.
        agreed_digest: String,
        /// SHA-256 of the sealed ciphertext as delivered.
        sealed_digest: String,
    },
}

impl ComplaintMsg {
    /// Encode an osst complaint for the wire.
    pub fn encode(c: &dkg::Complaint<PallasPoint>) -> Result<Self, DkgError> {
        let evidence = match &c.evidence {
            dkg::ComplaintEvidence::ForgedProofOfKnowledge { package } => {
                ComplaintEvidenceMsg::ForgedProofOfKnowledge {
                    commitment: hex::encode(package.commitment.to_bytes()),
                    pok_r: point_hex(&package.proof_of_knowledge.r),
                    pok_z: scalar_hex(&package.proof_of_knowledge.z),
                }
            }
            dkg::ComplaintEvidence::BadSubShare { evidence } => {
                ComplaintEvidenceMsg::BadSubShare {
                    subshare: hex::encode(evidence.subshare),
                    agreed_digest: hex::encode(evidence.agreed_digest),
                    sealed_digest: hex::encode(evidence.sealed_digest),
                }
            }
        };
        Ok(Self {
            epoch: c.epoch,
            session_id: c.session_id,
            round: c.round,
            accuser_index: c.accuser_index,
            accused_index: c.accused_index,
            evidence,
            sig_r: point_hex(&c.r),
            sig_s: scalar_hex(&c.s),
        })
    }

    /// Decode into the osst type. `threshold` is the inner threshold, which is
    /// how many points a dealer commitment has.
    pub fn decode(&self, threshold: u32) -> Result<dkg::Complaint<PallasPoint>, DkgError> {
        let bad = |what| DkgError::MalformedComplaint(self.accuser_index, what);
        let digest32 = |s: &str, what| -> Result<[u8; 32], DkgError> {
            hex::decode(s)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .ok_or_else(|| bad(what))
        };
        let evidence = match &self.evidence {
            ComplaintEvidenceMsg::ForgedProofOfKnowledge {
                commitment,
                pok_r,
                pok_z,
            } => {
                let commitment = DealerCommitment::<PallasPoint>::from_bytes(
                    &hex::decode(commitment).map_err(|_| bad("commitment is not hex"))?,
                    threshold,
                )?;
                dkg::ComplaintEvidence::ForgedProofOfKnowledge {
                    package: dkg::Round1Package {
                        commitment,
                        proof_of_knowledge: dkg::ProofOfKnowledge {
                            r: point_from_hex(pok_r).ok_or(bad("proof commitment"))?,
                            z: crate::codec::scalar_from_hex(pok_z)
                                .ok_or(bad("proof response"))?,
                        },
                    },
                }
            }
            ComplaintEvidenceMsg::BadSubShare {
                subshare,
                agreed_digest,
                sealed_digest,
            } => dkg::ComplaintEvidence::BadSubShare {
                evidence: dkg::BadSubShareEvidence {
                    // Reconstructed, not carried: osst cross-checks these
                    // against the complaint's own copies, and the signature
                    // covers both, so there is no drift to exploit.
                    dealer_index: self.accused_index,
                    recipient_index: self.accuser_index,
                    session_id: self.session_id,
                    round: self.round,
                    subshare: digest32(subshare, "sub-share scalar")?,
                    agreed_digest: digest32(agreed_digest, "agreed commitment digest")?,
                    sealed_digest: digest32(sealed_digest, "sealed ciphertext digest")?,
                },
            },
        };
        Ok(dkg::Complaint {
            epoch: self.epoch,
            session_id: self.session_id,
            round: self.round,
            accuser_index: self.accuser_index,
            accused_index: self.accused_index,
            evidence,
            r: point_from_hex(&self.sig_r).ok_or(bad("signature commitment"))?,
            s: crate::codec::scalar_from_hex(&self.sig_s).ok_or(bad("signature scalar"))?,
        })
    }
}

/// Why a ceremony stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbortReason {
    /// An upheld complaint against a dealer.
    Dealer(u32),
    /// The members do not agree on what round 1 was; these echoed differently.
    EchoMismatch(Vec<u32>),
    /// A sealed package this node was sent does not open, or its envelope
    /// disagrees with its contents. Not an accusation — a corrupted byte on
    /// the wire looks the same — so it stops this node and goes to the log.
    /// A package that opens and fails the Feldman check is a
    /// [`ComplaintMsg`] instead.
    SealedPackage(u32),
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
    #[error("DKG aborted: {0:?}")]
    Aborted(AbortReason),
    #[error("DKG already aborted: {0:?}")]
    AlreadyAborted(AbortReason),
    #[error("malformed complaint from member {0}: {1}")]
    MalformedComplaint(u32, &'static str),
    #[error("complaint from member {0} does not verify for this ceremony")]
    InvalidComplaint(u32),
    #[error(
        "this node holds no valid sub-share from dealer {0}, and fewer than the \
         threshold of members have said the same, so the dealer is not \
         disqualified. This node cannot derive a share and must not finalize; \
         re-run the ceremony without that member."
    )]
    ExcludedDealer(u32),
    #[error(
        "complaint from member {0} names a commitment this node has not agreed on: \
         either round 1 is not confirmed here yet, or the accuser is looking at a \
         different ceremony. Nothing sound to check it against, so it is dropped."
    )]
    UnknownAgreedCommitment(u32),
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
    /// The round-1 broadcasts as accepted, by dealer — the evidence a
    /// `ForgedProofOfKnowledge` complaint carries.
    round1_msgs: BTreeMap<u32, DkgRound1Broadcast>,
    /// The agreed round-1 set for each coefficient, once round 1 has closed
    /// and every member has echoed the same digest (M-5).
    ///
    /// osst 0.5.0 owns this: `DkgState::agreed_round1` produces the set and
    /// its digest, `AgreedRound1::confirm_all` is the comparison, and the
    /// round-2 entry points — `open_subshare_agreed`, `Aggregator::from_agreed`
    /// — take the agreed set rather than a commitment that arrived alongside
    /// a sub-share. Holding one is not proof of agreement; `confirmed` is.
    agreed: Vec<Option<dkg::AgreedRound1<PallasPoint>>>,
    /// Every member's echoed digests, by index — one per coefficient.
    echoes: BTreeMap<u32, Vec<dkg::EchoDigest>>,
    /// Whether `confirm_all` has passed.
    confirmed: bool,
    /// This node's round-1 broadcast, sampled once.
    ///
    /// `Dealer::round1_package` draws a fresh proof-of-knowledge nonce on
    /// every call, so calling it twice would make an honest node look like an
    /// equivocating dealer to the echo round.
    our_broadcast: DkgRound1Broadcast,
    /// Why the ceremony stopped, if it has.
    aborted: Option<AbortReason>,
    /// This node's identity secret on the ceremony curve, which signs its
    /// complaints.
    identity_secret: PallasScalar,
    /// Complaints this node raised and has not yet handed to the caller.
    pending_complaints: Vec<ComplaintMsg>,
    /// Accusers whose complaints were authentic but unfounded.
    flagged: BTreeSet<u32>,
    /// `(accuser, accused)` of complaints already seen, so a re-broadcast does
    /// not loop.
    seen_complaints: BTreeSet<(u32, u32)>,
    /// Distinct accusers with upheld complaints, per accused dealer.
    ///
    /// A `BadSubShare` complaint is checkable but not attributable (see
    /// [`ComplaintEvidenceMsg`]), so no single one disqualifies anybody. This
    /// is osst's `t`-of-`n` gate over them, and this node's own detection is
    /// recorded here alongside its peers'.
    tally: dkg::ComplaintTally,
    /// Dealers this node holds no usable sub-share from, because their round-2
    /// package failed the Feldman check and the tally has not reached `t`.
    ///
    /// The ceremony is not aborted for them — one accuser is not evidence —
    /// but this node cannot derive a share, so it must not finalize. That is
    /// exclusion rather than a split key, and it is the residual osst's
    /// `ComplaintEvidence` documents: closing it needs the GJKR dealer-defence
    /// round, which needs a reliable broadcast and a timeout.
    excluded_dealers: BTreeSet<u32>,
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
    #[allow(clippy::too_many_arguments)] // a ceremony has this many parameters
    pub fn new(
        holder_index: u32,
        roster: Arc<Roster>,
        x25519_secret: [u8; 32],
        identity_secret: PallasScalar,
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
            agreed: (0..outer_t).map(|_| None).collect(),
            echoes: BTreeMap::new(),
            confirmed: false,
            our_broadcast: DkgRound1Broadcast {
                dealer_index: holder_index,
                epoch,
                ceremony_nonce,
                roster_hash: String::new(),
                coefficients: Vec::new(),
            },
            aborted: None,
            identity_secret,
            pending_complaints: Vec::new(),
            flagged: BTreeSet::new(),
            seen_complaints: BTreeSet::new(),
            tally: dkg::ComplaintTally::new(inner_t),
            excluded_dealers: BTreeSet::new(),
            result: None,
        };
        ceremony.our_broadcast = ceremony.sample_round1_broadcast();
        Ok(ceremony)
    }

    /// Why this ceremony stopped, if it has.
    pub fn abort_reason(&self) -> Option<&AbortReason> {
        self.aborted.as_ref()
    }

    fn check_live(&self) -> Result<(), DkgError> {
        match &self.aborted {
            Some(c) => Err(DkgError::AlreadyAborted(c.clone())),
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
            // The complaint that follows is transferable — the round-1 package
            // is public, so every other node re-runs `Round1Package::verify`
            // and reaches this verdict without trusting this node at all.
            let evidence = dkg::ComplaintEvidence::ForgedProofOfKnowledge {
                package: dkg::Round1Package {
                    commitment: package.commitment.clone(),
                    proof_of_knowledge: dkg::ProofOfKnowledge {
                        r: package.proof_of_knowledge.r,
                        z: package.proof_of_knowledge.z,
                    },
                },
            };
            match self.states[coeff as usize].submit_commitment(package) {
                Ok(_) => {}
                Err(OsstError::InvalidProofOfKnowledge(idx)) => {
                    let mut rng = rand_core::OsRng;
                    let complaint = dkg::Complaint::<PallasPoint>::sign(
                        self.epoch,
                        self.session_id,
                        1,
                        self.holder_index,
                        evidence,
                        &self.identity_secret,
                        &mut rng,
                    )?;
                    self.pending_complaints
                        .extend(ComplaintMsg::encode(&complaint).ok());
                    return Err(self.abort(AbortReason::Dealer(idx)));
                }
                Err(e) => return Err(DkgError::Osst(e)),
            }
        }

        self.round1_msgs.insert(msg.dealer_index, msg.clone());
        Ok(self.round1_complete())
    }

    /// The agreed round-1 sets, one per coefficient, and this node's echo
    /// digest over them (M-5).
    ///
    /// `None` until round 1 is complete for every coefficient: echoing a
    /// partial set agrees on nothing, because a member that has not yet
    /// received dealer `i`'s commitment would echo a different digest for an
    /// entirely honest reason.
    fn agreed_sets(&self) -> Option<Vec<dkg::AgreedRound1<PallasPoint>>> {
        self.states
            .iter()
            .map(|s| s.agreed_round1().ok())
            .collect()
    }

    /// A single digest over every coefficient's agreed set, for the status
    /// page. Not what is compared — see [`DkgEcho`] — just a short way to say
    /// "this node's view of round 1" in a log line.
    pub fn round1_digest(&self) -> Option<[u8; 32]> {
        let sets = self.agreed_sets()?;
        let mut h = Sha256::new();
        h.update(ECHO_DOMAIN);
        h.update(self.epoch.to_le_bytes());
        h.update(self.session_id);
        h.update((sets.len() as u64).to_le_bytes());
        for set in &sets {
            h.update(set.digest().as_bytes());
        }
        Some(h.finalize().into())
    }

    /// This node's echo of the round-1 digests, to broadcast.
    pub fn echo(&self) -> Option<DkgEcho> {
        let sets = self.agreed_sets()?;
        Some(DkgEcho {
            sender_index: self.holder_index,
            epoch: self.epoch,
            session_id: self.session_id,
            digests: sets
                .iter()
                .map(|s| hex::encode(s.digest().as_bytes()))
                .collect(),
        })
    }

    /// Accept a member's echo (M-5).
    ///
    /// Returns `true` once every roster member has echoed the digests this
    /// node computed, at which point the agreed sets are recorded and round 2
    /// may start. The comparison is osst's: `AgreedRound1::confirm` per member
    /// so that a mismatch can name them, and `confirm_all` over the full set
    /// before anything is recorded, which is also what enforces "enough
    /// echoes".
    ///
    /// A disagreement aborts. A dealer equivocated, or the broadcast is not
    /// reliable; osst is right that the two cannot be told apart from inside,
    /// and the remedy is the same either way.
    pub fn receive_echo(&mut self, echo: &DkgEcho) -> Result<bool, DkgError> {
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
        if echo.digests.len() != self.outer_t as usize {
            return Err(DkgError::MalformedRound1(
                echo.sender_index,
                "echo does not cover every coefficient",
            ));
        }
        let digests: Vec<dkg::EchoDigest> = echo
            .digests
            .iter()
            .map(|h| {
                hex::decode(h)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                    .map(dkg::EchoDigest)
                    .ok_or(DkgError::MalformedRound1(
                        echo.sender_index,
                        "echo digest is not 32 bytes of hex",
                    ))
            })
            .collect::<Result<_, _>>()?;

        // Our own view has to exist before anyone else's can be compared
        // against it: echoing a partial set agrees on nothing.
        let sets = self.agreed_sets().ok_or(DkgError::Round1Incomplete {
            got: self.round1_msgs.len(),
            need: self.inner_n as usize,
        })?;

        self.echoes.entry(echo.sender_index).or_insert(digests);

        // Name the members that differ, using osst's comparison per set.
        let differing: Vec<u32> = self
            .echoes
            .iter()
            .filter(|(_, theirs)| {
                sets.iter()
                    .zip(theirs.iter())
                    .any(|(set, d)| set.confirm(d).is_err())
            })
            .map(|(i, _)| *i)
            .collect();
        if !differing.is_empty() {
            self.aborted = Some(AbortReason::EchoMismatch(differing.clone()));
            return Err(DkgError::EchoMismatch { differing });
        }

        // And the agreement itself, per coefficient, over every member's echo.
        // `confirm_all` is where "enough echoes" is decided, so a short set is
        // `InsufficientContributions` from osst rather than a count this crate
        // keeps beside it.
        let n = self.inner_n as usize;
        for (j, set) in sets.iter().enumerate() {
            let peers: Vec<dkg::EchoDigest> =
                self.echoes.values().filter_map(|d| d.get(j).copied()).collect();
            match set.confirm_all(&peers, n) {
                Ok(()) => {}
                Err(OsstError::InsufficientContributions { .. }) => {
                    return Ok(false);
                }
                Err(_) => {
                    let differing = vec![echo.sender_index];
                    self.aborted = Some(AbortReason::EchoMismatch(differing.clone()));
                    return Err(DkgError::EchoMismatch { differing });
                }
            }
        }

        // Every member agrees. From here on, "which commitment is dealer i's"
        // is answered from these sets and not from whatever arrives with a
        // sub-share.
        self.agreed = sets.into_iter().map(Some).collect();
        self.confirmed = true;
        Ok(true)
    }

    /// Every member has echoed our digest.
    pub fn round1_agreed(&self) -> bool {
        self.confirmed
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

        // Nothing is opened before the group agrees what round 1 was, for the
        // same reason nothing is sent: the commitment a sub-share is checked
        // against has to be the one every member saw.
        if !self.confirmed {
            return Err(DkgError::EchoIncomplete {
                collected: self.echoes.len(),
                needed: self.inner_n as usize,
            });
        }

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

            // M-5: the commitment comes from the *agreed* round-1 set, not
            // from anything that arrived with the sub-share. That is the
            // difference `open_subshare_agreed` exists to make: a dealer that
            // sent Alice C_A and Bob C_B cannot have both in the agreed set,
            // and the echo round refused to start round 2 at all when they
            // disagreed.
            let agreed = self.agreed[coeff as usize]
                .as_ref()
                .ok_or(DkgError::EchoIncomplete {
                    collected: self.echoes.len(),
                    needed: self.inner_n as usize,
                })?;

            let sealed_package = SealedSubShare {
                dealer_index: msg.dealer_index,
                recipient_index: self.holder_index,
                ciphertext,
            };

            match sealed::open_subshare_agreed_with_evidence::<PallasPoint>(
                &self.x25519_secret,
                self.holder_index,
                &self.sealed_roster,
                ROUND_SUBSHARE,
                &sealed_package,
                agreed,
            ) {
                Ok(subshare) => {
                    self.subshares[coeff as usize]
                        .insert(msg.dealer_index, *subshare.value());
                }
                // The accusable case: it opened under this ceremony's keys and
                // prologue, and the scalar inside is not an evaluation of the
                // dealer's *agreed* commitment. osst hands back the plaintext
                // as evidence every other member re-checks against its own
                // agreed set, which is what turns a local abort into something
                // the group can reach a verdict on (M-6 residual).
                Err(sealed::OpenFailure::BadSubShare { evidence }) => {
                    let mut rng = rand_core::OsRng;
                    let complaint = dkg::Complaint::<PallasPoint>::sign(
                        self.epoch,
                        self.session_id,
                        ROUND_SUBSHARE,
                        self.holder_index,
                        dkg::ComplaintEvidence::BadSubShare { evidence },
                        &self.identity_secret,
                        &mut rng,
                    )?;
                    tracing::error!(
                        "dealer {} sent this node a sub-share for coefficient {} that \
                         fails the Feldman check against the agreed commitment; \
                         complaining",
                        msg.dealer_index,
                        coeff
                    );
                    self.pending_complaints
                        .extend(ComplaintMsg::encode(&complaint).ok());
                    // This node's own accusation counts once, like anyone
                    // else's, and does not abort the ceremony on its own.
                    self.record_upheld(self.holder_index, msg.dealer_index);
                }
                // Not accusable. A package that does not open could as easily
                // be a corrupted byte on the wire as a hostile dealer, and an
                // accusation built from unauthenticated bytes is one anyone
                // could manufacture against anyone — the denial-of-service
                // channel M-6 is about. It stops this node and goes to the log.
                Err(other) => {
                    tracing::error!(
                        "round-2 package from dealer {} for coefficient {}: {}",
                        msg.dealer_index,
                        coeff,
                        other
                    );
                    return Err(self.abort(AbortReason::SealedPackage(msg.dealer_index)));
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
        // A dealer this node complained about that the group did not
        // disqualify: this node has no valid sub-share from it, so there is no
        // share to derive. Finalizing anyway would write a key package whose
        // public half disagrees with everyone else's — the exclusion residual
        // in `excluded_dealers`.
        if let Some(d) = self.excluded_dealers.iter().next() {
            return Err(DkgError::ExcludedDealer(*d));
        }

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

            let agreed = self.agreed[j as usize]
                .as_ref()
                .ok_or(DkgError::EchoIncomplete {
                    collected: self.echoes.len(),
                    needed: self.inner_n as usize,
                })?;
            // The dealer set comes from the agreed round-1 set, so every node
            // aggregates over the same dealers.
            let mut agg = dkg::Aggregator::<PallasPoint>::from_agreed(self.holder_index, agreed)?;
            for &dealer_index in &dealer_set {
                let value = subs.get(&dealer_index).ok_or(DkgError::Round2Incomplete {
                    coeff_index: j,
                    got: subs.len(),
                    need: self.inner_n as usize,
                })?;
                let commitment = agreed.commitment(dealer_index)?;
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

    /// The agreed round-1 set a `BadSubShare` complaint is about.
    ///
    /// narsild runs `outer_t` independent Feldman ceremonies, one per outer
    /// coefficient, so "the agreed set" is `outer_t` of them and a complaint
    /// has to say which. It says so by naming the dealer's commitment with
    /// `agreed_digest`, and this matches that against the node's own sets —
    /// rather than carrying a coefficient index, which would be a number a
    /// verifier could be pointed at the wrong ceremony with.
    fn agreed_for(
        &self,
        dealer_index: u32,
        agreed_digest: &[u8; 32],
    ) -> Option<&dkg::AgreedRound1<PallasPoint>> {
        self.agreed.iter().flatten().find(|a| {
            a.commitment(dealer_index)
                .map(|c| &dkg::commitment_digest(c) == agreed_digest)
                .unwrap_or(false)
        })
    }

    /// Record one upheld accusation and act if it reaches the threshold.
    fn record_upheld(&mut self, accuser: u32, accused: u32) {
        if self
            .tally
            .record(accuser, accused, dkg::ComplaintVerdict::Upheld)
            .is_err()
        {
            return;
        }
        if self.tally.reached(accused) {
            tracing::error!(
                "DKG aborted: {} of {} members hold an upheld complaint against dealer {} ({:?})",
                self.tally.count(accused),
                self.tally.threshold(),
                accused,
                self.tally.accusers(accused)
            );
            for state in self.states.iter_mut() {
                let _ = state.disqualify(accused);
            }
            self.excluded_dealers.remove(&accused);
            if self.aborted.is_none() {
                self.aborted = Some(AbortReason::Dealer(accused));
            }
        } else {
            tracing::warn!(
                "{} of {} members have complained about dealer {}; recording, not acting",
                self.tally.count(accused),
                self.tally.threshold(),
                accused
            );
            // Whether or not the dealer is ever disqualified, *this* node has
            // no usable share from it if it was the one cheated.
            if accuser == self.holder_index {
                self.excluded_dealers.insert(accused);
            }
        }
    }

    /// Accept a complaint raised by another participant, and adjudicate it
    /// (M-6).
    ///
    /// osst 0.5.1 does the checkable half. [`osst::dkg::Complaint::verify`]
    /// checks that the complaint belongs to this ceremony, that its accused
    /// index and its evidence's own binding agree with it, that the Schnorr
    /// signature verifies under the accuser's identity key — which must come
    /// from the roster, never from the complaint — and then whether the
    /// evidence shows what it claims. For a `BadSubShare` complaint the
    /// Feldman check is recomputed against the dealer's commitment in **this
    /// node's** agreed round-1 set, so the accuser does not get to choose what
    /// its own evidence is checked against.
    ///
    /// What is left to the caller is agreement, and it is exactly the list
    /// osst's own documentation says a library cannot provide:
    ///
    /// 1. re-broadcast on receipt, so a complaint delivered to one node does
    ///    not stop that node while the rest finalize;
    /// 2. verify before acting, and drop anything that does not check;
    /// 3. count an `Unfounded` verdict against the *accuser*;
    /// 4. apply the same upheld complaints on every node before deriving a key
    ///    — `disqualify` is a local mutation, and it is sound here only
    ///    because every node reaches the verdict from the same public evidence.
    ///
    /// # Why an upheld `BadSubShare` complaint does not disqualify anybody
    ///
    /// Noise_K authenticates a dealer to its recipient and to nobody else, so
    /// a lying recipient can fabricate a scalar that fails the Feldman check
    /// exactly as a genuinely bad one does. `Upheld` means "this scalar is not
    /// a valid sub-share for that commitment", not "the dealer sent it", and
    /// `Upheld`/`Unfounded` cannot tell a cheated node from a lying one.
    ///
    /// So the gate is quorum: [`osst::dkg::ComplaintTally`] counts distinct
    /// accusers and the dealer goes only at `t` of them — a coalition small
    /// enough to be tolerated cannot frame an honest member. A lone complaint
    /// is recorded and logged, the accuser is not believed and not punished,
    /// and the ceremony continues.
    ///
    /// A `ForgedProofOfKnowledge` complaint needs no quorum: the round-1
    /// package is public, so one is proof. It is recorded in the same tally
    /// and acted on immediately.
    ///
    /// Returns whether the caller should re-broadcast — true the first time a
    /// verified complaint is seen, so it reaches the group without looping.
    ///
    /// # Errors
    ///
    /// [`DkgError::UnknownAgreedCommitment`] for a round-2 complaint whose
    /// evidence names a commitment this node has not agreed on — round 1 is
    /// not confirmed here yet, or the accuser is looking at a different
    /// ceremony. Either way there is nothing sound to check it against, and it
    /// is dropped rather than buffered, which is the same "no ordering or
    /// retry" this crate has everywhere else.
    pub fn receive_complaint(&mut self, msg: &ComplaintMsg) -> Result<bool, DkgError> {
        let complaint = msg.decode(self.inner_t)?;
        self.roster.get(complaint.accuser_index)?;
        self.roster.get(complaint.accused_index)?;

        let agreed = match &complaint.evidence {
            dkg::ComplaintEvidence::ForgedProofOfKnowledge { .. } => None,
            dkg::ComplaintEvidence::BadSubShare { evidence } => Some(
                self.agreed_for(evidence.dealer_index, &evidence.agreed_digest)
                    .ok_or(DkgError::UnknownAgreedCommitment(complaint.accuser_index))?,
            ),
        };

        let accuser_key = self.roster.identity_key(complaint.accuser_index)?;
        let verdict = complaint
            .verify(self.epoch, &self.session_id, &accuser_key, agreed)
            .map_err(|_| DkgError::InvalidComplaint(complaint.accuser_index))?;

        let key = (complaint.accuser_index, complaint.accused_index);
        if !self.seen_complaints.insert(key) {
            return Ok(false);
        }

        match verdict {
            dkg::ComplaintVerdict::Upheld => {
                let transferable = matches!(
                    complaint.evidence,
                    dkg::ComplaintEvidence::ForgedProofOfKnowledge { .. }
                );
                tracing::error!(
                    "member {} holds an upheld complaint against dealer {} from round {}",
                    complaint.accuser_index,
                    complaint.accused_index,
                    complaint.round
                );
                if transferable {
                    // Publicly checkable: one is enough.
                    let _ = self.tally.record(
                        complaint.accuser_index,
                        complaint.accused_index,
                        verdict,
                    );
                    for state in self.states.iter_mut() {
                        let _ = state.disqualify(complaint.accused_index);
                    }
                    if self.aborted.is_none() {
                        self.aborted = Some(AbortReason::Dealer(complaint.accused_index));
                    }
                } else {
                    self.record_upheld(complaint.accuser_index, complaint.accused_index);
                }
            }
            dkg::ComplaintVerdict::Unfounded => {
                tracing::warn!(
                    "ignoring an unfounded complaint from member {} against dealer {}: \
                     its own evidence verifies",
                    complaint.accuser_index,
                    complaint.accused_index
                );
                let _ = self.tally.record(
                    complaint.accuser_index,
                    complaint.accused_index,
                    verdict,
                );
                self.flagged.insert(complaint.accuser_index);
            }
        }
        Ok(true)
    }

    /// Dealers this node holds no usable sub-share from, below the threshold.
    pub fn excluded_dealers(&self) -> &BTreeSet<u32> {
        &self.excluded_dealers
    }

    /// The complaints this node raised, for the caller to broadcast.
    ///
    /// More than one is normal: a dealer that cheats does so in every
    /// coefficient ceremony it wants to break, and each failure is its own
    /// evidence.
    pub fn take_complaints(&mut self) -> Vec<ComplaintMsg> {
        core::mem::take(&mut self.pending_complaints)
    }

    /// Accusers whose complaints were authentic but unfounded.
    #[allow(dead_code)]
    pub fn flagged_accusers(&self) -> &BTreeSet<u32> {
        &self.flagged
    }

    fn abort(&mut self, reason: AbortReason) -> DkgError {
        tracing::error!("DKG aborted: {:?}", reason);
        self.aborted = Some(reason.clone());
        DkgError::Aborted(reason)
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
