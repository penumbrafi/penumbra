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
use std::collections::BTreeMap;
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

/// A recipient's accusation against a dealer, naming the dealer index.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Complaint {
    pub complainant_index: u32,
    pub dealer_index: u32,
    pub coeff_index: u32,
    pub reason: String,
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
    #[error("DKG aborted by complaint against dealer {}: {}", .0.dealer_index, .0.reason)]
    Aborted(Complaint),
    #[error("DKG already aborted by complaint against dealer {}", .0.dealer_index)]
    AlreadyAborted(Complaint),
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
            match self.states[coeff as usize].submit_commitment(package) {
                Ok(_) => {}
                Err(OsstError::InvalidProofOfKnowledge(idx)) => {
                    return Err(self.abort(Complaint {
                        complainant_index: self.holder_index,
                        dealer_index: idx,
                        coeff_index: coeff,
                        reason: "invalid proof of knowledge of the constant term".into(),
                    }))
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
                self.aborted = Some(Complaint {
                    complainant_index: self.holder_index,
                    dealer_index: *differing.first().unwrap_or(&0),
                    coeff_index: 0,
                    reason: "round-1 set disagreement".into(),
                });
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
                    let reason = match e {
                        OsstError::SealedOpenFailed(_) => {
                            "sealed package does not open for this ceremony"
                        }
                        OsstError::InvalidSubShare(_) => {
                            "sub-share fails the Feldman check against the dealer's commitment"
                        }
                        _ => "sealed package rejected",
                    };
                    return Err(self.abort(Complaint {
                        complainant_index: self.holder_index,
                        dealer_index: msg.dealer_index,
                        coeff_index: coeff,
                        reason: reason.into(),
                    }));
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

    /// Accept a complaint raised by another participant, and abort.
    ///
    /// A complaint is not publicly verifiable: the package it is about was
    /// sealed to the complainant, so nobody else can check it. Accepting one
    /// on trust means any single member can halt a ceremony — a liveness
    /// denial, and the price of confidentiality in round 2 without a
    /// publicly-verifiable encryption scheme. It is the right trade here: the
    /// roster is fixed and restarting a ceremony is cheap, whereas members
    /// continuing without the complainant is how one partition ends up with
    /// two groups holding different keys.
    ///
    /// Idempotent, and the first complaint is the one recorded.
    pub fn receive_complaint(&mut self, complaint: &Complaint) -> Result<(), DkgError> {
        self.roster.get(complaint.complainant_index)?;
        self.roster.get(complaint.dealer_index)?;
        if self.aborted.is_none() {
            tracing::error!(
                "DKG aborted: holder {} complains of dealer {} for coefficient {}: {}",
                complaint.complainant_index,
                complaint.dealer_index,
                complaint.coeff_index,
                complaint.reason
            );
            self.aborted = Some(complaint.clone());
        }
        Ok(())
    }

    fn abort(&mut self, complaint: Complaint) -> DkgError {
        tracing::error!(
            "DKG aborted: complaint against dealer {} for coefficient {}: {}",
            complaint.dealer_index,
            complaint.coeff_index,
            complaint.reason
        );
        self.aborted = Some(complaint.clone());
        DkgError::Aborted(complaint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
