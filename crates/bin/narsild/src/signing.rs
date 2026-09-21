//! Nested FROST v2 signing.
//!
//! # What changed, and why the old code could not stay
//!
//! The previous implementation hand-rolled the inner round: an inner binding
//! factor `H("frostito-inner-bind" ‖ k ‖ m ‖ B)`, an inner Lagrange
//! coefficient, and `z_k = d_k + ρ_k·e_k + (λ·c·μ_k)·σ_k` with `λ` and `c`
//! taken verbatim from whatever the coordinator posted. That is nested FROST
//! **v1**, which osst 0.4.0 removed from the default build as finding R-1:
//! pre-binding the inner nonces hands the outer protocol a single point with
//! an identity binding commitment, which severs the outer binding coupling and
//! admits a ROS-style forgery. It also meant an inner holder signed a message
//! it had only been told about — finding N-1 — so a coordinator could derive
//! the outer context honestly over a payload of its own choosing, collect
//! inner shares and assemble a valid signature the inner group never saw.
//!
//! v2 inverts the direction of trust. The coordinator supplies the **whole**
//! outer [`SigningRequest`] — every outer commitment, the group key, the
//! nested position, the session id — and each node recomputes the binding
//! factor, the challenge and the Lagrange coefficient itself.
//! [`osst::nested::inner_sign_v2`] refuses to produce a share unless
//!
//! 1. the package's message is byte-for-byte the bytes this node approved
//!    ([`osst::OsstError::MessageMismatch`]);
//! 2. the round-1 commitment set contains this node's own commitment for this
//!    session id, matching the nonces being consumed;
//! 3. the package's entry for the nested position is exactly `(Σ D_k, Σ E_k)`
//!    over that set.
//!
//! The scalars the coordinator sends alongside are not used: they are checked
//! against the locally derived ones with
//! [`osst::nested::InnerSigningParamsV2::from_coordinator_checked`], which
//! returns [`osst::OsstError::ChallengeMismatch`] on any disagreement.
//!
//! # Epoch binding
//!
//! The bytes signed are not the application message but
//! `SigningContext { epoch, manifest_hash, message }.encode()`, and the epoch
//! and manifest hash come from **this node's own key package**, never from the
//! request. The epoch is the DKG generation counter; the manifest hash is the
//! roster fingerprint. A node whose shares were generated in epoch `e` builds
//! context bytes for epoch `e`; a coordinator running the outer round for
//! epoch `e+1` built its package over different bytes; the node therefore
//! refuses with `MessageMismatch` rather than contributing a share. That is
//! what stops a pre-rotation quorum signing after a reshare, which a
//! key-preserving reshare cannot otherwise prevent — the group key is
//! deliberately unchanged.
//!
//! This binding only works where the verifier is osst-aware. It does not apply
//! to a protocol-defined signature such as an Orchard `SpendAuthSig` over a
//! consensus-fixed sighash, where there is nowhere to put the epoch; retiring
//! shares there needs an on-chain rotation to a new group key. See
//! `osst::context`.

use crate::accumulator::{AccumulateResult, Contribution, ThresholdAccumulator};
use crate::broadcast::PeerSet;
use crate::codec::{point_from_hex, point_hex, scalar_from_hex, scalar_hex};
use osst::frost::{SigningCommitments, SigningPackage};
use osst::nested::{
    self, InnerCommitments, InnerNonces, InnerSigningParamsV2, NestedSigningRequest,
};
use osst::{OsstError, SecretShare, SigningContext};
use pasta_curves::pallas::{Point as PallasPoint, Scalar as PallasScalar};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// One inner holder's round-1 nonce commitments. Public; broadcast.
///
/// `message_hex` rides along so that a node asked to join a session can put
/// the message past its [`crate::policy::SigningPolicy`] *before* it samples
/// nonces (M-2, M-18). A commitment round is not free: it produces live secret
/// nonce material, and doing that for any session an unknown party announces
/// is both a signing-oracle precondition and an unbounded allocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InnerCommitment {
    pub session_id: [u8; 32],
    /// The application message this session is for, hex.
    pub message_hex: String,
    pub holder_index: u32,
    /// `D_k`, canonical compressed, hex.
    pub hiding: String,
    /// `E_k`, canonical compressed, hex.
    pub binding: String,
}

impl Contribution for InnerCommitment {
    type Id = u32;
    fn contributor_id(&self) -> u32 {
        self.holder_index
    }
}

impl InnerCommitment {
    fn decode(&self) -> Option<InnerCommitments<PallasPoint>> {
        Some(InnerCommitments {
            holder_index: self.holder_index,
            session_id: self.session_id,
            hiding: point_from_hex(&self.hiding)?,
            binding: point_from_hex(&self.binding)?,
        })
    }
}

/// The collected round-1 set. Aggregation is a no-op: the set itself is what
/// a coordinator needs in order to build the outer package.
pub type CommitmentList = Vec<InnerCommitment>;

/// One outer signer's commitments, as the coordinator publishes them.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OuterCommitment {
    pub index: u32,
    pub hiding: String,
    pub binding: String,
}

/// Everything the coordinator must supply for round 2.
///
/// Note what is *not* here: a message the node is asked to take on faith, and
/// a set of scalars it is asked to apply. The message is reconstructed from
/// this node's own epoch and manifest; the scalars are recomputed and the
/// supplied ones merely checked.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningRequest {
    pub session_id: [u8; 32],
    /// The application message being authorized, hex.
    pub message_hex: String,
    /// The bytes the outer package was actually built over, hex — i.e. the
    /// coordinator's `SigningContext::encode()`. Compared against this node's
    /// own encoding; a mismatch is `MessageMismatch`.
    pub signed_bytes_hex: String,
    /// The nested position's index in the OUTER signing set.
    pub nested_index: u32,
    /// The outer group public key, canonical compressed, hex.
    pub group_pubkey: String,
    /// Every outer signer's commitments — the full set, not just ours.
    pub outer_commitments: Vec<OuterCommitment>,
    /// The inner round-1 commitment set this round is running over.
    pub inner_commitments: Vec<InnerCommitment>,
    /// The inner quorum actually signing.
    pub active_indices: Vec<u32>,
    /// The coordinator's outer binding factor, challenge and Lagrange
    /// coefficient. Checked, never trusted.
    pub outer_binding: String,
    pub outer_challenge: String,
    pub outer_lambda: String,
}

/// One inner holder's round-2 share.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InnerShare {
    pub session_id: [u8; 32],
    pub holder_index: u32,
    /// `z_k`, canonical, hex.
    pub response: String,
}

impl Contribution for InnerShare {
    type Id = u32;
    fn contributor_id(&self) -> u32 {
        self.holder_index
    }
}

/// The collected round-2 set. Summing is deliberately NOT done here: a share
/// must be checked against its commitment and public share before it is folded
/// in, which needs the whole request.
pub type ShareList = Vec<InnerShare>;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("osst: {0}")]
    Osst(OsstError),
    #[error("no nonces for this session: round 1 was not run, or its nonces are spent")]
    NoNonces,
    #[error("this node has no key package; run the DKG first")]
    NoShare,
    #[error(
        "request names nested position {asked}, this node is configured for {ours}"
    )]
    WrongNestedPosition { asked: u32, ours: u32 },
    #[error("malformed request: {0}")]
    Malformed(&'static str),
    #[error("inner shares rejected from holders {0:?}")]
    BadShares(Vec<u32>),
    #[error("the local signing policy does not approve this message")]
    PolicyRefused,
    #[error(
        "session {0} has already been signed: signing it again would publish a second \
         response under one nonce, which discloses the share"
    )]
    SessionSpent(String),
    #[error("cannot record the session as spent: {0}")]
    SpentStore(String),
    #[error("session {0} was opened for a different message")]
    MessageChanged(String),
    #[error(
        "the request names an outer group key this node's key package does not: \
         the challenge is bound to Y, so Y comes from the key package or nowhere"
    )]
    WrongGroupKey,
}

impl From<OsstError> for SigningError {
    fn from(e: OsstError) -> Self {
        SigningError::Osst(e)
    }
}

// ---------------------------------------------------------------------------
// Local signer
// ---------------------------------------------------------------------------

/// This node's share material and its live nonce state.
pub struct LocalSigner {
    pub holder_index: u32,
    /// The nested position this node's share is evaluated at.
    pub nested_position: u32,
    /// DKG generation. The epoch of every [`SigningContext`] this node builds.
    pub epoch: u64,
    /// Roster fingerprint at generation time — the context's manifest hash.
    pub manifest_hash: [u8; 32],
    /// `σ_k`, this node's share of the nested position's outer secret.
    /// `None` until a key package is loaded.
    share_scalar: Option<PallasScalar>,
    /// The outer group public key from THIS node's key package (M-4). A
    /// request naming a different `Y` is refused: the challenge is
    /// `c = H(R ‖ Y ‖ m)`, so a coordinator free to choose `Y` is a
    /// coordinator free to choose `c` over a message the node approved, which
    /// is exactly the degree of freedom the ROS literature is about. `Y` is
    /// public data, but public is not the same as locally anchored.
    group_pubkey: Option<PallasPoint>,
    /// `P_j = σ_j·G` for every inner holder, for share verification.
    public_shares: Vec<(u32, PallasPoint)>,
    /// Live nonces, one per session. `InnerNonces` is not `Clone` and zeroizes
    /// on drop, so taking one out of the map is what spends it.
    nonces: BTreeMap<[u8; 32], InnerNonces<PallasScalar>>,
}

impl LocalSigner {
    pub fn new(
        holder_index: u32,
        nested_position: u32,
        epoch: u64,
        manifest_hash: [u8; 32],
        share_scalar: Option<PallasScalar>,
        public_shares: Vec<(u32, PallasPoint)>,
        group_pubkey: Option<PallasPoint>,
    ) -> Self {
        Self {
            holder_index,
            nested_position,
            epoch,
            manifest_hash,
            share_scalar,
            group_pubkey,
            public_shares,
            nonces: BTreeMap::new(),
        }
    }

    /// Install share material from a key package.
    pub fn install(
        &mut self,
        share: PallasScalar,
        public_shares: Vec<(u32, PallasPoint)>,
        group_pubkey: Option<PallasPoint>,
    ) {
        self.share_scalar = Some(share);
        self.public_shares = public_shares;
        self.group_pubkey = group_pubkey;
    }

    /// Whether this node can sign at all.
    pub fn has_share(&self) -> bool {
        self.share_scalar.is_some()
    }

    /// Public shares of the inner holders, for verified aggregation.
    pub fn public_shares(&self) -> &[(u32, PallasPoint)] {
        &self.public_shares
    }

    /// Round 1: sample nonces for `session_id` and publish the commitments.
    pub fn commit(&mut self, session_id: [u8; 32], message: &[u8]) -> InnerCommitment {
        let mut rng = rand_core::OsRng;
        let (nonces, commitments) =
            nested::inner_commit::<PallasPoint, _>(self.holder_index, session_id, &mut rng);
        let wire = InnerCommitment {
            session_id,
            message_hex: hex::encode(message),
            holder_index: self.holder_index,
            hiding: point_hex(&commitments.hiding),
            binding: point_hex(&commitments.binding),
        };
        self.nonces.insert(session_id, nonces);
        wire
    }

    /// Whether this node has live nonces for a session.
    pub fn has_nonces(&self, session_id: &[u8; 32]) -> bool {
        self.nonces.contains_key(session_id)
    }

    /// Round 2.
    ///
    /// The nonces are consumed whatever happens — they are moved into
    /// `inner_sign_v2_with_context` — so a refusal is terminal for this
    /// session and a retry needs a fresh round 1. That is the intended
    /// behaviour: one commitment round, one share.
    pub fn sign(&mut self, req: &SigningRequest) -> Result<InnerShare, SigningError> {
        if req.nested_index != self.nested_position {
            return Err(SigningError::WrongNestedPosition {
                asked: req.nested_index,
                ours: self.nested_position,
            });
        }
        let share_scalar = self.share_scalar.ok_or(SigningError::NoShare)?;
        let group_pubkey = self.group_pubkey.ok_or(SigningError::NoShare)?;

        // M-4: before anything is consumed. `from_coordinator_checked` below
        // recomputes rho, c and lambda *using the supplied Y*, so a
        // substituted Y yields a self-consistent package that passes every
        // other check.
        if crate::codec::point_from_hex(&req.group_pubkey) != Some(group_pubkey) {
            return Err(SigningError::WrongGroupKey);
        }

        let nonces = self
            .nonces
            .remove(&req.session_id)
            .ok_or(SigningError::NoNonces)?;

        let parsed = ParsedRequest::parse(req)?;

        // The scalars the coordinator asserted are checked against the ones
        // derived here; a disagreement is ChallengeMismatch.
        InnerSigningParamsV2::<PallasScalar>::from_coordinator_checked::<PallasPoint>(
            &parsed.outer_binding,
            &parsed.outer_challenge,
            &parsed.outer_lambda,
            &parsed.package,
            &parsed.group_pubkey,
            req.nested_index,
        )?;

        // The context comes from OUR state. If the coordinator built the outer
        // package for a different epoch or a different roster, these bytes
        // differ from the package's message and inner_sign_v2 refuses.
        let ctx = SigningContext::new(self.epoch, self.manifest_hash, &parsed.message);

        let share = SecretShare::new(self.holder_index, share_scalar)?;
        let request = NestedSigningRequest {
            package: &parsed.package,
            // The local value, not the parsed one — they are equal by the
            // check above, and this is the one that stays right if that check
            // is ever moved.
            group_pubkey: &group_pubkey,
            nested_index: req.nested_index,
            session_id: req.session_id,
            inner_commitments: &parsed.inner_commitments,
            active_indices: &req.active_indices,
        };

        let sig = nested::inner_sign_v2_with_context::<PallasPoint>(
            nonces, &share, &ctx, &request,
        )?;

        Ok(InnerShare {
            session_id: req.session_id,
            holder_index: sig.holder_index,
            response: scalar_hex(&sig.response),
        })
    }
}

/// A [`SigningRequest`] decoded into osst types.
pub struct ParsedRequest {
    pub message: Vec<u8>,
    pub package: SigningPackage<PallasPoint>,
    pub group_pubkey: PallasPoint,
    pub inner_commitments: Vec<InnerCommitments<PallasPoint>>,
    pub outer_binding: PallasScalar,
    pub outer_challenge: PallasScalar,
    pub outer_lambda: PallasScalar,
}

impl ParsedRequest {
    pub fn parse(req: &SigningRequest) -> Result<Self, SigningError> {
        let message = hex::decode(&req.message_hex)
            .map_err(|_| SigningError::Malformed("message_hex is not hex"))?;
        let signed_bytes = hex::decode(&req.signed_bytes_hex)
            .map_err(|_| SigningError::Malformed("signed_bytes_hex is not hex"))?;
        let group_pubkey = point_from_hex(&req.group_pubkey)
            .ok_or(SigningError::Malformed("group_pubkey is not a canonical point"))?;

        let outer: Vec<SigningCommitments<PallasPoint>> = req
            .outer_commitments
            .iter()
            .map(|c| {
                Ok(SigningCommitments {
                    index: c.index,
                    hiding: point_from_hex(&c.hiding).ok_or(SigningError::Malformed(
                        "outer hiding commitment is not a canonical point",
                    ))?,
                    binding: point_from_hex(&c.binding).ok_or(SigningError::Malformed(
                        "outer binding commitment is not a canonical point",
                    ))?,
                })
            })
            .collect::<Result<_, SigningError>>()?;

        let inner_commitments: Vec<InnerCommitments<PallasPoint>> = req
            .inner_commitments
            .iter()
            .map(|c| {
                c.decode().ok_or(SigningError::Malformed(
                    "inner commitment is not a canonical point",
                ))
            })
            .collect::<Result<_, SigningError>>()?;

        Ok(Self {
            message,
            package: SigningPackage::new(signed_bytes, outer)?,
            group_pubkey,
            inner_commitments,
            outer_binding: scalar_from_hex(&req.outer_binding)
                .ok_or(SigningError::Malformed("outer_binding is not a canonical scalar"))?,
            outer_challenge: scalar_from_hex(&req.outer_challenge)
                .ok_or(SigningError::Malformed("outer_challenge is not a canonical scalar"))?,
            outer_lambda: scalar_from_hex(&req.outer_lambda)
                .ok_or(SigningError::Malformed("outer_lambda is not a canonical scalar"))?,
        })
    }
}

// ---------------------------------------------------------------------------
// Signing service
// ---------------------------------------------------------------------------

/// Composes the accumulator, the peer transport and the local signer.
pub struct SigningService {
    pub round1: ThresholdAccumulator<[u8; 32], InnerCommitment, CommitmentList>,
    pub round2: ThresholdAccumulator<[u8; 32], InnerShare, ShareList>,
    pub signer: Arc<Mutex<LocalSigner>>,
    pub peers: PeerSet,
    /// The message each session was opened for, as first seen. A session's
    /// message never changes: round 2 must be for the message round 1's
    /// nonces were sampled under, and the policy approved.
    pub approved: Arc<Mutex<BTreeMap<[u8; 32], Vec<u8>>>>,
    /// What this node is willing to sign.
    pub policy: Arc<dyn crate::policy::SigningPolicy>,
    /// Session ids this node has already released a share for (M-13).
    pub spent: Arc<dyn crate::agreement::SpentSessions>,
    /// The round-2 request per session, as first seen.
    pub requests: Arc<Mutex<BTreeMap<[u8; 32], SigningRequest>>>,
    /// `z_nested` per session, once a verified quorum has been aggregated.
    pub results: Arc<Mutex<BTreeMap<[u8; 32], String>>>,
}

impl Clone for SigningService {
    fn clone(&self) -> Self {
        Self {
            round1: self.round1.clone(),
            round2: self.round2.clone(),
            signer: self.signer.clone(),
            peers: self.peers.clone(),
            approved: self.approved.clone(),
            policy: self.policy.clone(),
            spent: self.spent.clone(),
            requests: self.requests.clone(),
            results: self.results.clone(),
        }
    }
}

impl SigningService {
    pub fn new(
        signer: LocalSigner,
        threshold: usize,
        peers: PeerSet,
        policy: Arc<dyn crate::policy::SigningPolicy>,
        spent: Arc<dyn crate::agreement::SpentSessions>,
    ) -> Self {
        Self {
            round1: ThresholdAccumulator::new(threshold),
            round2: ThresholdAccumulator::new(threshold),
            signer: Arc::new(Mutex::new(signer)),
            peers,
            approved: Arc::new(Mutex::new(BTreeMap::new())),
            policy,
            spent,
            requests: Arc::new(Mutex::new(BTreeMap::new())),
            results: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Record the message a session is for, refusing a change of message and
    /// a message the policy does not approve.
    ///
    /// This is the gate in front of nonce sampling: a session that does not
    /// get past it produces no secret state at all.
    async fn open_session(&self, session_id: [u8; 32], message: &[u8]) -> Result<(), SigningError> {
        // M-13: before anything else. A session id whose share has been
        // released must never open again, whatever the message or the policy
        // says.
        if self.spent.is_spent(&session_id) {
            return Err(SigningError::SessionSpent(hex::encode(session_id)));
        }
        let mut approved = self.approved.lock().await;
        match approved.get(&session_id) {
            Some(existing) if existing == message => Ok(()),
            Some(_) => Err(SigningError::MessageChanged(hex::encode(session_id))),
            None => {
                if !self.policy.approve(message) {
                    return Err(SigningError::PolicyRefused);
                }
                approved.insert(session_id, message.to_vec());
                Ok(())
            }
        }
    }

    /// Round 1: commit, accumulate locally, broadcast. Public data only.
    pub async fn start_round1(
        &self,
        session_id: [u8; 32],
        message: &[u8],
    ) -> Result<InnerCommitment, SigningError> {
        self.open_session(session_id, message).await?;
        self.round1
            .ensure_session(session_id, |c| c.to_vec())
            .await;
        let commitment = self.signer.lock().await.commit(session_id, message);
        let _ = self.round1.accumulate(&session_id, commitment.clone()).await;
        self.peers.broadcast("/sign/commitment", &commitment);
        Ok(commitment)
    }

    /// Accept a peer's round-1 commitment, contributing our own if we have not.
    pub async fn receive_commitment(
        &self,
        commitment: InnerCommitment,
    ) -> Result<AccumulateResult<CommitmentList>, SigningError> {
        let session_id = commitment.session_id;
        let message = hex::decode(&commitment.message_hex)
            .map_err(|_| SigningError::Malformed("message_hex is not hex"))?;
        self.open_session(session_id, &message).await?;

        self.round1
            .ensure_session(session_id, |c| c.to_vec())
            .await;
        let result = self.round1.accumulate(&session_id, commitment).await;

        let mut signer = self.signer.lock().await;
        if !signer.has_nonces(&session_id) {
            let ours = signer.commit(session_id, &message);
            drop(signer);
            let _ = self.round1.accumulate(&session_id, ours.clone()).await;
            self.peers.broadcast("/sign/commitment", &ours);
        }
        Ok(result)
    }

    /// Round 2: produce our share, accumulate it, and pass the request on so
    /// peers produce theirs.
    ///
    /// The request is relayed verbatim — every field in it is public, and each
    /// peer re-derives everything that matters from it anyway.
    pub async fn start_round2(&self, req: SigningRequest) -> Result<InnerShare, SigningError> {
        let session_id = req.session_id;
        let message = hex::decode(&req.message_hex)
            .map_err(|_| SigningError::Malformed("message_hex is not hex"))?;

        // The message must be the one this session's nonces were sampled
        // under, and the policy must still approve it. Both checks, in that
        // order: a session opened for message A must not produce a share over
        // message B even if B is separately approved.
        self.open_session(session_id, &message).await?;

        // First seen wins, as the doc comment always claimed. Overwriting the
        // request lets a later caller swap the active set out from under an
        // aggregation that is already collecting shares (M-18).
        self.requests
            .lock()
            .await
            .entry(session_id)
            .or_insert_with(|| req.clone());
        self.round2
            .ensure_session(session_id, |s| s.to_vec())
            .await;

        // M-13: the durable record goes down before the share is produced, not
        // after. A crash between releasing a share and recording the session
        // is the window that makes a restart a nonce reuse.
        self.spent
            .mark_spent(&session_id)
            .map_err(|e| SigningError::SpentStore(e.to_string()))?;

        let share = self.signer.lock().await.sign(&req)?;
        let _ = self.round2.accumulate(&session_id, share.clone()).await;
        self.peers.broadcast("/sign/share", &share);
        self.peers.broadcast("/sign/round2", &req);
        self.try_aggregate(&session_id).await;
        Ok(share)
    }

    /// Accept a peer's round-2 share.
    pub async fn receive_share(&self, share: InnerShare) -> AccumulateResult<ShareList> {
        let session_id = share.session_id;
        self.round2
            .ensure_session(session_id, |s| s.to_vec())
            .await;
        let result = self.round2.accumulate(&session_id, share).await;
        self.try_aggregate(&session_id).await;
        result
    }

    /// `z_nested` for a session, if a verified quorum has been aggregated.
    pub async fn result(&self, session_id: &[u8; 32]) -> Option<String> {
        self.results.lock().await.get(session_id).cloned()
    }

    /// Verify and aggregate, if the quorum's shares are all in.
    ///
    /// Every share is checked as `z_k·G == (D_k + ρ·E_k) + (λ·c·μ_k)·P_k`
    /// before it is folded in. An unverified sum silently produces a signature
    /// that fails with no indication of which holder was at fault; this names
    /// them.
    async fn try_aggregate(&self, session_id: &[u8; 32]) -> Option<String> {
        if self.results.lock().await.contains_key(session_id) {
            return self.result(session_id).await;
        }
        let req = self.requests.lock().await.get(session_id).cloned()?;
        let collected = self.round2.contributions(session_id).await;
        if !req
            .active_indices
            .iter()
            .all(|k| collected.iter().any(|s| s.holder_index == *k))
        {
            return None;
        }

        match self.aggregate(&req, &collected).await {
            Ok(z) => {
                let hex = scalar_hex(&z);
                self.results.lock().await.insert(*session_id, hex.clone());
                Some(hex)
            }
            Err(e) => {
                tracing::error!("aggregation failed: {}", e);
                None
            }
        }
    }

    async fn aggregate(
        &self,
        req: &SigningRequest,
        collected: &[InnerShare],
    ) -> Result<PallasScalar, SigningError> {
        let parsed = ParsedRequest::parse(req)?;
        let params = InnerSigningParamsV2::<PallasScalar>::from_outer::<PallasPoint>(
            &parsed.package,
            &parsed.group_pubkey,
            req.nested_index,
        )?;

        let mut sigs = Vec::with_capacity(collected.len());
        for s in collected {
            if !req.active_indices.contains(&s.holder_index) {
                continue;
            }
            let response = scalar_from_hex(&s.response)
                .ok_or(SigningError::Malformed("share response is not a canonical scalar"))?;
            sigs.push(nested::InnerSignatureShare {
                holder_index: s.holder_index,
                response,
            });
        }

        let public_shares = self.signer.lock().await.public_shares().to_vec();
        nested::aggregate_inner_shares_verified::<PallasPoint>(
            &sigs,
            &parsed.inner_commitments,
            &public_shares,
            &params,
            &req.active_indices,
        )
        .map_err(SigningError::BadShares)
    }
}

/// The nested position's outer commitment pair `(D_nested, E_nested)` for a
/// round-1 set — what a coordinator puts in the outer package under the nested
/// index.
pub fn nested_commitment_pair(
    session_id: &[u8; 32],
    commitments: &[InnerCommitment],
) -> Result<(PallasPoint, PallasPoint), SigningError> {
    let decoded: Vec<InnerCommitments<PallasPoint>> = commitments
        .iter()
        .map(|c| {
            c.decode()
                .ok_or(SigningError::Malformed("inner commitment is not a canonical point"))
        })
        .collect::<Result<_, SigningError>>()?;
    Ok(nested::aggregate_inner_commitment_pair::<PallasPoint>(
        session_id, &decoded,
    )?)
}
