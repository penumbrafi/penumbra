//! nested FROST signing service
//!
//! composes ThresholdAccumulator + PeerBroadcast for the two-round
//! signing protocol. each round is: contribute locally → broadcast → accumulate.

use crate::accumulator::{AccumulateResult, Contribution, Aggregate, ThresholdAccumulator};
use crate::broadcast::PeerSet;
use pasta_curves::pallas::{Point, Scalar};
use pasta_curves::group::{ff::Field, ff::PrimeField, ff::FromUniformBytes, Group, GroupEncoding};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Round 1: inner nonce commitments
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InnerCommitment {
    pub session_id: [u8; 32],
    pub holder_index: u32,
    pub hiding: [u8; 32],
    pub binding: [u8; 32],
    /// message bytes so receiving peers can store them
    #[serde(default)]
    pub message_hex: Option<String>,
}

impl Contribution for InnerCommitment {
    type Id = u32;
    fn contributor_id(&self) -> u32 { self.holder_index }
}

/// round 1 aggregate: the collected commitment list (not a single value —
/// the client needs the full list to compute R_nested)
#[derive(Clone, Debug)]
pub struct CommitmentList(pub Vec<InnerCommitment>);
impl Aggregate for CommitmentList {}

// ---------------------------------------------------------------------------
// Round 2: inner signature shares
// ---------------------------------------------------------------------------

/// round 2 params broadcast to peers so they can produce their shares
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round2Broadcast {
    pub session_id: [u8; 32],
    pub outer_challenge_hex: String,
    pub outer_lambda_hex: String,
    pub active_indices: Vec<u32>,
    /// message bytes so peers can compute inner binding factors
    pub message_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InnerShare {
    pub session_id: [u8; 32],
    pub holder_index: u32,
    pub response_hex: String,
}

impl Contribution for InnerShare {
    type Id = u32;
    fn contributor_id(&self) -> u32 { self.holder_index }
}

/// round 2 aggregate: z_nested = Σ z_k
#[derive(Clone, Debug)]
pub struct NestedResponse {
    pub z_nested: Scalar,
    pub z_hex: String,
}
impl Aggregate for NestedResponse {}

// ---------------------------------------------------------------------------
// Local node identity (holds our share, produces contributions)
// ---------------------------------------------------------------------------

pub struct LocalSigner {
    pub holder_index: u32,
    pub share_scalar: Scalar,
    /// ephemeral nonces for active sessions: session_id → (d, e)
    nonces: std::collections::HashMap<[u8; 32], (Scalar, Scalar)>,
}

impl LocalSigner {
    pub fn new(holder_index: u32, share_scalar: Scalar) -> Self {
        Self { holder_index, share_scalar, nonces: std::collections::HashMap::new() }
    }

    /// generate nonce commitment for round 1
    pub fn commit(&mut self, session_id: [u8; 32]) -> InnerCommitment {
        let mut rng = rand_core::OsRng;
        let d = Scalar::random(&mut rng);
        let e = Scalar::random(&mut rng);
        let hiding: [u8; 32] = (Point::generator() * d).to_bytes().into();
        let binding: [u8; 32] = (Point::generator() * e).to_bytes().into();
        self.nonces.insert(session_id, (d, e));
        InnerCommitment { session_id, holder_index: self.holder_index, hiding, binding, message_hex: None }
    }

    /// produce signature share for round 2
    pub fn sign(
        &mut self,
        session_id: &[u8; 32],
        outer_challenge: Scalar,
        outer_lambda: Scalar,
        commitments: &[InnerCommitment],
        active_indices: &[u32],
        message: &[u8],
    ) -> Option<InnerShare> {
        let (d, e) = self.nonces.remove(session_id)?;

        // inner binding factor
        let rho_inner = {
            use sha2::{Sha512, Digest};
            let mut h = Sha512::new();
            h.update(b"frostito-inner-bind");
            h.update(self.holder_index.to_le_bytes());
            h.update((message.len() as u64).to_le_bytes());
            h.update(message);
            for c in commitments {
                h.update(c.holder_index.to_le_bytes());
                h.update(&c.hiding);
                h.update(&c.binding);
            }
            let hash: [u8; 64] = h.finalize().into();
            Scalar::from_uniform_bytes(&hash)
        };

        // inner Lagrange coefficient
        let mu_k = {
            let x_i = Scalar::from(self.holder_index as u64);
            let mut mu = Scalar::ONE;
            for &idx_j in active_indices {
                if idx_j == self.holder_index { continue; }
                let x_j = Scalar::from(idx_j as u64);
                mu = mu * x_j * (x_j - x_i).invert().unwrap();
            }
            mu
        };

        // z_{p,k} = d_k + ρ_inner_k·e_k + (λ_outer·c·μ_k)·σ_k
        let z_k = d + rho_inner * e + outer_lambda * outer_challenge * mu_k * self.share_scalar;
        let response_hex = hex::encode(z_k.to_repr().as_ref());

        Some(InnerShare {
            session_id: *session_id,
            holder_index: self.holder_index,
            response_hex,
        })
    }
}

// ---------------------------------------------------------------------------
// Signing service: composes accumulator + broadcast + local signer
// ---------------------------------------------------------------------------

pub struct SigningService {
    pub round1: ThresholdAccumulator<[u8; 32], InnerCommitment, CommitmentList>,
    pub round2: ThresholdAccumulator<[u8; 32], InnerShare, NestedResponse>,
    pub signer: std::sync::Arc<tokio::sync::Mutex<LocalSigner>>,
    pub peers: PeerSet,
    /// message bytes per session
    pub messages: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<[u8; 32], Vec<u8>>>>,
}

impl Clone for SigningService {
    fn clone(&self) -> Self {
        Self {
            round1: self.round1.clone(),
            round2: self.round2.clone(),
            signer: self.signer.clone(),
            peers: self.peers.clone(),
            messages: self.messages.clone(),
        }
    }
}

impl SigningService {
    pub fn new(holder_index: u32, share_scalar: Scalar, threshold: usize, peers: PeerSet) -> Self {
        Self {
            round1: ThresholdAccumulator::new(threshold),
            round2: ThresholdAccumulator::new(threshold),
            signer: std::sync::Arc::new(tokio::sync::Mutex::new(
                LocalSigner::new(holder_index, share_scalar),
            )),
            peers,
            messages: std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// initiate round 1: generate our commitment, broadcast, accumulate
    pub async fn start_round1(&self, session_id: [u8; 32], message: Vec<u8>) -> InnerCommitment {
        // store message
        let msg_hex = hex::encode(&message);
        self.messages.lock().await.insert(session_id, message);

        // ensure session with aggregation function
        self.round1.ensure_session(session_id, |contribs| {
            CommitmentList(contribs.to_vec())
        }).await;

        // produce our commitment
        let mut commitment = self.signer.lock().await.commit(session_id);
        commitment.message_hex = Some(msg_hex);

        // accumulate locally
        let _ = self.round1.accumulate(&session_id, commitment.clone()).await;

        // broadcast (includes message so peers can store it)
        self.peers.broadcast("/sign/commitment", &commitment);

        commitment
    }

    /// receive a peer's commitment: accumulate, auto-contribute if needed
    pub async fn receive_commitment(&self, commitment: InnerCommitment) -> AccumulateResult<CommitmentList> {
        let session_id = commitment.session_id;

        // store message if provided
        if let Some(ref msg_hex) = commitment.message_hex {
            if let Ok(msg_bytes) = hex::decode(msg_hex) {
                self.messages.lock().await
                    .entry(session_id)
                    .or_insert(msg_bytes);
            }
        }

        // ensure session exists
        self.round1.ensure_session(session_id, |contribs| {
            CommitmentList(contribs.to_vec())
        }).await;

        // accumulate
        let result = self.round1.accumulate(&session_id, commitment).await;

        // auto-contribute if we haven't yet
        let holder_index = self.signer.lock().await.holder_index;
        let already_contributed = self.round1.contributions(&session_id).await
            .iter()
            .any(|c| c.holder_index == holder_index);

        if !already_contributed {
            let our_commitment = self.signer.lock().await.commit(session_id);
            let _ = self.round1.accumulate(&session_id, our_commitment.clone()).await;
            self.peers.broadcast("/sign/commitment", &our_commitment);
        }

        result
    }

    /// initiate round 2: produce our signature share, broadcast, accumulate
    pub async fn start_round2(
        &self,
        session_id: [u8; 32],
        outer_challenge: Scalar,
        outer_lambda: Scalar,
        active_indices: Vec<u32>,
    ) -> Option<InnerShare> {
        let commitments = self.round1.contributions(&session_id).await;
        let message = self.messages.lock().await.get(&session_id)?.clone();

        // ensure round2 session
        self.round2.ensure_session(session_id, |shares| {
            let mut z = Scalar::ZERO;
            for s in shares {
                if let Some(bytes) = hex::decode(&s.response_hex).ok() {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        let ct = Scalar::from_repr(arr.into());
                        if bool::from(ct.is_some()) {
                            z = z + ct.unwrap();
                        }
                    }
                }
            }
            NestedResponse {
                z_hex: hex::encode(z.to_repr().as_ref()),
                z_nested: z,
            }
        }).await;

        let share = self.signer.lock().await.sign(
            &session_id, outer_challenge, outer_lambda,
            &commitments, &active_indices, &message,
        )?;

        let _ = self.round2.accumulate(&session_id, share.clone()).await;
        self.peers.broadcast("/sign/share", &share);

        // broadcast round2 params so peers produce their shares too
        self.peers.broadcast("/sign/round2", &Round2Broadcast {
            session_id,
            outer_challenge_hex: hex::encode(outer_challenge.to_repr().as_ref()),
            outer_lambda_hex: hex::encode(outer_lambda.to_repr().as_ref()),
            active_indices,
            message_hex: hex::encode(&message),
        });

        Some(share)
    }

    /// receive a peer's signature share
    // TODO: before accumulating, verify each share against its commitment:
    //   z_k * G == R_k + (lambda_outer * c * mu_k) * Y_k
    // where R_k = D_k + rho_k * E_k is the holder's bound commitment.
    // this requires storing per-holder verification keys (Y_k) and the
    // commitment list from round 1. without this check a malicious holder
    // can submit a garbage share that corrupts z_nested silently.
    pub async fn receive_share(&self, share: InnerShare) -> AccumulateResult<NestedResponse> {
        let session_id = share.session_id;

        // ensure session (aggregate fn same as start_round2)
        self.round2.ensure_session(session_id, |shares| {
            let mut z = Scalar::ZERO;
            for s in shares {
                if let Some(bytes) = hex::decode(&s.response_hex).ok() {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        let ct = Scalar::from_repr(arr.into());
                        if bool::from(ct.is_some()) {
                            z = z + ct.unwrap();
                        }
                    }
                }
            }
            NestedResponse {
                z_hex: hex::encode(z.to_repr().as_ref()),
                z_nested: z,
            }
        }).await;

        self.round2.accumulate(&session_id, share).await
    }
}
