//! narsil client — the coordinator role of the two-round nested FROST v2 flow.
//!
//! # What the coordinator is, and is not
//!
//! Under v1 the coordinator computed the outer challenge and Lagrange
//! coefficient and posted them as two scalars; each node applied them. That is
//! finding N-1: the nodes had no input from which to tell what they were
//! authorizing, so a coordinator could derive the outer context honestly over
//! a message of its own choosing and assemble a signature the inner group
//! never saw.
//!
//! Under v2 the coordinator's job is only to *publish the outer round*. It
//! sends the full [`SigningRequest`]: the message, the bytes the outer package
//! was built over, every outer signer's commitments, the outer group key, the
//! nested index and the session id. Each node rebuilds the package, recomputes
//! the binding factor, challenge and Lagrange coefficient, and checks the
//! scalars the coordinator sent against its own — see
//! [`crate::signing`]. A coordinator that lies is refused with
//! `MessageMismatch` or `ChallengeMismatch` rather than obeyed.
//!
//! # The coordinator is a roster member
//!
//! Every mutating endpoint takes a signed envelope (M-2), so the coordinator
//! holds a roster identity and signs what it posts. There is no anonymous
//! coordinator role any more: driving a signing round is an authorized action,
//! and the authorization is the same ed25519 key the roster already names.
//! `/sign/status` is read-only and stays open.
//!
//! The coordinator must therefore build its context over the *same* epoch and
//! manifest hash the nodes hold, which it reads from `/health` and
//! `/sign/status`. If it does not, nothing is signed. That is the intended
//! failure mode of a reshare: the old quorum simply cannot produce a share.

use crate::codec::{point_hex, scalar_from_hex, scalar_hex};
use crate::signing::{InnerCommitment, OuterCommitment, SigningRequest};
use osst::frost::{SigningCommitments, SigningPackage};
use osst::nested::InnerSigningParamsV2;
use osst::SigningContext;
use pasta_curves::pallas::{Point as PallasPoint, Scalar as PallasScalar};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Client for driving nested FROST signing against a narsild node.
pub struct NarsilClient {
    endpoint: String,
    client: reqwest::Client,
    /// Signs this coordinator's requests as a roster member.
    auth: Arc<crate::auth::Authenticator>,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("narsild error: {0}")]
    Narsild(String),
    #[error("timeout waiting for threshold")]
    Timeout,
    #[error("bad response: {0}")]
    BadResponse(String),
    #[error("osst: {0}")]
    Osst(osst::OsstError),
    #[error("cannot sign the request: {0}")]
    Auth(#[from] crate::auth::AuthError),
}

impl From<osst::OsstError> for ClientError {
    fn from(e: osst::OsstError) -> Self {
        ClientError::Osst(e)
    }
}

/// The outer round the nested position is taking part in.
///
/// The coordinator owns this; the inner group only ever sees it as public data
/// it re-derives from.
pub struct OuterRound {
    /// The outer group public key.
    pub group_pubkey: PallasPoint,
    /// The nested position's index in the outer signing set.
    pub nested_index: u32,
    /// Every OTHER outer signer's commitments. The nested position's own pair
    /// is computed from the inner round-1 set.
    pub other_commitments: Vec<SigningCommitments<PallasPoint>>,
    /// The epoch the group is in — must match the nodes' key packages.
    pub epoch: u64,
    /// The roster fingerprint — must match the nodes' key packages.
    pub manifest_hash: [u8; 32],
}

/// What round 1 produced.
pub struct Round1Output {
    pub session_id: [u8; 32],
    pub commitments: Vec<InnerCommitment>,
    /// `(D_nested, E_nested)` — the nested position's entry in the outer
    /// package.
    pub nested_commitment: (PallasPoint, PallasPoint),
}

impl NarsilClient {
    pub fn new(endpoint: &str, auth: Arc<crate::auth::Authenticator>) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .timeout(crate::broadcast::PEER_TIMEOUT)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            auth,
        }
    }

    /// POST a signed envelope to `path`.
    async fn post_signed<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<serde_json::Value, ClientError> {
        let envelope = self.auth.seal(path, body)?;
        Ok(self
            .client
            .post(format!("{}{}", self.endpoint, path))
            .json(&envelope)
            .send()
            .await?
            .json()
            .await?)
    }

    /// A session id for a message. Public, and agreed before round 1.
    pub fn session_id_for(message: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"narsil.session.v1");
        h.update((message.len() as u64).to_le_bytes());
        h.update(message);
        h.finalize().into()
    }

    /// Round 1: start the inner commitment round and wait for the threshold.
    pub async fn round1(
        &self,
        session_id: [u8; 32],
        message: &[u8],
    ) -> Result<Round1Output, ClientError> {
        let resp = self
            .post_signed(
                "/sign/round1",
                &serde_json::json!({
                    "session_id": session_id,
                    "message_hex": hex::encode(message),
                }),
            )
            .await?;
        if let Some(e) = resp.get("error") {
            return Err(ClientError::Narsild(e.to_string()));
        }
        self.poll_round1(session_id).await
    }

    /// Round 2: publish the outer round and wait for `z_nested`.
    pub async fn round2(
        &self,
        round1: &Round1Output,
        outer: &OuterRound,
        message: &[u8],
        active_indices: Vec<u32>,
    ) -> Result<PallasScalar, ClientError> {
        let request = build_request(round1, outer, message, active_indices)?;

        let resp = self.post_signed("/sign/round2", &request).await?;
        if let Some(e) = resp.get("error") {
            return Err(ClientError::Narsild(e.to_string()));
        }
        if let Some(z) = resp.get("z_nested").and_then(|v| v.as_str()) {
            return scalar_from_hex(z)
                .ok_or_else(|| ClientError::BadResponse("bad z_nested scalar".into()));
        }
        self.poll_round2(round1.session_id).await
    }

    /// The whole flow.
    pub async fn sign(
        &self,
        message: &[u8],
        outer: &OuterRound,
    ) -> Result<PallasScalar, ClientError> {
        let session_id = Self::session_id_for(message);
        let round1 = self.round1(session_id, message).await?;
        let active: Vec<u32> = round1.commitments.iter().map(|c| c.holder_index).collect();
        self.round2(&round1, outer, message, active).await
    }

    async fn poll_round1(&self, session_id: [u8; 32]) -> Result<Round1Output, ClientError> {
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let resp = self.status(session_id).await?;
            if resp
                .pointer("/round1/ready")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                let commitments: Vec<InnerCommitment> = resp
                    .get("commitments")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let nested_commitment =
                    crate::signing::nested_commitment_pair(&session_id, &commitments)
                        .map_err(|e| ClientError::BadResponse(e.to_string()))?;
                return Ok(Round1Output {
                    session_id,
                    commitments,
                    nested_commitment,
                });
            }
        }
        Err(ClientError::Timeout)
    }

    async fn poll_round2(&self, session_id: [u8; 32]) -> Result<PallasScalar, ClientError> {
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let resp = self.status(session_id).await?;
            if resp
                .pointer("/round2/complete")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                let z = resp
                    .pointer("/round2/z_nested")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ClientError::BadResponse("missing z_nested".into()))?;
                return scalar_from_hex(z)
                    .ok_or_else(|| ClientError::BadResponse("bad z_nested".into()));
            }
        }
        Err(ClientError::Timeout)
    }

    async fn status(&self, session_id: [u8; 32]) -> Result<serde_json::Value, ClientError> {
        Ok(self
            .client
            .post(format!("{}/sign/status", self.endpoint))
            .json(&serde_json::json!({ "session_id": session_id }))
            .send()
            .await?
            .json()
            .await?)
    }
}

/// Assemble the round-2 request: the full outer round, plus the coordinator's
/// own derivation of the three scalars for the nodes to check against.
pub fn build_request(
    round1: &Round1Output,
    outer: &OuterRound,
    message: &[u8],
    active_indices: Vec<u32>,
) -> Result<SigningRequest, ClientError> {
    let ctx = SigningContext::new(outer.epoch, outer.manifest_hash, message);
    let signed_bytes = ctx.encode();

    let mut commitments = vec![SigningCommitments {
        index: outer.nested_index,
        hiding: round1.nested_commitment.0,
        binding: round1.nested_commitment.1,
    }];
    commitments.extend(outer.other_commitments.iter().cloned());

    let package = SigningPackage::<PallasPoint>::new(signed_bytes.clone(), commitments.clone())?;
    let params = InnerSigningParamsV2::<PallasScalar>::from_outer::<PallasPoint>(
        &package,
        &outer.group_pubkey,
        outer.nested_index,
    )?;

    Ok(SigningRequest {
        session_id: round1.session_id,
        message_hex: hex::encode(message),
        signed_bytes_hex: hex::encode(&signed_bytes),
        nested_index: outer.nested_index,
        group_pubkey: point_hex(&outer.group_pubkey),
        outer_commitments: commitments
            .iter()
            .map(|c| OuterCommitment {
                index: c.index,
                hiding: point_hex(&c.hiding),
                binding: point_hex(&c.binding),
            })
            .collect(),
        inner_commitments: round1.commitments.clone(),
        active_indices,
        outer_binding: scalar_hex(params.outer_binding()),
        outer_challenge: scalar_hex(params.outer_challenge()),
        outer_lambda: scalar_hex(params.outer_lambda()),
    })
}
