//! narsil client — orchestrates the 2-round nested FROST signing flow
//!
//! usage:
//! ```ignore
//! let client = NarsilClient::new("http://localhost:9200");
//! let (commitments, session_id) = client.round1(message).await?;
//!
//! // compute R_nested from commitments, build outer FROST package,
//! // derive outer_challenge and outer_lambda...
//!
//! let z_nested = client.round2(session_id, outer_challenge, outer_lambda, active).await?;
//! // use z_nested as the nested position's FROST signature share
//! ```

use pasta_curves::pallas::{Point, Scalar};
use pasta_curves::group::{ff::{Field, PrimeField, FromUniformBytes}, Group, GroupEncoding};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest, Sha512};

/// client for driving nested FROST signing against narsild
pub struct NarsilClient {
    endpoint: String,
    client: reqwest::Client,
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
}

/// commitment from one inner holder
#[derive(Clone, Debug, Deserialize)]
pub struct CommitmentEntry {
    pub holder_index: u32,
    pub hiding: String,
    pub binding: String,
}

impl NarsilClient {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// round 1: initiate signing, wait for threshold commitments.
    /// returns (commitment list, session_id, R_nested point).
    pub async fn round1(
        &self,
        message: &[u8],
    ) -> Result<(Vec<CommitmentEntry>, [u8; 32], Point), ClientError> {
        let session_id = {
            let mut h = Sha256::new();
            h.update(b"narsil.session.v1");
            h.update(message);
            let r: [u8; 32] = h.finalize().into();
            r
        };

        // start round 1
        let resp: serde_json::Value = self.client
            .post(format!("{}/sign/round1", self.endpoint))
            .json(&serde_json::json!({
                "session_id": session_id,
                "message_hex": hex::encode(message),
            }))
            .send().await?
            .json().await?;

        if let Some(err) = resp.get("error") {
            return Err(ClientError::Narsild(err.to_string()));
        }

        // poll until threshold met
        let commitments = self.poll_round1(session_id).await?;

        // compute R_nested = Σ (D_k + ρ_k * E_k)
        let r_nested = compute_r_nested(&commitments, message);

        Ok((commitments, session_id, r_nested))
    }

    /// round 2: send outer params, wait for z_nested.
    pub async fn round2(
        &self,
        session_id: [u8; 32],
        outer_challenge: Scalar,
        outer_lambda: Scalar,
        active_indices: Vec<u32>,
    ) -> Result<Scalar, ClientError> {
        let resp: serde_json::Value = self.client
            .post(format!("{}/sign/round2", self.endpoint))
            .json(&serde_json::json!({
                "session_id": session_id,
                "outer_challenge_hex": hex::encode(outer_challenge.to_repr().as_ref()),
                "outer_lambda_hex": hex::encode(outer_lambda.to_repr().as_ref()),
                "active_indices": active_indices,
            }))
            .send().await?
            .json().await?;

        if let Some(err) = resp.get("error") {
            return Err(ClientError::Narsild(err.to_string()));
        }

        // if z_nested already in response (threshold met immediately)
        if let Some(z_hex) = resp.get("z_nested").and_then(|v| v.as_str()) {
            return scalar_from_hex(z_hex)
                .ok_or_else(|| ClientError::BadResponse("bad z_nested scalar".into()));
        }

        // poll for completion
        self.poll_round2(session_id).await
    }

    /// full signing flow: round1 + compute outer params + round2.
    /// `outer_signer` is a closure that takes (R_nested, commitment_list)
    /// and returns (outer_challenge, outer_lambda, active_indices, buyer_sig_share).
    pub async fn sign<F>(
        &self,
        message: &[u8],
        outer_signer: F,
    ) -> Result<Scalar, ClientError>
    where
        F: FnOnce(Point, &[CommitmentEntry]) -> (Scalar, Scalar, Vec<u32>),
    {
        let (commitments, session_id, r_nested) = self.round1(message).await?;
        let (outer_challenge, outer_lambda, active_indices) = outer_signer(r_nested, &commitments);
        self.round2(session_id, outer_challenge, outer_lambda, active_indices).await
    }

    // --- internal ---

    async fn poll_round1(&self, session_id: [u8; 32]) -> Result<Vec<CommitmentEntry>, ClientError> {
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let resp: serde_json::Value = self.client
                .post(format!("{}/sign/status", self.endpoint))
                .json(&serde_json::json!({"session_id": session_id}))
                .send().await?
                .json().await?;

            let ready = resp.pointer("/round1/ready")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if ready {
                let commitments: Vec<CommitmentEntry> = resp.get("commitments")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                return Ok(commitments);
            }
        }
        Err(ClientError::Timeout)
    }

    async fn poll_round2(&self, session_id: [u8; 32]) -> Result<Scalar, ClientError> {
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let resp: serde_json::Value = self.client
                .post(format!("{}/sign/status", self.endpoint))
                .json(&serde_json::json!({"session_id": session_id}))
                .send().await?
                .json().await?;

            let complete = resp.pointer("/round2/complete")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if complete {
                let z_hex = resp.pointer("/round2/z_nested")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ClientError::BadResponse("missing z_nested".into()))?;
                return scalar_from_hex(z_hex)
                    .ok_or_else(|| ClientError::BadResponse("bad z_nested".into()));
            }
        }
        Err(ClientError::Timeout)
    }
}

/// compute R_nested = Σ (D_k + ρ_inner_k * E_k) from commitment list
fn compute_r_nested(commitments: &[CommitmentEntry], message: &[u8]) -> Point {
    let mut r_agg = Point::identity();

    for c in commitments {
        let hiding_bytes = hex::decode(&c.hiding).unwrap_or_default();
        let binding_bytes = hex::decode(&c.binding).unwrap_or_default();

        let d_k = point_from_bytes(&hiding_bytes);
        let e_k = point_from_bytes(&binding_bytes);

        // inner binding factor
        let rho = {
            let mut h = Sha512::new();
            h.update(b"frostito-inner-bind");
            h.update(c.holder_index.to_le_bytes());
            h.update((message.len() as u64).to_le_bytes());
            h.update(message);
            for cc in commitments {
                h.update(cc.holder_index.to_le_bytes());
                h.update(&hex::decode(&cc.hiding).unwrap_or_default());
                h.update(&hex::decode(&cc.binding).unwrap_or_default());
            }
            let hash: [u8; 64] = h.finalize().into();
            Scalar::from_uniform_bytes(&hash)
        };

        r_agg = r_agg + d_k + e_k * rho;
    }

    r_agg
}

fn point_from_bytes(bytes: &[u8]) -> Point {
    if bytes.len() != 32 { return Point::identity(); }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    let ct = Point::from_bytes(&arr.into());
    if bool::from(ct.is_some()) { ct.unwrap() } else { Point::identity() }
}

fn scalar_from_hex(hex_str: &str) -> Option<Scalar> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 { return None; }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let ct = Scalar::from_repr(arr.into());
    if bool::from(ct.is_some()) { Some(ct.unwrap()) } else { None }
}
