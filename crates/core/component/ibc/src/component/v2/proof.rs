//! Proof verification over raw byte paths for IBC v2.
//!
//! `ibc_types::MerkleProof::verify_membership` takes string-typed key paths;
//! v2 keys are not UTF-8, so the chained ICS23 verification is done here on
//! bytes, the same way ibc-go and the Eureka membership program do it.

use anyhow::{Context, Result};
use async_trait::async_trait;
use cnidarium::StateRead;
use ibc_types::core::{client::ClientId, client::Height, commitment::MerkleProof};
use tendermint::Time;

use crate::component::client::StateReadExt as _;

/// Chained membership: proofs[0] proves `value` at `keys[last]` under the
/// innermost root, proofs[i] proves that root at `keys[last-i]`, and the
/// outermost computed root must equal `root`.
pub fn verify_membership_raw(
    proof: &MerkleProof,
    specs: &[ics23::ProofSpec],
    root: &[u8],
    keys: &[Vec<u8>],
    value: &[u8],
) -> Result<()> {
    anyhow::ensure!(!proof.proofs.is_empty(), "empty merkle proof");
    anyhow::ensure!(
        proof.proofs.len() == specs.len(),
        "proof has {} layers but client has {} proof specs",
        proof.proofs.len(),
        specs.len()
    );
    anyhow::ensure!(
        keys.len() == specs.len(),
        "merkle path has {} elements but client has {} proof specs",
        keys.len(),
        specs.len()
    );
    let mut subroot: Vec<u8> = Vec::new();
    let mut val = value.to_vec();
    for ((p, spec), key) in proof.proofs.iter().zip(specs).zip(keys.iter().rev()) {
        let ex = match &p.proof {
            Some(ics23::commitment_proof::Proof::Exist(ex)) => ex,
            _ => anyhow::bail!("expected an existence proof"),
        };
        subroot = ics23::calculate_existence_root::<ics23::HostFunctionsManager>(ex)
            .map_err(|e| anyhow::anyhow!("invalid existence proof: {e:?}"))?;
        anyhow::ensure!(
            ics23::verify_membership::<ics23::HostFunctionsManager>(p, spec, &subroot, key, &val),
            "membership proof failed at key {}",
            hex::encode(key)
        );
        val = subroot.clone();
    }
    anyhow::ensure!(subroot == root, "merkle proof root does not match consensus state root");
    Ok(())
}

/// Chained non-membership: proofs[0] is a non-existence proof for
/// `keys[last]`; the outer layers are existence proofs of the inner roots.
pub fn verify_non_membership_raw(
    proof: &MerkleProof,
    specs: &[ics23::ProofSpec],
    root: &[u8],
    keys: &[Vec<u8>],
) -> Result<()> {
    anyhow::ensure!(!proof.proofs.is_empty(), "empty merkle proof");
    anyhow::ensure!(
        proof.proofs.len() == specs.len() && keys.len() == specs.len(),
        "proof, specs and path must have the same number of layers"
    );
    let nex = match &proof.proofs[0].proof {
        Some(ics23::commitment_proof::Proof::Nonexist(nex)) => nex,
        _ => anyhow::bail!("expected a non-existence proof at the innermost layer"),
    };
    let neighbour = nex
        .left
        .as_ref()
        .or(nex.right.as_ref())
        .ok_or_else(|| anyhow::anyhow!("non-existence proof has no neighbour"))?;
    let mut subroot = ics23::calculate_existence_root::<ics23::HostFunctionsManager>(neighbour)
        .map_err(|e| anyhow::anyhow!("invalid existence proof: {e:?}"))?;
    let innermost_key = &keys[keys.len() - 1];
    anyhow::ensure!(
        ics23::verify_non_membership::<ics23::HostFunctionsManager>(
            &proof.proofs[0],
            &specs[0],
            &subroot,
            innermost_key
        ),
        "non-membership proof failed at key {}",
        hex::encode(innermost_key)
    );
    for (i, (p, spec)) in proof.proofs.iter().zip(specs).enumerate().skip(1) {
        let key = &keys[keys.len() - 1 - i];
        let ex = match &p.proof {
            Some(ics23::commitment_proof::Proof::Exist(ex)) => ex,
            _ => anyhow::bail!("expected an existence proof at layer {i}"),
        };
        let next = ics23::calculate_existence_root::<ics23::HostFunctionsManager>(ex)
            .map_err(|e| anyhow::anyhow!("invalid existence proof: {e:?}"))?;
        anyhow::ensure!(
            ics23::verify_membership::<ics23::HostFunctionsManager>(p, spec, &next, key, &subroot),
            "membership proof failed at layer {i}"
        );
        subroot = next;
    }
    anyhow::ensure!(subroot == root, "merkle proof root does not match consensus state root");
    Ok(())
}

#[async_trait]
pub trait ProofVerifierV2: StateRead + Sized {
    /// Verify `value` at `path` (counterparty prefix already applied) against
    /// the consensus state of `client_id` at `height`. No delay period: ibc-go
    /// v2 passes `0, 0`.
    async fn verify_membership_v2(
        &self,
        client_id: &ClientId,
        height: &Height,
        proof: &MerkleProof,
        path: &[Vec<u8>],
        value: &[u8],
    ) -> Result<()> {
        let client_state = self.get_client_state(client_id).await?;
        anyhow::ensure!(!client_state.is_frozen(), "client {client_id} is frozen");
        client_state.verify_height(*height)?;
        let consensus_state = self
            .get_verified_consensus_state(height, client_id)
            .await
            .with_context(|| format!("no consensus state for {client_id} at {height}"))?;
        verify_membership_raw(
            proof,
            &client_state.proof_specs,
            &consensus_state.root.hash,
            path,
            value,
        )
    }

    async fn verify_non_membership_v2(
        &self,
        client_id: &ClientId,
        height: &Height,
        proof: &MerkleProof,
        path: &[Vec<u8>],
    ) -> Result<()> {
        let client_state = self.get_client_state(client_id).await?;
        anyhow::ensure!(!client_state.is_frozen(), "client {client_id} is frozen");
        client_state.verify_height(*height)?;
        let consensus_state = self
            .get_verified_consensus_state(height, client_id)
            .await
            .with_context(|| format!("no consensus state for {client_id} at {height}"))?;
        verify_non_membership_raw(
            proof,
            &client_state.proof_specs,
            &consensus_state.root.hash,
            path,
        )
    }

    /// Timestamp of the counterparty consensus state at `height`.
    async fn consensus_timestamp_v2(&self, client_id: &ClientId, height: &Height) -> Result<Time> {
        let consensus_state = self
            .get_verified_consensus_state(height, client_id)
            .await
            .with_context(|| format!("no consensus state for {client_id} at {height}"))?;
        Ok(consensus_state.timestamp)
    }
}

impl<T: StateRead> ProofVerifierV2 for T {}

/// Unix seconds of a tendermint time, saturating at zero for pre-epoch times.
pub fn unix_seconds(time: Time) -> u64 {
    time.unix_timestamp().max(0) as u64
}
