//! Light client abstraction.
//!
//! Client and consensus states are stored on disk as protobuf `Any`
//! (`TendermintClientState: DomainType<Proto = Any>`), so the kind of a
//! client is read from the type URL of its stored client state without
//! touching the Tendermint decode path. Clients are compiled into `pd` and
//! dispatched with a `match` on [`LightClientKind`]: async methods generic
//! over the state are not object-safe, and the design (`docs/design/ibc-v2.md`
//! §1) wants no runtime VM.
//!
//! The classic connection and channel handlers stay Tendermint-only; only
//! chains with classic IBC (Tendermint) can reach them. IBC v2 proof
//! verification and the client lifecycle handlers (`CreateClient`,
//! `UpdateClient`, `SubmitMisbehaviour`) dispatch through this module, so a
//! second client kind (the Eureka Ethereum light client, phase 2) plugs in
//! by adding a variant and an implementation.

use anyhow::{Context, Result};
use async_trait::async_trait;
use cnidarium::StateRead;
use ibc_proto::google::protobuf::Any;
use ibc_types::{
    core::{
        client::{ClientId, ClientType, Height},
        commitment::MerkleProof,
    },
    lightclients::tendermint::{
        client_state::{ClientState as TendermintClientState, TENDERMINT_CLIENT_STATE_TYPE_URL},
        consensus_state::ConsensusState as TendermintConsensusState,
        TENDERMINT_CLIENT_TYPE,
    },
    path::ClientStatePath,
};
use penumbra_sdk_proto::StateReadProto as _;
use tendermint::Time;

use crate::{
    component::{
        client::{ClientStatus, Ics2ClientExt as _, StateReadExt as _},
        ics02_validation,
        msg_handler::{verify_tendermint_misbehaviour, verify_tendermint_update},
        v2::proof::{verify_membership_raw, verify_non_membership_raw},
        HostInterface,
    },
    prefix::MerklePrefixExt as _,
    IBC_COMMITMENT_PREFIX,
};

/// The light client implementations compiled into `pd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LightClientKind {
    Tendermint,
}

impl LightClientKind {
    /// Resolve a kind from a client state type URL.
    pub fn from_client_state_type_url(type_url: &str) -> Result<Self> {
        if type_url == TENDERMINT_CLIENT_STATE_TYPE_URL {
            Ok(LightClientKind::Tendermint)
        } else {
            anyhow::bail!("unsupported light client type {type_url:?}")
        }
    }

    /// The ICS-02 client type string (`07-tendermint`, ...).
    pub fn client_type(self) -> ClientType {
        match self {
            LightClientKind::Tendermint => ClientType::new(TENDERMINT_CLIENT_TYPE.to_string()),
        }
    }
}

/// The outcome of verifying a client update.
#[derive(Debug, Clone)]
pub struct VerifiedUpdate {
    /// Height the new consensus state is stored at.
    pub height: Height,
    /// The next client state (possibly frozen on equivocation), as stored.
    pub client_state: Any,
    /// The verified consensus state, as stored.
    pub consensus_state: Any,
    /// The header bytes to publish in the `UpdateClient` event.
    pub header_bytes: Vec<u8>,
}

/// One light client implementation. All methods read the client's stored
/// client and consensus states through `state`.
#[async_trait]
pub trait LightClient {
    const KIND: LightClientKind;

    /// Verify `client_message` (a header) against the stored state and
    /// return the next client and consensus states. Must not write.
    async fn verify_header<S: StateRead, HI: HostInterface>(
        state: &S,
        client_id: &ClientId,
        client_message: Any,
    ) -> Result<VerifiedUpdate>;

    /// Verify `misbehaviour` and return the frozen client state to store.
    async fn check_misbehaviour<S: StateRead, HI: HostInterface>(
        state: &S,
        client_id: &ClientId,
        misbehaviour: Any,
    ) -> Result<Any>;

    /// Active, frozen or expired at `now`.
    async fn status<S: StateRead>(state: &S, client_id: &ClientId, now: Time)
        -> Result<ClientStatus>;

    /// Membership of `value` at `path` (counterparty prefix already applied)
    /// under the consensus state at `height`.
    async fn verify_membership<S: StateRead>(
        state: &S,
        client_id: &ClientId,
        height: &Height,
        proof: &MerkleProof,
        path: &[Vec<u8>],
        value: &[u8],
    ) -> Result<()>;

    async fn verify_non_membership<S: StateRead>(
        state: &S,
        client_id: &ClientId,
        height: &Height,
        proof: &MerkleProof,
        path: &[Vec<u8>],
    ) -> Result<()>;

    /// Timestamp of the consensus state at `height`.
    async fn consensus_timestamp<S: StateRead>(
        state: &S,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<Time>;
}

/// Read the kind of a stored client from its client state type URL.
#[async_trait]
pub trait ClientKindRead: StateRead {
    async fn client_kind(&self, client_id: &ClientId) -> Result<LightClientKind> {
        let any: Any = self
            .get_proto(
                &IBC_COMMITMENT_PREFIX.apply_string(ClientStatePath(client_id.clone()).to_string()),
            )
            .await?
            .with_context(|| format!("could not find client state for {client_id}"))?;
        LightClientKind::from_client_state_type_url(&any.type_url)
    }
}

impl<T: StateRead + ?Sized> ClientKindRead for T {}

/// ICS-07 Tendermint, backed by the existing verification code.
pub struct TendermintLightClient;

#[async_trait]
impl LightClient for TendermintLightClient {
    const KIND: LightClientKind = LightClientKind::Tendermint;

    async fn verify_header<S: StateRead, HI: HostInterface>(
        state: &S,
        client_id: &ClientId,
        client_message: Any,
    ) -> Result<VerifiedUpdate> {
        let untrusted_header = ics02_validation::get_tendermint_header(client_message)?;
        let trusted_header = verify_tendermint_update::<&S, HI>(state, client_id, untrusted_header)
            .await?;
        let client_state = state.get_client_state(client_id).await?;
        let (next_client_state, next_consensus_state) = state
            .next_tendermint_state(client_id.clone(), client_state, trusted_header.clone())
            .await;
        Ok(VerifiedUpdate {
            height: trusted_header.height(),
            client_state: next_client_state.into(),
            consensus_state: next_consensus_state.into(),
            header_bytes: <ibc_types::lightclients::tendermint::header::Header as ibc_proto::Protobuf<
                ibc_proto::ibc::lightclients::tendermint::v1::Header,
            >>::encode_vec(trusted_header),
        })
    }

    async fn check_misbehaviour<S: StateRead, HI: HostInterface>(
        state: &S,
        client_id: &ClientId,
        misbehaviour: Any,
    ) -> Result<Any> {
        let untrusted_misbehaviour = ics02_validation::get_tendermint_misbehavior(misbehaviour)?;
        let frozen: TendermintClientState =
            verify_tendermint_misbehaviour::<&S, HI>(state, client_id, &untrusted_misbehaviour)
                .await?;
        Ok(frozen.into())
    }

    async fn status<S: StateRead>(
        state: &S,
        client_id: &ClientId,
        now: Time,
    ) -> Result<ClientStatus> {
        let client_state = state.get_client_state(client_id).await?;
        if client_state.is_frozen() {
            return Ok(ClientStatus::Frozen);
        }
        let latest: TendermintConsensusState = state
            .get_verified_consensus_state(&client_state.latest_height(), client_id)
            .await?;
        let elapsed = now.duration_since(latest.timestamp)?;
        if client_state.expired(elapsed) {
            return Ok(ClientStatus::Expired);
        }
        Ok(ClientStatus::Active)
    }

    async fn verify_membership<S: StateRead>(
        state: &S,
        client_id: &ClientId,
        height: &Height,
        proof: &MerkleProof,
        path: &[Vec<u8>],
        value: &[u8],
    ) -> Result<()> {
        let client_state = state.get_client_state(client_id).await?;
        anyhow::ensure!(!client_state.is_frozen(), "client {client_id} is frozen");
        client_state.verify_height(*height)?;
        let consensus_state = state
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

    async fn verify_non_membership<S: StateRead>(
        state: &S,
        client_id: &ClientId,
        height: &Height,
        proof: &MerkleProof,
        path: &[Vec<u8>],
    ) -> Result<()> {
        let client_state = state.get_client_state(client_id).await?;
        anyhow::ensure!(!client_state.is_frozen(), "client {client_id} is frozen");
        client_state.verify_height(*height)?;
        let consensus_state = state
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

    async fn consensus_timestamp<S: StateRead>(
        state: &S,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<Time> {
        let consensus_state = state
            .get_verified_consensus_state(height, client_id)
            .await
            .with_context(|| format!("no consensus state for {client_id} at {height}"))?;
        Ok(consensus_state.timestamp)
    }
}
