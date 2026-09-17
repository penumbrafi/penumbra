//! End-to-end IBC v2 between two Penumbra chains backed by real `Storage`, so
//! that packet, receipt and acknowledgement proofs are real JMT proofs over
//! the byte-keyed ICS-24 v2 paths.
//!
//! Header verification is out of scope here: each chain's Tendermint client
//! for the other is installed directly with a consensus state whose root is
//! the other storage's app hash, which is exactly what `UpdateClient` would
//! leave behind.

use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use cnidarium::{Snapshot, StateDelta, StateRead, StateWrite, Storage};
use ibc_types::{
    core::{
        channel::msgs::{
            MsgAcknowledgement, MsgChannelCloseConfirm, MsgChannelCloseInit, MsgChannelOpenAck,
            MsgChannelOpenConfirm, MsgChannelOpenInit, MsgChannelOpenTry, MsgRecvPacket,
            MsgTimeout,
        },
        client::{ClientId, Height},
        commitment::{MerkleProof, MerkleRoot},
        connection::ChainId,
    },
    lightclients::tendermint::{
        client_state::{AllowUpdate, ClientState as TendermintClientState},
        consensus_state::ConsensusState as TendermintConsensusState,
        TrustThreshold,
    },
};
use penumbra_sdk_sct::{
    component::clock::{EpochManager as _, EpochRead as _},
    epoch::Epoch,
};
use tendermint::Time;

use crate::{
    component::{
        app_handler::{AppHandler, AppHandlerCheck, AppHandlerExecute},
        client::{ConsensusStateWriteExt as _, StateWriteExt as _},
        v2::{
            state::StateReadExt as _, state::StateWriteExt as _, state_key, AppHandlerV2,
            SendPacketV2Read as _, SendPacketV2Write as _,
        },
        HostInterface,
    },
    v2::{
        commitment::{
            commit_acknowledgement, packet_acknowledgement_key, packet_commitment_key,
            packet_receipt_key, universal_error_acknowledgement,
        },
        Acknowledgement, MsgAcknowledgement as MsgAcknowledgementV2, MsgRecvPacket as MsgRecvPacketV2,
        MsgRegisterCounterparty, MsgTimeout as MsgTimeoutV2, Packet, Payload,
    },
    IbcRelay, StateWriteExt as _, IBC_PROOF_SPECS,
};

const NOW: i64 = 1_700_000_000;
const TEST_PORT: &str = "testport";

struct MockHost {}

#[async_trait]
impl HostInterface for MockHost {
    async fn get_chain_id<S: StateRead>(_state: S) -> Result<String> {
        Ok("mock".into())
    }
    async fn get_revision_number<S: StateRead>(_state: S) -> Result<u64> {
        Ok(0)
    }
    async fn get_block_height<S: StateRead>(state: S) -> Result<u64> {
        state.get_block_height().await
    }
    async fn get_block_timestamp<S: StateRead>(state: S) -> Result<Time> {
        state.get_current_block_timestamp().await
    }
}

/// A test application on `testport`: records what it saw, fails on demand.
struct TestApp {}

#[async_trait]
impl AppHandlerCheck for TestApp {
    async fn chan_open_init_check<S: StateRead>(_: S, _: &MsgChannelOpenInit) -> Result<()> {
        Ok(())
    }
    async fn chan_open_try_check<S: StateRead>(_: S, _: &MsgChannelOpenTry) -> Result<()> {
        Ok(())
    }
    async fn chan_open_ack_check<S: StateRead>(_: S, _: &MsgChannelOpenAck) -> Result<()> {
        Ok(())
    }
    async fn chan_open_confirm_check<S: StateRead>(_: S, _: &MsgChannelOpenConfirm) -> Result<()> {
        Ok(())
    }
    async fn chan_close_confirm_check<S: StateRead>(
        _: S,
        _: &MsgChannelCloseConfirm,
    ) -> Result<()> {
        Ok(())
    }
    async fn chan_close_init_check<S: StateRead>(_: S, _: &MsgChannelCloseInit) -> Result<()> {
        Ok(())
    }
    async fn recv_packet_check<S: StateRead>(_: S, _: &MsgRecvPacket) -> Result<()> {
        Ok(())
    }
    async fn timeout_packet_check<S: StateRead>(_: S, _: &MsgTimeout) -> Result<()> {
        Ok(())
    }
    async fn acknowledge_packet_check<S: StateRead>(_: S, _: &MsgAcknowledgement) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl AppHandlerExecute for TestApp {
    async fn chan_open_init_execute<S: StateWrite>(_: S, _: &MsgChannelOpenInit) {}
    async fn chan_open_try_execute<S: StateWrite>(_: S, _: &MsgChannelOpenTry) {}
    async fn chan_open_ack_execute<S: StateWrite>(_: S, _: &MsgChannelOpenAck) {}
    async fn chan_open_confirm_execute<S: StateWrite>(_: S, _: &MsgChannelOpenConfirm) {}
    async fn chan_close_confirm_execute<S: StateWrite>(_: S, _: &MsgChannelCloseConfirm) {}
    async fn chan_close_init_execute<S: StateWrite>(_: S, _: &MsgChannelCloseInit) {}
    async fn recv_packet_execute<S: StateWrite>(_: S, _: &MsgRecvPacket) -> Result<()> {
        Ok(())
    }
    async fn timeout_packet_execute<S: StateWrite>(_: S, _: &MsgTimeout) -> Result<()> {
        Ok(())
    }
    async fn acknowledge_packet_execute<S: StateWrite>(_: S, _: &MsgAcknowledgement) -> Result<()> {
        Ok(())
    }
}

fn recv_key(seq: u64) -> String {
    format!("test/recv/{seq}")
}
fn ack_key(seq: u64) -> String {
    format!("test/ack/{seq}")
}
fn timeout_key(seq: u64) -> String {
    format!("test/timeout/{seq}")
}

#[async_trait]
impl AppHandlerV2 for TestApp {
    fn handles_port_v2(port: &str) -> bool {
        port == TEST_PORT
    }
    async fn recv_payload_v2<S: StateWrite>(
        mut state: S,
        packet: &Packet,
        payload: &Payload,
    ) -> Result<Vec<u8>> {
        // Write first, then fail: proves the rollback.
        state.put_raw(recv_key(packet.sequence), payload.value.clone());
        if payload.value == b"fail" {
            anyhow::bail!("application refused the payload");
        }
        Ok(b"ok".to_vec())
    }
    async fn acknowledge_payload_v2<S: StateWrite>(
        mut state: S,
        packet: &Packet,
        _payload: &Payload,
        ack: &[u8],
    ) -> Result<()> {
        state.put_raw(ack_key(packet.sequence), ack.to_vec());
        Ok(())
    }
    async fn timeout_payload_v2<S: StateWrite>(
        mut state: S,
        packet: &Packet,
        _payload: &Payload,
    ) -> Result<()> {
        state.put_raw(timeout_key(packet.sequence), b"timed out".to_vec());
        Ok(())
    }
}

impl AppHandler for TestApp {}

fn time(secs: i64) -> Time {
    Time::from_unix_timestamp(secs, 0).unwrap()
}

fn client_state(latest_height: u64) -> TendermintClientState {
    TendermintClientState::new(
        ChainId::from_string("other-chain"),
        TrustThreshold::ONE_THIRD,
        Duration::from_secs(1000 * 86400),
        Duration::from_secs(2000 * 86400),
        Duration::from_secs(60),
        Height::new(0, latest_height).unwrap(),
        IBC_PROOF_SPECS.clone(),
        vec!["upgrade".into(), "upgradedIBCState".into()],
        AllowUpdate {
            after_expiry: false,
            after_misbehaviour: false,
        },
        None,
    )
    .unwrap()
}

fn payload(value: &[u8]) -> Payload {
    Payload {
        source_port: TEST_PORT.into(),
        destination_port: TEST_PORT.into(),
        version: "v1".into(),
        encoding: "application/octet-stream".into(),
        value: value.to_vec(),
    }
}

/// One Penumbra chain with a v2 client for the other chain.
struct Chain {
    storage: Storage,
    /// Our client id for the counterparty. Both chains use `07-tendermint-0`.
    client: ClientId,
    height: u64,
}

impl Chain {
    async fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let storage = Storage::load(dir.into_path(), vec![crate::IBC_SUBSTORE_PREFIX.to_string()]).await?;
        let mut chain = Chain {
            storage,
            client: "07-tendermint-0".parse()?,
            height: 1,
        };
        let mut state = chain.begin();
        state.put_epoch_by_height(0, Epoch { index: 0, start_height: 0 });
        state.put_epoch_by_height(1, Epoch { index: 0, start_height: 0 });
        state.put_ibc_params(crate::params::IBCParameters {
            ibc_enabled: true,
            inbound_ics20_transfers_enabled: true,
            outbound_ics20_transfers_enabled: true,
        });
        chain.commit(state).await?;
        Ok(chain)
    }

    /// Start a block: a fresh delta with the block height and time set.
    fn begin(&mut self) -> StateDelta<Snapshot> {
        let mut state = StateDelta::new(self.storage.latest_snapshot());
        state.put_block_height(self.height);
        state.put_block_timestamp(self.height, time(NOW));
        state
    }

    async fn commit(&mut self, state: StateDelta<Snapshot>) -> Result<()> {
        self.storage.commit(state).await?;
        self.height += 1;
        Ok(())
    }

    async fn root(&self) -> Result<Vec<u8>> {
        Ok(self.storage.latest_snapshot().root_hash().await?.0.to_vec())
    }

    async fn proof(&self, key: &[u8]) -> Result<(Option<Vec<u8>>, MerkleProof)> {
        self.storage
            .latest_snapshot()
            .get_with_proof(state_key::commitment(key))
            .await
    }

    /// Install the counterparty's `root` at `height` with `timestamp`, as an
    /// `UpdateClient` would, and bump the client's latest height.
    async fn trust(
        &mut self,
        state: &mut StateDelta<Snapshot>,
        root: Vec<u8>,
        height: u64,
        timestamp: Time,
    ) -> Result<()> {
        state.put_client(&self.client, client_state(height));
        state
            .put_verified_consensus_state::<MockHost>(
                Height::new(0, height)?,
                self.client.clone(),
                TendermintConsensusState::new(
                    MerkleRoot { hash: root },
                    timestamp,
                    tendermint::Hash::Sha256([0u8; 32]),
                ),
            )
            .await
    }

    async fn relay(&self, state: &mut StateDelta<Snapshot>, action: IbcRelay) -> Result<()> {
        let action = action.with_handler::<TestApp, MockHost>();
        action.check_stateless(()).await?;
        // `check_historical` only verifies the IBC params, which `begin` sets.
        action.check_and_execute(state).await
    }
}

fn register(client: &ClientId) -> IbcRelay {
    IbcRelay::RegisterCounterparty(MsgRegisterCounterparty {
        client_id: client.clone(),
        counterparty_merkle_prefix: vec![b"ibc-data".to_vec(), b"".to_vec()],
        counterparty_client_id: "07-tendermint-0".into(),
        signer: String::new(),
    })
}

/// Bring up two chains, each with a client for the other (installed at the
/// other's genesis root) and a registered counterparty.
async fn pair() -> Result<(Chain, Chain)> {
    let mut a = Chain::new().await?;
    let mut b = Chain::new().await?;
    let (root_a, root_b) = (a.root().await?, b.root().await?);

    for (chain, root) in [(&mut a, root_b), (&mut b, root_a)] {
        let mut state = chain.begin();
        chain.trust(&mut state, root, 1, time(NOW)).await?;
        // Simulate `CreateClient` earlier in the same transaction.
        state.mark_client_created_in_tx(chain.client.clone());
        chain.relay(&mut state, register(&chain.client)).await?;
        assert_eq!(state.get_next_sequence_send_v2("07-tendermint-0").await?, 1);
        chain.commit(state).await?;
    }
    Ok((a, b))
}

#[tokio::test]
async fn register_counterparty_requires_create_client_in_same_tx() -> Result<()> {
    let mut a = Chain::new().await?;
    let mut state = a.begin();
    a.trust(&mut state, vec![0u8; 32], 1, time(NOW)).await?;
    // The client exists but was not created in this transaction.
    let err = a.relay(&mut state, register(&a.client)).await.unwrap_err();
    assert!(format!("{err:#}").contains("same transaction"), "{err:#}");

    state.mark_client_created_in_tx(a.client.clone());
    a.relay(&mut state, register(&a.client)).await?;
    // And only once.
    let err = a.relay(&mut state, register(&a.client)).await.unwrap_err();
    assert!(format!("{err:#}").contains("already has a registered counterparty"), "{err:#}");
    Ok(())
}

#[tokio::test]
async fn send_recv_ack_round_trip() -> Result<()> {
    let (mut a, mut b) = pair().await?;
    let timeout = NOW as u64 + 3600;

    // A sends.
    let mut state = a.begin();
    state
        .send_packet_v2_check(&a.client, timeout, &payload(b"hello"), time(NOW))
        .await?;
    let packet = state
        .send_packet_v2_execute(&a.client, timeout, payload(b"hello"))
        .await?;
    assert_eq!(packet.sequence, 1);
    assert_eq!(packet.destination_client, "07-tendermint-0");
    assert_eq!(state.get_next_sequence_send_v2(a.client.as_str()).await?, 2);
    a.commit(state).await?;

    // B trusts A's new root and receives with a real proof.
    let (value, proof) = a
        .proof(&packet_commitment_key(&packet.source_client, packet.sequence))
        .await?;
    assert!(value.is_some());
    let mut state = b.begin();
    let a_height = a.height - 1;
    b.trust(&mut state, a.root().await?, a_height, time(NOW)).await?;
    let recv = IbcRelay::RecvPacketV2(MsgRecvPacketV2 {
        packet: packet.clone(),
        proof_commitment: proof.clone(),
        proof_height: Height::new(0, a_height)?,
        signer: String::new(),
    });
    b.relay(&mut state, recv.clone()).await?;
    assert_eq!(
        state.get_raw(&recv_key(1)).await?.as_deref(),
        Some(b"hello".as_slice()),
        "application ran"
    );
    assert!(state.has_packet_receipt_v2("07-tendermint-0", 1).await?);
    let expected_ack = Acknowledgement {
        app_acknowledgements: vec![b"ok".to_vec()],
    };
    assert_eq!(
        state.get_packet_acknowledgement_v2("07-tendermint-0", 1).await?,
        Some(commit_acknowledgement(&expected_ack.app_acknowledgements).to_vec())
    );
    // Replay is rejected.
    let err = b.relay(&mut state, recv).await.unwrap_err();
    assert!(format!("{err:#}").contains("already been received"), "{err:#}");
    b.commit(state).await?;

    // A trusts B's root and processes the acknowledgement.
    let (value, proof) = b
        .proof(&packet_acknowledgement_key(&packet.destination_client, packet.sequence))
        .await?;
    assert!(value.is_some());
    let mut state = a.begin();
    let b_height = b.height - 1;
    a.trust(&mut state, b.root().await?, b_height, time(NOW)).await?;
    a.relay(
        &mut state,
        IbcRelay::AcknowledgementV2(MsgAcknowledgementV2 {
            packet: packet.clone(),
            acknowledgement: expected_ack.clone(),
            proof_acked: proof.clone(),
            proof_height: Height::new(0, b_height)?,
            signer: String::new(),
        }),
    )
    .await?;
    assert_eq!(
        state.get_raw(&ack_key(1)).await?.as_deref(),
        Some(b"ok".as_slice())
    );
    assert!(state
        .get_packet_commitment_v2(a.client.as_str(), 1)
        .await?
        .is_none());
    // A wrong ack does not verify.
    let err = a
        .relay(
            &mut state,
            IbcRelay::AcknowledgementV2(MsgAcknowledgementV2 {
                packet: packet.clone(),
                acknowledgement: Acknowledgement {
                    app_acknowledgements: vec![b"forged".to_vec()],
                },
                proof_acked: proof,
                proof_height: Height::new(0, b_height)?,
                signer: String::new(),
            }),
        )
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("commitment not found"), "{err:#}");
    Ok(())
}

#[tokio::test]
async fn failing_app_rolls_back_and_writes_error_ack() -> Result<()> {
    let (mut a, mut b) = pair().await?;
    let timeout = NOW as u64 + 3600;

    let mut state = a.begin();
    let packet = state
        .send_packet_v2_execute(&a.client, timeout, payload(b"fail"))
        .await?;
    a.commit(state).await?;

    let (_, proof) = a
        .proof(&packet_commitment_key(&packet.source_client, packet.sequence))
        .await?;
    let mut state = b.begin();
    let a_height = a.height - 1;
    b.trust(&mut state, a.root().await?, a_height, time(NOW)).await?;
    b.relay(
        &mut state,
        IbcRelay::RecvPacketV2(MsgRecvPacketV2 {
            packet: packet.clone(),
            proof_commitment: proof,
            proof_height: Height::new(0, a_height)?,
            signer: String::new(),
        }),
    )
    .await?;
    assert!(
        state.get_raw(&recv_key(1)).await?.is_none(),
        "application write must be rolled back"
    );
    assert!(state.has_packet_receipt_v2("07-tendermint-0", 1).await?);
    assert_eq!(
        state.get_packet_acknowledgement_v2("07-tendermint-0", 1).await?,
        Some(commit_acknowledgement(&[universal_error_acknowledgement().to_vec()]).to_vec())
    );
    Ok(())
}

#[tokio::test]
async fn recv_rejects_wrong_counterparty_and_bad_proof() -> Result<()> {
    let (mut a, mut b) = pair().await?;
    let timeout = NOW as u64 + 3600;
    let mut state = a.begin();
    let packet = state
        .send_packet_v2_execute(&a.client, timeout, payload(b"x"))
        .await?;
    a.commit(state).await?;
    let (_, proof) = a
        .proof(&packet_commitment_key(&packet.source_client, packet.sequence))
        .await?;
    let a_height = a.height - 1;

    let mut state = b.begin();
    b.trust(&mut state, a.root().await?, a_height, time(NOW)).await?;

    let mut wrong = packet.clone();
    wrong.source_client = "client-99".into();
    let err = b
        .relay(
            &mut state,
            IbcRelay::RecvPacketV2(MsgRecvPacketV2 {
                packet: wrong,
                proof_commitment: proof.clone(),
                proof_height: Height::new(0, a_height)?,
                signer: String::new(),
            }),
        )
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("does not match counterparty"), "{err:#}");

    let mut tampered = packet.clone();
    tampered.payloads[0].value = b"y".to_vec();
    let err = b
        .relay(
            &mut state,
            IbcRelay::RecvPacketV2(MsgRecvPacketV2 {
                packet: tampered,
                proof_commitment: proof.clone(),
                proof_height: Height::new(0, a_height)?,
                signer: String::new(),
            }),
        )
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("proof failed"), "{err:#}");

    let mut expired = packet.clone();
    expired.timeout_timestamp = NOW as u64;
    let err = b
        .relay(
            &mut state,
            IbcRelay::RecvPacketV2(MsgRecvPacketV2 {
                packet: expired,
                proof_commitment: proof,
                proof_height: Height::new(0, a_height)?,
                signer: String::new(),
            }),
        )
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("timed out"), "{err:#}");
    Ok(())
}

#[tokio::test]
async fn timeout_with_non_membership_proof() -> Result<()> {
    let (mut a, mut b) = pair().await?;
    let timeout = NOW as u64 + 60;

    let mut state = a.begin();
    state
        .send_packet_v2_check(&a.client, timeout, &payload(b"late"), time(NOW))
        .await?;
    let packet = state
        .send_packet_v2_execute(&a.client, timeout, payload(b"late"))
        .await?;
    a.commit(state).await?;

    // B never receives; time passes on B. A learns B's root at a time past
    // the timeout and proves the receipt is absent.
    let mut state = b.begin();
    state.put_raw("unrelated".into(), b"tick".to_vec());
    b.commit(state).await?;
    let (value, absence) = b
        .proof(&packet_receipt_key(&packet.destination_client, packet.sequence))
        .await?;
    assert!(value.is_none());
    let b_height = b.height - 1;

    let mut state = a.begin();
    // Not yet: consensus timestamp before the timeout.
    a.trust(&mut state, b.root().await?, b_height, time(NOW + 30)).await?;
    let msg = |proof: MerkleProof| {
        IbcRelay::TimeoutV2(MsgTimeoutV2 {
            packet: packet.clone(),
            proof_unreceived: proof,
            proof_height: Height::new(0, b_height).unwrap(),
            signer: String::new(),
        })
    };
    let err = a.relay(&mut state, msg(absence.clone())).await.unwrap_err();
    assert!(format!("{err:#}").contains("has not timed out"), "{err:#}");

    a.trust(&mut state, b.root().await?, b_height, time(NOW + 120)).await?;
    a.relay(&mut state, msg(absence)).await?;
    assert_eq!(
        state.get_raw(&timeout_key(1)).await?.as_deref(),
        Some(b"timed out".as_slice())
    );
    assert!(state
        .get_packet_commitment_v2(a.client.as_str(), 1)
        .await?
        .is_none());
    // Second timeout: nothing left to time out.
    let (_, absence) = b
        .proof(&packet_receipt_key(&packet.destination_client, packet.sequence))
        .await?;
    let err = a.relay(&mut state, msg(absence)).await.unwrap_err();
    assert!(format!("{err:#}").contains("commitment not found"), "{err:#}");
    Ok(())
}

#[tokio::test]
async fn send_checks_timeout_window() -> Result<()> {
    let (mut a, _b) = pair().await?;
    let state = a.begin();
    let now = NOW as u64;
    for (timeout, what) in [
        (now, "not after"),
        (now + 86401, "more than"),
    ] {
        let err = state
            .send_packet_v2_check(&a.client, timeout, &payload(b"x"), time(NOW))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains(what), "{timeout}: {err:#}");
    }
    let err = state
        .send_packet_v2_check(
            &"07-tendermint-9".parse()?,
            now + 60,
            &payload(b"x"),
            time(NOW),
        )
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("no registered counterparty"), "{err:#}");
    Ok(())
}
