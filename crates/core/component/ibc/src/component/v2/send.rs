//! Sending IBC v2 packets. There is deliberately no relayer-style
//! `MsgSendPacket` action: an `IbcRelay` action carries no value balance, so a
//! generic send with a `transfer` payload would commit a packet the
//! counterparty mints against with nothing escrowed. Value-carrying actions
//! (`Ics20Withdrawal` with a source client) call these traits directly.

use anyhow::{Context, Result};
use async_trait::async_trait;
use cnidarium::{StateRead, StateWrite};
use ibc_types::core::client::ClientId;
use tendermint::Time;

use crate::{
    component::client::StateReadExt as _,
    v2::{
        commitment::{commit_packet, MAX_TIMEOUT_DELTA_SECS},
        Packet, Payload,
    },
};

use super::{
    events,
    proof::unix_seconds,
    state::{StateReadExt as _, StateWriteExt as _},
};

#[async_trait]
pub trait SendPacketV2Read: StateRead {
    /// Everything that can fail about a send, without writing.
    async fn send_packet_v2_check(
        &self,
        source_client: &ClientId,
        timeout_timestamp: u64,
        payload: &Payload,
        now: Time,
    ) -> Result<()> {
        payload.validate_basic()?;
        let counterparty = self
            .get_counterparty(source_client.as_str())
            .await?
            .ok_or_else(|| anyhow::anyhow!("client {source_client} has no registered counterparty"))?;
        anyhow::ensure!(
            self.get_next_sequence_send_v2(source_client.as_str()).await? != 0,
            "client {source_client} has no send sequence"
        );

        let client_state = self.get_client_state(source_client).await?;
        anyhow::ensure!(!client_state.is_frozen(), "client {source_client} is frozen");
        let latest_consensus_state = self
            .get_verified_consensus_state(&client_state.latest_height(), source_client)
            .await?;
        let elapsed = now.duration_since(latest_consensus_state.timestamp)?;
        anyhow::ensure!(!client_state.expired(elapsed), "client {source_client} is expired");

        // ibc-go `sendPacket`: now < timeout <= now + MaxTimeoutDelta, and the
        // packet must not already be timed out on the counterparty as far as
        // our client knows.
        let now_secs = unix_seconds(now);
        anyhow::ensure!(
            timeout_timestamp > now_secs,
            "timeout {timeout_timestamp} is not after the current block time {now_secs}"
        );
        anyhow::ensure!(
            timeout_timestamp <= now_secs + MAX_TIMEOUT_DELTA_SECS,
            "timeout {timeout_timestamp} is more than {MAX_TIMEOUT_DELTA_SECS}s after the current block time {now_secs}"
        );
        let counterparty_secs = unix_seconds(latest_consensus_state.timestamp);
        anyhow::ensure!(
            timeout_timestamp > counterparty_secs,
            "timeout {timeout_timestamp} is not after the counterparty's latest timestamp {counterparty_secs}"
        );
        let _ = counterparty;
        Ok(())
    }
}

impl<T: StateRead + ?Sized> SendPacketV2Read for T {}

#[async_trait]
pub trait SendPacketV2Write: StateWrite {
    /// Assign the sequence, store the commitment and emit `send_packet`.
    /// Assumes `send_packet_v2_check` passed.
    async fn send_packet_v2_execute(
        &mut self,
        source_client: &ClientId,
        timeout_timestamp: u64,
        payload: Payload,
    ) -> Result<Packet> {
        let counterparty = self
            .get_counterparty(source_client.as_str())
            .await?
            .context("counterparty must be registered (checked)")?;
        let sequence = self.get_next_sequence_send_v2(source_client.as_str()).await?;
        anyhow::ensure!(sequence != 0, "send sequence not initialised");
        self.put_next_sequence_send_v2(source_client.as_str(), sequence + 1);

        let packet = Packet {
            sequence,
            source_client: source_client.to_string(),
            destination_client: counterparty.client_id,
            timeout_timestamp,
            payloads: vec![payload],
        };
        self.put_packet_commitment_v2(source_client.as_str(), sequence, commit_packet(&packet));
        self.record(events::send_packet(&packet));
        Ok(packet)
    }
}

impl<T: StateWrite + ?Sized> SendPacketV2Write for T {}
