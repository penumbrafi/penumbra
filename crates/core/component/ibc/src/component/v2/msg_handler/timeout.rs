use anyhow::{Context, Result};
use async_trait::async_trait;
use cnidarium::StateWrite;
use ibc_types::core::client::ClientId;

use crate::{
    component::{
        app_handler::{AppHandlerCheck, AppHandlerExecute},
        v2::{
            app_handler::AppHandlerV2,
            events,
            proof::{unix_seconds, ProofVerifierV2 as _},
            state::{StateReadExt as _, StateWriteExt as _},
        },
        HostInterface, MsgHandler,
    },
    v2::{
        commitment::{build_merkle_path, commit_packet, packet_receipt_key},
        MsgTimeout,
    },
};

#[async_trait]
impl MsgHandler for MsgTimeout {
    async fn check_stateless<AH: AppHandlerCheck>(&self) -> Result<()> {
        self.packet.validate_basic()
    }

    async fn try_execute<
        S: StateWrite,
        AH: AppHandlerCheck + AppHandlerExecute + AppHandlerV2,
        HI: HostInterface,
    >(
        &self,
        mut state: S,
    ) -> Result<()> {
        tracing::debug!(msg = ?self);
        let packet = &self.packet;
        let source_client: ClientId = packet
            .source_client
            .parse()
            .context("source client is not a Penumbra client id")?;

        let counterparty = state
            .get_counterparty(&packet.source_client)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("client {} has no registered counterparty", packet.source_client)
            })?;
        anyhow::ensure!(
            counterparty.client_id == packet.destination_client,
            "packet destination client {} does not match counterparty {} of {}",
            packet.destination_client,
            counterparty.client_id,
            packet.source_client
        );

        let stored = state
            .get_packet_commitment_v2(&packet.source_client, packet.sequence)
            .await?
            .ok_or_else(|| anyhow::anyhow!("packet commitment not found"))?;
        anyhow::ensure!(
            stored == commit_packet(packet),
            "packet commitment does not match the stored commitment"
        );

        // The counterparty must have passed the timeout at the proof height.
        let proof_secs = unix_seconds(
            state
                .consensus_timestamp_v2(&source_client, &self.proof_height)
                .await?,
        );
        anyhow::ensure!(
            proof_secs >= packet.timeout_timestamp,
            "packet has not timed out on the counterparty: proof timestamp {proof_secs} < timeout {}",
            packet.timeout_timestamp
        );

        // ... and must not have written a receipt.
        let path = build_merkle_path(
            &counterparty.merkle_prefix,
            &packet_receipt_key(&packet.destination_client, packet.sequence),
        )?;
        state
            .verify_non_membership_v2(
                &source_client,
                &self.proof_height,
                &self.proof_unreceived,
                &path,
            )
            .await
            .context("packet receipt absence proof failed")?;

        let payload = packet.payload()?;
        anyhow::ensure!(
            AH::handles_port_v2(&payload.source_port),
            "no v2 application for port {}",
            payload.source_port
        );
        AH::timeout_payload_v2(&mut state, packet, payload)
            .await
            .context("v2 application failed to process timeout")?;

        state.delete_packet_commitment_v2(&packet.source_client, packet.sequence);
        state.record(events::timeout_packet(packet));
        Ok(())
    }
}
