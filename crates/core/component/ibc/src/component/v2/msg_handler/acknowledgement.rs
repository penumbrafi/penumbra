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
            proof::ProofVerifierV2 as _,
            state::{StateReadExt as _, StateWriteExt as _},
        },
        HostInterface, MsgHandler,
    },
    v2::{
        commitment::{
            build_merkle_path, commit_acknowledgement, commit_packet,
            packet_acknowledgement_key,
        },
        MsgAcknowledgement,
    },
};

#[async_trait]
impl MsgHandler for MsgAcknowledgement {
    async fn check_stateless<AH: AppHandlerCheck>(&self) -> Result<()> {
        self.packet.validate_basic()?;
        self.acknowledgement.validate_basic()
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

        // We must have sent it and not yet cleared it.
        let stored = state
            .get_packet_commitment_v2(&packet.source_client, packet.sequence)
            .await?
            .ok_or_else(|| anyhow::anyhow!("packet commitment not found"))?;
        anyhow::ensure!(
            stored == commit_packet(packet),
            "packet commitment does not match the stored commitment"
        );

        let path = build_merkle_path(
            &counterparty.merkle_prefix,
            &packet_acknowledgement_key(&packet.destination_client, packet.sequence),
        )?;
        state
            .verify_membership_v2(
                &source_client,
                &self.proof_height,
                &self.proof_acked,
                &path,
                &commit_acknowledgement(&self.acknowledgement.app_acknowledgements),
            )
            .await
            .context("acknowledgement proof failed")?;

        let payload = packet.payload()?;
        anyhow::ensure!(
            AH::handles_port_v2(&payload.source_port),
            "no v2 application for port {}",
            payload.source_port
        );
        AH::acknowledge_payload_v2(
            &mut state,
            packet,
            payload,
            &self.acknowledgement.app_acknowledgements[0],
        )
        .await
        .context("v2 application failed to process acknowledgement")?;

        state.delete_packet_commitment_v2(&packet.source_client, packet.sequence);
        state.record(events::acknowledge_packet(packet, &self.acknowledgement));
        Ok(())
    }
}
