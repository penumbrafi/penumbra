use anyhow::{Context, Result};
use async_trait::async_trait;
use cnidarium::{StateDelta, StateWrite};
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
        commitment::{
            build_merkle_path, commit_acknowledgement, commit_packet, packet_commitment_key,
            universal_error_acknowledgement,
        },
        Acknowledgement, MsgRecvPacket,
    },
};

#[async_trait]
impl MsgHandler for MsgRecvPacket {
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
        let dest_client: ClientId = packet
            .destination_client
            .parse()
            .context("destination client is not a Penumbra client id")?;

        let counterparty = state
            .get_counterparty(&packet.destination_client)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("client {} has no registered counterparty", packet.destination_client)
            })?;
        anyhow::ensure!(
            counterparty.client_id == packet.source_client,
            "packet source client {} does not match counterparty {} of {}",
            packet.source_client,
            counterparty.client_id,
            packet.destination_client
        );

        // Timeouts are unix seconds; reject if the block time has reached it.
        let now_secs = unix_seconds(HI::get_block_timestamp(&state).await?);
        anyhow::ensure!(
            now_secs < packet.timeout_timestamp,
            "packet has timed out: block time {now_secs} >= timeout {}",
            packet.timeout_timestamp
        );

        anyhow::ensure!(
            !state
                .has_packet_receipt_v2(&packet.destination_client, packet.sequence)
                .await?,
            "packet {} on {} has already been received",
            packet.sequence,
            packet.destination_client
        );

        let packet_commitment = commit_packet(packet);
        let path = build_merkle_path(
            &counterparty.merkle_prefix,
            &packet_commitment_key(&packet.source_client, packet.sequence),
        )?;
        state
            .verify_membership_v2(
                &dest_client,
                &self.proof_height,
                &self.proof_commitment,
                &path,
                &packet_commitment,
            )
            .await
            .context("packet commitment proof failed")?;

        // Run the application in a sub-delta so a failing app rolls back and
        // the packet is acknowledged with the universal error ack.
        let payload = packet.payload()?;
        let app_ack: Vec<u8> = if !AH::handles_port_v2(&payload.destination_port) {
            tracing::debug!(port = %payload.destination_port, "no v2 application for port");
            universal_error_acknowledgement().to_vec()
        } else {
            let mut sub = StateDelta::new(&mut state);
            match AH::recv_payload_v2(&mut sub, packet, payload).await {
                Ok(ack) if !ack.is_empty() => {
                    let (_, sub_events) = sub.apply();
                    for event in sub_events {
                        state.record(event);
                    }
                    ack
                }
                Ok(_) => {
                    tracing::debug!("v2 application returned an empty acknowledgement");
                    universal_error_acknowledgement().to_vec()
                }
                Err(e) => {
                    tracing::debug!("v2 application failed on recv: {e:#}");
                    universal_error_acknowledgement().to_vec()
                }
            }
        };
        let ack = Acknowledgement {
            app_acknowledgements: vec![app_ack],
        };

        state.put_packet_receipt_v2(&packet.destination_client, packet.sequence, packet_commitment);
        state.put_packet_acknowledgement_v2(
            &packet.destination_client,
            packet.sequence,
            commit_acknowledgement(&ack.app_acknowledgements),
        );
        state.record(events::recv_packet(packet));
        state.record(events::write_acknowledgement(packet, &ack));
        Ok(())
    }
}
