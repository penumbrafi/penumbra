use anyhow::Result;
use async_trait::async_trait;
use cnidarium::{StateRead, StateWrite};
use ibc_types::core::client::ClientId;
use penumbra_sdk_proto::{StateReadProto, StateWriteProto};

use crate::v2::{
    commitment::{packet_acknowledgement_key, packet_commitment_key, packet_receipt_key},
    proto::CounterpartyInfo,
};

use super::state_key;

#[async_trait]
pub trait StateReadExt: StateRead {
    async fn get_counterparty(&self, client_id: &str) -> Result<Option<CounterpartyInfo>> {
        self.get_proto(&state_key::counterparty(client_id)).await
    }

    /// `0` means the counterparty has not been registered.
    async fn get_next_sequence_send_v2(&self, client_id: &str) -> Result<u64> {
        Ok(self
            .get_proto::<u64>(&state_key::next_sequence_send(client_id))
            .await?
            .unwrap_or(0))
    }

    async fn get_packet_commitment_v2(
        &self,
        client_id: &str,
        sequence: u64,
    ) -> Result<Option<Vec<u8>>> {
        self.get_raw_bytes(&state_key::commitment(&packet_commitment_key(
            client_id, sequence,
        )))
        .await
    }

    async fn has_packet_receipt_v2(&self, client_id: &str, sequence: u64) -> Result<bool> {
        Ok(self
            .get_raw_bytes(&state_key::commitment(&packet_receipt_key(
                client_id, sequence,
            )))
            .await?
            .is_some())
    }

    async fn get_packet_acknowledgement_v2(
        &self,
        client_id: &str,
        sequence: u64,
    ) -> Result<Option<Vec<u8>>> {
        self.get_raw_bytes(&state_key::commitment(&packet_acknowledgement_key(
            client_id, sequence,
        )))
        .await
    }

    /// Clients created earlier in the current transaction.
    fn clients_created_in_tx(&self) -> Vec<ClientId> {
        self.object_get::<Vec<ClientId>>(state_key::CLIENTS_CREATED_IN_TX)
            .unwrap_or_default()
    }
}

impl<T: StateRead + ?Sized> StateReadExt for T {}

#[async_trait]
pub trait StateWriteExt: StateWrite + StateReadExt {
    fn put_counterparty(&mut self, client_id: &str, info: CounterpartyInfo) {
        self.put_proto(state_key::counterparty(client_id), info);
    }

    fn put_next_sequence_send_v2(&mut self, client_id: &str, sequence: u64) {
        self.put_proto::<u64>(state_key::next_sequence_send(client_id), sequence);
    }

    fn put_packet_commitment_v2(&mut self, client_id: &str, sequence: u64, commitment: [u8; 32]) {
        self.put_raw_bytes(
            state_key::commitment(&packet_commitment_key(client_id, sequence)),
            commitment.to_vec(),
        );
    }

    fn delete_packet_commitment_v2(&mut self, client_id: &str, sequence: u64) {
        self.delete_bytes(state_key::commitment(&packet_commitment_key(
            client_id, sequence,
        )));
    }

    /// Any non-zero value works; only non-membership is ever proved. We store
    /// the packet commitment so the receipt is self-describing.
    fn put_packet_receipt_v2(&mut self, client_id: &str, sequence: u64, packet_commitment: [u8; 32]) {
        self.put_raw_bytes(
            state_key::commitment(&packet_receipt_key(client_id, sequence)),
            packet_commitment.to_vec(),
        );
    }

    fn put_packet_acknowledgement_v2(
        &mut self,
        client_id: &str,
        sequence: u64,
        ack_commitment: [u8; 32],
    ) {
        self.put_raw_bytes(
            state_key::commitment(&packet_acknowledgement_key(client_id, sequence)),
            ack_commitment.to_vec(),
        );
    }

    /// Called at the start of every transaction so that a client created in
    /// one transaction cannot be paired by another (front-running guard).
    fn reset_clients_created_in_tx(&mut self) {
        self.object_put(state_key::CLIENTS_CREATED_IN_TX, Vec::<ClientId>::new());
    }

    fn mark_client_created_in_tx(&mut self, client_id: ClientId) {
        let mut created = self.clients_created_in_tx();
        created.push(client_id);
        self.object_put(state_key::CLIENTS_CREATED_IN_TX, created);
    }
}

impl<T: StateWrite + ?Sized> StateWriteExt for T {}
