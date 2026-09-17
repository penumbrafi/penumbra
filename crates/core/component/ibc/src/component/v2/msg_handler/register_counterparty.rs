use anyhow::Result;
use async_trait::async_trait;
use cnidarium::StateWrite;

use crate::{
    component::{
        app_handler::{AppHandlerCheck, AppHandlerExecute},
        client::StateReadExt as _,
        v2::{
            events,
            state::{StateReadExt as _, StateWriteExt as _},
        },
        HostInterface, MsgHandler,
    },
    v2::{proto::CounterpartyInfo, MsgRegisterCounterparty},
};

#[async_trait]
impl MsgHandler for MsgRegisterCounterparty {
    async fn check_stateless<AH: AppHandlerCheck>(&self) -> Result<()> {
        self.validate_basic()
    }

    /// ibc-go requires `signer == client creator`. Penumbra has no signer
    /// identity on relay actions and client creation is permissionless, so a
    /// permissionless one-shot registration could be front-run to mis-pair a
    /// fresh client forever. Instead, registration is accepted only in the
    /// same transaction as the `CreateClient` it pairs.
    async fn try_execute<
        S: StateWrite,
        AH: AppHandlerCheck + AppHandlerExecute + crate::component::v2::AppHandlerV2,
        HI: HostInterface,
    >(
        &self,
        mut state: S,
    ) -> Result<()> {
        tracing::debug!(msg = ?self);
        let client_id = self.client_id.as_str();

        // The client must exist (this also rejects unknown client types).
        state.get_client_state(&self.client_id).await?;

        anyhow::ensure!(
            state.get_counterparty(client_id).await?.is_none(),
            "client {client_id} already has a registered counterparty"
        );
        anyhow::ensure!(
            state.clients_created_in_tx().contains(&self.client_id),
            "RegisterCounterparty for {client_id} must be in the same transaction as its CreateClient"
        );

        state.put_counterparty(
            client_id,
            CounterpartyInfo {
                merkle_prefix: self.counterparty_merkle_prefix.clone(),
                client_id: self.counterparty_client_id.clone(),
            },
        );
        // ibc-go initialises the send sequence to 1 here.
        state.put_next_sequence_send_v2(client_id, 1);
        state.record(events::register_counterparty(
            client_id,
            &self.counterparty_client_id,
        ));
        Ok(())
    }
}
