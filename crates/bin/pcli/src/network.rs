use anyhow::Context;
use decaf377_rdsa::{Signature, SpendAuth};
use futures::{FutureExt, TryStreamExt};
use penumbra_sdk_governance::ValidatorVoteBody;
use penumbra_sdk_proto::{
    custody::v1::{AuthorizeValidatorDefinitionRequest, AuthorizeValidatorVoteRequest},
    util::tendermint_proxy::v1::tendermint_proxy_service_client::TendermintProxyServiceClient,
    view::v1::broadcast_transaction_response::Status as BroadcastStatus,
    DomainType,
};
use penumbra_sdk_stake::validator::Validator;
use penumbra_sdk_transaction::{txhash::TransactionId, Transaction, TransactionPlan};
use penumbra_sdk_view::{ViewClient, ViewServer};
use std::{fs, future::Future};
use tonic::transport::Channel;
use tracing::instrument;

use crate::App;

impl App {
    /// Whether the user asked for `--output json`.
    pub fn json_output(&self) -> bool {
        self.output == Some(crate::opt::OutputFormat::Json)
    }

    pub async fn build_and_submit_transaction(
        &mut self,
        plan: TransactionPlan,
    ) -> anyhow::Result<TransactionId> {
        let json = self.json_output();
        let asset_cache = self.view().assets().await?;
        let fee = &plan.transaction_parameters.fee.0;
        let fee_fmt = fee.format(&asset_cache);
        progress(
            json,
            format_args!("including transaction fee of {fee_fmt}..."),
        );
        if json {
            // `fee` keeps the exact string the text form prints; `amount` and
            // `denom` are the raw base units, so a caller can add the fee up
            // instead of parsing `1.727mpenumbra`.
            let denom = asset_cache
                .get(&fee.asset_id)
                .map(|denom| denom.to_string())
                .unwrap_or_else(|| fee.asset_id.to_string());
            println!(
                "{}",
                serde_json::json!({
                    "event": "fee",
                    "fee": fee_fmt,
                    "amount": u128::from(fee.amount).to_string(),
                    "denom": denom,
                })
            );
        }

        let transaction = self.build_transaction(plan).await?;
        self.submit_transaction(transaction).await
    }

    pub fn build_transaction(
        &mut self,
        plan: TransactionPlan,
    ) -> impl Future<Output = anyhow::Result<Transaction>> + '_ {
        let json = self.json_output();
        progress(
            json,
            format_args!(
                "building transaction [{} actions, {} proofs]...",
                plan.actions.len(),
                plan.num_proofs(),
            ),
        );
        let start = std::time::Instant::now();
        let tx = penumbra_sdk_wallet::build_transaction(
            &self.config.full_viewing_key,
            self.view.as_mut().expect("view service initialized"),
            &mut self.custody,
            plan,
        );
        async move {
            let tx = tx.await?;
            let elapsed = start.elapsed();
            progress(
                json,
                format_args!(
                    "finished proving in {}.{:03} seconds [{} actions, {} proofs, {} bytes]",
                    elapsed.as_secs(),
                    elapsed.subsec_millis(),
                    tx.actions().count(),
                    tx.num_proofs(),
                    tx.encode_to_vec().len()
                ),
            );
            Ok(tx)
        }
    }

    pub async fn sign_validator_definition(
        &mut self,
        validator_definition: Validator,
    ) -> anyhow::Result<Signature<SpendAuth>> {
        let request = AuthorizeValidatorDefinitionRequest {
            validator_definition: Some(validator_definition.into()),
            pre_authorizations: vec![],
        };
        self.custody
            .authorize_validator_definition(request)
            .await?
            .into_inner()
            .validator_definition_auth
            .ok_or_else(|| anyhow::anyhow!("missing validator definition auth"))?
            .try_into()
    }

    pub async fn sign_validator_vote(
        &mut self,
        validator_vote: ValidatorVoteBody,
    ) -> anyhow::Result<Signature<SpendAuth>> {
        let request = AuthorizeValidatorVoteRequest {
            validator_vote: Some(validator_vote.into()),
            pre_authorizations: vec![],
        };
        // Use the separate governance custody service, if one is configured, to sign the validator
        // vote. This allows the governance custody service to have a different key than the main
        // custody, which is useful for validators who want to have a separate key for voting.
        self.governance_custody // VERY IMPORTANT: use governance custody here!
            .authorize_validator_vote(request)
            .await?
            .into_inner()
            .validator_vote_auth
            .ok_or_else(|| anyhow::anyhow!("missing validator vote auth"))?
            .try_into()
    }

    /// Submits a transaction to the network.
    pub async fn submit_transaction(
        &mut self,
        transaction: Transaction,
    ) -> anyhow::Result<TransactionId> {
        let json = self.json_output();
        if let Some(file) = &self.save_transaction_here_instead {
            progress(
                json,
                format_args!(
                    "saving transaction to disk, path: {}",
                    file.to_string_lossy()
                ),
            );
            fs::write(file, &serde_json::to_vec(&transaction)?)?;
            let id = transaction.id();
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "saved",
                        "path": file.to_string_lossy(),
                        "tx_id": id.to_string(),
                    })
                );
            }
            return Ok(id);
        }

        progress(
            json,
            format_args!("broadcasting transaction and awaiting confirmation..."),
        );
        let mut rsp = self.view().broadcast_transaction(transaction, true).await?;

        let id = async move {
            while let Some(rsp) = rsp.try_next().await? {
                match rsp.status {
                    Some(status) => match status {
                        BroadcastStatus::BroadcastSuccess(bs) => {
                            progress(
                                json,
                                format_args!(
                                    "transaction broadcast successfully: {}",
                                    TransactionId::try_from(
                                        bs.id.expect("detected transaction missing id")
                                    )?
                                ),
                            );
                        }
                        BroadcastStatus::Confirmed(c) => {
                            let id: TransactionId =
                                c.id.expect("detected transaction missing id").try_into()?;
                            if c.detection_height != 0 {
                                progress(
                                    json,
                                    format_args!(
                                        "transaction confirmed and detected: {} @ height {}",
                                        id, c.detection_height
                                    ),
                                );
                            } else {
                                progress(
                                    json,
                                    format_args!("transaction confirmed and detected: {}", id),
                                );
                            }
                            if json {
                                let mut row = serde_json::json!({
                                    "event": "confirmed",
                                    "tx_id": id.to_string(),
                                });
                                if c.detection_height != 0 {
                                    row["height"] = serde_json::json!(c.detection_height);
                                }
                                println!("{row}");
                            }
                            return Ok(id);
                        }
                    },
                    None => {
                        // No status is unexpected behavior
                        return Err(anyhow::anyhow!(
                            "empty BroadcastTransactionResponse message"
                        ));
                    }
                }
            }

            Err(anyhow::anyhow!(
                "should have received BroadcastTransaction status or error"
            ))
        }
        .boxed()
        .await
        .context("error broadcasting transaction")?;

        Ok(id)
    }

    /// Submits a transaction to the network, returning `Ok` as soon as the
    /// transaction has been submitted, rather than waiting for confirmation.
    #[instrument(skip(self, transaction))]
    pub async fn submit_transaction_unconfirmed(
        &mut self,
        transaction: Transaction,
    ) -> anyhow::Result<()> {
        let json = self.json_output();
        progress(
            json,
            format_args!("broadcasting transaction without confirmation..."),
        );
        self.view()
            .broadcast_transaction(transaction, false)
            .await?;

        Ok(())
    }

    /// Convenience method for obtaining a `tonic::Channel` for the remote
    /// `pd` endpoint, as configured for `pcli`.
    pub async fn pd_channel(&self) -> anyhow::Result<Channel> {
        ViewServer::get_pd_channel(self.config.grpc_url.clone())
            .await
            .context(format!("could not connect to {}", self.config.grpc_url))
    }

    pub async fn tendermint_proxy_client(
        &self,
    ) -> anyhow::Result<TendermintProxyServiceClient<Channel>> {
        let channel = self.pd_channel().await?;
        Ok(TendermintProxyServiceClient::new(channel))
    }
}

/// Prints a progress, prompt, or status line.
///
/// Normally this goes to stdout, byte for byte as it always did, but when the
/// user asked for JSON it goes to stderr instead: in that mode stdout carries
/// one JSON object per line and nothing else.
pub(crate) fn progress(json: bool, msg: std::fmt::Arguments<'_>) {
    if json {
        eprintln!("{msg}");
    } else {
        println!("{msg}");
    }
}
