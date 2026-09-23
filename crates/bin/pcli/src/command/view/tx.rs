use anyhow::{Context, Result};
use penumbra_sdk_proto::{util::tendermint_proxy::v1::GetTxRequest, DomainType};
use penumbra_sdk_transaction::{MemoView, Transaction};
use penumbra_sdk_view::{TransactionInfo, ViewClient};

use crate::command::utils;
use crate::opt::OutputFormat;
use crate::transaction_view_ext::TransactionViewExt;
use crate::App;

/// Queries the chain for a transaction by hash.
#[derive(Debug, clap::Args)]
pub struct TxCmd {
    /// The hex-formatted transaction hash to query.
    hash: String,
    /// If set, print the raw transaction view rather than a formatted table.
    #[clap(long)]
    raw: bool,
}

impl TxCmd {
    pub fn offline(&self) -> bool {
        false
    }
    pub async fn exec(&self, app: &mut App) -> Result<()> {
        let output = app.output_or(OutputFormat::Text);

        let hash = self
            .hash
            // We have to convert to uppercase because `tendermint::Hash` only accepts uppercase :(
            .to_uppercase()
            .parse()
            .context("invalid transaction hash")?;

        // Retrieve Transaction from the view service first, or else the fullnode
        let tx_info = if let Ok(tx_info) = app.view().transaction_info_by_hash(hash).await {
            tx_info
        } else {
            if output == OutputFormat::Json {
                // stdout carries the result, so the progress note goes to stderr.
                eprintln!("Transaction not found in view service, fetching from fullnode...");
            } else if !self.raw {
                println!("Transaction not found in view service, fetching from fullnode...");
            } else {
                tracing::info!("Transaction not found in view service, fetching from fullnode...");
            }
            // Fall back to fetching from fullnode
            let mut client = app.tendermint_proxy_client().await?;
            let rsp = client
                .get_tx(GetTxRequest {
                    hash: hex::decode(self.hash.clone())?,
                    prove: false,
                })
                .await?;

            let rsp = rsp.into_inner();
            let tx = Transaction::decode(rsp.tx.as_slice())?;
            let txp = Default::default();
            let txv = tx.view_from_perspective(&txp);
            let summary = txv.summary();

            TransactionInfo {
                height: rsp.height,
                id: hash,
                transaction: tx,
                perspective: txp,
                view: txv,
                summary: summary,
            }
        };

        if output == OutputFormat::Json {
            // Exactly one object on stdout, whatever `--raw` would have printed:
            // the transaction's own fields, with the fee as a raw integer plus
            // its denom, and the rendered action rows.
            let fee = tx_info.view.body_view.transaction_parameters.fee;
            let asset_cache = app.view().assets().await?;
            let mut row = serde_json::json!({
                "tx_id": tx_info.id.to_string(),
                "height": tx_info.height,
                "fee": u128::from(fee.amount()).to_string(),
                "fee_denom": utils::denom(&fee.asset_id(), &asset_cache),
                "expiration_height": tx_info.view.body_view.transaction_parameters.expiry_height,
                "actions": tx_info
                    .view
                    .action_rows()
                    .into_iter()
                    .map(|(action, description)| serde_json::json!({
                        "action": action,
                        "description": description,
                    }))
                    .collect::<Vec<_>>(),
            });
            if let Some(MemoView::Visible { plaintext, .. }) = &tx_info.view.body_view.memo_view {
                row["memo_sender"] =
                    serde_json::Value::String(plaintext.return_address.address().to_string());
                row["memo_text"] = serde_json::Value::String(plaintext.text.clone());
            }
            println!("{row}");
        } else if self.raw {
            use colored_json::prelude::*;
            println!(
                "{}",
                serde_json::to_string_pretty(&tx_info.view)?.to_colored_json_auto()?
            );
        } else {
            tx_info.view.render_terminal();
        }

        Ok(())
    }
}
