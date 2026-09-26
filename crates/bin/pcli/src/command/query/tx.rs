use anyhow::Result;
use colored_json::prelude::*;
use penumbra_sdk_proto::{util::tendermint_proxy::v1::GetTxRequest, DomainType};
use penumbra_sdk_transaction::Transaction;

use crate::App;

use super::OutputFormat;

/// Queries the chain for a transaction by hash.
#[derive(Debug, clap::Args)]
pub struct Tx {
    /// The hex-formatted transaction hash to query.
    hash: String,
}

impl Tx {
    pub async fn exec(&self, app: &mut App) -> Result<()> {
        // This command has never had a text form, so JSON is its default and
        // `--output` only ever narrows it (`base64` for the raw bytes).
        let output = app.output_or(OutputFormat::Json);

        let mut client = app.tendermint_proxy_client().await?;

        let rsp = client
            .get_tx(GetTxRequest {
                hash: hex::decode(self.hash.clone())?,
                prove: false,
            })
            .await?;

        let rsp = rsp.into_inner();
        let tx = Transaction::decode(rsp.tx.as_slice())?;

        match output {
            OutputFormat::Json => {
                let tx_json = serde_json::to_string_pretty(&tx)?;
                println!("{}", tx_json.to_colored_json_auto()?);
            }
            OutputFormat::Base64 => {
                use base64::{display::Base64Display, engine::general_purpose::STANDARD};
                println!("{}", Base64Display::new(&rsp.tx, &STANDARD));
            }
            // No text form exists; the gate in `Command::check_output` rejects
            // it before we get here, and this keeps that honest if it moves.
            OutputFormat::Text => {
                anyhow::bail!("pcli q tx has no text form; use -o json or -o base64")
            }
        }

        Ok(())
    }
}
