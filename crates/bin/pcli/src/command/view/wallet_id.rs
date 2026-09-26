use anyhow::Result;

use crate::opt::OutputFormat;
use penumbra_sdk_keys::FullViewingKey;

#[derive(Debug, clap::Parser)]
pub struct WalletIdCmd {}

impl WalletIdCmd {
    /// Determine if this command requires a network sync before it executes.
    pub fn offline(&self) -> bool {
        true
    }

    pub fn exec(&self, fvk: &FullViewingKey, output: OutputFormat) -> Result<()> {
        let wallet_id = fvk.wallet_id();
        if output == OutputFormat::Json {
            println!(
                "{}",
                serde_json::json!({ "wallet_id": wallet_id.to_string() })
            );
        } else {
            println!("{wallet_id}");
        }

        Ok(())
    }
}
