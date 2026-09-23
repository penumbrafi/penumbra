use anyhow::Result;
use comfy_table::{presets, Table};

use crate::opt::OutputFormat;
use penumbra_sdk_keys::FullViewingKey;
use penumbra_sdk_transaction::MemoView;
use penumbra_sdk_view::ViewClient;

#[derive(Debug, clap::Args)]
pub struct TransactionHashesCmd {
    #[clap(short, long)]
    pub start_height: Option<u64>,
    #[clap(short, long)]
    pub end_height: Option<u64>,
}

impl TransactionHashesCmd {
    pub fn offline(&self) -> bool {
        false
    }

    pub async fn exec<V: ViewClient>(
        &self,
        _fvk: &FullViewingKey,
        view: &mut V,
        output: OutputFormat,
    ) -> Result<()> {
        // Initialize the table

        let mut table = Table::new();
        table.load_preset(presets::NOTHING);

        let txs = view
            .transaction_info(self.start_height, self.end_height)
            .await?;

        table.set_header(vec!["Height", "Transaction Hash", "Return Address", "Memo"]);

        for tx_info in txs {
            let (return_address, memo) = match tx_info.view.body_view.memo_view {
                Some(MemoView::Visible { plaintext, .. }) => (
                    plaintext.return_address.address().display_short_form(),
                    plaintext.text,
                ),
                _ => (String::new(), String::new()),
            };
            if output == OutputFormat::Json {
                // One object per transaction: `{"height":N,"tx_hash":"<64 hex>","return_address":"…","memo":"…"}`.
                println!(
                    "{}",
                    serde_json::json!({
                        "height": tx_info.height,
                        "tx_hash": hex::encode(tx_info.id),
                        "return_address": return_address,
                        "memo": memo,
                    })
                );
                continue;
            }
            table.add_row(vec![
                format!("{}", tx_info.height),
                format!("{}", hex::encode(tx_info.id)),
                format!("{}", return_address),
                format!("{}", memo),
            ]);
        }

        if output != OutputFormat::Json {
            println!("{table}");
        }

        Ok(())
    }
}
