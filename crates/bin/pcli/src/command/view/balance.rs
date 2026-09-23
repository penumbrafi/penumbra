use anyhow::Result;
use comfy_table::{presets, Table};

use crate::opt::OutputFormat;
use penumbra_sdk_asset::Value;
use penumbra_sdk_keys::AddressView;
use penumbra_sdk_sct::CommitmentSource;
use penumbra_sdk_view::ViewClient;

#[derive(Debug, clap::Args)]
pub struct BalanceCmd {
    #[clap(long)]
    /// If set, prints the value of each note individually.
    pub by_note: bool,
}

impl BalanceCmd {
    pub fn offline(&self) -> bool {
        false
    }

    pub async fn exec<V: ViewClient>(&self, view: &mut V, output: OutputFormat) -> Result<()> {
        let asset_cache = view.assets().await?;

        let notes = view.unspent_notes_by_account_and_asset().await?;

        if self.by_note {
            let rows = notes
                .iter()
                .flat_map(|(index, notes_by_asset)| {
                    // Include each note individually:
                    notes_by_asset.iter().flat_map(|(asset, notes)| {
                        notes.iter().map(|record| {
                            (
                                *index,
                                asset.value(record.note.amount()),
                                record.source.clone(),
                                record.return_address.clone(),
                            )
                        })
                    })
                })
                /* Don't exclude withdrawn LPNFTs in by_note, which is a more precise view.
                // Exclude withdrawn LPNFTs.
                .filter(|(_, value, _, _)| match asset_cache.get(&value.asset_id) {
                    None => true,
                    Some(denom) => !denom.is_withdrawn_position_nft(),
                });
                 */
                ;

            if output == OutputFormat::Json {
                for (index, value, source, return_address) in rows {
                    println!(
                        "{}",
                        json_row(
                            index,
                            &value,
                            &asset_cache,
                            Some(&format_source(&source)),
                            Some(&format_return_address(&return_address)),
                        )
                    );
                }
                return Ok(());
            }

            // Initialize the table
            let mut table = Table::new();
            table.load_preset(presets::NOTHING);
            table.set_header(vec!["Account", "Value", "Source", "Sender"]);

            for (index, value, source, return_address) in rows {
                table.add_row(vec![
                    format!("# {}", index),
                    value.format(&asset_cache),
                    format_source(&source),
                    format_return_address(&return_address),
                ]);
            }

            println!("{table}");

            return Ok(());
        } else {
            let rows = notes
                .iter()
                .flat_map(|(index, notes_by_asset)| {
                    // Sum the notes for each asset:
                    notes_by_asset.iter().map(|(asset, notes)| {
                        let sum: u128 = notes
                            .iter()
                            .map(|record| u128::from(record.note.amount()))
                            .sum();
                        (*index, asset.value(sum.into()))
                    })
                })
                // Exclude withdrawn LPNFTs and withdrawn auction NFTs.
                .filter(|(_, value)| match asset_cache.get(&value.asset_id) {
                    None => true,
                    Some(denom) => {
                        !denom.is_withdrawn_position_nft() && !denom.is_withdrawn_auction_nft()
                    }
                });

            if output == OutputFormat::Json {
                for (index, value) in rows {
                    println!("{}", json_row(index, &value, &asset_cache, None, None));
                }
                return Ok(());
            }

            let mut table = Table::new();
            table.load_preset(presets::NOTHING);
            table.set_header(vec!["Account", "Amount"]);

            for (index, value) in rows {
                table.add_row(vec![format!("# {}", index), value.format(&asset_cache)]);
            }

            println!("{table}");

            return Ok(());
        }
    }
}

/// One balance row as JSON: `{"account":N,"amount":"<raw u128>","denom":"…"}`.
///
/// `amount` is the raw integer, deliberately *not* `Value::format(&asset_cache)`,
/// which prints display units with a suffix (`1.727mpenumbra`) — a string whose
/// number is not the balance, and which every caller then has to un-format.
/// `by_note` rows carry the note's source and sender too.
fn json_row(
    account: u32,
    value: &Value,
    asset_cache: &penumbra_sdk_asset::asset::Cache,
    source: Option<&str>,
    sender: Option<&str>,
) -> serde_json::Value {
    let denom = asset_cache
        .get(&value.asset_id)
        .map(|denom| denom.to_string())
        .unwrap_or_else(|| value.asset_id.to_string());
    let mut row = serde_json::json!({
        "account": account,
        "amount": u128::from(value.amount).to_string(),
        "denom": denom,
    });
    if let Some(source) = source {
        row["source"] = serde_json::Value::String(source.to_owned());
    }
    if let Some(sender) = sender {
        row["sender"] = serde_json::Value::String(sender.to_owned());
    }
    row
}

fn format_source(source: &CommitmentSource) -> String {
    match source {
        CommitmentSource::Genesis => "Genesis".to_owned(),
        CommitmentSource::Transaction { id: None } => "Tx (Unknown)".to_owned(),
        CommitmentSource::Transaction { id: Some(id) } => format!("Tx {}", hex::encode(&id[..])),
        CommitmentSource::FundingStreamReward { epoch_index } => {
            format!("Funding Stream (Epoch {})", epoch_index)
        }
        CommitmentSource::CommunityPoolOutput => format!("CommunityPoolOutput"),
        CommitmentSource::Ics20Transfer {
            packet_seq,
            channel_id,
            sender,
        } => format!(
            "ICS20 packet {} via {} from {}",
            packet_seq, channel_id, sender
        ),
        CommitmentSource::LiquidityTournamentReward { epoch, tx_hash } => {
            format!(
                "Liquidity tournament reward (Epoch {}, Tx {})",
                epoch, tx_hash
            )
        }
    }
}

fn format_return_address(return_address: &Option<penumbra_sdk_keys::AddressView>) -> String {
    match return_address {
        None => "Unknown".to_owned(),
        Some(AddressView::Opaque { address }) => address.display_short_form(),
        Some(AddressView::Decoded { index, .. }) => {
            if index.is_ephemeral() {
                format!("[account {} (IBC deposit address)]", index.account)
            } else {
                format!("[account {}]", index.account)
            }
        }
    }
}
