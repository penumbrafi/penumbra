use anyhow::Result;
use comfy_table::{presets, Cell, ContentArrangement, Table};
use penumbra_sdk_asset::Value;
use penumbra_sdk_auction::auction::dutch::DutchAuction;
use penumbra_sdk_keys::FullViewingKey;
use penumbra_sdk_num::fixpoint::U128x128;
use penumbra_sdk_num::Amount;
use penumbra_sdk_proto::{core::component::auction::v1 as pb_auction, DomainType, Name};
use penumbra_sdk_view::ViewClient;

use crate::command::query::auction::render_dutch_auction;
use crate::opt::OutputFormat;

#[derive(Debug, clap::Args)]
pub struct AuctionCmd {
    #[clap(long)]
    /// If set, includes the inactive auctions as well.
    pub include_inactive: bool,
    /// If set, make the view server query an RPC and pcli render the full auction state
    #[clap(long, default_value_t = true)]
    pub query_latest_state: bool,
}

impl AuctionCmd {
    pub fn offline(&self) -> bool {
        false
    }

    pub async fn exec<V: ViewClient>(
        &self,
        view_client: &mut V,
        _fvk: &FullViewingKey,
        output: OutputFormat,
    ) -> Result<()> {
        let auctions: Vec<(
            penumbra_sdk_auction::auction::AuctionId,
            penumbra_sdk_view::SpendableNoteRecord,
            u64,
            Option<pbjson_types::Any>,
            Vec<penumbra_sdk_dex::lp::position::Position>,
        )> = view_client
            .auctions(None, self.include_inactive, self.query_latest_state)
            .await?;

        for (auction_id, _, local_seq, maybe_auction_state, positions) in auctions.into_iter() {
            if let Some(pb_auction_state) = maybe_auction_state {
                if pb_auction_state.type_url == pb_auction::DutchAuction::type_url() {
                    let dutch_auction = DutchAuction::decode(pb_auction_state.value)
                        .expect("no deserialization error");
                    let asset_cache = view_client.assets().await?;
                    if output == OutputFormat::Json {
                        println!(
                            "{}",
                            dutch_auction_json(
                                &asset_cache,
                                &dutch_auction,
                                local_seq,
                                positions.get(0),
                            )
                        );
                    } else {
                        render_dutch_auction(
                            &asset_cache,
                            &dutch_auction,
                            Some(local_seq),
                            positions.get(0).cloned(),
                        )
                        .await
                        .expect("no rendering errors");
                    }
                } else {
                    unimplemented!("only supporting dutch auctions at the moment, come back later");
                }
            } else {
                let position_ids: Vec<String> = positions
                    .into_iter()
                    .map(|lp: penumbra_sdk_dex::lp::position::Position| format!("{}", lp.id()))
                    .collect();

                if output == OutputFormat::Json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "auction_id": auction_id.to_string(),
                            "positions": position_ids,
                        })
                    );
                } else {
                    let mut auction_table = Table::new();
                    auction_table.load_preset(presets::ASCII_FULL);
                    auction_table
                        .set_header(vec!["Auction id", "LPs"])
                        .set_content_arrangement(ContentArrangement::DynamicFullWidth)
                        .add_row(vec![
                            Cell::new(&auction_id).set_delimiter('.'),
                            Cell::new(format!("{:?}", position_ids))
                                .set_alignment(comfy_table::CellAlignment::Center),
                        ]);

                    println!("{auction_table}");
                }
            }
        }
        Ok(())
    }
}

/// One dutch auction as JSON: `{"auction_id":"…","state":"opened",…}`.
///
/// Amounts are `{"amount":"<raw u128>","denom":"…"}` — the raw integer,
/// deliberately not `Value::format(&asset_cache)`, which prints display units
/// with a suffix (`1.727mpenumbra`) that a caller must then un-format. Prices
/// stay strings because they are fixed-point, not integer amounts.
fn dutch_auction_json(
    asset_cache: &penumbra_sdk_asset::asset::Cache,
    dutch_auction: &DutchAuction,
    local_seq: u64,
    position: Option<&penumbra_sdk_dex::lp::position::Position>,
) -> serde_json::Value {
    let value_json = |value: &Value| {
        let denom = asset_cache
            .get(&value.asset_id)
            .map(|denom| denom.to_string())
            .unwrap_or_else(|| value.asset_id.to_string());
        serde_json::json!({
            "amount": u128::from(value.amount).to_string(),
            "denom": denom,
        })
    };

    let input = dutch_auction.description.input;
    let output_id = dutch_auction.description.output_id;
    let min_output = Value {
        amount: dutch_auction.description.min_output,
        asset_id: output_id,
    };
    let max_output = Value {
        amount: dutch_auction.description.max_output,
        asset_id: output_id,
    };

    let (position_input_reserve, position_output_reserve) = position.map_or_else(
        || (Amount::zero(), Amount::zero()),
        |lp| {
            (
                lp.reserves_for(input.asset_id).unwrap_or_else(Amount::zero),
                lp.reserves_for(output_id).unwrap_or_else(Amount::zero),
            )
        },
    );
    let input_reserves = Value {
        amount: position_input_reserve + dutch_auction.state.input_reserves,
        asset_id: input.asset_id,
    };
    let output_reserves = Value {
        amount: position_output_reserve + dutch_auction.state.output_reserves,
        asset_id: output_id,
    };

    let initial_input_amount = U128x128::from(input.amount);
    let start_price = (U128x128::from(dutch_auction.description.max_output) / initial_input_amount)
        .ok()
        .map(|price| price.to_string());
    let end_price = (U128x128::from(dutch_auction.description.min_output) / initial_input_amount)
        .ok()
        .map(|price| price.to_string());

    let state = match dutch_auction.state.sequence {
        0 => "opened",
        1 => "closed",
        _ => "withdrawn",
    };

    serde_json::json!({
        "auction_id": dutch_auction.description.id().to_string(),
        "state": state,
        "sequence": dutch_auction.state.sequence,
        "local_seq": local_seq,
        "start_height": dutch_auction.description.start_height,
        "end_height": dutch_auction.description.end_height,
        "step_count": dutch_auction.description.step_count,
        "start_price": start_price,
        "end_price": end_price,
        "input": value_json(&input),
        "min_output": value_json(&min_output),
        "max_output": value_json(&max_output),
        "input_reserves": value_json(&input_reserves),
        "output_reserves": value_json(&output_reserves),
        "position_id": dutch_auction.state.current_position.map(|id| id.to_string()),
    })
}
