use anyhow::{anyhow, Result};
use futures::stream::TryStreamExt;
use penumbra_sdk_dex::lp::position::{Position, State};
use penumbra_sdk_proto::core::component::dex::v1::{
    query_service_client::QueryServiceClient as DexQueryServiceClient,
    LiquidityPositionsByIdRequest,
};
use penumbra_sdk_view::ViewClient;

use crate::{command::utils, opt::OutputFormat, App};

#[derive(Debug, clap::Args)]
pub struct LiquidityPositionsCmd {}

impl LiquidityPositionsCmd {
    pub fn offline(&self) -> bool {
        false
    }

    pub async fn exec(&self, app: &mut App) -> Result<()> {
        let output = app.output_or(OutputFormat::Text);

        let my_position_ids = app
            .view()
            .owned_position_ids(Some(State::Opened), None, None)
            .await?;
        let mut dex_client = DexQueryServiceClient::new(app.pd_channel().await?);

        let positions_stream = dex_client
            .liquidity_positions_by_id(LiquidityPositionsByIdRequest {
                position_id: my_position_ids.into_iter().map(Into::into).collect(),
            })
            .await?
            .into_inner()
            .map_err(|e| anyhow!("error fetching liquidity positions: {}", e))
            .and_then(|msg| async move {
                msg.data
                    .ok_or_else(|| anyhow!("missing liquidity position in response"))
                    .map(Position::try_from)?
            });

        let asset_cache = app.view().assets().await?;

        let positions = positions_stream.try_collect::<Vec<_>>().await?;

        if output == OutputFormat::Json {
            // One object per position, with raw reserve amounts and the two
            // assets they are denominated in, rather than the table's
            // display-unit amounts and derived prices.
            for position in &positions {
                let trading_pair = position.phi.pair;
                println!(
                    "{}",
                    serde_json::json!({
                        "position_id": position.id().to_string(),
                        "state": position.state.to_string(),
                        "fee_bps": position.phi.component.fee,
                        "asset_1": utils::denom(&trading_pair.asset_1(), &asset_cache),
                        "asset_2": utils::denom(&trading_pair.asset_2(), &asset_cache),
                        "reserve_1": u128::from(position.reserves.r1).to_string(),
                        "reserve_2": u128::from(position.reserves.r2).to_string(),
                    })
                );
            }
            return Ok(());
        }

        println!("{}", utils::render_positions(&asset_cache, &positions));

        Ok(())
    }
}
