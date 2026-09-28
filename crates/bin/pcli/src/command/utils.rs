use anyhow::Result;
use comfy_table::{presets, Table};
use penumbra_sdk_asset::asset::{self, Id, Metadata};
use penumbra_sdk_dex::lp::position::Position;
use penumbra_sdk_proto::core::component::shielded_pool::v1::{
    query_service_client::QueryServiceClient as ShieldedPoolQueryServiceClient,
    AssetMetadataByIdRequest,
};
use tonic::transport::Channel;

/// The asset IDs referenced by the trading pairs of the given positions.
pub(crate) fn position_asset_ids(positions: &[Position]) -> impl Iterator<Item = Id> + '_ {
    positions
        .iter()
        .flat_map(|position| [position.phi.pair.asset_1(), position.phi.pair.asset_2()])
}

/// Adds on-chain denomination metadata to `asset_cache` for any of the given
/// `asset_ids` that are missing from it.
///
/// The local view only records metadata for assets it has actually seen (e.g. in
/// its own notes), so commands that list chain-wide data such as
/// `pcli query dex lp-positions` encounter assets the cache knows nothing about.
/// Querying the chain lets those render with their registered denomination
/// instead of a raw `passet…` ID. Assets with no on-chain metadata record are
/// left absent, so callers can fall back to [`asset::Metadata::from_id`].
pub(crate) async fn add_chain_metadata(
    channel: Channel,
    asset_cache: &mut asset::Cache,
    asset_ids: impl IntoIterator<Item = Id>,
) -> Result<()> {
    let mut client = ShieldedPoolQueryServiceClient::new(channel);
    let mut queried = Vec::new();
    for asset_id in asset_ids {
        if queried.contains(&asset_id) || asset_cache.get(&asset_id).is_some() {
            continue;
        }
        queried.push(asset_id);

        if let Some(denom_metadata) = client
            .asset_metadata_by_id(AssetMetadataByIdRequest {
                asset_id: Some(asset_id.into()),
            })
            .await?
            .into_inner()
            .denom_metadata
        {
            asset_cache.extend(std::iter::once(Metadata::try_from(denom_metadata)?));
        }
    }

    Ok(())
}

/// Renders a table of liquidity positions.
///
/// Assets missing from `asset_cache` (e.g. because the registry is out of date)
/// are rendered by their raw bech32 `passet…` ID rather than as "Unknown asset".
/// Callers that can reach a node should first enrich the cache with
/// [`add_chain_metadata`], so assets the chain knows about render with their
/// registered denomination.
pub(crate) fn render_positions(asset_cache: &asset::Cache, positions: &[Position]) -> String {
    // Fill in base-unit metadata keyed by the raw `passet…` IDs for any asset the
    // cache doesn't know about, so the sell price and reserves still render.
    let mut enriched_cache = asset_cache.clone();
    for asset_id in position_asset_ids(positions) {
        if enriched_cache.get(&asset_id).is_none() {
            enriched_cache.extend(std::iter::once(Metadata::from_id(asset_id)));
        }
    }
    let asset_cache = &enriched_cache;

    let mut table = Table::new();
    table.load_preset(presets::NOTHING);
    table.set_header(vec!["ID", "State", "Fee", "Sell Price", "Reserves"]);
    table
        .get_column_mut(2)
        .expect("column 2 exists")
        .set_cell_alignment(comfy_table::CellAlignment::Right);
    table
        .get_column_mut(3)
        .expect("column 3 exists")
        .set_cell_alignment(comfy_table::CellAlignment::Right);
    table
        .get_column_mut(4)
        .expect("column 4 exists")
        .set_cell_alignment(comfy_table::CellAlignment::Right);

    for position in positions {
        if let Some(sell_order) = position.interpret_as_sell() {
            table.add_row(vec![
                position.id().to_string(),
                position.state.to_string(),
                format!("{}bps", position.phi.component.fee),
                format!(
                    "{}",
                    sell_order.price_str(asset_cache).expect("assets are known"),
                ),
                sell_order.offered.format(asset_cache),
            ]);
        } else if let Some((sell_order_1, sell_order_2)) = position.interpret_as_mixed() {
            table.add_row(vec![
                position.id().to_string(),
                position.state.to_string(),
                format!("{}bps", position.phi.component.fee),
                format!(
                    "{}",
                    sell_order_1
                        .price_str(asset_cache)
                        .expect("assets are known"),
                ),
                sell_order_1.offered.format(asset_cache),
            ]);
            table.add_row(vec![
                // Add a mark indicating this row is associated with the same position.
                "└──────────────────────────────────────────────────────────────▶".to_string(),
                String::new(),
                format!("{}bps", position.phi.component.fee),
                format!(
                    "{}",
                    sell_order_2
                        .price_str(asset_cache)
                        .expect("assets are known"),
                ),
                sell_order_2.offered.format(asset_cache),
            ]);
        } else {
            table.add_row(vec![
                position.id().to_string(),
                position.state.to_string(),
                "Error interpreting position (this should not happen)".to_string(),
            ]);
        }
    }

    format!("{table}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use penumbra_sdk_asset::{asset::Id, Value};
    use penumbra_sdk_dex::lp::SellOrder;
    use penumbra_sdk_num::Amount;
    use std::str::FromStr;

    #[test]
    fn unknown_assets_render_as_bech32_instead_of_unknown() {
        // Two `passet…` asset IDs present in no asset cache/registry.
        let asset_1 =
            Id::from_str("passet167kw6zx5gtysvk9mwuxn0vxdx84afd6t76jyg62szljntlq0lvrsygwl44")
                .expect("valid bech32 asset id");
        let asset_2 =
            Id::from_str("passet1mxerhdavu7uj8zukdp9llc52ukyxffegdw774lzu7ujhycvfkgrsy8rfmu")
                .expect("valid bech32 asset id");

        let order = SellOrder {
            offered: Value {
                amount: Amount::from(1_000_000u64),
                asset_id: asset_1,
            },
            desired: Value {
                amount: Amount::from(2_000_000u64),
                asset_id: asset_2,
            },
            fee: 100,
        };
        let position = order.into_position(rand_core::OsRng);

        let rendered = render_positions(&asset::Cache::default(), &[position]);

        assert!(
            !rendered.contains("Unknown asset"),
            "unknown assets must not be rendered as `Unknown asset`:\n{rendered}"
        );
        assert!(
            rendered.contains(&asset_1.to_string()),
            "asset 1 should render by its bech32 ID:\n{rendered}"
        );
        assert!(
            rendered.contains(&asset_2.to_string()),
            "asset 2 should render by its bech32 ID:\n{rendered}"
        );
    }
}
