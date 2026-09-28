use comfy_table::{presets, Table};
use penumbra_sdk_asset::asset;
use penumbra_sdk_dex::lp::position::Position;

pub(crate) fn render_positions(asset_cache: &asset::Cache, positions: &[Position]) -> String {
    // Assets whose metadata is missing from the cache (e.g. because the registry
    // is out of date) would otherwise render as "Unknown asset". Fill in
    // base-unit metadata keyed by their bech32 `passet…` IDs so the sell price
    // and reserves still render.
    let mut enriched_cache = asset_cache.clone();
    for position in positions {
        for asset_id in [position.phi.pair.asset_1(), position.phi.pair.asset_2()] {
            if enriched_cache.get(&asset_id).is_none() {
                enriched_cache.extend(std::iter::once(asset::Metadata::from_id(asset_id)));
            }
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
