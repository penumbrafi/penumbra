use std::collections::BTreeMap;

use anyhow::Result;
use comfy_table::{presets, Table};
use futures::TryStreamExt;
use tonic::transport::Channel;

use penumbra_sdk_asset::{Value, STAKING_TOKEN_ASSET_ID};
use penumbra_sdk_keys::FullViewingKey;
use penumbra_sdk_proto::core::component::stake::v1::{
    query_service_client::QueryServiceClient as StakeQueryServiceClient, ValidatorInfoRequest,
};
use penumbra_sdk_stake::{validator, DelegationToken};
use penumbra_sdk_view::ViewClient;

use crate::{command::utils, opt::OutputFormat};

#[derive(Debug, clap::Parser)]
pub struct StakedCmd {}

impl StakedCmd {
    pub fn offline(&self) -> bool {
        false
    }

    pub async fn exec(
        &self,
        _fvk: &FullViewingKey,
        view_client: &mut impl ViewClient,
        pd_channel: Channel,
        output: OutputFormat,
    ) -> Result<()> {
        let asset_cache = view_client.assets().await?;

        let mut client = StakeQueryServiceClient::new(pd_channel);

        let validators = client
            .validator_info(ValidatorInfoRequest {
                show_inactive: true,
                ..Default::default()
            })
            .await?
            .into_inner()
            .try_collect::<Vec<_>>()
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<validator::Info>, _>>()?;

        let notes = view_client.unspent_notes_by_asset_and_address().await?;
        let mut total = 0u128;

        // Collect the rows first, so the text rendering (display units) and the
        // JSON rendering (raw integers and denoms) describe exactly the same set.
        let mut rows = Vec::new();

        for (asset_id, notes_by_address) in notes.iter() {
            let dt = if let Some(Ok(dt)) = asset_cache
                .get(asset_id)
                .map(|denom| DelegationToken::try_from(denom.clone()))
            {
                dt
            } else {
                continue;
            };

            let delegation = Value {
                amount: notes_by_address
                    .values()
                    .flat_map(|notes| notes.iter().map(|n| n.note.amount()))
                    .sum(),
                asset_id: dt.id(),
            };

            let info = match validators
                .iter()
                .find(|v| v.validator.identity_key == dt.validator())
            {
                Some(info) => info,
                None => {
                    rows.push(Row {
                        kind: "missing",
                        name: "missing data".to_string(),
                        amount: None,
                        exchange_rate: None,
                        tokens: Some(delegation),
                    });
                    continue;
                }
            };

            let unbonded = Value {
                amount: info
                    .rate_data
                    // TODO fix with new rate calcs
                    .unbonded_amount(delegation.amount)
                    .into(),
                asset_id: *STAKING_TOKEN_ASSET_ID,
            };

            let rate = {
                let validator_exchange_rate = info.rate_data.validator_exchange_rate.value() as f64;
                validator_exchange_rate / 1_0000_0000.0
            };

            rows.push(Row {
                kind: "validator",
                name: info.validator.name.clone(),
                amount: Some(unbonded),
                exchange_rate: Some(rate),
                tokens: Some(delegation),
            });

            total += u128::from(unbonded.amount);
        }

        let unbonded = Value {
            amount: notes
                .get(&*STAKING_TOKEN_ASSET_ID)
                .unwrap_or(&BTreeMap::default())
                .values()
                .flat_map(|notes| notes.iter().map(|n| u128::from(n.note.amount())))
                .sum::<u128>()
                .into(),
            asset_id: *STAKING_TOKEN_ASSET_ID,
        };

        total += u128::from(unbonded.amount);

        rows.push(Row {
            kind: "unbonded",
            name: "Unbonded Stake".to_string(),
            amount: Some(unbonded),
            exchange_rate: Some(1.0),
            tokens: Some(unbonded),
        });

        let total = Value {
            amount: total.into(),
            asset_id: *STAKING_TOKEN_ASSET_ID,
        };

        rows.push(Row {
            kind: "total",
            name: "Total".to_string(),
            amount: Some(total),
            exchange_rate: None,
            tokens: None,
        });

        if output == OutputFormat::Json {
            for row in &rows {
                println!("{}", row.json(&asset_cache));
            }
            return Ok(());
        }

        let mut table = Table::new();
        table.load_preset(presets::NOTHING);
        table.set_header(vec!["Name", "Value", "Exch. Rate", "Tokens"]);
        table
            .get_column_mut(1)
            .expect("column 1 exists")
            .set_cell_alignment(comfy_table::CellAlignment::Right);

        for row in &rows {
            table.add_row(vec![
                row.name.clone(),
                row.amount
                    .map(|value| value.format(&asset_cache))
                    .unwrap_or_else(|| "missing data".to_string()),
                match (row.kind, row.exchange_rate) {
                    (_, Some(rate)) => format!("{rate:.4}"),
                    ("missing", None) => "missing data".to_string(),
                    _ => String::new(),
                },
                row.tokens
                    .map(|value| value.format(&asset_cache))
                    .unwrap_or_default(),
            ]);
        }
        println!("{table}");

        Ok(())
    }
}

/// A `v staked` row, kept as raw values so both renderings agree.
struct Row {
    /// `"validator"`, `"missing"`, `"unbonded"`, or `"total"`.
    kind: &'static str,
    /// The table's `Name` column: the validator, or a summary row label.
    name: String,
    /// The staking-token equivalent of the delegation token (the `Value` column).
    amount: Option<Value>,
    /// The table's `Exch. Rate` column.
    exchange_rate: Option<f64>,
    /// The delegation token itself (the `Tokens` column).
    tokens: Option<Value>,
}

impl Row {
    /// This row as JSON: `{"kind":…,"name":…,"amount":"<raw u128>","denom":…,…}`.
    ///
    /// `amount` and `token_amount` are raw integers, deliberately *not*
    /// `Value::format(&asset_cache)`, which prints display units with a suffix
    /// (`1.727mpenumbra`) — a string whose number is not the amount, and which
    /// every caller then has to un-format. Denoms are the resolved asset names.
    /// Columns the table fills with `missing data` or nothing are `null`.
    fn json(&self, asset_cache: &penumbra_sdk_asset::asset::Cache) -> serde_json::Value {
        serde_json::json!({
            "kind": self.kind,
            "name": self.name,
            "amount": self.amount.map(|value| u128::from(value.amount).to_string()),
            "denom": self.amount.map(|value| utils::denom(&value.asset_id, asset_cache)),
            "exchange_rate": self.exchange_rate,
            "token_amount": self.tokens.map(|value| u128::from(value.amount).to_string()),
            "token_denom": self.tokens.map(|value| utils::denom(&value.asset_id, asset_cache)),
        })
    }
}
