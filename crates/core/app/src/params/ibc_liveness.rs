//! State-aware validation of parameter changes: assets that governance names as
//! DEX routing candidates or alternative fee assets must be backed by a live IBC
//! client (see penumbrafi/penumbra#34).
//!
//! [`AppParameters::check_valid_update`] is pure and cannot look at chain state,
//! so the liveness rule lives here and is applied by
//! [`apply_parameter_change`], which both the `ProposalSubmit` handler and the
//! enactment path in `App::begin_block` call.

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use cnidarium::StateRead;
use penumbra_sdk_asset::STAKING_TOKEN_ASSET_ID;
use penumbra_sdk_governance::change::ParameterChange;
use penumbra_sdk_shielded_pool::component::IbcAssetLiveness as _;

use crate::app::StateReadExt as _;
use crate::params::change::ParameterChangeExt as _;
use crate::params::AppParameters;

/// Checks that every ICS-20 asset named in `params.dex_params.fixed_candidates`
/// or `params.fee_params.fixed_alt_gas_prices` is backed by an IBC client that
/// is `Active` as of `current_block_time`.
///
/// The staking token and any asset that is not an ICS-20 transfer asset (or has
/// no denom metadata registered on chain) are exempt.
pub async fn check_ibc_asset_liveness<S: StateRead>(
    state: &S,
    params: &AppParameters,
    current_block_time: tendermint::Time,
) -> Result<()> {
    let mut candidates = BTreeSet::new();
    for asset_id in &params.dex_params.fixed_candidates {
        candidates.insert((*asset_id, "DEX routing candidate"));
    }
    for prices in &params.fee_params.fixed_alt_gas_prices {
        candidates.insert((prices.asset_id, "alternative fee asset"));
    }

    for (asset_id, role) in candidates {
        if asset_id == *STAKING_TOKEN_ASSET_ID {
            continue;
        }
        state
            .ibc_asset_status(&asset_id, current_block_time)
            .await
            .with_context(|| format!("could not determine IBC liveness of {role} {asset_id}"))?
            .ensure_live(&asset_id)
            .with_context(|| format!("invalid {role}"))?;
    }

    Ok(())
}

/// Applies `change` to the app parameters currently in `state`, running both the
/// pure validity checks ([`AppParameters::check_valid_update`]) and the
/// state-dependent IBC asset liveness check.
///
/// `current_block_time` must be the timestamp of the block in which the change
/// is being evaluated. At enactment in `begin_block` the SCT component has not
/// yet recorded the new block's timestamp, so callers there must pass the
/// header time explicitly rather than reading it from state.
pub async fn apply_parameter_change<S: StateRead>(
    state: &S,
    change: &ParameterChange,
    current_block_time: tendermint::Time,
) -> Result<AppParameters> {
    let current_parameters = state.get_app_params().await?;
    let new_parameters = change.apply_changes(current_parameters)?;
    check_ibc_asset_liveness(state, &new_parameters, current_block_time)
        .await
        .context("parameter change names an asset that is not backed by a live IBC client")?;
    Ok(new_parameters)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::Result;
    use async_trait::async_trait;
    use cnidarium::{ArcStateDeltaExt, StateDelta, StateRead};
    use ibc_types::core::channel::channel::{Order, State as ChannelState};
    use ibc_types::core::channel::{ChannelEnd, ChannelId, PortId, Version as ChannelVersion};
    use ibc_types::core::client::{ClientId, Height};
    use ibc_types::core::commitment::{MerklePrefix, MerkleRoot};
    use ibc_types::core::connection::{
        ChainId, ConnectionEnd, ConnectionId, Counterparty as ConnectionCounterparty,
        State as ConnectionState, Version as ConnectionVersion,
    };
    use ibc_types::lightclients::tendermint::client_state::{AllowUpdate, ClientState};
    use ibc_types::lightclients::tendermint::consensus_state::ConsensusState;
    use ibc_types::lightclients::tendermint::TrustThreshold;
    use penumbra_sdk_asset::{asset, Value, STAKING_TOKEN_ASSET_ID};
    use penumbra_sdk_fee::component::FeePay as _;
    use penumbra_sdk_fee::{Fee, Gas, GasPrices};
    use penumbra_sdk_governance::change::{EncodedParameter, ParameterChange};
    use penumbra_sdk_ibc::component::{
        ChannelStateWriteExt as _, ClientStateWriteExt as _, ClientStatus,
        ConnectionStateWriteExt as _, ConsensusStateWriteExt as _, HostInterface,
    };
    use penumbra_sdk_sct::component::clock::{EpochManager as _, EpochRead as _};
    use penumbra_sdk_shielded_pool::component::IbcAssetStatus;
    use penumbra_sdk_shielded_pool::component::{AssetRegistry as _, IbcAssetLiveness as _};
    use tendermint::Time;

    use super::*;
    use crate::app::StateWriteExt as _;
    use crate::genesis;

    const TRUSTING_PERIOD: Duration = Duration::from_secs(14 * 24 * 60 * 60);

    struct MockHost {}

    #[async_trait]
    impl HostInterface for MockHost {
        async fn get_chain_id<S: StateRead>(_state: S) -> Result<String> {
            Ok("penumbra-test".to_string())
        }
        async fn get_revision_number<S: StateRead>(_state: S) -> Result<u64> {
            Ok(0)
        }
        async fn get_block_height<S: StateRead>(state: S) -> Result<u64> {
            state.get_block_height().await
        }
        async fn get_block_timestamp<S: StateRead>(state: S) -> Result<Time> {
            state.get_current_block_timestamp().await
        }
    }

    fn now() -> Time {
        Time::parse_from_rfc3339("2026-09-23T12:00:00Z").expect("valid time")
    }

    fn default_app_params() -> AppParameters {
        let content = genesis::Content::default().with_chain_id("penumbra-test".to_string());
        AppParameters {
            chain_id: content.chain_id,
            auction_params: content.auction_content.auction_params,
            community_pool_params: content.community_pool_content.community_pool_params,
            distributions_params: content.distributions_content.distributions_params,
            fee_params: content.fee_content.fee_params,
            funding_params: content.funding_content.funding_params,
            governance_params: content.governance_content.governance_params,
            ibc_params: content.ibc_content.ibc_params,
            sct_params: content.sct_content.sct_params,
            shielded_pool_params: content.shielded_pool_content.shielded_pool_params,
            stake_params: content.stake_content.stake_params,
            dex_params: content.dex_content.dex_params,
        }
    }

    /// A chain state at height 1 / `now()` with default app parameters.
    async fn base_state() -> Arc<StateDelta<()>> {
        let mut state = Arc::new(StateDelta::new(()));
        let mut tx = state.try_begin_transaction().expect("unique");
        tx.put_chain_id("penumbra-test".to_string());
        tx.put_block_height(1);
        tx.put_block_timestamp(1, now());
        tx.put_app_params(default_app_params());
        tx.apply();
        state
    }

    /// Installs client `07-tendermint-{n}` <- `connection-{n}` <- `channel-{n}` on the
    /// transfer port, with a latest consensus state timestamped `age` before `now()`,
    /// and registers the denom `transfer/channel-{n}/{remote_denom}`. Returns the
    /// asset id and client id.
    async fn install_ibc_asset(
        state: &mut Arc<StateDelta<()>>,
        n: u64,
        remote_denom: &str,
        age: Duration,
        frozen: bool,
    ) -> (asset::Id, ClientId) {
        let client_id = ClientId::from_str(&format!("07-tendermint-{n}")).expect("valid");
        let connection_id = ConnectionId::new(n);
        let channel_id = ChannelId::new(n);
        let latest_height = Height::new(0, 1000 + n).expect("valid");

        let client_state = ClientState::new(
            // Revision number 0 must match `latest_height`'s revision number.
            ChainId::new(format!("counterparty{n}"), 0),
            TrustThreshold::ONE_THIRD,
            TRUSTING_PERIOD,
            TRUSTING_PERIOD * 2,
            Duration::from_secs(30),
            latest_height,
            penumbra_sdk_ibc::IBC_PROOF_SPECS.clone(),
            vec!["upgrade".to_string(), "upgradedIBCState".to_string()],
            AllowUpdate {
                after_expiry: false,
                after_misbehaviour: false,
            },
            frozen.then(|| Height::new(0, 1).expect("valid")),
        )
        .expect("valid client state");

        let consensus_state = ConsensusState::new(
            MerkleRoot {
                hash: vec![0u8; 32],
            },
            (now() - age).expect("valid time"),
            tendermint::Hash::Sha256([0u8; 32]),
        );

        let connection = ConnectionEnd {
            state: ConnectionState::Open,
            client_id: client_id.clone(),
            counterparty: ConnectionCounterparty {
                client_id: ClientId::from_str("07-tendermint-0").expect("valid"),
                connection_id: Some(ConnectionId::new(0)),
                prefix: MerklePrefix {
                    key_prefix: b"ibc".to_vec(),
                },
            },
            versions: vec![ConnectionVersion::default()],
            delay_period: Duration::ZERO,
        };

        let channel = ChannelEnd::new(
            ChannelState::Open,
            Order::Unordered,
            ibc_types::core::channel::Counterparty::new(
                PortId::transfer(),
                Some(ChannelId::new(0)),
            ),
            vec![connection_id.clone()],
            ChannelVersion::new("ics20-1".to_string()),
            0,
        );

        let metadata = asset::REGISTRY
            .parse_denom(&format!("transfer/channel-{n}/{remote_denom}"))
            .expect("valid denom");

        let mut tx = state.try_begin_transaction().expect("unique");
        tx.put_client(&client_id, client_state);
        tx.put_verified_consensus_state::<MockHost>(
            latest_height,
            client_id.clone(),
            consensus_state,
        )
        .await
        .expect("can write consensus state");
        tx.put_new_connection(&connection_id, connection)
            .await
            .expect("can write connection");
        tx.put_channel(&channel_id, &PortId::transfer(), channel);
        tx.register_denom(&metadata).await;
        tx.apply();

        (metadata.id(), client_id)
    }

    fn alt_gas_prices(asset_id: asset::Id) -> GasPrices {
        GasPrices {
            asset_id,
            block_space_price: 1,
            compact_block_space_price: 1,
            verification_price: 1,
            execution_price: 1,
        }
    }

    /// A parameter change setting `feeParams.fixedAltGasPrices` and
    /// `dexParams.fixedCandidates` to the given assets.
    fn change_naming(fee_assets: &[asset::Id], candidates: &[asset::Id]) -> ParameterChange {
        let alt: Vec<GasPrices> = fee_assets.iter().copied().map(alt_gas_prices).collect();
        let alt_json = serde_json::to_value(alt).expect("serializes");
        let candidates_json = serde_json::to_value(candidates.to_vec()).expect("serializes");
        ParameterChange {
            changes: vec![
                EncodedParameter {
                    component: "feeParams".to_string(),
                    key: "fixedAltGasPrices".to_string(),
                    value: alt_json.to_string(),
                },
                EncodedParameter {
                    component: "dexParams".to_string(),
                    key: "fixedCandidates".to_string(),
                    value: candidates_json.to_string(),
                },
            ],
            preconditions: vec![],
        }
    }

    #[tokio::test]
    async fn asset_status_resolves_through_channel_to_client() {
        let mut state = base_state().await;
        let (live, live_client) =
            install_ibc_asset(&mut state, 1, "uusdc", Duration::from_secs(60), false).await;
        let (expired, expired_client) = install_ibc_asset(
            &mut state,
            2,
            "utia",
            TRUSTING_PERIOD + Duration::from_secs(1),
            false,
        )
        .await;
        let (frozen, frozen_client) =
            install_ibc_asset(&mut state, 3, "uosmo", Duration::from_secs(60), true).await;
        // Colon in the remote denom must not confuse the parser.
        let (colon, _) = install_ibc_asset(
            &mut state,
            4,
            "cw20:inj19vy83ne9tzta2yqynj8yg7dq9ghca6yqn9hyej",
            Duration::from_secs(60),
            false,
        )
        .await;

        assert_eq!(
            state.ibc_asset_status(&live, now()).await.unwrap(),
            IbcAssetStatus::Live {
                channel_id: ChannelId::new(1),
                client_id: live_client
            }
        );
        assert_eq!(
            state.ibc_asset_status(&expired, now()).await.unwrap(),
            IbcAssetStatus::Dead {
                channel_id: ChannelId::new(2),
                client_id: Some(expired_client),
                status: Some(ClientStatus::Expired),
            }
        );
        assert_eq!(
            state.ibc_asset_status(&frozen, now()).await.unwrap(),
            IbcAssetStatus::Dead {
                channel_id: ChannelId::new(3),
                client_id: Some(frozen_client),
                status: Some(ClientStatus::Frozen),
            }
        );
        assert!(matches!(
            state.ibc_asset_status(&colon, now()).await.unwrap(),
            IbcAssetStatus::Live { .. }
        ));
        // The staking token and an unregistered asset are not IBC assets.
        assert_eq!(
            state
                .ibc_asset_status(&STAKING_TOKEN_ASSET_ID, now())
                .await
                .unwrap(),
            IbcAssetStatus::NotIbc
        );
        let unknown = asset::REGISTRY.parse_denom("unotonchain").unwrap().id();
        assert_eq!(
            state.ibc_asset_status(&unknown, now()).await.unwrap(),
            IbcAssetStatus::NotIbc
        );
        // An ICS-20 denom whose channel was never opened is dead.
        let orphan = asset::REGISTRY
            .parse_denom("transfer/channel-99/uorphan")
            .unwrap();
        let mut tx = state.try_begin_transaction().unwrap();
        tx.register_denom(&orphan).await;
        tx.apply();
        assert_eq!(
            state.ibc_asset_status(&orphan.id(), now()).await.unwrap(),
            IbcAssetStatus::Dead {
                channel_id: ChannelId::new(99),
                client_id: None,
                status: None,
            }
        );
    }

    #[tokio::test]
    async fn parameter_change_with_expired_client_is_rejected() {
        let mut state = base_state().await;
        let (expired, expired_client) = install_ibc_asset(
            &mut state,
            3,
            "utia",
            TRUSTING_PERIOD + Duration::from_secs(1),
            false,
        )
        .await;

        // As an alternative fee asset.
        let change = change_naming(&[expired], &[]);
        let err = apply_parameter_change(&*state, &change, now())
            .await
            .expect_err("expired client must be rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains(&expired_client.to_string()), "{msg}");
        assert!(msg.contains("Expired"), "{msg}");
        assert!(msg.contains("alternative fee asset"), "{msg}");

        // As a DEX routing candidate.
        let change = change_naming(&[], &[expired]);
        let err = apply_parameter_change(&*state, &change, now())
            .await
            .expect_err("expired client must be rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains("DEX routing candidate"), "{msg}");

        // The pure checks still run: an otherwise-invalid change is rejected
        // regardless of liveness.
        let mut change = change_naming(&[], &[]);
        change.changes.push(EncodedParameter {
            component: "sctParams".to_string(),
            key: "epochDuration".to_string(),
            value: r#""12345""#.to_string(),
        });
        let err = apply_parameter_change(&*state, &change, now())
            .await
            .expect_err("epoch duration is frozen");
        assert!(format!("{err:#}").contains("epoch duration"), "{err:#}");
    }

    #[tokio::test]
    async fn parameter_change_with_active_client_is_accepted() {
        let mut state = base_state().await;
        let (live, _) =
            install_ibc_asset(&mut state, 2, "uusdc", Duration::from_secs(60), false).await;
        let unknown_non_ibc = asset::REGISTRY.parse_denom("unotonchain").unwrap().id();

        let change = change_naming(
            &[live, *STAKING_TOKEN_ASSET_ID],
            &[live, unknown_non_ibc, *STAKING_TOKEN_ASSET_ID],
        );
        let new_params = apply_parameter_change(&*state, &change, now())
            .await
            .expect("active client must be accepted");
        assert_eq!(new_params.fee_params.fixed_alt_gas_prices.len(), 2);
        assert_eq!(new_params.dex_params.fixed_candidates.len(), 3);

        // Time passing beyond the trusting period flips the verdict.
        let later = (now() + (TRUSTING_PERIOD + Duration::from_secs(60))).unwrap();
        apply_parameter_change(&*state, &change, later)
            .await
            .expect_err("client expires with time");
    }

    #[tokio::test]
    async fn live_routing_params_drop_candidates_with_dead_clients() {
        use penumbra_sdk_dex::component::StateReadExt as _;

        let mut state = base_state().await;
        let (live, _) =
            install_ibc_asset(&mut state, 2, "uusdc", Duration::from_secs(60), false).await;
        let (expired, _) = install_ibc_asset(
            &mut state,
            3,
            "utia",
            TRUSTING_PERIOD + Duration::from_secs(1),
            false,
        )
        .await;
        let (frozen, _) =
            install_ibc_asset(&mut state, 4, "uosmo", Duration::from_secs(60), true).await;
        let unknown_non_ibc = asset::REGISTRY.parse_denom("unotonchain").unwrap().id();

        let mut params = default_app_params();
        params.dex_params.fixed_candidates = vec![
            *STAKING_TOKEN_ASSET_ID,
            live,
            expired,
            frozen,
            unknown_non_ibc,
        ];
        let mut tx = state.try_begin_transaction().unwrap();
        tx.put_app_params(params);
        tx.apply();

        // The unfiltered view still returns everything.
        assert_eq!(
            state.routing_params().await.unwrap().fixed_candidates.len(),
            5
        );

        let live_params = state.live_routing_params().await.unwrap();
        assert_eq!(
            *live_params.fixed_candidates,
            vec![*STAKING_TOKEN_ASSET_ID, live, unknown_non_ibc]
        );
    }

    #[tokio::test]
    async fn pay_fee_rejects_alt_fee_asset_with_expired_client() {
        let mut state = base_state().await;
        let (live, _) =
            install_ibc_asset(&mut state, 2, "uusdc", Duration::from_secs(60), false).await;
        let (expired, expired_client) = install_ibc_asset(
            &mut state,
            3,
            "utia",
            TRUSTING_PERIOD + Duration::from_secs(1),
            false,
        )
        .await;

        // Install both as alt fee assets directly (as if the lists had been set
        // while both clients were live).
        let mut params = default_app_params();
        params.fee_params.fixed_alt_gas_prices =
            vec![alt_gas_prices(live), alt_gas_prices(expired)];
        let mut tx = state.try_begin_transaction().unwrap();
        tx.put_app_params(params);
        tx.apply();

        let gas = Gas {
            block_space: 1,
            compact_block_space: 1,
            verification: 1,
            execution: 1,
        };
        let fee_in = |asset_id| {
            Fee(Value {
                amount: 1_000_000u64.into(),
                asset_id,
            })
        };

        let mut tx = state.try_begin_transaction().unwrap();
        let err = tx
            .pay_fee(gas, fee_in(expired))
            .await
            .expect_err("fee in an asset with an expired client must be rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains(&expired.to_string()), "{msg}");
        assert!(msg.contains(&expired_client.to_string()), "{msg}");
        assert!(msg.contains("Expired"), "{msg}");

        tx.pay_fee(gas, fee_in(live))
            .await
            .expect("fee in an asset with an active client is accepted");
        tx.pay_fee(gas, Fee::from_staking_token_amount(1_000_000u64.into()))
            .await
            .expect("fee in the staking token is always accepted");
        // An alt fee asset that is not on the list is still rejected as before.
        let unknown = asset::REGISTRY.parse_denom("unotonchain").unwrap().id();
        let err = tx.pay_fee(gas, fee_in(unknown)).await.unwrap_err();
        assert!(format!("{err:#}").contains("not recognized"), "{err:#}");
    }
}
