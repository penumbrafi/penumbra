//! Coordinated-restart ("hard-fork") migration for a chain halted by liveness loss.
//!
//! Removes the given validators from the active set (Active -> Jailed, or Disabled) so that the
//! remaining validators can resume consensus, and writes a checkpoint genesis exactly like
//! `mainnet4.rs` does for a regular upgrade. The app version is NOT bumped.
//!
//! Unlike `Migration::migrate`, this does not require the chain halt bit to be set (a liveness
//! halt never sets it), but it keeps the state-version == block-height corruption check.
use std::path::PathBuf;

use anyhow::{ensure, Context, Result};
use cnidarium::{StateDelta, Storage};
use futures::StreamExt as _;
use jmt::RootHash;
use penumbra_sdk_app::app::StateReadExt as _;
use penumbra_sdk_app::SUBSTORE_PREFIXES;
use penumbra_sdk_governance::{StateReadExt as _, StateWriteExt as _};
use penumbra_sdk_proto::StateWriteProto as _;
use penumbra_sdk_sct::component::clock::{EpochManager as _, EpochRead as _};
use penumbra_sdk_stake::component::stake::ConsensusIndexRead as _;
use penumbra_sdk_stake::component::validator_handler::{
    ValidatorDataRead as _, ValidatorManager as _,
};
use penumbra_sdk_stake::{state_key, validator, CurrentConsensusKeys};

use crate::network::generate::NetworkConfig;

pub async fn run(
    pd_home: PathBuf,
    comet_home: Option<PathBuf>,
    remove: Vec<[u8; 20]>,
    new_state: validator::State,
) -> Result<()> {
    ensure!(
        matches!(
            new_state,
            validator::State::Jailed | validator::State::Disabled
        ),
        "removed validators must become Jailed or Disabled"
    );
    ensure!(!remove.is_empty(), "no validators to remove");

    let storage = Storage::load(pd_home.join("rocksdb"), SUBSTORE_PREFIXES.to_vec()).await?;
    let latest_version = storage.latest_version();
    let initial_state = storage.latest_snapshot();
    let pre_height = initial_state.get_block_height().await?;
    ensure!(
        latest_version == pre_height,
        "local chain state version is corrupted: {} != {}",
        latest_version,
        pre_height
    );
    let halted = initial_state.is_chain_halted().await;
    let chain_id = initial_state.get_chain_id().await?;
    let genesis_start = initial_state
        .get_current_block_timestamp()
        .await
        .context("reading last block timestamp")?;
    let pre_root: RootHash = initial_state.root_hash().await?.into();
    let post_height = pre_height.wrapping_add(1);
    tracing::info!(
        ?pre_root,
        pre_height,
        post_height,
        halted,
        %chain_id,
        %genesis_start,
        "restart-fork: pre-migration state"
    );

    let mut delta = StateDelta::new(initial_state);

    // 1. Move every REMOVE validator out of Active. Must happen BEFORE put_block_height(0):
    //    the (Active, Jailed) transition reads the current height to schedule unbonding.
    for addr in &remove {
        let def = delta
            .get_validator_definition_by_cometbft_address(addr)
            .await?
            .with_context(|| {
                format!(
                    "no validator with cometbft address {}",
                    hex::encode_upper(addr)
                )
            })?;
        let id = def.identity_key;
        let (old, new) = delta.set_validator_state(&id, new_state.clone()).await?;
        ensure!(
            old == validator::State::Active,
            "validator {} ({}) was {:?}, expected Active",
            id,
            hex::encode_upper(addr),
            old
        );
        tracing::info!(
            %id,
            cometbft_address = hex::encode_upper(addr),
            name = def.name,
            ?old,
            ?new,
            "restart-fork: removed validator from active set"
        );
    }

    // 2. Rewrite CurrentConsensusKeys to exactly the validators still Active. Otherwise
    //    build_cometbft_validator_updates() emits power-0 entries for the removed keys at
    //    InitChain and CometBFT's NewValidatorSet panics on them.
    let mut keep_keys = Vec::new();
    let mut ids = delta.consensus_set_stream()?;
    while let Some(id) = ids.next().await {
        let id = id?;
        let state = delta
            .get_validator_state(&id)
            .await?
            .with_context(|| format!("validator {id} has no state"))?;
        if state != validator::State::Active {
            continue;
        }
        let consensus_key = delta
            .fetch_validator_consensus_key(&id)
            .await?
            .with_context(|| format!("active validator {id} has no consensus key"))?;
        let power = delta
            .get_validator_power(&id)
            .await?
            .with_context(|| format!("active validator {id} has no power"))?;
        ensure!(power.value() > 0, "active validator {id} has zero power");
        let comet_addr = tendermint::account::Id::from(consensus_key);
        tracing::info!(
            %id,
            cometbft_address = %comet_addr,
            power = power.value(),
            "restart-fork: keeping active validator"
        );
        keep_keys.push(consensus_key);
    }
    ensure!(!keep_keys.is_empty(), "no active validators would remain");
    let n_keep = keep_keys.len();
    delta.put(
        state_key::consensus_update::consensus_keys().to_owned(),
        CurrentConsensusKeys {
            consensus_keys: keep_keys,
        },
    );

    // 3. Same tail as mainnet4.rs, minus migrate_app_version (APP_VERSION stays as-is).
    delta.ready_to_start();
    delta.put_block_height(0u64);
    let post_root = storage.commit_in_place(delta).await?;
    storage.release().await;
    tracing::info!(?post_root, n_keep, "restart-fork: post-migration root hash");

    // 4. Checkpoint genesis, identical in shape to mainnet4.rs.
    let app_state = penumbra_sdk_app::genesis::Content {
        chain_id,
        ..Default::default()
    };
    let mut genesis = NetworkConfig::make_genesis(app_state).expect("can make genesis");
    genesis.app_hash = post_root
        .0
        .to_vec()
        .try_into()
        .expect("infallible conversion");
    genesis.initial_height = post_height as i64;
    genesis.genesis_time = genesis_start;
    let genesis = NetworkConfig::make_checkpoint(genesis, Some(post_root.0.to_vec()));
    let genesis_json = serde_json::to_string(&genesis).expect("can serialize genesis");
    tracing::info!("genesis: {}", genesis_json);
    let genesis_path = pd_home.join("genesis.json");
    std::fs::write(&genesis_path, genesis_json).context("writing genesis.json")?;

    let validator_state_path = pd_home.join("priv_validator_state.json");
    std::fs::write(
        validator_state_path,
        crate::network::generate::NetworkValidator::initial_state(),
    )
    .context("writing priv_validator_state.json")?;

    if let Some(comet_home) = comet_home {
        crate::migrate::migrate_comet_data(comet_home, genesis_path).await?;
    }

    tracing::info!(
        pre_height,
        post_height,
        ?pre_root,
        ?post_root,
        removed = remove.len(),
        kept = n_keep,
        "restart-fork: successful migration!"
    );
    Ok(())
}
