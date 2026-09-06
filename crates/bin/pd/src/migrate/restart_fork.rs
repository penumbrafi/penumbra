//! Coordinated-restart ("hard-fork") migration for a chain halted by liveness loss.
//!
//! 1. Removes the given validators from the active set (Active -> Jailed, or Disabled) so
//!    that the remaining validators hold all of the voting power, and rewrites the consensus
//!    key record so `InitChain` never reports a zero-power validator to CometBFT.
//! 2. Executes an **empty application block** at `halt_height + 1` through the same
//!    `App::begin_block` / `end_block` / `commit` path `pd` uses for every block, with a
//!    fixed, deterministic header.
//! 3. Writes a checkpoint genesis with `initial_height = halt_height + 2`.
//!
//! Step 2 exists because every validator that was online at the halt already signed votes
//! for `halt_height + 1` (rounds 0..2) on the halted chain. CometBFT's double-sign protection
//! will not let them sign those rounds again, and a round only advances on two-thirds of
//! votes, so a chain restarted at `halt_height + 1` can never produce a block (verified on a
//! copy of the mainnet halt state). Restarting at `halt_height + 2` sidesteps the signed
//! rounds entirely, and no vote from the halted chain can ever become evidence on the
//! restarted chain, because the halted chain never had that height. Executing the empty
//! block inside the migration keeps the application state and the compact block stream
//! contiguous, so wallets keep syncing. There is simply no CometBFT block `halt_height + 1`.
//!
//! The app version is NOT bumped. Unlike `Migration::migrate`, this does not require the
//! chain halt bit to be set (a liveness halt never sets it), but it keeps the
//! state-version == block-height corruption check.
use std::path::PathBuf;

use anyhow::{ensure, Context, Result};
use cnidarium::{StateDelta, Storage};
use futures::StreamExt as _;
use jmt::RootHash;
use penumbra_sdk_app::app::App;
use penumbra_sdk_app::app::{StateReadExt as _, StateWriteExt as _};
use penumbra_sdk_app::SUBSTORE_PREFIXES;
use penumbra_sdk_governance::{StateReadExt as _, StateWriteExt as _};
use penumbra_sdk_proto::StateWriteProto as _;
use penumbra_sdk_sct::component::clock::{EpochManager as _, EpochRead as _};
use penumbra_sdk_stake::component::stake::ConsensusIndexRead as _;
use penumbra_sdk_stake::component::validator_handler::{
    ValidatorDataRead as _, ValidatorManager as _,
};
use penumbra_sdk_stake::component::StateWriteExt as _;
use penumbra_sdk_stake::{state_key, validator, CurrentConsensusKeys};
use tendermint::abci::request;
use tendermint::abci::types::{BlockSignatureInfo, CommitInfo, Validator, VoteInfo};
use tendermint::block::BlockIdFlag;
use tendermint::PublicKey;

use crate::network::generate::NetworkConfig;

/// Drill-only knobs. Never used on mainnet; they change the resulting state.
#[derive(Debug, Default, Clone)]
pub struct UnsafeTestOptions {
    /// Replace the chain id (so a drill can never talk to mainnet peers).
    pub chain_id: Option<String>,
    /// Replace consensus keys `(old, new)` of kept validators with throwaway keys.
    pub rekey: Vec<(PublicKey, PublicKey)>,
}

struct Kept {
    consensus_key: PublicKey,
    power: u64,
}

/// sha256 of the empty string: the hash CometBFT uses for empty commits,
/// empty transaction lists and empty evidence lists.
fn empty_hash() -> tendermint::Hash {
    tendermint::Hash::Sha256(
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes"),
    )
}

/// The deterministic header of the empty block executed by the migration.
fn synthetic_begin_block(
    chain_id: &str,
    height: u64,
    time: tendermint::Time,
    app_hash: RootHash,
    kept: &[Kept],
) -> Result<request::BeginBlock> {
    let infos = kept
        .iter()
        .map(|v| {
            Ok(tendermint::validator::Info::new(
                v.consensus_key,
                tendermint::vote::Power::try_from(v.power).context("voting power")?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let validators_hash = tendermint::validator::Set::without_proposer(infos).hash();

    let header = tendermint::block::Header {
        version: tendermint::block::header::Version {
            block: 11,
            app: penumbra_sdk_app::APP_VERSION,
        },
        chain_id: chain_id.parse().context("chain id")?,
        height: height.try_into().context("height")?,
        time,
        last_block_id: None,
        last_commit_hash: Some(empty_hash()),
        data_hash: Some(empty_hash()),
        validators_hash,
        next_validators_hash: validators_hash,
        consensus_hash: empty_hash(),
        app_hash: tendermint::AppHash::try_from(app_hash.0.to_vec()).context("app hash")?,
        last_results_hash: Some(empty_hash()),
        evidence_hash: Some(empty_hash()),
        // Nobody proposed this block.
        proposer_address: tendermint::account::Id::new([0u8; 20]),
    };

    // Count every kept validator as having signed the previous block, so the
    // empty block neither rewards nor penalises anyone's uptime.
    let votes = kept
        .iter()
        .map(|v| {
            Ok(VoteInfo {
                validator: Validator {
                    address: tendermint::account::Id::from(v.consensus_key)
                        .as_bytes()
                        .try_into()
                        .expect("20-byte address"),
                    power: tendermint::vote::Power::try_from(v.power).context("voting power")?,
                },
                sig_info: BlockSignatureInfo::Flag(BlockIdFlag::Commit),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(request::BeginBlock {
        hash: tendermint::Hash::None,
        header,
        last_commit_info: CommitInfo {
            round: 0u8.into(),
            votes,
        },
        byzantine_validators: vec![],
    })
}

pub async fn run(
    pd_home: PathBuf,
    comet_home: Option<PathBuf>,
    remove: Vec<[u8; 20]>,
    new_state: validator::State,
    unsafe_test: UnsafeTestOptions,
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
    let pre_root: RootHash = initial_state.root_hash().await?.into();
    let last_block_time = initial_state
        .get_current_block_timestamp()
        .await
        .context("reading last block timestamp")?;
    // The empty block carries the halted chain's last timestamp; the restarted
    // chain's first block (= genesis time) comes one second later.
    let synthetic_time = last_block_time;
    let genesis_start =
        (last_block_time + std::time::Duration::from_secs(1)).context("genesis time")?;
    let synthetic_height = pre_height + 1;
    let post_height = pre_height + 2;
    tracing::info!(
        ?pre_root,
        pre_height,
        synthetic_height,
        post_height,
        halted,
        %last_block_time,
        %genesis_start,
        "restart-fork: pre-migration state"
    );

    let mut delta = StateDelta::new(initial_state);

    if let Some(chain_id) = &unsafe_test.chain_id {
        let old = delta.get_chain_id().await?;
        tracing::warn!(%old, new = %chain_id, "DRILL: overriding chain id");
        delta.put_chain_id(chain_id.clone());
    }
    let chain_id = delta.get_chain_id().await?;

    // 1. Move every REMOVE validator out of Active. Must happen while the block height is
    //    still the halt height: the (Active, Jailed/Disabled) transition reads it to
    //    schedule unbonding.
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

    // 1b. Drill only: swap consensus keys of kept validators for throwaway keys.
    for (old, new) in &unsafe_test.rekey {
        let id = delta
            .lookup_identity_key_by_consensus_key(old)
            .await
            .with_context(|| format!("DRILL: no validator with consensus key {old:?}"))?;
        let mut def = delta
            .get_validator_definition(&id)
            .await?
            .with_context(|| format!("no definition for {id}"))?;
        tracing::warn!(%id, name = def.name, "DRILL: replacing consensus key");
        def.consensus_key = *new;
        delta.register_consensus_key(&id, new);
        delta.put(state_key::validators::definitions::by_id(&id), def);
    }

    // 2. Rewrite CurrentConsensusKeys to exactly the validators still Active. Otherwise
    //    build_cometbft_validator_updates() emits power-0 entries for the removed keys at
    //    InitChain and CometBFT's NewValidatorSet panics on them.
    let mut kept = Vec::new();
    let mut total_power: u128 = 0;
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
        let def = delta
            .get_validator_definition(&id)
            .await?
            .with_context(|| format!("active validator {id} has no definition"))?;
        let consensus_key = def.consensus_key;
        let power = delta
            .get_validator_power(&id)
            .await?
            .with_context(|| format!("active validator {id} has no power"))?;
        ensure!(power.value() > 0, "active validator {id} has zero power");
        total_power += power.value();
        let comet_addr = tendermint::account::Id::from(consensus_key);
        tracing::info!(
            %id,
            name = def.name,
            cometbft_address = %comet_addr,
            power = power.value(),
            "restart-fork: keeping active validator"
        );
        kept.push(Kept {
            consensus_key,
            power: u64::try_from(power.value()).context("voting power fits in u64")?,
        });
    }
    ensure!(!kept.is_empty(), "no active validators would remain");
    let n_keep = kept.len();
    delta.put(
        state_key::consensus_update::consensus_keys().to_owned(),
        CurrentConsensusKeys {
            consensus_keys: kept.iter().map(|k| k.consensus_key).collect(),
        },
    );
    let root_after_changes = storage.commit_in_place(delta).await?;
    tracing::info!(
        ?root_after_changes,
        n_keep,
        total_power,
        "restart-fork: committed validator changes at height {pre_height}"
    );

    // 3. The empty block at halt_height + 1.
    let begin_block = synthetic_begin_block(
        &chain_id,
        synthetic_height,
        synthetic_time,
        root_after_changes,
        &kept,
    )?;
    tracing::info!(
        height = synthetic_height,
        time = %synthetic_time,
        validators_hash = %begin_block.header.validators_hash,
        "restart-fork: executing the empty application block"
    );
    let mut app = App::new(storage.latest_snapshot());
    let begin_events = app.begin_block(&begin_block).await;
    let end_events = app
        .end_block(&request::EndBlock {
            height: synthetic_height as i64,
        })
        .await;
    let root_after_block = app.commit(storage.clone()).await;
    ensure!(
        storage.latest_version() == synthetic_height,
        "state version {} after the empty block, expected {synthetic_height}",
        storage.latest_version()
    );
    tracing::info!(
        ?root_after_block,
        begin_block_events = begin_events.len(),
        end_block_events = end_events.len(),
        "restart-fork: empty block {synthetic_height} committed"
    );

    // 4. Same tail as mainnet4.rs, minus migrate_app_version (APP_VERSION stays as-is).
    //    put_block_height(0) is what makes CometBFT issue InitChain on start.
    let mut delta = StateDelta::new(storage.latest_snapshot());
    let committed_height = delta.get_block_height().await?;
    ensure!(
        committed_height == synthetic_height,
        "block height {committed_height} after the empty block, expected {synthetic_height}"
    );
    delta.ready_to_start();
    delta.put_block_height(0u64);
    let post_root = storage.commit_in_place(delta).await?;
    ensure!(
        storage.latest_version() == synthetic_height,
        "state version {} after the final commit, expected {synthetic_height}",
        storage.latest_version()
    );
    storage.release().await;
    tracing::info!(?post_root, n_keep, "restart-fork: post-migration root hash");

    // 5. Checkpoint genesis, identical in shape to mainnet4.rs.
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
        synthetic_height,
        post_height,
        ?pre_root,
        ?post_root,
        removed = remove.len(),
        kept = n_keep,
        "restart-fork: successful migration!"
    );
    Ok(())
}
