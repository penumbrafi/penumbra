//! Liveness of the IBC client backing an ICS-20 transferred asset.
//!
//! Governance may name arbitrary assets as DEX routing candidates or as
//! alternative fee assets. For an asset that arrived over IBC, those roles only
//! make sense while the light client for its channel is still usable; once the
//! client expires or is frozen the asset can neither be deposited nor
//! withdrawn. This module resolves `asset id -> denom metadata -> local channel
//! -> connection -> client -> status` from consensus state so that components
//! can reject or ignore such assets deterministically.

use anyhow::Result;
use async_trait::async_trait;
use cnidarium::StateRead;
use ibc_types::core::channel::{ChannelId, PortId};
use ibc_types::core::client::ClientId;
use penumbra_sdk_asset::asset;
use penumbra_sdk_ibc::component::{ChannelStateReadExt as _, ClientStatus};
use penumbra_sdk_sct::component::clock::EpochRead as _;
use std::str::FromStr;

use super::AssetRegistryRead as _;

/// The result of checking whether an asset is backed by a live IBC client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IbcAssetStatus {
    /// The asset is not an ICS-20 transferred asset, or has no denom metadata
    /// registered on chain (in which case its provenance cannot be determined).
    NotIbc,
    /// The asset arrived over `channel_id`, whose client `client_id` is active.
    Live {
        channel_id: ChannelId,
        client_id: ClientId,
    },
    /// The asset arrived over `channel_id` but cannot currently be moved over it:
    /// either the channel or connection is missing (`client_id: None`) or the
    /// client is not [`ClientStatus::Active`].
    Dead {
        channel_id: ChannelId,
        client_id: Option<ClientId>,
        status: Option<ClientStatus>,
    },
}

impl IbcAssetStatus {
    pub fn is_dead(&self) -> bool {
        matches!(self, IbcAssetStatus::Dead { .. })
    }

    /// Returns an error describing why `asset_id` is unusable if the status is
    /// [`IbcAssetStatus::Dead`], and `Ok(())` otherwise.
    pub fn ensure_live(&self, asset_id: &asset::Id) -> Result<()> {
        match self {
            IbcAssetStatus::NotIbc | IbcAssetStatus::Live { .. } => Ok(()),
            IbcAssetStatus::Dead {
                channel_id,
                client_id: Some(client_id),
                status: Some(status),
            } => anyhow::bail!(
                "IBC asset {asset_id} (received over {channel_id}) is not backed by a live client: client {client_id} is {status}"
            ),
            IbcAssetStatus::Dead { channel_id, .. } => anyhow::bail!(
                "IBC asset {asset_id} (received over {channel_id}) is not backed by a live client: channel or connection does not exist"
            ),
        }
    }
}

/// Read access to the IBC liveness of assets.
#[async_trait]
pub trait IbcAssetLiveness: StateRead {
    /// Determines whether `asset_id` is an ICS-20 asset and, if so, whether the
    /// client backing its channel is active as of `current_block_time`.
    ///
    /// Assets without registered denom metadata, and assets whose base denom is
    /// not of the form `transfer/channel-N/...`, are reported as
    /// [`IbcAssetStatus::NotIbc`] and are never considered dead.
    async fn ibc_asset_status(
        &self,
        asset_id: &asset::Id,
        current_block_time: tendermint::Time,
    ) -> Result<IbcAssetStatus> {
        let Some(metadata) = self.denom_metadata_by_asset(asset_id).await else {
            return Ok(IbcAssetStatus::NotIbc);
        };
        let Some(channel) = metadata.ibc_transfer_channel() else {
            return Ok(IbcAssetStatus::NotIbc);
        };
        // The parser only accepts canonical `channel-N` identifiers, so this
        // cannot fail; treat a failure as "not IBC" rather than erroring.
        let Ok(channel_id) = ChannelId::from_str(&channel) else {
            return Ok(IbcAssetStatus::NotIbc);
        };

        match self
            .get_channel_client_status(&channel_id, &PortId::transfer(), current_block_time)
            .await?
        {
            Some((client_id, ClientStatus::Active)) => Ok(IbcAssetStatus::Live {
                channel_id,
                client_id,
            }),
            Some((client_id, status)) => Ok(IbcAssetStatus::Dead {
                channel_id,
                client_id: Some(client_id),
                status: Some(status),
            }),
            None => Ok(IbcAssetStatus::Dead {
                channel_id,
                client_id: None,
                status: None,
            }),
        }
    }

    /// Like [`IbcAssetLiveness::ibc_asset_status`], using the current block
    /// timestamp recorded in state by the SCT component.
    ///
    /// The timestamp is only read once the asset is known to be an ICS-20 asset,
    /// so non-IBC assets never depend on it being present.
    async fn ibc_asset_status_now(&self, asset_id: &asset::Id) -> Result<IbcAssetStatus> {
        let Some(metadata) = self.denom_metadata_by_asset(asset_id).await else {
            return Ok(IbcAssetStatus::NotIbc);
        };
        if metadata.ibc_transfer_channel().is_none() {
            return Ok(IbcAssetStatus::NotIbc);
        }
        let now = self.get_current_block_timestamp().await?;
        self.ibc_asset_status(asset_id, now).await
    }

    /// Errors if `asset_id` is an ICS-20 asset whose client is not active as of
    /// the current block timestamp.
    async fn ensure_ibc_asset_live(&self, asset_id: &asset::Id) -> Result<()> {
        self.ibc_asset_status_now(asset_id)
            .await?
            .ensure_live(asset_id)
    }
}

impl<T: StateRead + ?Sized> IbcAssetLiveness for T {}
