use ibc_types::core::{
    channel::ChannelId, channel::PortId, client::ClientId, client::Height as IbcHeight,
};
use penumbra_sdk_asset::{
    asset::{self, Metadata},
    Balance, Value,
};
use penumbra_sdk_keys::Address;
use penumbra_sdk_num::Amount;
use penumbra_sdk_proto::{
    penumbra::core::component::ibc::v1::{self as pb, FungibleTokenPacketData},
    DomainType,
};
use penumbra_sdk_txhash::{EffectHash, EffectingData};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[cfg(feature = "component")]
use penumbra_sdk_ibc::component::packet::{IBCPacket, Unchecked};

/// Where an ICS-20 withdrawal leaves Penumbra: a classic IBC channel, or an
/// IBC v2 client (client-routed packets, no channel).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ics20WithdrawalSource {
    Channel(ChannelId),
    Client(ClientId),
}

impl std::fmt::Display for Ics20WithdrawalSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ics20WithdrawalSource::Channel(c) => write!(f, "{c}"),
            Ics20WithdrawalSource::Client(c) => write!(f, "{c}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "pb::Ics20Withdrawal", into = "pb::Ics20Withdrawal")]
pub struct Ics20Withdrawal {
    // a transparent value consisting of an amount and a denom.
    pub amount: Amount,
    pub denom: asset::Metadata,
    // the address on the destination chain to send the transfer to
    pub destination_chain_address: String,
    // a "sender" penumbra address to use to return funds from this withdrawal.
    // this should be an ephemeral address
    pub return_address: Address,
    // the height (on Penumbra) at which this transfer expires (and funds are sent
    // back to the return address?). NOTE: if funds are sent back to the sender,
    // we MUST verify a nonexistence proof before accepting the timeout, to
    // prevent relayer censorship attacks. The core IBC implementation does this
    // in its handling of validation of timeouts.
    pub timeout_height: IbcHeight,
    // the timestamp at which this transfer expires, in nanoseconds after unix epoch.
    // For IBC v2 withdrawals this is truncated to seconds on the wire.
    pub timeout_time: u64,
    // the source channel (classic) or client (IBC v2) used for the withdrawal
    pub source: Ics20WithdrawalSource,

    // Whether to use a "compat" (bech32, non-m) address for the return address in the withdrawal,
    // for compatibility with chains that expect to be able to parse the return address as bech32.
    pub use_compat_address: bool,

    // Arbitrary string data to be included in the `memo` field
    // of the ICS-20 FungibleTokenPacketData for this withdrawal.
    // Commonly used for packet forwarding support, or other protocols that may support usage of the memo field.
    pub ics20_memo: String,
    // Whether to use a transparent address for the return address in the withdrawal.
    pub use_transparent_address: bool,
}

impl Ics20Withdrawal {
    /// The classic (channel-routed) packet for this withdrawal, if it is one.
    #[cfg(feature = "component")]
    pub fn v1_packet(&self) -> Option<IBCPacket<Unchecked>> {
        match &self.source {
            Ics20WithdrawalSource::Channel(source_channel) => Some(IBCPacket::new(
                PortId::transfer(),
                source_channel.clone(),
                self.timeout_height,
                self.timeout_time,
                self.packet_data(),
            )),
            Ics20WithdrawalSource::Client(_) => None,
        }
    }

    /// The source channel, for classic withdrawals.
    pub fn source_channel(&self) -> Option<&ChannelId> {
        match &self.source {
            Ics20WithdrawalSource::Channel(c) => Some(c),
            Ics20WithdrawalSource::Client(_) => None,
        }
    }

    /// The source client, for IBC v2 withdrawals.
    pub fn source_client(&self) -> Option<&ClientId> {
        match &self.source {
            Ics20WithdrawalSource::Channel(_) => None,
            Ics20WithdrawalSource::Client(c) => Some(c),
        }
    }

    /// IBC v2 timeouts are unix seconds; `timeout_time` is nanoseconds and is
    /// required to be minute-aligned, so this is exact.
    pub fn timeout_time_seconds(&self) -> u64 {
        self.timeout_time / 1_000_000_000
    }

    pub fn value(&self) -> Value {
        Value {
            amount: self.amount,
            asset_id: self.denom.id(),
        }
    }

    pub fn balance(&self) -> Balance {
        -Balance::from(self.value())
    }

    pub fn packet_data(&self) -> Vec<u8> {
        let ftpd: FungibleTokenPacketData = self.clone().into();

        // In violation of the ICS20 spec, ibc-go encodes transfer packets as JSON.
        serde_json::to_vec(&ftpd).expect("can serialize FungibleTokenPacketData as JSON")
    }

    // stateless validation of an Ics20 withdrawal action.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.timeout_time == 0 {
            anyhow::bail!("timeout time must be non-zero");
        }

        // in order to prevent clients from inadvertently identifying themselves by their clock
        // skew, enforce that timeout time is rounded to the nearest minute
        if self.timeout_time % 60_000_000_000 != 0 {
            anyhow::bail!(
                "withdrawal timeout timestamp {} is not rounded to one minute",
                self.timeout_time
            );
        }

        // NOTE: we could validate the destination chain address as bech32 to prevent mistyped
        // addresses, but this would preclude sending to chains that don't use bech32 addresses.

        Ok(())
    }
}

impl EffectingData for Ics20Withdrawal {
    fn effect_hash(&self) -> EffectHash {
        EffectHash::from_proto_effecting_data(&self.to_proto())
    }
}

impl DomainType for Ics20Withdrawal {
    type Proto = pb::Ics20Withdrawal;
}

#[allow(deprecated)]
impl From<Ics20Withdrawal> for pb::Ics20Withdrawal {
    fn from(w: Ics20Withdrawal) -> Self {
        let source_channel = w.source_channel().map(ToString::to_string).unwrap_or_default();
        let source_client = w.source_client().map(ToString::to_string).unwrap_or_default();
        pb::Ics20Withdrawal {
            amount: Some(w.amount.into()),
            denom: Some(w.denom.base_denom().into()),
            destination_chain_address: w.destination_chain_address,
            return_address: Some(w.return_address.into()),
            timeout_height: Some(w.timeout_height.into()),
            timeout_time: w.timeout_time,
            source_channel,
            source_client,
            use_compat_address: w.use_compat_address,
            ics20_memo: w.ics20_memo.to_string(),
            use_transparent_address: w.use_transparent_address,
        }
    }
}

#[allow(deprecated)]
impl TryFrom<pb::Ics20Withdrawal> for Ics20Withdrawal {
    type Error = anyhow::Error;
    fn try_from(s: pb::Ics20Withdrawal) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: s
                .amount
                .ok_or_else(|| anyhow::anyhow!("missing amount"))?
                .try_into()?,
            denom: Metadata::default_for(
                &s.denom
                    .ok_or_else(|| anyhow::anyhow!("missing denom metadata"))?
                    .try_into()?,
            )
            .ok_or_else(|| anyhow::anyhow!("could not generate default denom metadata"))?,
            destination_chain_address: s.destination_chain_address,
            return_address: s
                .return_address
                .ok_or_else(|| anyhow::anyhow!("missing sender"))?
                .try_into()?,
            timeout_height: s
                .timeout_height
                .ok_or_else(|| anyhow::anyhow!("missing timeout height"))?
                .try_into()?,
            timeout_time: s.timeout_time,
            source: match (s.source_channel.is_empty(), s.source_client.is_empty()) {
                (false, true) => Ics20WithdrawalSource::Channel(ChannelId::from_str(&s.source_channel)?),
                (true, false) => Ics20WithdrawalSource::Client(ClientId::from_str(&s.source_client)?),
                (false, false) => anyhow::bail!(
                    "ics20 withdrawal must set only one of source_channel and source_client"
                ),
                // Legacy: an empty source channel was accepted (and rejected at execution).
                (true, true) => Ics20WithdrawalSource::Channel(ChannelId::from_str(&s.source_channel)?),
            },
            use_compat_address: s.use_compat_address,
            ics20_memo: s.ics20_memo,
            use_transparent_address: s.use_transparent_address,
        })
    }
}

impl From<Ics20Withdrawal> for pb::FungibleTokenPacketData {
    fn from(w: Ics20Withdrawal) -> Self {
        let ordinary_return_address = w.return_address.to_string();

        let return_address = if w.use_transparent_address {
            w.return_address
                .encode_as_transparent_address()
                .unwrap_or_else(|| ordinary_return_address)
        } else {
            ordinary_return_address
        };

        pb::FungibleTokenPacketData {
            amount: w.value().amount.to_string(),
            denom: w.denom.to_string(),
            receiver: w.destination_chain_address,
            sender: return_address,
            memo: w.ics20_memo,
        }
    }
}
