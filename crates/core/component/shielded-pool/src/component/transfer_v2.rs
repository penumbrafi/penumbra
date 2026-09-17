//! ICS-20 fungible token transfer over IBC v2 (client-routed packets).
//!
//! Wire compatibility with ibc-go v10 and the Eureka `ICS20Transfer` contract:
//! port `transfer`, version `ics20-1`, payload encoding `application/x-protobuf`
//! of `ibc.applications.transfer.v2.FungibleTokenPacketData` (JSON accepted on
//! receive), success acknowledgement `{"result":"AQ=="}`, refunds on the
//! universal error acknowledgement. Escrow is keyed by the *local* client id
//! the transfer was routed over, and the denomination hop prefix is
//! `transfer/{client_id}/`.

use std::str::FromStr;

use anyhow::{Context, Result};
use async_trait::async_trait;
use cnidarium::{StateRead, StateWrite};
use ibc_types::{core::client::ClientId, transfer::acknowledgement::TokenTransferAcknowledgement};
use penumbra_sdk_asset::{asset, Value};
use penumbra_sdk_ibc::{
    component::{
        state_key,
        v2::{AppHandlerV2, SendPacketV2Read as _, SendPacketV2Write as _},
    },
    v2::{commitment::universal_error_acknowledgement, Packet, Payload},
};
use penumbra_sdk_keys::Address;
use penumbra_sdk_num::Amount;
use penumbra_sdk_proto::{
    penumbra::core::component::ibc::v1::FungibleTokenPacketData, DomainType as _, StateReadProto,
    StateWriteProto,
};
use penumbra_sdk_sct::CommitmentSource;
use prost::Message as _;
use tendermint::Time;

use super::Ics20Transfer;
use crate::{
    component::{AssetRegistry, NoteManager},
    event::{self, FungibleTokenTransferPacketMetadata},
    Ics20Withdrawal,
};

pub const PORT: &str = "transfer";
pub const VERSION: &str = "ics20-1";
pub const ENCODING_PROTOBUF: &str = "application/x-protobuf";
pub const ENCODING_JSON: &str = "application/json";

type RawFungibleTokenPacketData = ibc_proto::ibc::applications::transfer::v2::FungibleTokenPacketData;

fn encode_packet_data(data: &FungibleTokenPacketData) -> Vec<u8> {
    RawFungibleTokenPacketData {
        denom: data.denom.clone(),
        amount: data.amount.clone(),
        sender: data.sender.clone(),
        receiver: data.receiver.clone(),
        memo: data.memo.clone(),
    }
    .encode_to_vec()
}

fn decode_packet_data(payload: &Payload) -> Result<FungibleTokenPacketData> {
    match payload.encoding.as_str() {
        ENCODING_PROTOBUF => {
            let raw = RawFungibleTokenPacketData::decode(payload.value.as_slice())
                .context("invalid protobuf FungibleTokenPacketData")?;
            Ok(FungibleTokenPacketData {
                denom: raw.denom,
                amount: raw.amount,
                sender: raw.sender,
                receiver: raw.receiver,
                memo: raw.memo,
            })
        }
        ENCODING_JSON => {
            serde_json::from_slice(&payload.value).context("invalid JSON FungibleTokenPacketData")
        }
        other => anyhow::bail!("unsupported ICS-20 payload encoding {other:?}"),
    }
}

/// Denomination prefix for tokens that arrived over `client_id`.
fn hop_prefix(port: &str, client_id: &str) -> String {
    format!("{port}/{client_id}/")
}

/// The v2 payload for a withdrawal.
pub fn payload_for(withdrawal: &Ics20Withdrawal) -> Payload {
    let data: FungibleTokenPacketData = withdrawal.clone().into();
    Payload {
        source_port: PORT.into(),
        destination_port: PORT.into(),
        version: VERSION.into(),
        encoding: ENCODING_PROTOBUF.into(),
        value: encode_packet_data(&data),
    }
}

pub(super) async fn withdrawal_check_v2<S: StateRead + ?Sized>(
    state: &S,
    withdrawal: &Ics20Withdrawal,
    source_client: &ClientId,
    now: Time,
) -> Result<()> {
    let payload = payload_for(withdrawal);
    state
        .send_packet_v2_check(
            source_client,
            withdrawal.timeout_time_seconds(),
            &payload,
            now,
        )
        .await
}

pub(super) async fn withdrawal_execute_v2<S: StateWrite + ?Sized>(
    state: &mut S,
    withdrawal: &Ics20Withdrawal,
    source_client: &ClientId,
) -> Result<()> {
    let client = source_client.as_str();
    let key = state_key::ics20_value_balance::by_client_id(client, &withdrawal.denom.id());
    let balance: Amount = state.get(&key).await?.unwrap_or_else(Amount::zero);

    if !withdrawal.denom.starts_with(&hop_prefix(PORT, client)) {
        // We are the source: escrow.
        let new_balance = balance
            .checked_add(&withdrawal.amount)
            .ok_or_else(|| anyhow::anyhow!("overflow adding value balance in ics20 withdrawal"))?;
        state.put(key, new_balance);
    } else {
        // The token came in over this client: burn, never more than came in.
        anyhow::ensure!(
            balance >= withdrawal.amount,
            "insufficient balance to withdraw tokens"
        );
        let new_balance = balance
            .checked_sub(&withdrawal.amount)
            .ok_or_else(|| anyhow::anyhow!("underflow subtracting value balance in ics20 withdrawal"))?;
        state.put(key, new_balance);
    }

    let packet = state
        .send_packet_v2_execute(
            source_client,
            withdrawal.timeout_time_seconds(),
            payload_for(withdrawal),
        )
        .await?;

    state.record_proto(
        event::EventOutboundFungibleTokenTransfer {
            value: withdrawal.value(),
            sender: withdrawal.return_address.clone(),
            receiver: withdrawal.destination_chain_address.clone(),
            meta: FungibleTokenTransferPacketMetadata {
                channel: client.to_string(),
                sequence: packet.sequence,
            },
        }
        .to_proto(),
    );
    Ok(())
}

async fn recv_transfer_v2<S: StateWrite>(
    mut state: S,
    packet: &Packet,
    payload: &Payload,
) -> Result<()> {
    anyhow::ensure!(
        payload.version == VERSION,
        "unsupported ICS-20 version {:?}",
        payload.version
    );
    anyhow::ensure!(
        payload.destination_port == PORT,
        "unexpected destination port {:?}",
        payload.destination_port
    );
    let data = decode_packet_data(payload)?;
    let amount: Amount = data
        .amount
        .clone()
        .try_into()
        .context("couldnt decode amount in ICS20 transfer")?;
    let receiver = Address::from_str(&data.receiver).context("invalid receiver address")?;
    // Escrow is keyed by our own client id.
    let our_client = packet.destination_client.as_str();
    let source_prefix = hop_prefix(&payload.source_port, &packet.source_client);

    if let Some(unprefixed) = data.denom.strip_prefix(&source_prefix) {
        // The token originated here and is coming back: unescrow.
        let denom: asset::Metadata = unprefixed
            .try_into()
            .context("couldnt decode denom in ICS20 transfer")?;
        let value = Value {
            amount,
            asset_id: denom.id(),
        };
        let key = state_key::ics20_value_balance::by_client_id(our_client, &denom.id());
        let balance: Amount = state.get(&key).await?.unwrap_or_else(Amount::zero);
        anyhow::ensure!(balance >= amount, "transfer coins failed");
        state
            .mint_note(
                value,
                &receiver,
                CommitmentSource::Ics20Transfer {
                    packet_seq: packet.sequence,
                    channel_id: packet.source_client.clone(),
                    sender: data.sender.clone(),
                },
            )
            .await
            .context("unable to mint note when receiving ics20 transfer packet")?;
        let new_balance = balance
            .checked_sub(&amount)
            .context("underflow subtracting value balance in ics20 transfer")?;
        state.put(key, new_balance);
        state.record_proto(
            event::EventInboundFungibleTokenTransfer {
                value,
                sender: data.sender.clone(),
                receiver,
                meta: FungibleTokenTransferPacketMetadata {
                    channel: packet.source_client.clone(),
                    sequence: packet.sequence,
                },
            }
            .to_proto(),
        );
    } else {
        // Foreign token: mint a voucher under `transfer/{our_client}/{denom}`.
        let prefixed = format!("{}/{}/{}", payload.destination_port, our_client, data.denom);
        let denom: asset::Metadata = prefixed
            .as_str()
            .try_into()
            .context("unable to parse denom in ics20 transfer as DenomMetadata")?;
        state.register_denom(&denom).await;
        let value = Value {
            amount,
            asset_id: denom.id(),
        };
        state
            .mint_note(
                value,
                &receiver,
                CommitmentSource::Ics20Transfer {
                    packet_seq: packet.sequence,
                    channel_id: packet.source_client.clone(),
                    sender: data.sender.clone(),
                },
            )
            .await
            .context("failed to mint notes in ibc transfer")?;
        let key = state_key::ics20_value_balance::by_client_id(our_client, &denom.id());
        let balance: Amount = state.get(&key).await?.unwrap_or_else(Amount::zero);
        state.put(key, balance.saturating_add(&amount));
        state.record_proto(
            event::EventInboundFungibleTokenTransfer {
                value,
                sender: data.sender.clone(),
                receiver,
                meta: FungibleTokenTransferPacketMetadata {
                    channel: packet.source_client.clone(),
                    sequence: packet.sequence,
                },
            }
            .to_proto(),
        );
    }
    Ok(())
}

async fn refund_v2<S: StateWrite>(
    mut state: S,
    packet: &Packet,
    payload: &Payload,
    reason: event::FungibleTokenRefundReason,
) -> Result<()> {
    let data = decode_packet_data(payload)?;
    let denom: asset::Metadata = data
        .denom
        .as_str()
        .try_into()
        .context("couldn't decode denom in ics20 transfer refund")?;
    let amount: Amount = data
        .amount
        .clone()
        .try_into()
        .context("couldn't decode amount in ics20 transfer refund")?;
    // The original sender is the refund receiver.
    let receiver = Address::from_str(&data.sender)
        .context("couldn't decode sender address in ics20 refund")?;
    let value = Value {
        amount,
        asset_id: denom.id(),
    };
    let our_client = packet.source_client.as_str();
    let key = state_key::ics20_value_balance::by_client_id(our_client, &denom.id());
    let balance: Amount = state.get(&key).await?.unwrap_or_else(Amount::zero);

    if !denom.starts_with(&hop_prefix(&payload.source_port, our_client)) {
        // We were the source: unescrow back to the sender.
        anyhow::ensure!(
            balance >= amount,
            "couldn't return coins in refund: not enough value balance"
        );
        state
            .mint_note(
                value,
                &receiver,
                CommitmentSource::Ics20Transfer {
                    packet_seq: packet.sequence,
                    channel_id: our_client.to_string(),
                    sender: data.sender.clone(),
                },
            )
            .await
            .context("couldn't mint note in ics20 refund")?;
        let new_balance = balance
            .checked_sub(&amount)
            .context("underflow in ics20 refund value balance subtraction")?;
        state.put(key, new_balance);
    } else {
        // The voucher was burned on send: mint it back.
        state
            .mint_note(
                value,
                &receiver,
                CommitmentSource::Ics20Transfer {
                    packet_seq: packet.sequence,
                    channel_id: our_client.to_string(),
                    sender: data.sender.clone(),
                },
            )
            .await
            .context("failed to mint return voucher in ics20 refund")?;
        state.put(key, balance.saturating_add(&amount));
    }
    state.record_proto(
        event::EventOutboundFungibleTokenRefund {
            value,
            sender: receiver,
            receiver: data.receiver.clone(),
            reason,
            meta: FungibleTokenTransferPacketMetadata {
                channel: our_client.to_string(),
                sequence: packet.sequence,
            },
        }
        .to_proto(),
    );
    Ok(())
}

#[async_trait]
impl AppHandlerV2 for Ics20Transfer {
    fn handles_port_v2(port: &str) -> bool {
        port == PORT
    }

    async fn recv_payload_v2<S: StateWrite>(
        mut state: S,
        packet: &Packet,
        payload: &Payload,
    ) -> Result<Vec<u8>> {
        recv_transfer_v2(&mut state, packet, payload).await?;
        Ok(TokenTransferAcknowledgement::success().into())
    }

    async fn acknowledge_payload_v2<S: StateWrite>(
        mut state: S,
        packet: &Packet,
        payload: &Payload,
        ack: &[u8],
    ) -> Result<()> {
        // ibc-go v2 transfer: the universal error ack refunds; otherwise the
        // ack is an ICS-20 JSON acknowledgement and an error result refunds.
        let failed = if ack == universal_error_acknowledgement().as_slice() {
            true
        } else {
            let parsed: TokenTransferAcknowledgement =
                serde_json::from_slice(ack).context("unparseable ICS-20 acknowledgement")?;
            !parsed.is_successful()
        };
        if failed {
            refund_v2(
                &mut state,
                packet,
                payload,
                event::FungibleTokenRefundReason::Error,
            )
            .await
            .context("unable to refund acknowledged packet")?;
        }
        Ok(())
    }

    async fn timeout_payload_v2<S: StateWrite>(
        mut state: S,
        packet: &Packet,
        payload: &Payload,
    ) -> Result<()> {
        refund_v2(
            &mut state,
            packet,
            payload,
            event::FungibleTokenRefundReason::Timeout,
        )
        .await
        .context("unable to refund timed out packet")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data() -> FungibleTokenPacketData {
        FungibleTokenPacketData {
            denom: "upenumbra".into(),
            amount: "1000000".into(),
            sender: "sender".into(),
            receiver: "receiver".into(),
            memo: "memo".into(),
        }
    }

    #[test]
    fn protobuf_payload_round_trips_through_ibc_go_type() {
        let bytes = encode_packet_data(&data());
        let raw = RawFungibleTokenPacketData::decode(bytes.as_slice()).unwrap();
        assert_eq!(raw.denom, "upenumbra");
        assert_eq!(raw.amount, "1000000");
        let payload = Payload {
            source_port: PORT.into(),
            destination_port: PORT.into(),
            version: VERSION.into(),
            encoding: ENCODING_PROTOBUF.into(),
            value: bytes,
        };
        assert_eq!(decode_packet_data(&payload).unwrap(), data());
    }

    #[test]
    fn json_payload_is_accepted_and_unknown_encoding_is_not() {
        let json = br#"{"denom":"upenumbra","amount":"1000000","sender":"sender","receiver":"receiver","memo":"memo"}"#;
        let mut payload = Payload {
            source_port: PORT.into(),
            destination_port: PORT.into(),
            version: VERSION.into(),
            encoding: ENCODING_JSON.into(),
            value: json.to_vec(),
        };
        assert_eq!(decode_packet_data(&payload).unwrap(), data());
        payload.encoding = "application/x-solidity-abi".into();
        assert!(decode_packet_data(&payload).is_err());
    }

    #[test]
    fn success_ack_is_ibc_go_json() {
        let ack: Vec<u8> = TokenTransferAcknowledgement::success().into();
        assert_eq!(ack, br#"{"result":"AQ=="}"#);
    }
}
