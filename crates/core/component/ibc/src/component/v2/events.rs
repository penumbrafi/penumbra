//! ABCI events for IBC v2, emitted with ibc-go's event types and attribute
//! keys verbatim so the Eureka proof-api's Cosmos listener and Hermes parse
//! Penumbra without a bespoke decoder.

use penumbra_sdk_proto::DomainType as _;
use tendermint::abci::{Event, EventAttributeIndexExt as _};

use crate::v2::{proto, Acknowledgement, Packet};

pub const EVENT_TYPE_SEND_PACKET: &str = "send_packet";
pub const EVENT_TYPE_RECV_PACKET: &str = "recv_packet";
pub const EVENT_TYPE_TIMEOUT_PACKET: &str = "timeout_packet";
pub const EVENT_TYPE_ACKNOWLEDGE_PACKET: &str = "acknowledge_packet";
pub const EVENT_TYPE_WRITE_ACK: &str = "write_acknowledgement";
pub const EVENT_TYPE_REGISTER_COUNTERPARTY: &str = "register_counterparty";

pub const ATTRIBUTE_KEY_SRC_CLIENT: &str = "packet_source_client";
pub const ATTRIBUTE_KEY_DST_CLIENT: &str = "packet_dest_client";
pub const ATTRIBUTE_KEY_SEQUENCE: &str = "packet_sequence";
pub const ATTRIBUTE_KEY_TIMEOUT_TIMESTAMP: &str = "packet_timeout_timestamp";
pub const ATTRIBUTE_KEY_ENCODED_PACKET_HEX: &str = "encoded_packet_hex";
pub const ATTRIBUTE_KEY_ENCODED_ACK_HEX: &str = "encoded_acknowledgement_hex";
pub const ATTRIBUTE_KEY_CLIENT_ID: &str = "client_id";
pub const ATTRIBUTE_KEY_COUNTERPARTY_CLIENT_ID: &str = "counterparty_client_id";

fn packet_event(kind: &str, packet: &Packet, ack: Option<&Acknowledgement>) -> Event {
    let mut attrs = vec![
        (ATTRIBUTE_KEY_SRC_CLIENT, packet.source_client.clone()).index(),
        (ATTRIBUTE_KEY_DST_CLIENT, packet.destination_client.clone()).index(),
        (ATTRIBUTE_KEY_SEQUENCE, packet.sequence.to_string()).index(),
        (
            ATTRIBUTE_KEY_TIMEOUT_TIMESTAMP,
            packet.timeout_timestamp.to_string(),
        )
            .index(),
        (
            ATTRIBUTE_KEY_ENCODED_PACKET_HEX,
            hex::encode(packet.encode_to_vec()),
        )
            .index(),
    ];
    if let Some(ack) = ack {
        let raw: proto::Acknowledgement = ack.clone().into();
        attrs.push(
            (
                ATTRIBUTE_KEY_ENCODED_ACK_HEX,
                hex::encode(prost::Message::encode_to_vec(&raw)),
            )
                .index(),
        );
    }
    Event::new(kind, attrs)
}

pub fn send_packet(packet: &Packet) -> Event {
    packet_event(EVENT_TYPE_SEND_PACKET, packet, None)
}

pub fn recv_packet(packet: &Packet) -> Event {
    packet_event(EVENT_TYPE_RECV_PACKET, packet, None)
}

pub fn write_acknowledgement(packet: &Packet, ack: &Acknowledgement) -> Event {
    packet_event(EVENT_TYPE_WRITE_ACK, packet, Some(ack))
}

pub fn acknowledge_packet(packet: &Packet, ack: &Acknowledgement) -> Event {
    packet_event(EVENT_TYPE_ACKNOWLEDGE_PACKET, packet, Some(ack))
}

pub fn timeout_packet(packet: &Packet) -> Event {
    packet_event(EVENT_TYPE_TIMEOUT_PACKET, packet, None)
}

pub fn register_counterparty(client_id: &str, counterparty_client_id: &str) -> Event {
    Event::new(
        EVENT_TYPE_REGISTER_COUNTERPARTY,
        vec![
            (ATTRIBUTE_KEY_CLIENT_ID, client_id.to_string()).index(),
            (
                ATTRIBUTE_KEY_COUNTERPARTY_CLIENT_ID,
                counterparty_client_id.to_string(),
            )
                .index(),
        ],
    )
}
