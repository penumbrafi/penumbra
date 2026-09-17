//! Hand-written prost definitions for `ibc.core.channel.v2` and
//! `ibc.core.client.v2` (ibc-go v10), which `ibc-proto` 0.51 does not ship.
//!
//! Field numbers are copied from ibc-go's `proto/ibc/core/channel/v2/{packet,tx}.proto`
//! and `proto/ibc/core/client/v2/tx.proto`; the type URLs are what relayers
//! and the proof-api put on the wire, so they must match exactly.

use ibc_proto::ibc::core::client::v1::Height;

macro_rules! prost_name {
    ($ty:ident, $pkg:literal) => {
        impl ::prost::Name for $ty {
            const NAME: &'static str = stringify!($ty);
            const PACKAGE: &'static str = $pkg;
            fn full_name() -> ::prost::alloc::string::String {
                concat!($pkg, ".", stringify!($ty)).into()
            }
            fn type_url() -> ::prost::alloc::string::String {
                concat!("/", $pkg, ".", stringify!($ty)).into()
            }
        }
    };
}

/// A single application payload inside a v2 packet.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Payload {
    #[prost(string, tag = "1")]
    pub source_port: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub destination_port: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub version: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub encoding: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "5")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
prost_name!(Payload, "ibc.core.channel.v2");

/// A v2 packet, routed by client id.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Packet {
    #[prost(uint64, tag = "1")]
    pub sequence: u64,
    #[prost(string, tag = "2")]
    pub source_client: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub destination_client: ::prost::alloc::string::String,
    /// Unix seconds.
    #[prost(uint64, tag = "4")]
    pub timeout_timestamp: u64,
    #[prost(message, repeated, tag = "5")]
    pub payloads: ::prost::alloc::vec::Vec<Payload>,
}
prost_name!(Packet, "ibc.core.channel.v2");

/// One acknowledgement per payload.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Acknowledgement {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub app_acknowledgements: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
prost_name!(Acknowledgement, "ibc.core.channel.v2");

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSendPacket {
    #[prost(string, tag = "1")]
    pub source_client: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub timeout_timestamp: u64,
    #[prost(message, repeated, tag = "3")]
    pub payloads: ::prost::alloc::vec::Vec<Payload>,
    #[prost(string, tag = "4")]
    pub signer: ::prost::alloc::string::String,
}
prost_name!(MsgSendPacket, "ibc.core.channel.v2");

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgRecvPacket {
    #[prost(message, optional, tag = "1")]
    pub packet: ::core::option::Option<Packet>,
    #[prost(bytes = "vec", tag = "2")]
    pub proof_commitment: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub proof_height: ::core::option::Option<Height>,
    #[prost(string, tag = "4")]
    pub signer: ::prost::alloc::string::String,
}
prost_name!(MsgRecvPacket, "ibc.core.channel.v2");

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgTimeout {
    #[prost(message, optional, tag = "1")]
    pub packet: ::core::option::Option<Packet>,
    #[prost(bytes = "vec", tag = "2")]
    pub proof_unreceived: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub proof_height: ::core::option::Option<Height>,
    #[prost(string, tag = "5")]
    pub signer: ::prost::alloc::string::String,
}
prost_name!(MsgTimeout, "ibc.core.channel.v2");

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgAcknowledgement {
    #[prost(message, optional, tag = "1")]
    pub packet: ::core::option::Option<Packet>,
    #[prost(message, optional, tag = "2")]
    pub acknowledgement: ::core::option::Option<Acknowledgement>,
    #[prost(bytes = "vec", tag = "3")]
    pub proof_acked: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub proof_height: ::core::option::Option<Height>,
    #[prost(string, tag = "5")]
    pub signer: ::prost::alloc::string::String,
}
prost_name!(MsgAcknowledgement, "ibc.core.channel.v2");

/// Stored pairing of a local client with its counterparty (`ibc.core.client.v2`).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CounterpartyInfo {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub merkle_prefix: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(string, tag = "2")]
    pub client_id: ::prost::alloc::string::String,
}
prost_name!(CounterpartyInfo, "ibc.core.client.v2");

/// Pairs a local client with a counterparty client (`ibc.core.client.v2`).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgRegisterCounterparty {
    #[prost(string, tag = "1")]
    pub client_id: ::prost::alloc::string::String,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub counterparty_merkle_prefix: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(string, tag = "3")]
    pub counterparty_client_id: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub signer: ::prost::alloc::string::String,
}
prost_name!(MsgRegisterCounterparty, "ibc.core.client.v2");

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Name;

    #[test]
    fn type_urls_match_ibc_go() {
        assert_eq!(MsgRecvPacket::type_url(), "/ibc.core.channel.v2.MsgRecvPacket");
        assert_eq!(MsgTimeout::type_url(), "/ibc.core.channel.v2.MsgTimeout");
        assert_eq!(
            MsgAcknowledgement::type_url(),
            "/ibc.core.channel.v2.MsgAcknowledgement"
        );
        assert_eq!(MsgSendPacket::type_url(), "/ibc.core.channel.v2.MsgSendPacket");
        assert_eq!(
            MsgRegisterCounterparty::type_url(),
            "/ibc.core.client.v2.MsgRegisterCounterparty"
        );
        assert_eq!(Packet::type_url(), "/ibc.core.channel.v2.Packet");
    }
}
