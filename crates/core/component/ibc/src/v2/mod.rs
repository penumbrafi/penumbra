//! IBC v2 ("Eureka") packet layer: client-routed packets without connections
//! or channels. See `docs/design/ibc-v2.md`.
//!
//! This module holds the parts that are needed without the `component`
//! feature: wire types, domain types and the commitment scheme. The state
//! machine lives in [`crate::component::v2`].

pub mod commitment;
pub mod msgs;
pub mod proto;

pub use msgs::{
    Acknowledgement, MsgAcknowledgement, MsgRecvPacket, MsgRegisterCounterparty, MsgTimeout,
    Packet, Payload,
};
