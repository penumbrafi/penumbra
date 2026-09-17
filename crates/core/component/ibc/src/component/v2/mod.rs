//! IBC v2 state machine: counterparty registry, client-routed packets,
//! byte-keyed ICS-24 v2 commitments, and the payload router.
//!
//! Key/client matrix (the classic v2 bug is mixing these up):
//!
//! | handler  | verify on client            | key                                  | proof                          |
//! |----------|-----------------------------|--------------------------------------|--------------------------------|
//! | recv     | `packet.destination_client` | `source_client ‖ 0x01 ‖ seq`         | membership of `commit_packet`  |
//! | ack      | `packet.source_client`      | `destination_client ‖ 0x03 ‖ seq`    | membership of `commit_ack`     |
//! | timeout  | `packet.source_client`      | `destination_client ‖ 0x02 ‖ seq`    | non-membership                 |
//!
//! recv additionally requires `counterparty(destination_client).client_id ==
//! source_client`; ack and timeout require the mirror. The merkle path is the
//! counterparty prefix with the key concatenated onto its last element.

pub mod app_handler;
pub mod events;
pub mod msg_handler;
pub mod proof;
pub mod send;
pub mod state;
pub mod state_key;

pub use app_handler::AppHandlerV2;
pub use send::{SendPacketV2Read, SendPacketV2Write};
pub use state::{StateReadExt as V2StateReadExt, StateWriteExt as V2StateWriteExt};

#[cfg(test)]
mod tests;
