//! State keys for IBC v2.
//!
//! The ICS-24 v2 commitment keys are raw bytes at the root of the `ibc-data`
//! substore (see [`crate::v2::commitment`]); everything here is internal
//! bookkeeping that counterparties never prove against.

use crate::IBC_SUBSTORE_PREFIX;

/// Counterparty registration for a local client.
pub fn counterparty(client_id: &str) -> String {
    format!("{IBC_SUBSTORE_PREFIX}/v2/counterparty/{client_id}")
}

/// Next send sequence for a local client; `1` once the counterparty is registered.
pub fn next_sequence_send(client_id: &str) -> String {
    format!("{IBC_SUBSTORE_PREFIX}/v2/nextSequenceSend/{client_id}")
}

/// Ephemeral (object store) list of client ids created in the current
/// transaction, reset by `Ibc::begin_transaction`. `RegisterCounterparty` is
/// only accepted for clients in this list.
pub const CLIENTS_CREATED_IN_TX: &str = "ibc/v2/clients_created_in_tx";

/// Full verifiable-store key for an ICS-24 v2 commitment key.
pub fn commitment(key: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(IBC_SUBSTORE_PREFIX.len() + 1 + key.len());
    k.extend_from_slice(IBC_SUBSTORE_PREFIX.as_bytes());
    k.push(b'/');
    k.extend_from_slice(key);
    k
}
