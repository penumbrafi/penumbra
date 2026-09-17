//! Payload router for IBC v2 applications.
//!
//! v2 has no channel handshake, so the handshake-shaped [`super::super::app_handler`]
//! is not extended. An application answers for a port string and gets one
//! callback per packet lifecycle event. On receive, the application runs in a
//! sub-delta: an `Err` rolls its writes back and the packet is acknowledged
//! with the universal error acknowledgement, while the transaction succeeds.

use anyhow::Result;
use async_trait::async_trait;
use cnidarium::StateWrite;

use crate::v2::{Packet, Payload};

#[async_trait]
pub trait AppHandlerV2: Send + Sync {
    /// Whether this application handles `port`.
    fn handles_port_v2(port: &str) -> bool;

    /// Process an inbound payload. Returns the app acknowledgement bytes.
    /// An `Err` is turned into the universal error acknowledgement and the
    /// application's state changes are discarded.
    async fn recv_payload_v2<S: StateWrite>(
        state: S,
        packet: &Packet,
        payload: &Payload,
    ) -> Result<Vec<u8>>;

    /// The counterparty acknowledged a payload we sent. `ack` is the app
    /// acknowledgement, or the universal error acknowledgement on failure.
    async fn acknowledge_payload_v2<S: StateWrite>(
        state: S,
        packet: &Packet,
        payload: &Payload,
        ack: &[u8],
    ) -> Result<()>;

    /// A payload we sent timed out and was provably never received.
    async fn timeout_payload_v2<S: StateWrite>(
        state: S,
        packet: &Packet,
        payload: &Payload,
    ) -> Result<()>;
}
