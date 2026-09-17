//! Domain types for IBC v2 packets and relay messages.
//!
//! Client identifiers inside packets are kept as validated strings rather
//! than [`ibc_types::core::client::ClientId`]: the Eureka Ethereum router
//! names its clients `client-N` (8 characters), which ibc-types' 9-character
//! minimum would reject. ibc-go validates v2 client ids with the channel
//! identifier rule (8 to 64 characters), and so do we. Penumbra's *own*
//! client id in a packet is parsed into a `ClientId` at the point of use.

use anyhow::{Context, Result};
use ibc_types::core::{client::Height, commitment::MerkleProof};
use ibc_types::DomainType as IbcDomainType;
use penumbra_sdk_proto::DomainType;

use super::proto;

/// Validate an ICS-24 identifier: length bounds, no path separator, ICS-24 charset.
fn validate_identifier(id: &str, min: usize, max: usize, what: &str) -> Result<()> {
    anyhow::ensure!(!id.is_empty(), "{what} must not be empty");
    anyhow::ensure!(
        (min..=max).contains(&id.len()),
        "{what} {id:?} must be between {min} and {max} characters"
    );
    anyhow::ensure!(!id.contains('/'), "{what} {id:?} must not contain '/'");
    anyhow::ensure!(
        id.chars()
            .all(|c| c.is_ascii_alphanumeric() || ".+_-#[]<>".contains(c)),
        "{what} {id:?} contains characters outside the ICS-24 set"
    );
    Ok(())
}

/// ibc-go validates v2 client ids (`Packet.source_client`, counterparty ids)
/// with `ChannelIdentifierValidator`: 8 to 64 characters.
pub fn validate_client_id(id: &str) -> Result<()> {
    validate_identifier(id, 8, 64, "client id")
}

/// ibc-go `PortIdentifierValidator`: 2 to 128 characters.
pub fn validate_port_id(id: &str) -> Result<()> {
    validate_identifier(id, 2, 128, "port id")
}

/// One application payload. A v2 packet carries a list of these, but both
/// ibc-go's transfer app and the Eureka router only handle exactly one, so
/// Penumbra enforces exactly one (see [`Packet::validate_basic`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub source_port: String,
    pub destination_port: String,
    pub version: String,
    pub encoding: String,
    pub value: Vec<u8>,
}

impl Payload {
    pub fn validate_basic(&self) -> Result<()> {
        validate_port_id(&self.source_port).context("payload source port")?;
        validate_port_id(&self.destination_port).context("payload destination port")?;
        anyhow::ensure!(!self.version.trim().is_empty(), "payload version cannot be empty");
        anyhow::ensure!(
            !self.encoding.trim().is_empty(),
            "payload encoding cannot be empty"
        );
        anyhow::ensure!(!self.value.is_empty(), "payload value cannot be empty");
        Ok(())
    }
}

/// Upper bound on the total payload bytes in one packet (ibc-go `MaximumPayloadsSize`).
pub const MAXIMUM_PAYLOADS_SIZE: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub sequence: u64,
    pub source_client: String,
    pub destination_client: String,
    /// Unix seconds. Classic IBC uses nanoseconds; do not share helpers.
    pub timeout_timestamp: u64,
    pub payloads: Vec<Payload>,
}

impl Packet {
    pub fn validate_basic(&self) -> Result<()> {
        anyhow::ensure!(self.sequence != 0, "packet sequence cannot be 0");
        anyhow::ensure!(
            self.timeout_timestamp != 0,
            "packet timeout timestamp cannot be 0"
        );
        validate_client_id(&self.source_client).context("packet source client")?;
        validate_client_id(&self.destination_client).context("packet destination client")?;
        anyhow::ensure!(
            self.payloads.len() == 1,
            "packet must carry exactly one payload, got {}",
            self.payloads.len()
        );
        let total: usize = self.payloads.iter().map(|p| p.value.len()).sum();
        anyhow::ensure!(
            total <= MAXIMUM_PAYLOADS_SIZE,
            "packet data bytes cannot exceed {MAXIMUM_PAYLOADS_SIZE} bytes"
        );
        for payload in &self.payloads {
            payload.validate_basic()?;
        }
        Ok(())
    }

    /// The single payload (see [`Packet::validate_basic`]).
    pub fn payload(&self) -> Result<&Payload> {
        anyhow::ensure!(self.payloads.len() == 1, "packet must carry exactly one payload");
        Ok(&self.payloads[0])
    }
}

/// One app acknowledgement per payload; on failure a single
/// [`super::commitment::universal_error_acknowledgement`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acknowledgement {
    pub app_acknowledgements: Vec<Vec<u8>>,
}

impl Acknowledgement {
    pub fn validate_basic(&self) -> Result<()> {
        anyhow::ensure!(
            self.app_acknowledgements.len() == 1,
            "acknowledgement must carry exactly one app acknowledgement"
        );
        anyhow::ensure!(
            !self.app_acknowledgements[0].is_empty(),
            "app acknowledgement cannot be empty"
        );
        Ok(())
    }

    pub fn is_error(&self) -> bool {
        self.app_acknowledgements.len() == 1
            && self.app_acknowledgements[0]
                == super::commitment::universal_error_acknowledgement().as_slice()
    }
}

#[derive(Debug, Clone)]
pub struct MsgRecvPacket {
    pub packet: Packet,
    pub proof_commitment: MerkleProof,
    pub proof_height: Height,
    pub signer: String,
}

#[derive(Debug, Clone)]
pub struct MsgAcknowledgement {
    pub packet: Packet,
    pub acknowledgement: Acknowledgement,
    pub proof_acked: MerkleProof,
    pub proof_height: Height,
    pub signer: String,
}

#[derive(Debug, Clone)]
pub struct MsgTimeout {
    pub packet: Packet,
    pub proof_unreceived: MerkleProof,
    pub proof_height: Height,
    pub signer: String,
}

/// Pair a local client with its counterparty. Penumbra accepts this only in
/// the same transaction as the `CreateClient` it refers to (see
/// `component::v2::msg_handler::register_counterparty`).
#[derive(Debug, Clone)]
pub struct MsgRegisterCounterparty {
    pub client_id: ibc_types::core::client::ClientId,
    /// Counterparty merkle prefix, e.g. `["ibc", ""]` for a Cosmos chain,
    /// `["ibc-data", ""]` for Penumbra.
    pub counterparty_merkle_prefix: Vec<Vec<u8>>,
    pub counterparty_client_id: String,
    pub signer: String,
}

impl MsgRegisterCounterparty {
    pub fn validate_basic(&self) -> Result<()> {
        validate_client_id(&self.counterparty_client_id).context("counterparty client id")?;
        anyhow::ensure!(
            !self.counterparty_merkle_prefix.is_empty(),
            "counterparty merkle prefix must not be empty"
        );
        anyhow::ensure!(
            !self.counterparty_merkle_prefix[0].is_empty(),
            "first element of counterparty merkle prefix must not be empty"
        );
        Ok(())
    }
}

// --- proto conversions -------------------------------------------------------

impl From<Payload> for proto::Payload {
    fn from(p: Payload) -> Self {
        proto::Payload {
            source_port: p.source_port,
            destination_port: p.destination_port,
            version: p.version,
            encoding: p.encoding,
            value: p.value,
        }
    }
}

impl From<proto::Payload> for Payload {
    fn from(p: proto::Payload) -> Self {
        Payload {
            source_port: p.source_port,
            destination_port: p.destination_port,
            version: p.version,
            encoding: p.encoding,
            value: p.value,
        }
    }
}

impl From<Packet> for proto::Packet {
    fn from(p: Packet) -> Self {
        proto::Packet {
            sequence: p.sequence,
            source_client: p.source_client,
            destination_client: p.destination_client,
            timeout_timestamp: p.timeout_timestamp,
            payloads: p.payloads.into_iter().map(Into::into).collect(),
        }
    }
}

impl DomainType for Packet {
    type Proto = proto::Packet;
}

impl TryFrom<proto::Packet> for Packet {
    type Error = anyhow::Error;
    fn try_from(p: proto::Packet) -> Result<Self> {
        Ok(Packet {
            sequence: p.sequence,
            source_client: p.source_client,
            destination_client: p.destination_client,
            timeout_timestamp: p.timeout_timestamp,
            payloads: p.payloads.into_iter().map(Into::into).collect(),
        })
    }
}

impl From<Acknowledgement> for proto::Acknowledgement {
    fn from(a: Acknowledgement) -> Self {
        proto::Acknowledgement {
            app_acknowledgements: a.app_acknowledgements,
        }
    }
}

impl From<proto::Acknowledgement> for Acknowledgement {
    fn from(a: proto::Acknowledgement) -> Self {
        Acknowledgement {
            app_acknowledgements: a.app_acknowledgements,
        }
    }
}

fn decode_proof(bytes: &[u8], what: &str) -> Result<MerkleProof> {
    <MerkleProof as IbcDomainType>::decode(bytes).with_context(|| format!("invalid {what}"))
}

fn decode_height(h: Option<ibc_proto::ibc::core::client::v1::Height>) -> Result<Height> {
    let h = h.ok_or_else(|| anyhow::anyhow!("missing proof height"))?;
    Height::try_from(h).context("invalid proof height")
}

impl DomainType for MsgRecvPacket {
    type Proto = proto::MsgRecvPacket;
}

impl TryFrom<proto::MsgRecvPacket> for MsgRecvPacket {
    type Error = anyhow::Error;
    fn try_from(m: proto::MsgRecvPacket) -> Result<Self> {
        Ok(Self {
            packet: m
                .packet
                .ok_or_else(|| anyhow::anyhow!("missing packet"))?
                .try_into()?,
            proof_commitment: decode_proof(&m.proof_commitment, "proof_commitment")?,
            proof_height: decode_height(m.proof_height)?,
            signer: m.signer,
        })
    }
}

impl From<MsgRecvPacket> for proto::MsgRecvPacket {
    fn from(m: MsgRecvPacket) -> Self {
        proto::MsgRecvPacket {
            packet: Some(m.packet.into()),
            proof_commitment: m.proof_commitment.encode_to_vec(),
            proof_height: Some(m.proof_height.into()),
            signer: m.signer,
        }
    }
}

impl DomainType for MsgAcknowledgement {
    type Proto = proto::MsgAcknowledgement;
}

impl TryFrom<proto::MsgAcknowledgement> for MsgAcknowledgement {
    type Error = anyhow::Error;
    fn try_from(m: proto::MsgAcknowledgement) -> Result<Self> {
        Ok(Self {
            packet: m
                .packet
                .ok_or_else(|| anyhow::anyhow!("missing packet"))?
                .try_into()?,
            acknowledgement: m
                .acknowledgement
                .ok_or_else(|| anyhow::anyhow!("missing acknowledgement"))?
                .into(),
            proof_acked: decode_proof(&m.proof_acked, "proof_acked")?,
            proof_height: decode_height(m.proof_height)?,
            signer: m.signer,
        })
    }
}

impl From<MsgAcknowledgement> for proto::MsgAcknowledgement {
    fn from(m: MsgAcknowledgement) -> Self {
        proto::MsgAcknowledgement {
            packet: Some(m.packet.into()),
            acknowledgement: Some(m.acknowledgement.into()),
            proof_acked: m.proof_acked.encode_to_vec(),
            proof_height: Some(m.proof_height.into()),
            signer: m.signer,
        }
    }
}

impl DomainType for MsgTimeout {
    type Proto = proto::MsgTimeout;
}

impl TryFrom<proto::MsgTimeout> for MsgTimeout {
    type Error = anyhow::Error;
    fn try_from(m: proto::MsgTimeout) -> Result<Self> {
        Ok(Self {
            packet: m
                .packet
                .ok_or_else(|| anyhow::anyhow!("missing packet"))?
                .try_into()?,
            proof_unreceived: decode_proof(&m.proof_unreceived, "proof_unreceived")?,
            proof_height: decode_height(m.proof_height)?,
            signer: m.signer,
        })
    }
}

impl From<MsgTimeout> for proto::MsgTimeout {
    fn from(m: MsgTimeout) -> Self {
        proto::MsgTimeout {
            packet: Some(m.packet.into()),
            proof_unreceived: m.proof_unreceived.encode_to_vec(),
            proof_height: Some(m.proof_height.into()),
            signer: m.signer,
        }
    }
}

impl DomainType for MsgRegisterCounterparty {
    type Proto = proto::MsgRegisterCounterparty;
}

impl TryFrom<proto::MsgRegisterCounterparty> for MsgRegisterCounterparty {
    type Error = anyhow::Error;
    fn try_from(m: proto::MsgRegisterCounterparty) -> Result<Self> {
        Ok(Self {
            client_id: m.client_id.parse().context("invalid client id")?,
            counterparty_merkle_prefix: m.counterparty_merkle_prefix,
            counterparty_client_id: m.counterparty_client_id,
            signer: m.signer,
        })
    }
}

impl From<MsgRegisterCounterparty> for proto::MsgRegisterCounterparty {
    fn from(m: MsgRegisterCounterparty) -> Self {
        proto::MsgRegisterCounterparty {
            client_id: m.client_id.to_string(),
            counterparty_merkle_prefix: m.counterparty_merkle_prefix,
            counterparty_client_id: m.counterparty_client_id,
            signer: m.signer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eureka_style_client_ids_are_accepted() {
        validate_client_id("client-0").unwrap();
        validate_client_id("07-tendermint-0").unwrap();
        assert!(validate_client_id("client").is_err());
        assert!(validate_client_id("a/b-cdefgh").is_err());
    }

    #[test]
    fn exactly_one_payload() {
        let payload = Payload {
            source_port: "transfer".into(),
            destination_port: "transfer".into(),
            version: "ics20-1".into(),
            encoding: "application/x-protobuf".into(),
            value: vec![1],
        };
        let mut packet = Packet {
            sequence: 1,
            source_client: "07-tendermint-0".into(),
            destination_client: "client-0".into(),
            timeout_timestamp: 1,
            payloads: vec![payload.clone()],
        };
        packet.validate_basic().unwrap();
        packet.payloads.push(payload);
        assert!(packet.validate_basic().is_err());
        packet.payloads.clear();
        assert!(packet.validate_basic().is_err());
    }

    #[test]
    fn msg_round_trips_through_proto() {
        let msg = MsgRecvPacket {
            packet: Packet {
                sequence: 7,
                source_client: "client-0".into(),
                destination_client: "07-tendermint-0".into(),
                timeout_timestamp: 1_700_000_000,
                payloads: vec![Payload {
                    source_port: "transfer".into(),
                    destination_port: "transfer".into(),
                    version: "ics20-1".into(),
                    encoding: "application/json".into(),
                    value: b"{}".to_vec(),
                }],
            },
            proof_commitment: MerkleProof { proofs: vec![] },
            proof_height: Height::new(0, 5).unwrap(),
            signer: "relayer".into(),
        };
        let bytes = msg.encode_to_vec();
        let back = MsgRecvPacket::decode(bytes.as_slice()).unwrap();
        assert_eq!(back.packet, msg.packet);
        assert_eq!(back.proof_height, msg.proof_height);
    }
}
