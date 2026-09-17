//! IBC v2 commitment scheme and ICS-24 v2 key layout.
//!
//! Pinned byte for byte to ibc-go `modules/core/04-channel/v2/types/commitment.go`
//! and `cosmos/solidity-ibc-eureka` `ICS24Host.sol`, which agree. The Ethereum
//! router recomputes these on receive, so one byte off is a silent, total
//! failure; the tests carry ibc-go's fixed vectors.

use sha2::{Digest, Sha256};

use super::msgs::{Packet, Payload};

/// Version byte prepended to every v2 commitment.
const COMMITMENT_VERSION: u8 = 0x02;

/// Key separator for packet commitments: `clientId || 0x01 || u64_be(seq)`.
pub const PACKET_COMMITMENT_SEPARATOR: u8 = 0x01;
/// Key separator for packet receipts: `clientId || 0x02 || u64_be(seq)`.
pub const PACKET_RECEIPT_SEPARATOR: u8 = 0x02;
/// Key separator for acknowledgements: `clientId || 0x03 || u64_be(seq)`.
pub const PACKET_ACKNOWLEDGEMENT_SEPARATOR: u8 = 0x03;

/// Longest a v2 packet may live: sender rejects `timeout > now + MAX_TIMEOUT_DELTA_SECS`
/// (ibc-go `MaxTimeoutDelta`, Eureka `MAX_TIMEOUT_DURATION`, both one day).
pub const MAX_TIMEOUT_DELTA_SECS: u64 = 24 * 60 * 60;

/// `sha256("UNIVERSAL_ERROR_ACKNOWLEDGEMENT")`: the single app acknowledgement
/// written when any payload's application fails on receive.
pub fn universal_error_acknowledgement() -> [u8; 32] {
    Sha256::digest(b"UNIVERSAL_ERROR_ACKNOWLEDGEMENT").into()
}

/// `hash_payload(p) = sha256(h(src_port) || h(dst_port) || h(version) || h(encoding) || h(value))`.
pub fn hash_payload(payload: &Payload) -> [u8; 32] {
    let mut buf = Vec::with_capacity(5 * 32);
    buf.extend_from_slice(&Sha256::digest(payload.source_port.as_bytes()));
    buf.extend_from_slice(&Sha256::digest(payload.destination_port.as_bytes()));
    buf.extend_from_slice(&Sha256::digest(payload.version.as_bytes()));
    buf.extend_from_slice(&Sha256::digest(payload.encoding.as_bytes()));
    buf.extend_from_slice(&Sha256::digest(&payload.value));
    Sha256::digest(&buf).into()
}

/// `sha256(0x02 || h(dest_client) || h(u64_be(timeout)) || h(concat(hash_payload(p))))`.
pub fn commit_packet(packet: &Packet) -> [u8; 32] {
    let mut app_bytes = Vec::with_capacity(packet.payloads.len() * 32);
    for payload in &packet.payloads {
        app_bytes.extend_from_slice(&hash_payload(payload));
    }
    let mut buf = Vec::with_capacity(1 + 3 * 32);
    buf.push(COMMITMENT_VERSION);
    buf.extend_from_slice(&Sha256::digest(packet.destination_client.as_bytes()));
    buf.extend_from_slice(&Sha256::digest(packet.timeout_timestamp.to_be_bytes()));
    buf.extend_from_slice(&Sha256::digest(&app_bytes));
    Sha256::digest(&buf).into()
}

/// `sha256(0x02 || h(ack_1) || h(ack_2) || ...)`.
pub fn commit_acknowledgement(app_acknowledgements: &[Vec<u8>]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + app_acknowledgements.len() * 32);
    buf.push(COMMITMENT_VERSION);
    for ack in app_acknowledgements {
        buf.extend_from_slice(&Sha256::digest(ack));
    }
    Sha256::digest(&buf).into()
}

fn key(client_id: &str, separator: u8, sequence: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(client_id.len() + 1 + 8);
    k.extend_from_slice(client_id.as_bytes());
    k.push(separator);
    k.extend_from_slice(&sequence.to_be_bytes());
    k
}

/// ICS-24 v2 packet commitment key, relative to the IBC commitment prefix.
pub fn packet_commitment_key(client_id: &str, sequence: u64) -> Vec<u8> {
    key(client_id, PACKET_COMMITMENT_SEPARATOR, sequence)
}

/// ICS-24 v2 packet receipt key, relative to the IBC commitment prefix.
pub fn packet_receipt_key(client_id: &str, sequence: u64) -> Vec<u8> {
    key(client_id, PACKET_RECEIPT_SEPARATOR, sequence)
}

/// ICS-24 v2 packet acknowledgement key, relative to the IBC commitment prefix.
pub fn packet_acknowledgement_key(client_id: &str, sequence: u64) -> Vec<u8> {
    key(client_id, PACKET_ACKNOWLEDGEMENT_SEPARATOR, sequence)
}

/// Combine a counterparty merkle prefix with a key the way ibc-go's
/// `BuildMerklePath` and Eureka's `ICS24Host.prefixedPath` do: the key is
/// concatenated onto the *last* prefix element, not appended as a new one.
///
/// For a Cosmos counterparty the prefix is `["ibc", ""]`, so the path becomes
/// `["ibc", key]`; for Penumbra it is `["ibc-data", ""]`.
pub fn build_merkle_path(prefix: &[Vec<u8>], key: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    anyhow::ensure!(!prefix.is_empty(), "counterparty merkle prefix must not be empty");
    let mut path = prefix.to_vec();
    path.last_mut()
        .expect("non-empty prefix")
        .extend_from_slice(key);
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transfer_payload(encoding: &str, value: Vec<u8>) -> Payload {
        Payload {
            source_port: "transfer".into(),
            destination_port: "transfer".into(),
            version: "ics20-1".into(),
            encoding: encoding.into(),
            value,
        }
    }

    /// ibc-go `TestCommitPacket` (JSON case): sequence 1, 07-tendermint-0 →
    /// 07-tendermint-1, timeout 100, `json.Marshal(FungibleTokenPacketData{
    /// uatom, "1000000", sender, receiver, memo})`.
    #[test]
    fn packet_commitment_matches_ibc_go_vector() {
        let value = br#"{"denom":"uatom","amount":"1000000","sender":"sender","receiver":"receiver","memo":"memo"}"#.to_vec();
        let packet = Packet {
            sequence: 1,
            source_client: "07-tendermint-0".into(),
            destination_client: "07-tendermint-1".into(),
            timeout_timestamp: 100,
            payloads: vec![transfer_payload("application/json", value)],
        };
        assert_eq!(
            hex::encode(commit_packet(&packet)),
            "a096722aa6534040a0efbdae05765132a7b223ad306d6512f3734821bd046505"
        );
    }

    /// ibc-go `TestCommitAcknowledgement` and Eureka `test_packetAcknowledgementCommitment`.
    #[test]
    fn ack_commitment_matches_ibc_go_and_eureka_vector() {
        assert_eq!(
            hex::encode(commit_acknowledgement(&[b"some bytes".to_vec()])),
            "f03b4667413e56aaf086663267913e525c442b56fa1af4fa3f3dab9f37044c5b"
        );
    }

    /// ibc-go `TestCommitAcknowledgement` (failure case).
    #[test]
    fn error_ack_commitment_matches_ibc_go_vector() {
        assert_eq!(
            hex::encode(commit_acknowledgement(&[
                universal_error_acknowledgement().to_vec()
            ])),
            "e2fb30dfbf7abdeaca82d426534d2b3a9d5444dd2a87fa16d38b77ba1a13ced7"
        );
        // Eureka `ICS24Host.UNIVERSAL_ERROR_ACK`.
        assert_eq!(
            hex::encode(universal_error_acknowledgement()),
            "4774d4a575993f963b1c06573736617a457abef8589178db8d10c94b4ab511ab"
        );
    }

    /// Eureka `test_packetKeys`.
    #[test]
    fn keys_match_eureka_vectors() {
        assert_eq!(
            hex::encode(packet_commitment_key("channel-0", 1)),
            "6368616e6e656c2d30010000000000000001"
        );
        assert_eq!(
            hex::encode(packet_receipt_key("channel-1", 2)),
            "6368616e6e656c2d31020000000000000002"
        );
        assert_eq!(
            hex::encode(packet_acknowledgement_key("channel-2", 3)),
            "6368616e6e656c2d32030000000000000003"
        );
        // Sequence 128 is the first whose key is not valid UTF-8.
        assert!(std::str::from_utf8(&packet_commitment_key("07-tendermint-0", 128)).is_err());
    }

    /// Eureka `test_prefixedPath`.
    #[test]
    fn merkle_path_concatenates_onto_last_prefix_element() {
        let path = build_merkle_path(
            &[b"ibc".to_vec(), b"".to_vec()],
            b"clients/07-tendermint-0/clientState",
        )
        .unwrap();
        assert_eq!(path, vec![b"ibc".to_vec(), b"clients/07-tendermint-0/clientState".to_vec()]);
        let path = build_merkle_path(
            &[b"ibc".to_vec(), b"test/".to_vec()],
            b"clients/07-tendermint-0/clientState",
        )
        .unwrap();
        assert_eq!(
            path,
            vec![b"ibc".to_vec(), b"test/clients/07-tendermint-0/clientState".to_vec()]
        );
        assert!(build_merkle_path(&[], b"x").is_err());
    }
}
