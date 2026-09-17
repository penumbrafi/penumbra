# IBC v2 on Penumbra: phase 1 design

Status: draft, 2026-09-17. Tracks penumbrafi/penumbra#24. Phase 0 spikes are
recorded as comments on that issue; this note turns their answers into the
shape of the phase 1 change to `pd`.

Scope: v2 packet core, client abstraction, ICS-20 over v2, events. Out of
scope here: the Ethereum client itself (phase 2, decided as the Eureka
`ethereum-light-client` crate) and Solana.

## 0. Prerequisite: byte keys in cnidarium

IBC v2 commitment keys are raw bytes, not strings:

| commitment | key bytes |
|---|---|
| packet commitment | `clientId ‖ 0x01 ‖ u64_be(sequence)` |
| packet receipt | `clientId ‖ 0x02 ‖ u64_be(sequence)` |
| acknowledgement | `clientId ‖ 0x03 ‖ u64_be(sequence)` |

Counterparties compute these exact bytes when verifying membership against
Penumbra's app hash (Eureka: `ICS24Host.packetCommitmentPathCalldata` =
`abi.encodePacked(clientId, uint8(1), uint64ToBigEndian(seq))`; ibc-go v2:
`PacketCommitmentKey`). Penumbra cannot store them under any other encoding.

cnidarium's verifiable write API is string-typed: `StateWrite::put_raw(key:
String, ..)`, the cache is `BTreeMap<String, Option<Vec<u8>>>`, and reads are
`get_raw(&str)`. The big-endian sequence bytes are not valid UTF-8 as soon as
any byte is ≥ 0x80 (sequence 128 is the first), so these keys cannot be a
`String`. Parts of the stack are already byte-clean: the JMT hashes
`key.as_bytes()`, `MultistoreConfig::route_key_bytes` exists beside
`route_key_str`, and `Snapshot::get_with_proof(Vec<u8>)` routes through
`route_key_bytes` and hands the raw bytes to the JMT (verified). One part is
actively hostile: `Snapshot::prefix_raw` iterates the `jmt_keys` column family
and does `std::str::from_utf8(preimage).expect("saved jmt keys are utf-8
strings")`, so a single v2 key under `ibc-data` would panic every node that
prefix-scans that substore. Byte keys must not be written until that
iterator is byte-safe.

Change (in our cnidarium fork, one PR, before any v2 pd code):

- Make the cache and delta key type `Vec<u8>` internally; keep the `String`
  API as a thin wrapper so no existing caller changes.
- Add `put_raw_bytes(Vec<u8>, Vec<u8>)`, `delete_bytes(Vec<u8>)`,
  `get_raw_bytes(&[u8])`, `prefix_raw_bytes(&[u8])` to the traits.
- Substore routing for byte keys uses `route_key_bytes`; the `ibc-data/`
  prefix and `/` delimiter are ASCII so the split is unaffected.
- `prefix_raw` / `prefix_keys` iteration: drop the UTF-8 `expect`, yield
  bytes internally, and have the `&str` API skip (not panic on) non-UTF-8
  preimages; add `prefix_raw_bytes`.
- Test: write under a key containing `0xff`, commit, `get_with_proof` on the
  bytes, verify with `[ics23_spec(); 2]`; non-membership for the
  neighbouring sequence; and a string `prefix_raw` over the same substore
  that does not panic.

This is a storage-layer change and gates everything below that writes a
commitment. It is the one item that would be painful to find after phase 1
code exists.

## 1. Client abstraction

Phase 1 introduces one trait and moves Tendermint behind it. That move is the
only change to classic code in phase 1; everything else is additive.

```rust
pub trait LightClient: Send + Sync {
    /// Type URL this client answers for (`/ibc.lightclients.tendermint.v1.ClientState`, ...).
    fn client_type(&self) -> &'static str;

    /// Verify a header against stored client + consensus state. Returns the
    /// new consensus state and the height it is stored at. Must be
    /// deterministic and bounded; no allocation proportional to untrusted input
    /// beyond the message size.
    fn verify_header(&self, store: &dyn ClientStore, client_id: &ClientId,
                     header: Any, now: Timestamp) -> Result<(Height, ConsensusStateAny)>;

    /// Membership of `value` at `path` (raw bytes, already prefixed by the
    /// counterparty's merkle prefix by the caller) under the consensus state
    /// at `height`.
    fn verify_membership(&self, store: &dyn ClientStore, client_id: &ClientId,
                         height: Height, proof: &[u8], path: &[Vec<u8>], value: &[u8]) -> Result<()>;

    fn verify_non_membership(&self, store: &dyn ClientStore, client_id: &ClientId,
                             height: Height, proof: &[u8], path: &[Vec<u8>]) -> Result<()>;

    /// Returns Ok(true) if `evidence` proves misbehaviour; the caller freezes.
    fn check_misbehaviour(&self, store: &dyn ClientStore, client_id: &ClientId,
                          evidence: Any) -> Result<bool>;

    /// Consensus-state timestamp at `height`, for timeout checks.
    fn consensus_timestamp(&self, store: &dyn ClientStore, client_id: &ClientId,
                           height: Height) -> Result<Timestamp>;
}
```

`ClientStore` is the existing `ics02` state (client state, consensus states
by height, processed time/height for delay periods) generalised to store
`Any` rather than Tendermint types. Pruning of consensus states stays in the
component, keyed by height as today.

Dispatch is a static registry keyed by type URL, filled at genesis with
`TendermintClient` and, in phase 2, `EthereumClient`. No wasm VM: clients are
compiled into `pd` and enabled by chain upgrade, which is the same trust model
as everything else in consensus.

Retrofit: `ics02_validation.rs` stops matching type URLs by hand; the update,
misbehaviour and proof-verification handlers call the trait. Classic packet
handlers keep calling `verify_membership` through the same trait, so the
Tendermint retrofit is exercised by existing classic tests before any v2 code
lands.

## 2. v2 beside classic

ibc-go v10's choice, and ours: classic connections and channels keep working
unchanged (Noble, Osmosis, Celestia routes), and v2 is a second packet layer
over the same client store. No changes to `packet.rs`, `msg_handler/`
channel handlers, or the shielded-pool channel-keyed escrow.

New module: `component/v2/` with `counterparty.rs`, `packet.rs`,
`commitment.rs`, `router.rs`, `msg_handler/{send,recv,ack,timeout,register}.rs`.

### State layout (all under the `ibc-data` substore)

String-keyed, non-provable-by-counterparty (internal bookkeeping):

| key | value |
|---|---|
| `ibc-data/v2/counterparty/{client_id}` | `Counterparty { client_id: String, merkle_prefix: Vec<Vec<u8>> }` |
| `ibc-data/v2/next_sequence_send/{client_id}` | u64 |

Byte-keyed, ICS-24 v2, verified by counterparties (§0):

| key | value |
|---|---|
| `ibc-data/` ‖ `clientId‖0x01‖seq_be` | 32-byte packet commitment |
| `ibc-data/` ‖ `clientId‖0x02‖seq_be` | receipt: any non-zero value; we store 32-byte `sha256(packet)`. ibc-go stores a one-byte sentinel, Eureka `keccak256(abi.encode(packet))`; only non-membership is ever proved |
| `ibc-data/` ‖ `clientId‖0x03‖seq_be` | 32-byte ack commitment |

The counterparty's merkle prefix for Penumbra is `["ibc-data", ""]` today
(two-layer JMT). Note: the v2 keys are *not* under `ibc-data/v2/`; the
spec fixes them at the root of the provable IBC store.

### Commitment scheme (`commitment.rs`)

Pinned to ibc-go `04-channel/v2/types/commitment.go` and Eureka
`ICS24Host.sol`, which agree byte for byte:

```
hash_payload(p) = sha256(
    sha256(p.source_port) ‖ sha256(p.dest_port) ‖ sha256(p.version)
  ‖ sha256(p.encoding)    ‖ sha256(p.value) )

commit_packet(pkt) = sha256(
    0x02
  ‖ sha256(pkt.dest_client)
  ‖ sha256(u64_be(pkt.timeout_timestamp))
  ‖ sha256(concat(hash_payload(p) for p in pkt.payloads)) )

commit_ack(acks) = sha256( 0x02 ‖ concat(sha256(a) for a in acks) )
```

Universal error ack: `sha256("UNIVERSAL_ERROR_ACKNOWLEDGEMENT")` =
`4774d4a5…511ab`, used when any payload's app returns an error; the whole
packet is then acked as failed and no app state change persists.

Timeouts are **seconds** (Eureka compares `timeoutTimestamp` to
`block.timestamp`; ibc-go v2 `MsgSendPacket.timeout_timestamp` is seconds).
Classic Penumbra uses nanoseconds; do not share the helper. Send-side rule (ibc-go `sendPacket`):
`now < timeout ≤ now + MAX_TIMEOUT_DELTA` (Eureka: 1 day), and the
counterparty client's latest consensus timestamp must be `< timeout`, so a
packet cannot be born already timed out on the other side. Recv-side rule:
reject if `block_time_seconds ≥ timeout`. Timeout proof rule: counterparty
consensus timestamp at proof height `≥ timeout` and non-membership of the
receipt key.

Test vectors: take the ICS24Host Foundry tests' packet and expected
`bytes32`, and ibc-go's `TestCommitPacket`, as fixed vectors in
`commitment.rs`. One byte off is a silent total failure on the Ethereum side.

## 3. Actions and messages

Five new `IbcRelay` variants, one-to-one with ibc-go v2 messages so relayers
and the proof-api need no translation layer:

| variant | proto (`ibc.core.channel.v2`) | handler |
|---|---|---|
| `RegisterCounterparty` | `MsgRegisterCounterparty { client_id, counterparty_client_id, counterparty_merkle_prefix, signer }` | one-shot per client; rejects if already set |
| `SendPacketV2` | `MsgSendPacket { source_client, timeout_timestamp, payloads, signer }` | **not an `IbcRelay` variant in phase 1** (see below); the internal `send_packet` routine exists and is only reachable from value-carrying actions |
| `RecvPacketV2` | `MsgRecvPacket { packet, proof_commitment, proof_height, signer }` | verify counterparty pairing, timeout, membership; run `on_recv`; store receipt + ack commitment; emit `recv_packet` + `write_acknowledgement` |
| `AcknowledgementV2` | `MsgAcknowledgement { packet, acknowledgement, proof_acked, proof_height, signer }` | verify membership of ack commitment under counterparty key; run `on_ack`; delete commitment; emit `acknowledge_packet` |
| `TimeoutV2` | `MsgTimeout { packet, proof_unreceived, proof_height, signer }` | verify consensus timestamp ≥ timeout, non-membership of receipt; run `on_timeout`; delete commitment; emit `timeout_packet` |

`signer` is ignored, as with classic: the transaction's fee payer is the
relayer.

**Why there is no generic send action.** In ibc-go, transfer's `OnSendPacket`
debits `signer`'s bank account. Penumbra has no accounts: an `IbcRelay`
action contributes nothing to the transaction's value balance, so a
relayer-style `SendPacketV2` carrying a `transfer` payload would commit a
packet the counterparty mints against with nothing escrowed. Outbound
ICS-20 therefore goes only through a first-class `Ics20WithdrawalV2` action
(§4) that, like classic `Ics20Withdrawal`, burns value into the transaction
balance and calls the internal `send_packet` with a transfer payload. If a
generic `SendPacketV2` is ever added for non-value ports, it must reject
the `transfer` port at check time.

**`RegisterCounterparty` front-running.** ibc-go requires `signer ==` client
creator. Penumbra has no signer identity on `IbcRelay` and client creation
is permissionless, so a one-shot permissionless registration lets anyone
mis-pair a freshly created client forever. Phase 1 rule: `RegisterCounterparty`
is valid only in the same transaction as the `CreateClient` it pairs, and
must refer to the client id that transaction creates (atomic
create-and-pair). Governance-gated registration is the fallback if the
atomic form proves awkward for relayer tooling.

Hermes note: our fork's Penumbra endpoint does `IbcRelay::try_from(raw)
.expect(..)` on every IBC action it sees in blocks. Ship the Hermes update in
the same release as the chain upgrade or the relayer panics on the first v2
transaction. Same applies to `pcli view`.

## 4. Payload router and ICS-20 v2

v2 has no handshake, so the handshake-shaped `AppHandlerCheck/Execute` is
not extended. New trait, registered by port string:

```rust
pub trait PayloadApp {
    fn port(&self) -> &str;                       // "transfer"
    fn on_send(state, source_client, seq, payload) -> Result<()>;
    fn on_recv(state, packet, payload) -> Result<Ack>;   // Ack::Success(bytes) | Ack::Error
    fn on_ack(state, packet, payload, ack: &[u8]) -> Result<()>;
    fn on_timeout(state, packet, payload) -> Result<()>;
}
```

Multi-payload packets: run apps in order; any `Ack::Error` or `Err` aborts
the whole `RecvPacketV2` execution (state rolled back to before the first
payload) and writes the universal error ack. Phase 1 registers only
`transfer`; a packet with an unknown port is rejected at recv with the
universal error ack, and rejected outright at send.

ICS-20 v2: encoding `application/x-protobuf` with `FungibleTokenPacketData`
(ibc-go v2 uses ICS-20 v1 packet data over v2 transport; Eureka's
`ICS20Transfer.sol` uses ABI encoding, `application/x-solidity-abi`). The
payload app must accept both encodings, selected by `payload.encoding`;
phase 1 implements protobuf and stubs ABI with a decode test against a
Solidity-produced vector so phase 2 only fills in the transfer logic.

Escrow: new value-balance key `ics20_value_balance::by_client_id(client_id,
asset_id)` beside the channel-keyed one; denom traces use `transfer/{client_id}`
as the path segment (the existing trace parser already accepts it). No
migration of channel-keyed balances.

Wallet surface: `Ics20Withdrawal` gains nothing; a new
`Ics20WithdrawalV2 { source_client, timeout_timestamp_secs, ... }` action
burns value into the transaction balance and calls the internal v2
`send_packet` with one transfer payload. `pcli tx withdraw --client
07-tendermint-1` beside `--channel`.

Verify in phase 1, not assumed: ibc-go v10 transfer over v2 uses the v1
`FungibleTokenPacketData` struct with `application/x-protobuf` (the
multi-token v2 packet data was removed before release); and the merkle
prefix Penumbra advertises for v2 (`["ibc-data", ""]`, Eureka appends the
path to the last element) matches how Hermes configures Penumbra's prefix
for Cosmos clients today.

## 5. Events

Emit ibc-go v2 event types and attribute keys verbatim, so the proof-api's
Cosmos listener (`packages/proof-api/lib/src/events/cosmos_sdk.rs`) and
Hermes v2 parse Penumbra with a subclass, not a rewrite:

| event | attributes |
|---|---|
| `send_packet` | `packet_source_client`, `packet_dest_client`, `packet_sequence`, `packet_timeout_timestamp`, `encoded_packet_hex` |
| `recv_packet` | same as send |
| `write_acknowledgement` | packet attrs + `encoded_acknowledgement_hex` |
| `acknowledge_packet` | packet attrs + `encoded_acknowledgement_hex` |
| `timeout_packet` | packet attrs |
| `register_counterparty` | `client_id`, `counterparty_client_id` |

`encoded_packet_hex` is the protobuf `ibc.core.channel.v2.Packet` bytes, hex
lowercase, no prefix (what the proof-api decodes). Penumbra's own ABCI event
plumbing already emits typed events; these are added as plain attribute
events in the v2 handlers.

## 6. Ethereum router ownership (governance question, not decided here)

Phase 2 deploys `ICS26Router`, `ICS20Transfer`, and a Penumbra light client
on Ethereum. Someone owns the upgrade and pause keys. Two shapes:

- **Penumbra-operated**: a multisig of Penumbra validators (or, later, the
  validator FROST key from the custody work) holds admin. Penumbra governance
  can pause or upgrade the Ethereum side. Cost: we run key ceremonies and
  carry the operational risk; users trust the same set that runs the chain.
- **Cosmos Labs-operated**: deploy onto the shared Eureka router already on
  mainnet, with Penumbra as one more counterparty client. Cost: their
  timelock and admin can pause or upgrade our route; benefit: audited,
  operated contracts and a shared prover.

Either way the Penumbra client on Ethereum (SP1 ICS07 with JMT proof specs,
or the attestation client to start) is ours to specify. Governance should
decide this before phase 2 starts; phase 1 does not depend on it.

## 7. Phase 1 deliverables, in order

1. cnidarium byte-key PR with proof test (§0).
2. `LightClient` trait + Tendermint retrofit; classic tests green.
3. `commitment.rs` with fixed vectors from ibc-go and ICS24Host.
4. Protos + `IbcRelay` variants + handlers; counterparty registry; v2 keys.
5. `PayloadApp` + ICS-20 v2 (protobuf), client-keyed escrow.
6. Events; Hermes fork `RelayPathV2` for Penumbra ↔ Cosmos over v2;
   two-pd devnet with a v2 self-pairing (Penumbra ↔ Penumbra) as the first
   end-to-end test, then Penumbra ↔ a local ibc-go v10 simapp.
7. `pcli` plan/view; genesis params (`MAX_TIMEOUT_DURATION`, allowed
   client types); upgrade migration (no state migration needed, additive).

Open until phase 2: which Ethereum client to pair first (attestation vs
SP1), prover hosting, and §6.
