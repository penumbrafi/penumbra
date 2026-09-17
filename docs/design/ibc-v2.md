# IBC v2 on Penumbra: phase 1 design

Status: implemented on `spike/ibc-v2` (2026-09-17). Tracks penumbrafi/penumbra#24. Phase 0 spikes are recorded as
comments on that issue; this note describes the phase 1 change to `pd` as
built. Where the implementation diverged from the first draft, the text
says so.

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

Change, shipped as penumbrafi/cnidarium#3 (branch `feat/byte-keys`):

- `StateWrite::put_raw_bytes(Vec<u8>, Vec<u8>)`, `delete_bytes(Vec<u8>)`,
  `StateRead::get_raw_bytes(&[u8])`. A key that is valid UTF-8 routes to
  the existing `String` map, so a key has exactly one home and string and
  byte reads agree; only non-UTF-8 keys land in a parallel
  `Cache::unwritten_bytes_changes` map. No existing caller changes.
- Substore routing for byte keys uses `route_key_bytes`; the `ibc-data/`
  prefix and `/` delimiter are ASCII so the split is unaffected. Commit
  chains both maps into one JMT value set.
- `prefix_raw` / `prefix_keys` skip non-UTF-8 preimages instead of
  panicking. There is no `prefix_raw_bytes`: v2 reads commitments by exact
  key or `get_with_proof`, and byte keys are not surfaced in the rpc watch
  stream either.
- Test (`tests/byte_keys.rs`): sequence 200 under `ibc-data`, reads through
  delta, fork layer and snapshot; string streams unaffected; ICS23
  membership and non-membership over the raw path bytes under
  `[ics23_spec(); 2]`; delete then provable absence.

This is a storage-layer change and gates everything below that writes a
commitment. It is the one item that would be painful to find after phase 1
code exists.

## 1. Client abstraction

As built (`component/light_client.rs`): client and consensus states are
already stored as protobuf `Any` (`TendermintClientState: DomainType<Proto =
Any>`), so a client's kind is read from the type URL of its stored client
state without touching the Tendermint decode path. Dispatch is a `match` on
an enum, not `Box<dyn LightClient>`: async methods generic over the state
are not object-safe, and clients are compiled into `pd` (no wasm VM).

```rust
pub enum LightClientKind { Tendermint }          // one variant per compiled-in client

#[async_trait]
pub trait LightClient {
    const KIND: LightClientKind;
    async fn verify_header<S: StateRead, HI>(state: &S, client_id, client_message: Any) -> Result<VerifiedUpdate>;
    async fn check_misbehaviour<S: StateRead, HI>(state: &S, client_id, misbehaviour: Any) -> Result<Any>; // frozen client state
    async fn status<S: StateRead>(state: &S, client_id, now: Time) -> Result<ClientStatus>;
    async fn verify_membership<S: StateRead>(state: &S, client_id, height, proof, path: &[Vec<u8>], value: &[u8]) -> Result<()>;
    async fn verify_non_membership<S: StateRead>(state: &S, client_id, height, proof, path: &[Vec<u8>]) -> Result<()>;
    async fn consensus_timestamp<S: StateRead>(state: &S, client_id, height) -> Result<Time>;
}
```

`TendermintLightClient` implements it by calling the existing verification
code, which was factored into `verify_tendermint_update` and
`verify_tendermint_misbehaviour` (no writes) rather than rewritten. Dispatch
points: the v2 proof verifier (`component/v2/proof.rs`) and the tops of
`CreateClient`, `UpdateClient` and `SubmitMisbehaviour`, where the Tendermint
arm is the previous code. The classic connection and channel handlers stay
Tendermint-typed on purpose: only Tendermint chains speak classic IBC, and
Ethereum has no classic IBC to reach them. The client store's typed
accessors (`get_client_state` returning the Tendermint type) remain for
those callers; a second kind reads its own state through the `Any`.

Adding the Eureka Ethereum client in phase 2 means: a `LightClientKind`
variant, a `LightClient` impl over the `ethereum-light-client` crate, an arm
in `CreateClient` for its client id prefix and state validation, and an arm
in each dispatch `match`. Two pre-dispatch spots in `update_client.rs` are still Tendermint-hardcoded
and must be generalized with the arms: `check_stateless`'s
`header_is_tendermint` and the duplicate-update short-circuit
`update_is_already_committed`. Regression gate for the retrofit:
`test_create_and_update_light_client` (real header fixtures through the
real update path) and the classic `ics20_transfer_no_timeouts` app-test.

## 2. v2 beside classic

ibc-go v10's choice, and ours: classic connections and channels keep working
unchanged (Noble, Osmosis, Celestia routes), and v2 is a second packet layer
over the same client store. No changes to `packet.rs`, `msg_handler/`
channel handlers, or the shielded-pool channel-keyed escrow.

As built: `src/v2/{proto,msgs,commitment}.rs` (wire types, domain types and
the commitment scheme; usable without the `component` feature, e.g. by
relayers) and `src/component/v2/{state,state_key,proof,app_handler,events,
send,msg_handler/{register_counterparty,recv_packet,acknowledgement,timeout}}.rs`.
`ibc-proto` 0.51 ships no v2 protos, so `v2/proto.rs` hand-writes the
`ibc.core.channel.v2` / `ibc.core.client.v2` messages with ibc-go's field
numbers and type URLs.

### State layout (all under the `ibc-data` substore)

String-keyed, non-provable-by-counterparty (internal bookkeeping):

| key | value |
|---|---|
| `ibc-data/v2/counterparty/{client_id}` | `ibc.core.client.v2.CounterpartyInfo { merkle_prefix, client_id }` |
| `ibc-data/v2/nextSequenceSend/{client_id}` | u64, set to 1 at registration (ibc-go) |

Byte-keyed, ICS-24 v2, verified by counterparties (§0):

| key | value |
|---|---|
| `ibc-data/` ‖ `clientId‖0x01‖seq_be` | 32-byte packet commitment |
| `ibc-data/` ‖ `clientId‖0x02‖seq_be` | receipt: any non-zero value; we store the 32-byte packet commitment. ibc-go stores a one-byte sentinel, Eureka `keccak256(abi.encode(packet))`; only non-membership is ever proved |
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

Four new `IbcRelay` variants, one-to-one with ibc-go v2 messages so relayers
and the proof-api need no translation layer (a `MsgSendPacket` on the wire
falls through to `Unknown` and is rejected, see below):

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
mis-pair a freshly created client forever. Rule as built: `RegisterCounterparty`
is valid only in the same transaction as the `CreateClient` it pairs.
Mechanism: `CreateClient` appends the new id to an ephemeral object-store
list; `RegisterCounterparty` requires membership; the app's transaction
handler resets the list at the start of every transaction (ephemeral objects
survive `StateDelta::apply` into the block, so the per-transaction reset is
the whole security property). Our Hermes fork must bundle both messages in
one Penumbra transaction.

**Payload count.** Eureka's router rejects packets with more than one
payload and ibc-go's transfer app handles one; Penumbra requires exactly
one payload per packet in `check_stateless`, which also removes multi-app
rollback ordering from the router.

**Client ids inside packets** are validated strings (8 to 64 characters, no
`/`), not `ibc_types::ClientId`: the Eureka Ethereum router names its
clients `client-N` (8 characters), which ibc-types' 9-character minimum
would reject. Penumbra's own id in a packet is parsed to a `ClientId` at
the point of use.

Hermes note: our fork's Penumbra endpoint does `IbcRelay::try_from(raw)
.expect(..)` on every IBC action it sees in blocks. Ship the Hermes update in
the same release as the chain upgrade or the relayer panics on the first v2
transaction. Same applies to `pcli view`.

## 4. Payload router and ICS-20 v2

v2 has no handshake, so the handshake-shaped `AppHandlerCheck/Execute` is
not extended. `AppHandler` gains a supertrait, answered by port string:

```rust
pub trait AppHandlerV2 {
    fn handles_port_v2(port: &str) -> bool;                       // "transfer"
    async fn recv_payload_v2(state, packet, payload) -> Result<Vec<u8>>;   // app ack bytes
    async fn acknowledge_payload_v2(state, packet, payload, ack: &[u8]) -> Result<()>;
    async fn timeout_payload_v2(state, packet, payload) -> Result<()>;
}
```

On receive the application runs in a sub-`StateDelta`: `Err` (or an
unknown port) discards its writes and the packet is acknowledged with the
universal error acknowledgement while the transaction succeeds; `Ok(ack)`
applies the writes and re-records the application's events on the parent
(`StateDelta::apply` returns events rather than merging them). Sends have
no router callback: the value-carrying action builds the payload itself.

ICS-20 v2 (`shielded-pool/src/component/transfer_v2.rs`): port `transfer`,
version `ics20-1`, outbound encoding `application/x-protobuf` of
`ibc.applications.transfer.v2.FungibleTokenPacketData` (the ibc-go type,
from `ibc-proto`); `application/json` is accepted on receive;
`application/x-solidity-abi` (what Eureka's `ICS20Transfer.sol` emits) is
rejected with the error ack until phase 2 adds the ABI codec. Success ack is
ibc-go's `{"result":"AQ=="}`. On acknowledgement, the universal error ack
refunds; otherwise the bytes must parse as an ICS-20 JSON ack and an error
result refunds.

Escrow: value-balance key `ics20_value_balance::by_client_id(client_id,
asset_id)` beside the channel-keyed one, keyed by the *local* client id the
transfer was routed over; the hop prefix is `transfer/{client_id}/` (the
existing trace parser already accepts it). No migration of channel-keyed
balances.

Wallet surface (diverges from the first draft, which proposed a separate
`Ics20WithdrawalV2` action): `Ics20Withdrawal` gains proto field
`string source_client = 11`, and the domain type's `source_channel` becomes
`source: Ics20WithdrawalSource::{Channel(ChannelId), Client(ClientId)}`.
Exactly one of the two proto fields may be set; existing withdrawals encode
identically, so effect hashes and the signing test vectors are unchanged.
With a source client the action escrows or burns exactly as before and calls
the v2 `send_packet` with one transfer payload; `timeout_height` is ignored
and `timeout_time` (nanoseconds, minute-aligned) is truncated to seconds.
`pcli tx withdraw --client 07-tendermint-1` beside `--channel`, mutually
exclusive.

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
lowercase, no prefix (what the proof-api decodes);
`encoded_acknowledgement_hex` likewise for `Acknowledgement`. Emitted as
plain indexed attribute events from `component/v2/events.rs`.

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

## 7. Phase 1 status

Done on `spike/ibc-v2`:

1. cnidarium byte-key change (penumbrafi/cnidarium#3), pinned via
   `[patch.crates-io]` to the `feat/byte-keys-0.83` branch on the 0.83.0 tag.
2. `v2/commitment.rs` with ibc-go's fixed vectors (packet, success ack,
   error ack), Eureka's key vectors and prefixed-path vectors.
3. Hand-written v2 protos, domain types, `IbcRelay` variants, handlers,
   counterparty registry, byte-keyed v2 state, raw ICS23 proof verification.
4. `AppHandlerV2` + ICS-20 v2, client-keyed escrow, `Ics20Withdrawal`
   source client, `pcli --client`.
5. Events with ibc-go names; atomic create-and-pair with the per-transaction
   reset in the app.
6. Tests: two real `Storage` chains, each holding a client for the other,
   drive register → send → recv (ack written, app ran) → ack (commitment
   deleted); failing app rolls back and writes the universal error ack;
   replay, wrong counterparty, tampered packet, expired packet and forged
   ack rejected; timeout via non-membership proof with the consensus
   timestamp check both failing and passing; send window checks.

7. `LightClient` trait with the Tendermint implementation and dispatch in
   the client lifecycle handlers and v2 proofs (§1).

Not done:

- Hermes fork `RelayPathV2` for a Penumbra endpoint, and the two-pd devnet
  self-pairing run; then Penumbra ↔ a local ibc-go v10 simapp.
- Genesis/params (`MAX_TIMEOUT_DELTA` is a constant, allowed client types
  are still Tendermint-only), rpc queries for v2 state, `pcli view` of
  client-routed withdrawals.
- ABI codec for `application/x-solidity-abi` transfer payloads (phase 2).

Open until phase 2: which Ethereum client to pair first (attestation vs
SP1), prover hosting, and §6.
