# narsild

`narsild` is a threshold-custody sidecar daemon for Penumbra validators. One
instance runs alongside each participating validator. Together the instances
hold a single threshold key: no node ever materialises the group secret, and no
node can sign alone.

It is a prototype. It is not audited, not wired into `pd`, and not used by any
production system.

## Status

- Self-contained crate: `crates/bin/narsild/Cargo.toml` declares its own
  `[workspace]`, so it is not a member of the Penumbra root workspace and does
  not participate in the workspace lockfile or dependency set. It has its own
  `Cargo.lock` and its own `rust-toolchain.toml` (channel `1.92`, versus the
  repo-wide `1.83`).
- Cryptography comes from the `osst` crate (nested FROST with OSST
  identification, DKG and proactive resharing), on the Pallas curve — the curve
  Zcash Orchard uses for spend authorization.
- Persistence, authentication between peers, epoch binding and resharing are
  not implemented yet. Shares live in process memory.

## Design

The daemon follows a "your server as a function" decomposition (Marius
Eriksen): every protocol is built from three reusable services, and HTTP
handlers stay thin — extract request, call service, serialize response.

### `accumulator.rs` — `ThresholdAccumulator`

Generic "collect contributions from peers until a threshold is met, then
aggregate". Sessions are keyed, contributions are deduplicated by contributor
id, and progress is observable through a `watch` channel so a handler can await
the threshold instead of polling. Both the DKG and the signing protocol are
instances of this pattern.

### `broadcast.rs` — `PeerSet`

Fire-and-forget fan-out of a JSON message to every peer endpoint. It spawns a
task per peer and does not await responses; peers react by contributing their
own share back through the accumulator. Failures are logged, not retried.

### `dkg.rs` — `DkgCeremony`

Distributed interleaved key generation for the *nested* FROST position. Each
node acts as one dealer in `outer_t` independent Feldman VSS ceremonies, so the
inner group ends up holding Shamir shares of each coefficient of the outer
polynomial. Nobody learns the coefficients themselves.

1. **Round 1** — each node generates its dealers and broadcasts Feldman
   commitments.
2. **Round 2** — each node sends subshares to every other node.
3. **Round 3** — each node verifies received subshares against the commitments
   and aggregates them into its final `InnerShare`.

`close_round1()` locks in whoever committed in time, provided at least the
threshold did: validators who miss the window are simply excluded from this
ceremony's inner group rather than aborting it. `DkgResult::eval_at(position)`
evaluates the inner shares at the group's position in the outer FROST scheme.

### `signing.rs` — `SigningService`

Two-round nested FROST signing, composed from the accumulator and the
broadcaster.

1. **Round 1** — each node produces hiding and binding nonce commitments and
   broadcasts them. The coordinator collects the full commitment list, which it
   needs in order to compute `R_nested`.
2. **Round 2** — given the outer challenge and the outer Lagrange coefficient
   for the active signer set, each node produces its inner signature share.
   Once the threshold is reached the shares aggregate into `z_nested`, the
   signature share the nested position contributes to the outer FROST protocol.

Binding factors are derived with `from_uniform_bytes` rather than truncation.
See `SECURITY-nested-frost.md` in the `osst` repository for the v1 outer
binding gap and the v2 construction that fixes it — the nested path must be
reviewed before it guards value.

### `client.rs` — `NarsilClient`

Client side of the two-round flow: `round1(message)` returns the commitment
list and a session id; the caller computes `R_nested`, builds the outer FROST
package and derives the outer challenge and Lagrange coefficient; `round2(...)`
returns `z_nested`.

## HTTP API

All endpoints are JSON. Signing and DKG endpoints exist in both a
caller-facing form and a peer-facing form (peers post their contributions to
the `/sign/commitment`, `/sign/share` and `/dkg/round{1,2}` endpoints).

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/sign/round1` | Start a signing session for a message; returns commitments |
| POST | `/sign/commitment` | Peer submits its round-1 nonce commitment |
| POST | `/sign/status` | Poll accumulation progress for a session |
| POST | `/sign/round2` | Supply outer challenge and Lagrange coefficient; returns `z_nested` |
| POST | `/sign/share` | Peer submits its round-2 signature share |
| POST | `/dkg/init` | Begin a DKG ceremony |
| POST | `/dkg/round1` | Peer submits Feldman commitments |
| POST | `/dkg/round2` | Peer submits subshares |
| POST | `/dkg/activate` | Load the DKG result as this node's live signing share |
| GET | `/dkg/status` | Ceremony progress |
| GET | `/health` | Liveness |

There is no authentication on these endpoints today. Deployments must keep the
port on a private network.

## Running

```
cargo run --release -- \
  --bind 0.0.0.0:9200 \
  --peers http://val2:9200,http://val3:9200 \
  --threshold 3
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--bind` | `0.0.0.0:9200` | Listen address |
| `--peers` | – | Comma-separated peer `narsild` endpoints |
| `--threshold` | `3` | Inner FROST threshold |

Build from inside this directory so that the crate's own
`rust-toolchain.toml` applies:

```
cd crates/bin/narsild && cargo check
```

## Intended use

`narsild` is the custody half of a shielded bridge between Penumbra and Zcash:
the validator set holds an Orchard escrow, and `narsild` produces the
threshold Orchard spend-authorization signatures needed to release funds. See
`docs/design/zcash-shielded-bridge.md`.
