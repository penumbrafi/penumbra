# penumbra-1 recovery

penumbra-1 halted at block **12598600** (2026-09-02 19:37 UTC). Iqlusion and Polkachu stopped
validating and the core team is gone, so the chain sits below 2/3 and can't resume. Recovery is a
coordinated restart that drops the offline validators from the active set and continues from the
halt height. State, balances, positions and history are all carried forward — same chain-id, same
keys.

**Time constraint.** noble's light client of penumbra (`07-tendermint-109`, trust level 1/3) was last
updated at the halt and expires **2026-09-07 ~11:37 UTC**. Restart before then and a normal relayed
client update carries noble across the validator-set change. After expiry, reopening the bridge needs
noble governance to substitute the client.

## Parameters
- chain-id: `penumbra-1`
- binary: `pd 2.0.6`
- halt height: `12598600`
- restart height: `12598601`
- noble client: `07-tendermint-109`, trust_threshold 1/3

## Validator set
Total voting power 7,089,521,028,265.

Remove (offline): `iqlusion` 30.0%, `polkachu.com` 14.8%, plus any operator that does not restart.

Restart set = whoever comes back. Thresholds against the current set:
- **> 1/3 (33.3%, 2,363,173,676,089)** — minimum. noble's client follows without governance; bridge
  reopens; funds can move.
- **> 2/3 (66.7%)** — chain runs healthily on its own going forward.

Candidates (moniker — power):
```
rotko.net        18.5%
antumbra.net      7.4%
ghostinnet        4.9%
CryptoCrew        4.0%
Bryanlabs         3.7%
Tessellated       3.7%
silent            3.6%
Architect Nodes   3.4%
MathNodes         1.8%
Pro-Delegators    1.2%
AM Solutions      0.9%
OriginStake       0.7%
Validatus         0.7%
PathrockNetwork   0.7%
```

## Procedure

### 1. Produce the restart genesis (coordinator)
Work on a copy of the halted state (ZFS clone or a stopped node), never the live validator:
```
pd export  --home <pd_home> --export-directory <out>     # no --prune (unimplemented in 2.0.6)
pd migrate --home <pd_home> --comet-home <comet_home> --ready-to-start
```
In the resulting genesis: set the active validator set to the restarting operators, `initial_height`
= 12598601, `genesis_time` = agreed go-time, chain-id stays `penumbra-1`. Publish `genesis.json` and
its `sha256sum`.

### 2. Verify (independent)
At least one other operator reproduces the genesis from their own halted state and confirms the same
sha256. Match from two independent parties before anyone restarts.

### 3. Restart (each operator, at go-time)
```
systemctl stop penumbra
cp -a <home> <home>.bak
install the published genesis.json          # sha256 MUST match
pd migrate --home <pd_home> --comet-home <comet_home> --ready-to-start
systemctl start penumbra
curl -s localhost:26657/status              # height climbs past 12598601
```
One instance per key. Never run two nodes on the same consensus key.

### 4. Reopen IBC (relayer)
Relay a client update to noble for `07-tendermint-109`. The restart set signs as >1/3 of the old set,
which meets the 1/3 trust level, so the client follows to the new validator set — no governance. Then
relay the pending packets / withdrawals. Repeat for any other counterparty (osmosis etc.).

If the client has already expired: noble governance recovers it (client substitution) against a fresh
client tracking the restarted chain.

### 5. Services
Point RPC / pclientd, the explorer, and veil at the restarted chain.

## Rollback
Per node: `systemctl stop penumbra`, restore `<home>.bak`, start. Snapshot each node's home before its
restart.

## Notes
- No new keys, no new chain-id.
- `pd export --prune` panics (pruning unimplemented in 2.0.6) — omit it.
- Removing a validator drops its consensus role only; delegations and balances are untouched.
