#!/usr/bin/env bash
# penumbra-1 coordinated restart helper (--disable migration).
# Detects pd/cometbft homes + service, then walks the tested restart as CONFIRMED
# steps. The forked `pd migrate-restart` PRODUCES the genesis from your own state;
# you verify its sha256 matches the published value. The migration raises
# priv_validator_state to 12598602 itself; nothing is hand-edited.
#
# Usage: penumbra-restart.sh <pd-restart-binary> [<cometbft-binary>]
# Build pd-restart from the source patch first (see release notes); do NOT trust a
# prebuilt binary blindly — the genesis sha256 below is the real cross-check.
set -euo pipefail

GENESIS_SHA256="c099ccb02a2136d5071fb22b1511eeec1588ad09676e0a0532d072f28b433ed4"
POST_ROOT="1db72ab20c0babdb8696f361d5b08d790abd8032ac64d762b138ddc80f0f99f7"
RESTART_HEIGHT=12598602
# Remove ONLY the two clearly-departed offline validators (iqlusion, polkachu).
# Everyone else is kept in the active set — uncommitted operators can rejoin by
# simply starting their migrated node (no re-bond). The committed+online set is
# ~73% of the kept set, comfortably over the 2/3 needed to produce blocks.
REMOVE=(
  3969C0511C6ABE474757FEAB7C1B4004796D7E72  9B2D4391131198750FF28EE73EC953ECFCFD06EF
)

say(){ printf '   %s\n' "$*"; }
die(){ printf '!! %s\n' "$*" >&2; exit 1; }
ask(){ local a; read -r -p "$1 " a; printf '%s' "$a"; }
step(){ printf '\n== STEP %s\n' "$*"; }
confirm(){ [ "$(ask '   proceed? [y/N]')" = y ] || die "aborted at step: $*"; }

[ $# -ge 1 ] || die "usage: $0 <pd-restart-binary> [<cometbft-binary>]"
PDBIN="$1"; [ -x "$PDBIN" ] || die "pd-restart binary not executable: $PDBIN"
# Only the v2.0.9 recovery build restarts at 12598602; older builds cannot start the chain.
"$PDBIN" --version 2>&1 | grep -qE '2\.0\.9' || die "pd binary is not 2.0.9"
CBIN="${2:-$(command -v cometbft || true)}"

detect_pd_home(){ local c; for c in "${PENUMBRA_PD_HOME:-}" /opt/penumbra/network_data/node0/pd \
  "$HOME/.penumbra/network_data/node0/pd" /root/.penumbra/network_data/node0/pd ./network_data/node0/pd; do
  [ -n "$c" ] && [ -d "$c/rocksdb" ] && { printf '%s' "$c"; return; }; done; return 1; }
detect_comet_home(){ local c; for c in "${COMET_HOME:-}" /opt/penumbra/network_data/node0/cometbft \
  "$HOME/.penumbra/network_data/node0/cometbft" "$HOME/.cometbft" /root/.cometbft ./network_data/node0/cometbft; do
  [ -n "$c" ] && [ -f "$c/config/genesis.json" ] && { printf '%s' "$c"; return; }; done; return 1; }
detect_service(){ local s; for s in penumbra pd penumbra-pd cometbft; do
  systemctl list-unit-files 2>/dev/null | grep -q "^${s}\.service" && { printf '%s' "$s"; return; }; done; return 1; }

step "0 — detect paths"
PD_HOME="$(detect_pd_home || true)";     [ -n "$PD_HOME" ]    || PD_HOME="$(ask 'pd home not detected. Path to dir containing rocksdb:')"
[ -d "$PD_HOME/rocksdb" ] || die "no rocksdb under: $PD_HOME"
COMET_HOME="$(detect_comet_home || true)"; [ -n "$COMET_HOME" ] || COMET_HOME="$(ask 'cometbft home not detected. Path to cometbft dir:')"
[ -f "$COMET_HOME/config/genesis.json" ] || die "no config/genesis.json under: $COMET_HOME"
SERVICE="$(detect_service || true)";     [ -n "$SERVICE" ]    || SERVICE="$(ask 'service not detected. Service name (blank = manual):')"
[ -n "$CBIN" ] && [ -x "$CBIN" ] || CBIN="$(ask 'cometbft binary not found. Path to cometbft:')"
[ -x "$CBIN" ] || die "cometbft binary not executable: $CBIN"
say "pd home:    $PD_HOME"; say "comet home: $COMET_HOME"; say "service:    ${SERVICE:-<manual>}"; say "cometbft:   $CBIN"
confirm "0 — paths"

step "1 — stop this node, and confirm ALL old-chain nodes are down"
say "will run: ${SERVICE:+systemctl stop $SERVICE}"; confirm "1 — stop"
[ -n "$SERVICE" ] && sudo systemctl stop "$SERVICE"
pgrep -x pd >/dev/null && die "pd still running"; pgrep -x cometbft >/dev/null && die "cometbft still running"
say "tombstone safety: EVERY old-chain penumbra-1 node you run (validators, RPC, full nodes) must be stopped."
[ "$(ask '   all old-chain nodes stopped? [y/N]')" = y ] || die "stop them all first"

step "2 — back up priv_validator_state + state dir"
TS="$(date -u +%Y%m%dT%H%M%SZ)"; PVS="$COMET_HOME/data/priv_validator_state.json"; PVS_BAK="$COMET_HOME/priv_validator_state.$TS.bak"
[ -f "$PVS" ] || die "priv_validator_state.json not found at $PVS"
say "back up $PVS -> $PVS_BAK ; also take a ZFS snapshot / full copy of the node now (rollback point)."
confirm "2 — backup"
cp -a "$PVS" "$PVS_BAK"; say "priv_validator_state backed up"
[ "$(ask '   full snapshot/backup of the node done? [y/N]')" = y ] || die "snapshot first"

step "3 — run migrate-restart (produces the genesis; --disable removes iqlusion + polkachu)"
ulimit -n 1048576 || true
say "will run: $PDBIN migrate-restart --home $PD_HOME --comet-home $COMET_HOME --disable --remove <2 addrs>"
confirm "3 — migrate"
REMARGS=(); for a in "${REMOVE[@]}"; do REMARGS+=(--remove "$a"); done
"$PDBIN" migrate-restart --home "$PD_HOME" --comet-home "$COMET_HOME" "${REMARGS[@]}" --disable
say "migration done"

step "4 — verify the produced genesis sha256"
GOT="$(sha256sum "$COMET_HOME/config/genesis.json" | awk '{print $1}')"
say "expected: $GENESIS_SHA256"; say "got:      $GOT"
[ "$GOT" = "$GENESIS_SHA256" ] || die "GENESIS SHA MISMATCH — do not continue; your inputs differ from the release"
say "genesis matches the published hash"
confirm "4 — genesis verified"

step "5 — check priv_validator_state (raised to $RESTART_HEIGHT by the migration)"
PVS_H="$(grep -o '"height": *"[0-9]*"' "$PVS" | grep -o '[0-9]*')"
say "priv_validator_state height: $PVS_H (expected $RESTART_HEIGHT)"
[ "$PVS_H" = "$RESTART_HEIGHT" ] || die "priv_validator_state is not at $RESTART_HEIGHT — do not continue; ask the coordinator"
say "cometbft block store was cleared by the migration; no unsafe-reset-all needed"

step "6 — set KEEP-only peers + disable PEX for first blocks"
CFG="$COMET_HOME/config/config.toml"; cp -a "$CFG" "$CFG.$TS.bak"
KEEP_PEERS="${KEEP_PEERS:-$(ask 'paste persistent_peers string for the KEEP validators only (nodeid@host:port,...):')}"
say "will set persistent_peers = KEEP-only and pex = false in $CFG"
confirm "6 — peers"
sed -i "s|^persistent_peers *=.*|persistent_peers = \"$KEEP_PEERS\"|" "$CFG"
sed -i "s|^pex *=.*|pex = false|" "$CFG"
say "peers set, pex off (revert from $CFG.$TS.bak later to restore normal peering)"

step "7 — start the node"
say "will run: ${SERVICE:+systemctl start $SERVICE}${SERVICE:+ (else start pd then cometbft manually)}"
confirm "7 — start"
if [ -n "$SERVICE" ]; then sudo systemctl start "$SERVICE"; else say "start pd (forked) then cometbft manually now"; fi

step "8 — verify"
say "the first block is $RESTART_HEIGHT once >2/3 of the kept set is online; round timeouts until then are expected."
for _ in $(seq 1 60); do
  H="$(curl -s localhost:26657/status 2>/dev/null | grep -o '"latest_block_height":"[0-9]*"' | grep -o '[0-9]*' || true)"
  if [ -n "$H" ] && [ "$H" -ge "$RESTART_HEIGHT" ]; then say "OK — producing, height $H"; exit 0; fi
  sleep 4
done
say "node up, no block past $RESTART_HEIGHT yet — the network needs >2/3 of the new set online."
say "do NOT rollback while other operators are live; check with the coordinator."
