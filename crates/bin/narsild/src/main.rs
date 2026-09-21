//! narsild — Narsil sidecar daemon for Penumbra validators
//!
//! architecture: "your server as a function" (Marius Eriksen)
//!
//! every protocol (sealed DKG, nested FROST v2 signing) is composed from:
//!   - ThresholdAccumulator: collect contributions until threshold
//!   - PeerSet: broadcast public data, deliver secrets point-to-point
//!   - LocalSigner: produce this node's contribution
//!
//! handlers are thin: extract request → call service → serialize response.
//!
//! Two things every handler below depends on, stated once:
//!
//! - **The roster is configuration.** Peers are `index=url=x25519_pubkey`
//!   triples, identical on every node, and its hash is mixed into the DKG's
//!   Noise prologue and into every signing context. Nodes that disagree about
//!   the roster cannot complete a ceremony with each other.
//! - **Secrets are never broadcast.** DKG round 2 goes out with
//!   `PeerSet::send_to`, one sealed package to one recipient. Everything that
//!   uses `broadcast` is public by construction.

mod accumulator;
mod broadcast;
pub mod client;
mod codec;
mod dkg;
mod identity;
mod keypackage;
mod roster;
mod signing;
#[cfg(test)]
mod tests;

use accumulator::AccumulateResult;
use broadcast::PeerSet;
use identity::NodeIdentity;
use keypackage::KeyPackage;
use roster::Roster;
use signing::{InnerCommitment, InnerShare, LocalSigner, SigningRequest, SigningService};

use axum::{extract::State, response::IntoResponse, Json, Router};
use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    signing: SigningService,
    dkg_ceremony: Arc<Mutex<Option<dkg::DkgCeremony>>>,
    peers: PeerSet,
    identity: Arc<NodeIdentity>,
    roster: Arc<Roster>,
    data_dir: PathBuf,
    holder_index: u32,
    nested_position: u32,
    inner_threshold: u32,
    outer_threshold: u32,
}

fn err(msg: impl std::fmt::Display) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "error": msg.to_string() }))
}

// ---------------------------------------------------------------------------
// Signing handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Round1Request {
    session_id: [u8; 32],
}

#[derive(Deserialize)]
struct StatusRequest {
    session_id: [u8; 32],
}

async fn handle_round1(
    State(app): State<AppState>,
    Json(req): Json<Round1Request>,
) -> impl IntoResponse {
    let commitment = app.signing.start_round1(req.session_id).await;
    let (collected, threshold, _) = app
        .signing
        .round1
        .status(&req.session_id)
        .await
        .unwrap_or((1, 0, None));
    Json(serde_json::json!({
        "holder_index": commitment.holder_index,
        "hiding": commitment.hiding,
        "binding": commitment.binding,
        "collected": collected,
        "threshold": threshold,
    }))
}

async fn handle_commitment(
    State(app): State<AppState>,
    Json(commitment): Json<InnerCommitment>,
) -> impl IntoResponse {
    let session_id = commitment.session_id;
    let result = app.signing.receive_commitment(commitment).await;
    let (collected, threshold, _) = app
        .signing
        .round1
        .status(&session_id)
        .await
        .unwrap_or((0, 0, None));
    accumulate_json(&result, collected, threshold)
}

async fn handle_status(
    State(app): State<AppState>,
    Json(req): Json<StatusRequest>,
) -> impl IntoResponse {
    let commitments = app.signing.round1.contributions(&req.session_id).await;
    let (r1_collected, r1_threshold, _) = app
        .signing
        .round1
        .status(&req.session_id)
        .await
        .unwrap_or((0, 0, None));
    let (r2_collected, r2_threshold, _) = app
        .signing
        .round2
        .status(&req.session_id)
        .await
        .unwrap_or((0, 0, None));
    let z_nested = app.signing.result(&req.session_id).await;

    // The nested position's outer commitment pair, so a coordinator does not
    // have to reimplement the aggregation to build the outer package.
    let nested_pair = signing::nested_commitment_pair(&req.session_id, &commitments)
        .ok()
        .map(|(d, e)| {
            serde_json::json!({
                "hiding": codec::point_hex(&d),
                "binding": codec::point_hex(&e),
            })
        });

    Json(serde_json::json!({
        "session_id": hex::encode(req.session_id),
        "nested_index": app.nested_position,
        "round1": {
            "collected": r1_collected,
            "threshold": r1_threshold,
            "ready": r1_collected >= r1_threshold,
        },
        "round2": {
            "collected": r2_collected,
            "threshold": r2_threshold,
            "complete": z_nested.is_some(),
            "z_nested": z_nested,
        },
        "commitments": commitments,
        "nested_commitment": nested_pair,
    }))
}

async fn handle_round2(
    State(app): State<AppState>,
    Json(req): Json<SigningRequest>,
) -> impl IntoResponse {
    let session_id = req.session_id;
    match app.signing.start_round2(req).await {
        Ok(share) => {
            let (collected, threshold, _) = app
                .signing
                .round2
                .status(&session_id)
                .await
                .unwrap_or((1, 0, None));
            Json(serde_json::json!({
                "holder_index": share.holder_index,
                "response": share.response,
                "collected": collected,
                "threshold": threshold,
                "z_nested": app.signing.result(&session_id).await,
            }))
        }
        Err(e) => err(e),
    }
}

async fn handle_share(
    State(app): State<AppState>,
    Json(share): Json<InnerShare>,
) -> impl IntoResponse {
    let session_id = share.session_id;
    let result = app.signing.receive_share(share).await;
    let (collected, threshold, _) = app
        .signing
        .round2
        .status(&session_id)
        .await
        .unwrap_or((0, 0, None));
    let mut body = accumulate_json(&result, collected, threshold);
    if let Some(z) = app.signing.result(&session_id).await {
        body.0["z_nested"] = serde_json::Value::String(z);
    }
    body
}

fn accumulate_json<A: accumulator::Aggregate>(
    result: &AccumulateResult<A>,
    collected: usize,
    threshold: usize,
) -> Json<serde_json::Value> {
    match result {
        AccumulateResult::Pending {
            collected,
            threshold,
        } => Json(serde_json::json!({
            "accepted": true, "collected": collected, "threshold": threshold,
        })),
        AccumulateResult::Complete(_) => Json(serde_json::json!({
            "accepted": true, "collected": collected, "threshold": threshold,
            "threshold_met": true,
        })),
        AccumulateResult::Duplicate => Json(serde_json::json!({
            "accepted": false, "reason": "duplicate",
        })),
    }
}

// ---------------------------------------------------------------------------
// DKG handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DkgInitRequest {
    /// The generation to produce. Defaults to the loaded key package's epoch
    /// plus one, or 1 on a node that has never run a DKG.
    #[serde(default)]
    epoch: Option<u64>,
}

fn new_ceremony(app: &AppState, epoch: u64) -> Result<dkg::DkgCeremony, dkg::DkgError> {
    dkg::DkgCeremony::new(
        app.holder_index,
        app.roster.clone(),
        app.identity.x25519_secret(),
        epoch,
        app.inner_threshold,
        app.outer_threshold,
    )
}

async fn next_epoch(app: &AppState) -> u64 {
    app.signing.signer.lock().await.epoch + 1
}

/// Deliver round 2: one sealed message per recipient, to that recipient only,
/// and apply our own by the same code path.
async fn run_round2(app: &AppState, guard: &mut Option<dkg::DkgCeremony>) {
    let ceremony = match guard.as_mut() {
        Some(c) => c,
        None => return,
    };
    let messages = match ceremony.round2_messages() {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("DKG round 2: {}", e);
            return;
        }
    };

    let mut ours = None;
    for msg in messages {
        if msg.recipient_index == app.holder_index {
            ours = Some(msg);
        } else {
            // send_to, never broadcast: one recipient, one package.
            app.peers.send_to(msg.recipient_index, "/dkg/round2", &msg);
        }
    }
    tracing::info!("DKG round 2: sealed packages delivered point-to-point");

    if let Some(msg) = ours {
        if let Err(e) = ceremony.receive_round2(&msg) {
            tracing::error!("DKG round 2 (own packages): {}", e);
        }
    }
}

async fn maybe_finalize(app: &AppState, guard: &mut Option<dkg::DkgCeremony>) -> Option<String> {
    let ceremony = guard.as_mut()?;
    if !ceremony.round2_complete() {
        return None;
    }
    let result = match ceremony.finalize() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("DKG finalization: {}", e);
            return None;
        }
    };

    let package = result.key_package();
    match package.save(&app.data_dir) {
        Ok(path) => tracing::info!("DKG complete; key package written to {}", path.display()),
        Err(e) => tracing::error!("could not persist key package: {}", e),
    }
    install_share(app, &package).await;
    Some(result.coeff_commitments.first().cloned().unwrap_or_default())
}

/// Load a key package into the live signer.
async fn install_share(app: &AppState, package: &KeyPackage) {
    let share = package.share_at(app.nested_position);
    let public_shares = package.public_shares_at(app.nested_position);
    match (share, public_shares) {
        (Some(share), Some(public_shares)) => {
            let mut signer = app.signing.signer.lock().await;
            signer.epoch = package.epoch;
            signer.manifest_hash = package.manifest_hash();
            signer.install(share, public_shares);
            tracing::info!(
                "share installed: holder={} nested_position={} epoch={}",
                package.holder_index,
                app.nested_position,
                package.epoch
            );
        }
        _ => tracing::error!("key package does not decode into a usable share"),
    }
}

async fn handle_dkg_init(
    State(app): State<AppState>,
    Json(req): Json<DkgInitRequest>,
) -> impl IntoResponse {
    let epoch = match req.epoch {
        Some(e) => e,
        None => next_epoch(&app).await,
    };

    let ceremony = match new_ceremony(&app, epoch) {
        Ok(c) => c,
        Err(e) => return err(e),
    };
    let broadcast = ceremony.round1_broadcast();

    let mut guard = app.dkg_ceremony.lock().await;
    *guard = Some(ceremony);
    if let Some(c) = guard.as_mut() {
        if let Err(e) = c.receive_round1(&broadcast) {
            return err(e);
        }
    }
    app.peers.broadcast("/dkg/round1", &broadcast);

    tracing::info!(
        "DKG initiated: epoch {}, {}-of-{} inner, outer threshold {}",
        epoch,
        app.inner_threshold,
        app.roster.len(),
        app.outer_threshold
    );
    Json(serde_json::json!({
        "status": "round1_broadcast",
        "epoch": epoch,
        "holder_index": app.holder_index,
        "coefficients": broadcast.coefficients.len(),
    }))
}

async fn handle_dkg_round1(
    State(app): State<AppState>,
    Json(msg): Json<dkg::DkgRound1Broadcast>,
) -> impl IntoResponse {
    let mut guard = app.dkg_ceremony.lock().await;

    if guard.is_none() {
        // A peer started the ceremony; adopt its epoch and publish ours.
        let ceremony = match new_ceremony(&app, msg.epoch) {
            Ok(c) => c,
            Err(e) => return err(e),
        };
        let ours = ceremony.round1_broadcast();
        *guard = Some(ceremony);
        if let Some(c) = guard.as_mut() {
            if let Err(e) = c.receive_round1(&ours) {
                return err(e);
            }
        }
        app.peers.broadcast("/dkg/round1", &ours);
        tracing::info!("DKG auto-initiated from peer at epoch {}", msg.epoch);
    }

    let complete = match guard.as_mut().map(|c| c.receive_round1(&msg)) {
        Some(Ok(c)) => c,
        Some(Err(e)) => return err(e),
        None => return err("no DKG ceremony"),
    };

    tracing::info!(
        "DKG round 1: commitments from dealer {}, complete={}",
        msg.dealer_index,
        complete
    );

    if complete {
        run_round2(&app, &mut guard).await;
        let _ = maybe_finalize(&app, &mut guard).await;
    }

    Json(serde_json::json!({
        "accepted": true,
        "round1_complete": complete,
    }))
}

async fn handle_dkg_round2(
    State(app): State<AppState>,
    Json(msg): Json<dkg::DkgRound2Msg>,
) -> impl IntoResponse {
    let mut guard = app.dkg_ceremony.lock().await;
    let complete = match guard.as_mut().map(|c| c.receive_round2(&msg)) {
        Some(Ok(c)) => c,
        Some(Err(e)) => return err(e),
        None => return err("no DKG ceremony active"),
    };

    tracing::info!(
        "DKG round 2: sealed packages from dealer {}, complete={}",
        msg.dealer_index,
        complete
    );

    if complete {
        if let Some(group_key) = maybe_finalize(&app, &mut guard).await {
            return Json(serde_json::json!({
                "status": "complete",
                "holder_index": app.holder_index,
                "group_key": group_key,
            }));
        }
    }
    Json(serde_json::json!({"accepted": true, "round2_complete": complete}))
}

async fn handle_dkg_status(State(app): State<AppState>) -> impl IntoResponse {
    let guard = app.dkg_ceremony.lock().await;
    match guard.as_ref() {
        Some(c) => Json(serde_json::json!({
            "active": true,
            "epoch": c.epoch,
            "holder_index": c.holder_index,
            "round1_complete": c.round1_complete(),
            "round2_complete": c.round2_complete(),
            "aborted": c.abort_reason(),
            "result": c.result,
        })),
        None => Json(serde_json::json!({"active": false})),
    }
}

/// Re-install the persisted key package — after an operator has replaced it,
/// or to move this node to a different nested position without a restart.
async fn handle_dkg_activate(State(app): State<AppState>) -> impl IntoResponse {
    match KeyPackage::load(&app.data_dir) {
        Ok(Some(package)) => {
            install_share(&app, &package).await;
            Json(serde_json::json!({
                "status": "activated",
                "epoch": package.epoch,
                "holder_index": package.holder_index,
                "nested_position": app.nested_position,
            }))
        }
        Ok(None) => err("no key package on disk; run the DKG first"),
        Err(e) => err(e),
    }
}

async fn handle_health(State(app): State<AppState>) -> impl IntoResponse {
    let signer = app.signing.signer.lock().await;
    Json(serde_json::json!({
        "status": "ok",
        "holder_index": signer.holder_index,
        "nested_position": signer.nested_position,
        "epoch": signer.epoch,
        "has_share": signer.has_share(),
        "roster_hash": hex::encode(app.roster.hash()),
        "x25519_pub": hex::encode(app.identity.x25519_public()),
        "peers": app.peers.peer_count(),
    }))
}

// ---------------------------------------------------------------------------
// CLI + main
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "narsild", about = "Narsil sidecar for Penumbra validators")]
struct Cli {
    /// Listen address.
    #[arg(long, default_value = "0.0.0.0:9200")]
    bind: String,

    /// This node's 1-indexed holder index. Must appear in --peer.
    #[arg(long)]
    index: u32,

    /// Data directory: node identity and key package.
    #[arg(long, default_value = "./narsild-data")]
    data_dir: PathBuf,

    /// A roster entry: `index=url=x25519_pubkey_hex`. Repeat for every member
    /// of the group, this node included. Every node must be given the same
    /// set: its hash goes into the DKG prologue and the signing context.
    #[arg(long = "peer", value_name = "INDEX=URL=PUBKEY")]
    peers: Vec<String>,

    /// Inner FROST threshold.
    #[arg(long, default_value_t = 3)]
    threshold: u32,

    /// Outer FROST threshold — the number of coefficients of the nested
    /// position's outer polynomial.
    #[arg(long, default_value_t = 1)]
    outer_threshold: u32,

    /// The nested position's index in the outer signing set.
    #[arg(long, default_value_t = 1)]
    nested_position: u32,

    /// Print this node's X25519 public key and exit — what peers put in their
    /// roster. Generates the identity if there is not one yet.
    #[arg(long)]
    print_identity: bool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "narsild=info".into()),
        )
        .init();

    let cli = Cli::parse();

    let identity = match NodeIdentity::load_or_create(&cli.data_dir) {
        Ok(id) => Arc::new(id),
        Err(e) => {
            eprintln!("cannot open node identity: {e}");
            std::process::exit(1);
        }
    };

    if cli.print_identity {
        println!("{}", hex::encode(identity.x25519_public()));
        return;
    }

    let roster = match Roster::parse(&cli.peers) {
        Ok(r) => Arc::new(r),
        Err(e) => {
            eprintln!("bad roster: {e}");
            eprintln!("expected --peer INDEX=URL=X25519_PUBKEY_HEX, once per member");
            std::process::exit(1);
        }
    };

    // A node that is not in its own roster would seal to a key it does not
    // hold, and every peer's package to it would be undecryptable. Catch it
    // here rather than at round 2.
    match roster.get(cli.index) {
        Ok(me) if me.x25519_pub == identity.x25519_public() => {}
        Ok(me) => {
            eprintln!(
                "roster entry for index {} carries x25519 key {}, but this node's identity \
                 at {} is {}",
                cli.index,
                hex::encode(me.x25519_pub),
                identity.path().display(),
                hex::encode(identity.x25519_public())
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("this node's own index is not on the roster: {e}");
            std::process::exit(1);
        }
    }

    // The startup refusal: a key package predating the sealed DKG must not be
    // loaded, because the shares it holds were broadcast in plaintext.
    let package = match KeyPackage::load(&cli.data_dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let (epoch, manifest_hash, share, public_shares) = match &package {
        Some(p) => {
            if p.holder_index != cli.index {
                eprintln!(
                    "key package was generated for holder {}, but --index is {}",
                    p.holder_index, cli.index
                );
                std::process::exit(1);
            }
            (
                p.epoch,
                p.manifest_hash(),
                p.share_at(cli.nested_position),
                p.public_shares_at(cli.nested_position).unwrap_or_default(),
            )
        }
        None => {
            tracing::warn!(
                "no key package in {}; this node can take part in a DKG but cannot sign",
                cli.data_dir.display()
            );
            (0, roster.hash(), None, Vec::new())
        }
    };

    let peers = PeerSet::new(roster.clone(), cli.index);
    let signer = LocalSigner::new(
        cli.index,
        cli.nested_position,
        epoch,
        manifest_hash,
        share,
        public_shares,
    );
    let signing = SigningService::new(signer, cli.threshold as usize, peers.clone());

    let state = AppState {
        signing,
        dkg_ceremony: Arc::new(Mutex::new(None)),
        peers,
        identity,
        roster: roster.clone(),
        data_dir: cli.data_dir.clone(),
        holder_index: cli.index,
        nested_position: cli.nested_position,
        inner_threshold: cli.threshold,
        outer_threshold: cli.outer_threshold,
    };

    tracing::info!(
        "narsild starting: holder={} of {}, threshold={}, epoch={}, roster={}",
        cli.index,
        roster.len(),
        cli.threshold,
        epoch,
        hex::encode(roster.hash())
    );

    let app = Router::new()
        .route("/sign/round1", axum::routing::post(handle_round1))
        .route("/sign/commitment", axum::routing::post(handle_commitment))
        .route("/sign/status", axum::routing::post(handle_status))
        .route("/sign/round2", axum::routing::post(handle_round2))
        .route("/sign/share", axum::routing::post(handle_share))
        .route("/dkg/init", axum::routing::post(handle_dkg_init))
        .route("/dkg/round1", axum::routing::post(handle_dkg_round1))
        .route("/dkg/round2", axum::routing::post(handle_dkg_round2))
        .route("/dkg/activate", axum::routing::post(handle_dkg_activate))
        .route("/dkg/status", axum::routing::get(handle_dkg_status))
        .route("/health", axum::routing::get(handle_health))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cli.bind).await.unwrap();
    tracing::info!("narsild listening on {}", cli.bind);
    axum::serve(listener, app).await.unwrap();
}
