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
mod response;
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

use axum::{extract::State, response::{IntoResponse, Response}, Json, Router};
use response::{
    AccumulateResponse, ActivateResponse, DkgProgressResponse, DkgStartedResponse,
    DkgStatusResponse, ErrorResponse, HealthResponse, NestedCommitment, Round1Response,
    Round2Response, RoundStatus, SigningStatusResponse,
};
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

/// Report a failure to a peer.
///
/// The detail goes to the local log; the peer gets a code. Until M-17 lands
/// properly the code is still the error text, but every call site now goes
/// through one function, which is what makes that change a one-line change.
fn err(msg: impl std::fmt::Display) -> Response {
    let text = msg.to_string();
    tracing::warn!("request rejected: {}", text);
    (axum::http::StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "rejected" }))
        .into_response()
}

/// Report a DKG failure, telling the other members if it was a complaint.
///
/// A complaint that stays on the node that raised it is worse than useless:
/// the others finalize, write key packages, and the group ends up split
/// between nodes that completed a ceremony and one that did not. The complaint
/// itself is public — it names a dealer and a reason, not a share — so it is
/// broadcast.
fn report_dkg(app: &AppState, e: dkg::DkgError) -> Response {
    if let dkg::DkgError::Aborted(ref complaint) = e {
        app.peers.broadcast("/dkg/complaint", complaint);
    }
    err(e)
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
) -> Response {
    let commitment = app.signing.start_round1(req.session_id).await;
    let (collected, threshold, _) = app
        .signing
        .round1
        .status(&req.session_id)
        .await
        .unwrap_or((1, 0, None));
    Json(Round1Response {
        holder_index: commitment.holder_index,
        hiding: commitment.hiding,
        binding: commitment.binding,
        collected,
        threshold,
    })
    .into_response()
}

async fn handle_commitment(
    State(app): State<AppState>,
    Json(commitment): Json<InnerCommitment>,
) -> Response {
    let session_id = commitment.session_id;
    let result = app.signing.receive_commitment(commitment).await;
    let (collected, threshold, _) = app
        .signing
        .round1
        .status(&session_id)
        .await
        .unwrap_or((0, 0, None));
    Json(accumulate_response(&result, collected, threshold)).into_response()
}

async fn handle_status(
    State(app): State<AppState>,
    Json(req): Json<StatusRequest>,
) -> Response {
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
    let nested_commitment = signing::nested_commitment_pair(&req.session_id, &commitments)
        .ok()
        .map(|(d, e)| NestedCommitment {
            hiding: codec::point_hex(&d),
            binding: codec::point_hex(&e),
        });

    Json(SigningStatusResponse {
        session_id: hex::encode(req.session_id),
        nested_index: app.nested_position,
        round1: RoundStatus {
            collected: r1_collected,
            threshold: r1_threshold,
            ready: r1_collected >= r1_threshold,
        },
        round2: RoundStatus {
            collected: r2_collected,
            threshold: r2_threshold,
            ready: z_nested.is_some(),
        },
        commitments,
        nested_commitment,
        z_nested,
    })
    .into_response()
}

async fn handle_round2(
    State(app): State<AppState>,
    Json(req): Json<SigningRequest>,
) -> Response {
    let session_id = req.session_id;
    match app.signing.start_round2(req).await {
        Ok(share) => {
            let (collected, threshold, _) = app
                .signing
                .round2
                .status(&session_id)
                .await
                .unwrap_or((1, 0, None));
            Json(Round2Response {
                holder_index: share.holder_index,
                response: share.response,
                collected,
                threshold,
                z_nested: app.signing.result(&session_id).await,
            })
            .into_response()
        }
        Err(e) => err(e),
    }
}

async fn handle_share(
    State(app): State<AppState>,
    Json(share): Json<InnerShare>,
) -> Response {
    let session_id = share.session_id;
    let result = app.signing.receive_share(share).await;
    let (collected, threshold, _) = app
        .signing
        .round2
        .status(&session_id)
        .await
        .unwrap_or((0, 0, None));
    let mut body = accumulate_response(&result, collected, threshold);
    body.z_nested = app.signing.result(&session_id).await;
    Json(body).into_response()
}

fn accumulate_response<A: accumulator::Aggregate>(
    result: &AccumulateResult<A>,
    collected: usize,
    threshold: usize,
) -> AccumulateResponse {
    match result {
        AccumulateResult::Pending {
            collected,
            threshold,
        } => AccumulateResponse::pending(*collected, *threshold),
        AccumulateResult::Complete(_) => AccumulateResponse::complete(collected, threshold),
        AccumulateResult::Duplicate => AccumulateResponse::duplicate(collected, threshold),
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

/// Build a ceremony for `epoch`, refusing to go backwards.
///
/// The epoch is what makes an old share set unable to sign, so a node must
/// never be talked into re-running a generation it has already completed: the
/// key package it would overwrite is the one whose epoch its peers expect.
async fn new_ceremony(app: &AppState, epoch: u64) -> Result<dkg::DkgCeremony, dkg::DkgError> {
    let current = app.signing.signer.lock().await.epoch;
    if epoch <= current {
        return Err(dkg::DkgError::EpochNotAdvancing { current, asked: epoch });
    }
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
            if let dkg::DkgError::Aborted(ref c) = e {
                app.peers.broadcast("/dkg/complaint", c);
            }
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
            if let dkg::DkgError::Aborted(ref c) = e {
                app.peers.broadcast("/dkg/complaint", c);
            }
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
) -> Response {
    let epoch = match req.epoch {
        Some(e) => e,
        None => next_epoch(&app).await,
    };

    let ceremony = match new_ceremony(&app, epoch).await {
        Ok(c) => c,
        Err(e) => return err(e),
    };
    let broadcast = ceremony.round1_broadcast();

    let mut guard = app.dkg_ceremony.lock().await;
    *guard = Some(ceremony);
    if let Some(c) = guard.as_mut() {
        if let Err(e) = c.receive_round1(&broadcast) {
            return report_dkg(&app, e);
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
    Json(DkgStartedResponse {
        status: "round1_broadcast",
        epoch,
        session_id: hex::encode(app.roster.session_id(epoch)),
        holder_index: app.holder_index,
        coefficients: broadcast.coefficients.len(),
    })
    .into_response()
}

async fn handle_dkg_round1(
    State(app): State<AppState>,
    Json(msg): Json<dkg::DkgRound1Broadcast>,
) -> Response {
    let mut guard = app.dkg_ceremony.lock().await;

    if guard.is_none() {
        // A peer started the ceremony; adopt its epoch and publish ours.
        let ceremony = match new_ceremony(&app, msg.epoch).await {
            Ok(c) => c,
            Err(e) => return err(e),
        };
        let ours = ceremony.round1_broadcast();
        *guard = Some(ceremony);
        if let Some(c) = guard.as_mut() {
            if let Err(e) = c.receive_round1(&ours) {
                return report_dkg(&app, e);
            }
        }
        app.peers.broadcast("/dkg/round1", &ours);
        tracing::info!("DKG auto-initiated from peer at epoch {}", msg.epoch);
    }

    let complete = match guard.as_mut().map(|c| c.receive_round1(&msg)) {
        Some(Ok(c)) => c,
        Some(Err(e)) => return report_dkg(&app, e),
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

    Json(DkgProgressResponse {
        accepted: true,
        phase: "round1",
        round_complete: Some(complete),
        group_key: None,
    })
    .into_response()
}

async fn handle_dkg_round2(
    State(app): State<AppState>,
    Json(msg): Json<dkg::DkgRound2Msg>,
) -> Response {
    let mut guard = app.dkg_ceremony.lock().await;
    let complete = match guard.as_mut().map(|c| c.receive_round2(&msg)) {
        Some(Ok(c)) => c,
        Some(Err(e)) => return report_dkg(&app, e),
        None => return err("no DKG ceremony active"),
    };

    tracing::info!(
        "DKG round 2: sealed packages from dealer {}, complete={}",
        msg.dealer_index,
        complete
    );

    if complete {
        if let Some(group_key) = maybe_finalize(&app, &mut guard).await {
            return Json(DkgProgressResponse {
                accepted: true,
                phase: "complete",
                round_complete: Some(true),
                group_key: Some(group_key),
            })
            .into_response();
        }
    }
    Json(DkgProgressResponse {
        accepted: true,
        phase: "round2",
        round_complete: Some(complete),
        group_key: None,
    })
    .into_response()
}

/// A peer raised a complaint. Abort here too: a ceremony that continues
/// without one member produces a key that member does not hold.
async fn handle_dkg_complaint(
    State(app): State<AppState>,
    Json(complaint): Json<dkg::Complaint>,
) -> Response {
    let mut guard = app.dkg_ceremony.lock().await;
    match guard.as_mut() {
        Some(c) => match c.receive_complaint(&complaint) {
            Ok(()) => Json(DkgProgressResponse {
                accepted: true,
                phase: "aborted",
                round_complete: None,
                group_key: None,
            })
            .into_response(),
            Err(e) => err(e),
        },
        None => err("no DKG ceremony active"),
    }
}

/// The ceremony's phase and nothing else.
///
/// **M-1.** This used to serialize `c.result` — a [`dkg::DkgResult`], whose
/// `coefficient_shares` are this node's Shamir shares of every outer
/// coefficient — to any unauthenticated caller. The field is `serde(skip)`
/// now, and this handler builds a [`response::PublicDkgResult`] rather than
/// trusting that. Nothing here is secret: indices, a phase, commitment
/// digests.
async fn handle_dkg_status(State(app): State<AppState>) -> Response {
    let guard = app.dkg_ceremony.lock().await;
    let body = match guard.as_ref() {
        Some(c) => {
            let phase = if c.abort_reason().is_some() {
                "aborted"
            } else if c.result.is_some() {
                "complete"
            } else if c.round2_complete() {
                "round2_complete"
            } else if c.round1_complete() {
                "round1_complete"
            } else {
                "round1"
            };
            DkgStatusResponse {
                active: true,
                epoch: Some(c.epoch),
                session_id: Some(hex::encode(c.session_id)),
                holder_index: Some(c.holder_index),
                phase,
                round1_digest: None,
                aborted_against_dealer: c.abort_reason().map(|x| x.dealer_index),
                result: c.result.as_ref().map(|r| r.public_view()),
            }
        }
        None => DkgStatusResponse {
            active: false,
            epoch: None,
            session_id: None,
            holder_index: None,
            phase: "idle",
            round1_digest: None,
            aborted_against_dealer: None,
            result: None,
        },
    };
    Json(body).into_response()
}

/// Re-install the persisted key package — after an operator has replaced it,
/// or to move this node to a different nested position without a restart.
async fn handle_dkg_activate(State(app): State<AppState>) -> Response {
    match KeyPackage::load(&app.data_dir) {
        Ok(Some(package)) => {
            install_share(&app, &package).await;
            Json(ActivateResponse {
                status: "activated",
                epoch: package.epoch,
                holder_index: package.holder_index,
                nested_position: app.nested_position,
            })
            .into_response()
        }
        Ok(None) => err("no key package on disk; run the DKG first"),
        Err(e) => err(e),
    }
}

async fn handle_health(State(app): State<AppState>) -> Response {
    let signer = app.signing.signer.lock().await;
    Json(HealthResponse {
        status: "ok",
        holder_index: signer.holder_index,
        nested_position: signer.nested_position,
        epoch: signer.epoch,
        epoch_hwm: signer.epoch,
        has_share: signer.has_share(),
        roster_hash: hex::encode(app.roster.hash()),
        x25519_pub: hex::encode(app.identity.x25519_public()),
        ed25519_pub: String::new(),
        peers: app.peers.peer_count(),
    })
    .into_response()
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
        .route("/dkg/complaint", axum::routing::post(handle_dkg_complaint))
        .route("/dkg/activate", axum::routing::post(handle_dkg_activate))
        .route("/dkg/status", axum::routing::get(handle_dkg_status))
        .route("/health", axum::routing::get(handle_health))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cli.bind).await.unwrap();
    tracing::info!("narsild listening on {}", cli.bind);
    axum::serve(listener, app).await.unwrap();
}
