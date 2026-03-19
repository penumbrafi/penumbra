//! narsild — Narsil sidecar daemon for Penumbra validators
//!
//! architecture: "your server as a function" (Marius Eriksen)
//!
//! every protocol (OSST authorization, nested FROST signing) is composed from:
//!   - ThresholdAccumulator: collect contributions until threshold
//!   - PeerBroadcast: fan out to all validators
//!   - LocalSigner: produce this node's contribution
//!
//! handlers are thin: extract request → call service → serialize response.

mod accumulator;
mod broadcast;
pub mod client;
mod dkg;
mod signing;

use accumulator::AccumulateResult;
use broadcast::PeerSet;
use signing::{SigningService, InnerCommitment, InnerShare};

use axum::{Router, extract::State, response::IntoResponse, Json};
use clap::Parser;
use pasta_curves::pallas::Scalar;
use pasta_curves::group::ff::{Field, PrimeField};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Request/response types (JSON wire format)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Round1Request {
    session_id: [u8; 32],
    message_hex: String,
}

#[derive(Deserialize)]
struct Round2Request {
    session_id: [u8; 32],
    outer_challenge_hex: String,
    outer_lambda_hex: String,
    active_indices: Vec<u32>,
    /// included when broadcast from peer (so we can store the message)
    #[serde(default)]
    message_hex: Option<String>,
}

#[derive(Deserialize)]
struct StatusRequest {
    session_id: [u8; 32],
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    signing: SigningService,
    dkg_ceremony: Arc<Mutex<Option<dkg::DkgCeremony>>>,
    peers: PeerSet,
}

// ---------------------------------------------------------------------------
// Handlers — thin wrappers over service methods
// ---------------------------------------------------------------------------

async fn handle_round1(
    State(app): State<AppState>,
    Json(req): Json<Round1Request>,
) -> impl IntoResponse {
    let message = hex::decode(&req.message_hex).unwrap_or_default();
    let commitment = app.signing.start_round1(req.session_id, message).await;
    let (collected, threshold, _) = app.signing.round1.status(&req.session_id).await
        .unwrap_or((1, 0, None));

    Json(serde_json::json!({
        "holder_index": commitment.holder_index,
        "hiding": hex::encode(commitment.hiding),
        "binding": hex::encode(commitment.binding),
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
    accumulate_response(result, &app.signing.round1, &session_id).await
}

async fn handle_status(
    State(app): State<AppState>,
    Json(req): Json<StatusRequest>,
) -> impl IntoResponse {
    let commitments = app.signing.round1.contributions(&req.session_id).await;
    let (r1_collected, r1_threshold, _) = app.signing.round1.status(&req.session_id).await
        .unwrap_or((0, 0, None));
    let (r2_collected, r2_threshold, r2_result) = app.signing.round2.status(&req.session_id).await
        .unwrap_or((0, 0, None));

    let commitment_list: Vec<serde_json::Value> = commitments.iter().map(|c| {
        serde_json::json!({
            "holder_index": c.holder_index,
            "hiding": hex::encode(c.hiding),
            "binding": hex::encode(c.binding),
        })
    }).collect();

    Json(serde_json::json!({
        "session_id": hex::encode(req.session_id),
        "round1": { "collected": r1_collected, "threshold": r1_threshold, "ready": r1_collected >= r1_threshold },
        "round2": {
            "collected": r2_collected,
            "threshold": r2_threshold,
            "complete": r2_result.is_some(),
            "z_nested": r2_result.map(|r| r.z_hex),
        },
        "commitments": commitment_list,
    }))
}

async fn handle_round2(
    State(app): State<AppState>,
    Json(req): Json<Round2Request>,
) -> impl IntoResponse {
    let challenge = match scalar_from_hex(&req.outer_challenge_hex) {
        Some(s) => s,
        None => return Json(serde_json::json!({"error": "bad outer_challenge_hex"})),
    };
    let lambda = match scalar_from_hex(&req.outer_lambda_hex) {
        Some(s) => s,
        None => return Json(serde_json::json!({"error": "bad outer_lambda_hex"})),
    };

    // if message_hex provided (peer broadcast), store it so start_round2 can find it
    if let Some(ref msg_hex) = req.message_hex {
        if let Ok(msg_bytes) = hex::decode(msg_hex) {
            app.signing.messages.lock().await
                .entry(req.session_id)
                .or_insert(msg_bytes);
        }
    }

    match app.signing.start_round2(req.session_id, challenge, lambda, req.active_indices).await {
        Some(share) => {
            let (collected, threshold, result) = app.signing.round2.status(&req.session_id).await
                .unwrap_or((1, 0, None));
            Json(serde_json::json!({
                "holder_index": share.holder_index,
                "response": share.response_hex,
                "collected": collected,
                "threshold": threshold,
                "z_nested": result.map(|r| r.z_hex),
            }))
        }
        None => Json(serde_json::json!({"error": "signing failed (nonces consumed or missing)"})),
    }
}

async fn handle_share(
    State(app): State<AppState>,
    Json(share): Json<InnerShare>,
) -> impl IntoResponse {
    let session_id = share.session_id;
    let result = app.signing.receive_share(share).await;
    accumulate_response_r2(result, &app.signing.round2, &session_id).await
}

// ---------------------------------------------------------------------------
// DKG handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DkgInitRequest {
    inner_n: u32,
    inner_t: u32,
    outer_t: u32,
}

/// start DKG ceremony: initialize dealers and broadcast round 1 commitments
async fn handle_dkg_init(
    State(app): State<AppState>,
    Json(req): Json<DkgInitRequest>,
) -> impl IntoResponse {
    let holder_index = app.signing.signer.lock().await.holder_index;

    let ceremony = dkg::DkgCeremony::new(
        holder_index, req.inner_n, req.inner_t, req.outer_t, app.peers.clone(),
    );

    let broadcast = ceremony.round1_broadcast();

    // store ceremony
    *app.dkg_ceremony.lock().await = Some(ceremony);

    // receive our own commitments
    {
        let mut guard = app.dkg_ceremony.lock().await;
        if let Some(ref mut c) = *guard {
            c.receive_round1(&broadcast);
        }
    }

    // broadcast to peers
    app.peers.broadcast("/dkg/round1", &broadcast);

    tracing::info!("DKG initiated: {}-of-{} inner, {}-of-? outer", req.inner_t, req.inner_n, req.outer_t);

    Json(serde_json::json!({
        "status": "round1_broadcast",
        "holder_index": holder_index,
        "coefficients": broadcast.coefficients.len(),
    }))
}

/// receive round 1 commitments from a peer
async fn handle_dkg_round1(
    State(app): State<AppState>,
    Json(msg): Json<dkg::DkgRound1Broadcast>,
) -> impl IntoResponse {
    let mut guard = app.dkg_ceremony.lock().await;

    // if no ceremony exists, create one (peer initiated before us)
    if guard.is_none() {
        let holder_index = app.signing.signer.lock().await.holder_index;
        // infer params from the message
        let outer_t = msg.coefficients.len() as u32;
        let inner_t = msg.coefficients.first()
            .map(|c| c.commitments.len() as u32)
            .unwrap_or(3);
        let inner_n = app.peers.peer_count() as u32 + 1;

        let ceremony = dkg::DkgCeremony::new(
            holder_index, inner_n, inner_t, outer_t, app.peers.clone(),
        );

        // broadcast our own round 1
        let our_broadcast = ceremony.round1_broadcast();
        *guard = Some(ceremony);

        // receive our own
        if let Some(ref mut c) = *guard {
            c.receive_round1(&our_broadcast);
        }

        app.peers.broadcast("/dkg/round1", &our_broadcast);

        tracing::info!("DKG auto-initiated from peer, broadcasting our commitments");
    }

    let all_received = if let Some(ref mut c) = *guard {
        c.receive_round1(&msg)
    } else {
        false
    };

    tracing::info!("DKG round1: received from dealer {}, all_received={}", msg.dealer_index, all_received);

    // if all commitments received, auto-start round 2
    if all_received {
        if let Some(ref c) = *guard {
            let round2_msgs = c.round2_generate();
            let holder_index = c.holder_index;

            // send subshares to specific peers (and ourselves)
            for msg in &round2_msgs {
                if msg.recipient_index == holder_index {
                    // apply our own subshares
                    // (done outside this block to avoid double borrow)
                } else {
                    // send to the specific peer
                    // find which peer has this index
                    app.peers.broadcast("/dkg/round2", msg);
                }
            }

            // receive our own subshares
            let our_msg = round2_msgs.iter().find(|m| m.recipient_index == holder_index);
            if let Some(our_msg) = our_msg {
                if let Some(ref mut c) = *guard {
                    let _ = c.receive_round2(our_msg);
                }
            }

            tracing::info!("DKG round2: generated and sent {} subshare messages", round2_msgs.len());
        }
    }

    Json(serde_json::json!({
        "accepted": true,
        "all_commitments_received": all_received,
    }))
}

/// receive round 2 subshares from a peer
async fn handle_dkg_round2(
    State(app): State<AppState>,
    Json(msg): Json<dkg::DkgRound2Msg>,
) -> impl IntoResponse {
    let mut guard = app.dkg_ceremony.lock().await;
    let ceremony = match guard.as_mut() {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "no DKG ceremony active"})),
    };

    // only accept subshares addressed to us
    if msg.recipient_index != ceremony.holder_index {
        return Json(serde_json::json!({"accepted": false, "reason": "not our recipient"}));
    }

    match ceremony.receive_round2(&msg) {
        Ok(all_received) => {
            tracing::info!("DKG round2: received from dealer {}, all_received={}", msg.dealer_index, all_received);

            if all_received {
                match ceremony.finalize() {
                    Ok(result) => {
                        tracing::info!("DKG COMPLETE! holder={}, {} coefficient shares",
                            result.holder_index, result.coefficient_shares.len());

                        // update the signing service with the real share
                        // the share for signing is: evaluate InnerShare at the nested position
                        // for now store the raw coefficient shares
                        // TODO: combine with outer participant evaluations when escrow is created

                        return Json(serde_json::json!({
                            "status": "complete",
                            "holder_index": result.holder_index,
                            "coefficient_shares": result.coefficient_shares.len(),
                            "coeff_commitments": result.coeff_commitments,
                        }));
                    }
                    Err(e) => {
                        tracing::error!("DKG finalization error: {}", e);
                        return Json(serde_json::json!({"error": e}));
                    }
                }
            }

            Json(serde_json::json!({"accepted": true, "all_received": all_received}))
        }
        Err(e) => {
            tracing::error!("DKG round2 error: {}", e);
            Json(serde_json::json!({"error": e}))
        }
    }
}

/// DKG status
async fn handle_dkg_status(State(app): State<AppState>) -> impl IntoResponse {
    let guard = app.dkg_ceremony.lock().await;
    match guard.as_ref() {
        Some(c) => {
            Json(serde_json::json!({
                "active": true,
                "holder_index": c.holder_index,
                "complete": c.result.is_some(),
                "result": c.result.as_ref().map(|r| serde_json::json!({
                    "coefficient_shares": r.coefficient_shares.len(),
                    "coeff_commitments": r.coeff_commitments,
                    "inner_threshold": r.inner_threshold,
                    "inner_n": r.inner_n,
                    "outer_threshold": r.outer_threshold,
                })),
            }))
        }
        None => Json(serde_json::json!({"active": false})),
    }
}

async fn handle_health(State(app): State<AppState>) -> impl IntoResponse {
    let signer = app.signing.signer.lock().await;
    Json(serde_json::json!({
        "status": "ok",
        "holder_index": signer.holder_index,
        "peers": app.signing.peers.peer_count(),
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn accumulate_response<A: accumulator::Aggregate + std::fmt::Debug>(
    result: AccumulateResult<A>,
    acc: &accumulator::ThresholdAccumulator<[u8; 32], InnerCommitment, signing::CommitmentList>,
    session_id: &[u8; 32],
) -> Json<serde_json::Value> {
    let (collected, threshold, _) = acc.status(session_id).await.unwrap_or((0, 0, None));
    match result {
        AccumulateResult::Pending { .. } => Json(serde_json::json!({
            "accepted": true, "collected": collected, "threshold": threshold,
        })),
        AccumulateResult::Complete(_) => Json(serde_json::json!({
            "accepted": true, "collected": collected, "threshold": threshold, "threshold_met": true,
        })),
        AccumulateResult::Duplicate => Json(serde_json::json!({
            "accepted": false, "reason": "duplicate",
        })),
    }
}

async fn accumulate_response_r2(
    result: AccumulateResult<signing::NestedResponse>,
    acc: &accumulator::ThresholdAccumulator<[u8; 32], InnerShare, signing::NestedResponse>,
    session_id: &[u8; 32],
) -> Json<serde_json::Value> {
    let (collected, threshold, r) = acc.status(session_id).await.unwrap_or((0, 0, None));
    match result {
        AccumulateResult::Pending { .. } => Json(serde_json::json!({
            "accepted": true, "collected": collected, "threshold": threshold,
        })),
        AccumulateResult::Complete(ref nr) => Json(serde_json::json!({
            "accepted": true, "collected": collected, "threshold_met": true,
            "z_nested": nr.z_hex,
        })),
        AccumulateResult::Duplicate => Json(serde_json::json!({
            "accepted": false, "reason": "duplicate",
        })),
    }
}

fn scalar_from_hex(hex_str: &str) -> Option<Scalar> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 { return None; }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let ct: subtle::CtOption<Scalar> = Scalar::from_repr(arr.into());
    Option::from(ct)
}

// ---------------------------------------------------------------------------
// CLI + main
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "narsild", about = "Narsil sidecar for Penumbra validators")]
struct Cli {
    /// Listen address
    #[arg(long, default_value = "0.0.0.0:9200")]
    bind: String,

    /// Peer narsild endpoints (comma-separated)
    #[arg(long, value_delimiter = ',')]
    peers: Vec<String>,

    /// Inner FROST threshold (how many validators needed to sign)
    #[arg(long, default_value_t = 3)]
    threshold: usize,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("narsild=info")
        .init();

    let cli = Cli::parse();

    // Node index from bind port (9200 → 0, 9201 → 1, etc.)
    let node_index = cli.bind.split(':').last()
        .and_then(|p| p.parse::<u32>().ok())
        .map(|p| p - 9200)
        .unwrap_or(0);
    let holder_index = node_index + 1; // 1-indexed

    // In production: loaded from DKG output
    let share_scalar = Scalar::random(&mut rand_core::OsRng);

    let peers = PeerSet::new(cli.peers);
    let peers_clone = peers.clone();
    let signing = SigningService::new(holder_index, share_scalar, cli.threshold, peers);

    let state = AppState {
        signing,
        dkg_ceremony: Arc::new(Mutex::new(None)),
        peers: peers_clone,
    };

    tracing::info!("narsild starting: holder={}, threshold={}, bind={}",
        holder_index, cli.threshold, cli.bind);

    let app = Router::new()
        .route("/sign/round1", axum::routing::post(handle_round1))
        .route("/sign/commitment", axum::routing::post(handle_commitment))
        .route("/sign/status", axum::routing::post(handle_status))
        .route("/sign/round2", axum::routing::post(handle_round2))
        .route("/sign/share", axum::routing::post(handle_share))
        // Distributed interleaved DKG
        .route("/dkg/init", axum::routing::post(handle_dkg_init))
        .route("/dkg/round1", axum::routing::post(handle_dkg_round1))
        .route("/dkg/round2", axum::routing::post(handle_dkg_round2))
        .route("/dkg/status", axum::routing::get(handle_dkg_status))
        .route("/health", axum::routing::get(handle_health))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cli.bind).await.unwrap();
    tracing::info!("narsild listening on {}", cli.bind);
    axum::serve(listener, app).await.unwrap();
}
