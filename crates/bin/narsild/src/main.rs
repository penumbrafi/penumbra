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
mod agreement;
mod auth;
mod broadcast;
pub mod client;
mod codec;
mod dkg;
mod identity;
mod keypackage;
mod policy;
mod response;
mod roster;
mod signing;
#[cfg(test)]
mod tests;

use accumulator::AccumulateResult;
use auth::{Authenticator, Envelope};
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
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

/// A proposal this node has seen, and who has approved it (M-3).
#[derive(Default)]
struct ProposalRecord {
    proposal: Option<dkg::DkgProposal>,
    approvals: std::collections::BTreeSet<u32>,
    started: bool,
}

#[derive(Clone)]
struct AppState {
    signing: SigningService,
    dkg_ceremony: Arc<Mutex<Option<dkg::DkgCeremony>>>,
    /// Proposals by digest. Bounded by the roster: a member can propose, and
    /// only a member.
    proposals: Arc<Mutex<std::collections::BTreeMap<[u8; 32], ProposalRecord>>>,
    /// Whether this node's operator has consented to replacing an existing key
    /// package.
    allow_rotation: bool,
    peers: PeerSet,
    auth: Arc<Authenticator>,
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
/// The largest request body any endpoint accepts.
const MAX_BODY_BYTES: usize = 1 << 20;

/// How many DKG proposals this node will hold at once.
const MAX_PROPOSALS: usize = 16;

fn err(msg: impl std::fmt::Display) -> Response {
    let text = msg.to_string();
    tracing::warn!("request rejected: {}", text);
    (axum::http::StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "rejected" }))
        .into_response()
}

/// Verify an envelope for `path` and parse its body (M-2).
///
/// Every mutating endpoint goes through here. The read-only ones — `/health`,
/// `/sign/status`, `/dkg/status` — do not, because after M-1 they carry only
/// public data; that is a property of `response.rs`, enforced by a test there,
/// rather than a promise made here.
#[allow(clippy::result_large_err)] // the error *is* the HTTP response
fn authed<T: DeserializeOwned>(
    app: &AppState,
    path: &str,
    envelope: &Envelope,
) -> Result<(u32, T), Response> {
    app.auth.open::<T>(path, envelope).map_err(err)
}

/// Refuse a message whose own index does not match the envelope that carried
/// it: without this, an authenticated member can post a round-1 commitment,
/// a complaint or a share "from" another member (M-7).
#[allow(clippy::result_large_err)] // the error *is* the HTTP response
fn same_index(sender: u32, claimed: u32) -> Result<(), Response> {
    if sender == claimed {
        Ok(())
    } else {
        Err(err(format!(
            "member {sender} sent a message claiming to be from member {claimed}"
        )))
    }
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
#[serde(deny_unknown_fields)]
struct Round1Request {
    session_id: [u8; 32],
    /// The application message this session is for, hex. The local policy
    /// sees this before a single nonce is sampled.
    message_hex: String,
}

#[derive(Deserialize)]
struct StatusRequest {
    session_id: [u8; 32],
}

async fn handle_round1(
    State(app): State<AppState>,
    Json(envelope): Json<Envelope>,
) -> Response {
    let (_sender, req): (u32, Round1Request) = match authed(&app, "/sign/round1", &envelope) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let message = match hex::decode(&req.message_hex) {
        Ok(m) => m,
        Err(_) => return err("message_hex is not hex"),
    };
    let commitment = match app.signing.start_round1(req.session_id, &message).await {
        Ok(c) => c,
        Err(e) => return err(e),
    };
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
    Json(envelope): Json<Envelope>,
) -> Response {
    let (sender, commitment): (u32, InnerCommitment) =
        match authed(&app, "/sign/commitment", &envelope) {
            Ok(v) => v,
            Err(r) => return r,
        };
    if let Err(r) = same_index(sender, commitment.holder_index) {
        return r;
    }
    let session_id = commitment.session_id;
    let result = match app.signing.receive_commitment(commitment).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
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
    Json(envelope): Json<Envelope>,
) -> Response {
    let (_sender, req): (u32, SigningRequest) = match authed(&app, "/sign/round2", &envelope) {
        Ok(v) => v,
        Err(r) => return r,
    };
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
    Json(envelope): Json<Envelope>,
) -> Response {
    let (sender, share): (u32, InnerShare) = match authed(&app, "/sign/share", &envelope) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(r) = same_index(sender, share.holder_index) {
        return r;
    }
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
#[serde(deny_unknown_fields)]
struct DkgInitRequest {
    /// The generation to produce. Defaults to the loaded key package's epoch
    /// plus one, or 1 on a node that has never run a DKG.
    #[serde(default)]
    epoch: Option<u64>,
    /// Whether this ceremony is to replace an existing key package. A node
    /// that holds one approves nothing else.
    #[serde(default)]
    rotate: bool,
}

/// Build a ceremony for `epoch`, refusing to go backwards.
///
/// The epoch is what makes an old share set unable to sign, so a node must
/// never be talked into re-running a generation it has already completed: the
/// key package it would overwrite is the one whose epoch its peers expect.
async fn new_ceremony(
    app: &AppState,
    epoch: u64,
    ceremony_nonce: [u8; 32],
) -> Result<dkg::DkgCeremony, dkg::DkgError> {
    let current = app.signing.signer.lock().await.epoch;
    if epoch <= current {
        return Err(dkg::DkgError::EpochNotAdvancing { current, asked: epoch });
    }
    dkg::DkgCeremony::new(
        app.holder_index,
        app.roster.clone(),
        app.identity.x25519_secret(),
        epoch,
        ceremony_nonce,
        app.inner_threshold,
        app.outer_threshold,
    )
}

async fn next_epoch(app: &AppState) -> u64 {
    app.signing.signer.lock().await.epoch + 1
}

/// Round 1 is complete here: publish this node's digest of the round-1 set and
/// apply it to our own ceremony (M-5).
///
/// Nothing moves to round 2 until every member has echoed the same digest.
async fn run_echo(app: &AppState, guard: &mut Option<dkg::DkgCeremony>) -> bool {
    let echo = match guard.as_ref().and_then(|c| c.echo()) {
        Some(e) => e,
        None => return false,
    };
    app.peers.broadcast("/dkg/echo", &echo);
    match guard.as_mut().map(|c| c.receive_echo(&echo)) {
        Some(Ok(agreed)) => agreed,
        Some(Err(e)) => {
            tracing::error!("DKG echo round: {}", e);
            false
        }
        None => false,
    }
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
    // M-10: a save failure is fatal. Installing the share anyway leaves the
    // node running at epoch e+1 in memory over an on-disk epoch e, so it
    // signs under a generation it will silently revert out of on the next
    // restart — and the shares it would have needed are gone.
    match package.save(&app.data_dir) {
        Ok(path) => tracing::info!("DKG complete; key package written to {}", path.display()),
        Err(e) => {
            tracing::error!(
                "could not persist the key package ({}); this node cannot continue \
                 without silently running an epoch it has no record of",
                e
            );
            std::process::exit(1);
        }
    }
    install_share(app, &package).await;
    Some(result.coeff_commitments.first().cloned().unwrap_or_default())
}

/// Load a key package into the live signer.
async fn install_share(app: &AppState, package: &KeyPackage) {
    let manifest_hash = match package.manifest_hash() {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("refusing to install a key package: {}", e);
            return;
        }
    };
    let share = package.share_at(app.nested_position);
    let public_shares = package.public_shares_at(app.nested_position);
    match (share, public_shares) {
        (Some(share), Some(public_shares)) => {
            let mut signer = app.signing.signer.lock().await;
            signer.epoch = package.epoch;
            signer.manifest_hash = manifest_hash;
            signer.install(share, public_shares, package.group_pubkey());
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

/// Propose a DKG (M-3).
///
/// This does not start anything. It publishes a proposal — epoch, attempt
/// nonce, and whether an existing key package is to be replaced — which every
/// member decides on for itself. The ceremony begins on each node when it has
/// seen `inner_threshold` approvals of that exact proposal.
async fn handle_dkg_init(
    State(app): State<AppState>,
    Json(envelope): Json<Envelope>,
) -> Response {
    let (sender, req): (u32, DkgInitRequest) = match authed(&app, "/dkg/init", &envelope) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let epoch = match req.epoch {
        Some(e) => e,
        None => next_epoch(&app).await,
    };
    let mut ceremony_nonce = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut ceremony_nonce);

    let proposal = dkg::DkgProposal {
        epoch,
        ceremony_nonce,
        rotate: req.rotate,
        roster_hash: hex::encode(app.roster.hash()),
    };
    tracing::info!(
        "DKG proposed by roster member {}: epoch {}, rotate={}",
        sender,
        epoch,
        req.rotate
    );

    app.peers.broadcast("/dkg/propose", &proposal);
    consider_proposal(&app, &proposal).await
}

/// Whether this node approves a proposal.
///
/// The one rule that matters: a node holding a key package approves nothing
/// that does not say `rotate: true`, and approves a rotation only if its own
/// operator has consented with `--allow-rotation`. Everything else about a DKG
/// is recoverable; overwriting the shares is not.
async fn approves(app: &AppState, proposal: &dkg::DkgProposal) -> Result<(), &'static str> {
    let current = app.signing.signer.lock().await.epoch;
    let have_package = matches!(KeyPackage::load(&app.data_dir), Ok(Some(_)));
    dkg::may_approve(
        proposal,
        &hex::encode(app.roster.hash()),
        current,
        have_package,
        app.allow_rotation,
    )
}

/// Record a proposal, approve it if this node will, and start the ceremony if
/// the threshold is met.
async fn consider_proposal(app: &AppState, proposal: &dkg::DkgProposal) -> Response {
    let digest = proposal.digest();

    let approved = match approves(app, proposal).await {
        Ok(()) => true,
        Err(why) => {
            tracing::warn!("not approving the DKG proposal: {}", why);
            false
        }
    };

    {
        let mut proposals = app.proposals.lock().await;
        // Bound the table: a roster of n members has no business holding more
        // than a handful of live proposals (M-18).
        if proposals.len() >= MAX_PROPOSALS && !proposals.contains_key(&digest) {
            return err("too many open DKG proposals");
        }
        let record = proposals.entry(digest).or_default();
        record.proposal = Some(proposal.clone());
        if approved {
            record.approvals.insert(app.holder_index);
        }
    }

    if approved {
        let approval = dkg::DkgApproval {
            approver_index: app.holder_index,
            proposal_digest: digest,
        };
        app.peers.broadcast("/dkg/approve", &approval);
    }

    maybe_start(app, &digest).await
}

/// Start the ceremony for a proposal once `inner_threshold` members approve it.
async fn maybe_start(app: &AppState, digest: &[u8; 32]) -> Response {
    let (proposal, approvals) = {
        let proposals = app.proposals.lock().await;
        match proposals.get(digest) {
            Some(r) if !r.started => (r.proposal.clone(), r.approvals.len()),
            Some(r) => (None, r.approvals.len()),
            None => (None, 0),
        }
    };

    let needed = app.inner_threshold as usize;
    let proposal = match proposal {
        Some(p) if approvals >= needed => p,
        _ => {
            return Json(response::DkgProposalResponse {
                accepted: true,
                approvals,
                needed,
                proposal_digest: Some(hex::encode(digest)),
            })
            .into_response()
        }
    };

    let ceremony = match new_ceremony(app, proposal.epoch, proposal.ceremony_nonce).await {
        Ok(c) => c,
        Err(e) => return err(e),
    };
    let session_id = ceremony.session_id;
    let broadcast = ceremony.round1_broadcast();

    {
        let mut guard = app.dkg_ceremony.lock().await;
        if guard.is_some() {
            return err("a DKG ceremony is already in progress on this node");
        }
        *guard = Some(ceremony);
        if let Some(c) = guard.as_mut() {
            if let Err(e) = c.receive_round1(&broadcast) {
                return report_dkg(app, e);
            }
        }
    }
    app.proposals
        .lock()
        .await
        .entry(*digest)
        .or_default()
        .started = true;

    app.peers.broadcast("/dkg/round1", &broadcast);
    tracing::info!(
        "DKG started: epoch {}, session {}, {} approvals, {}-of-{} inner, outer \
         threshold {}",
        proposal.epoch,
        hex::encode(session_id),
        approvals,
        app.inner_threshold,
        app.roster.len(),
        app.outer_threshold
    );

    Json(DkgStartedResponse {
        status: "round1_broadcast",
        epoch: proposal.epoch,
        session_id: hex::encode(session_id),
        holder_index: app.holder_index,
        coefficients: broadcast.coefficients.len(),
    })
    .into_response()
}

/// A peer proposed a DKG.
async fn handle_dkg_propose(
    State(app): State<AppState>,
    Json(envelope): Json<Envelope>,
) -> Response {
    let (sender, proposal): (u32, dkg::DkgProposal) =
        match authed(&app, "/dkg/propose", &envelope) {
            Ok(v) => v,
            Err(r) => return r,
        };
    tracing::info!(
        "roster member {} proposes a DKG for epoch {} (rotate={})",
        sender,
        proposal.epoch,
        proposal.rotate
    );
    consider_proposal(&app, &proposal).await
}

/// A peer approved a proposal.
async fn handle_dkg_approve(
    State(app): State<AppState>,
    Json(envelope): Json<Envelope>,
) -> Response {
    let (sender, approval): (u32, dkg::DkgApproval) =
        match authed(&app, "/dkg/approve", &envelope) {
            Ok(v) => v,
            Err(r) => return r,
        };
    if let Err(r) = same_index(sender, approval.approver_index) {
        return r;
    }

    {
        let mut proposals = app.proposals.lock().await;
        match proposals.get_mut(&approval.proposal_digest) {
            Some(record) => {
                record.approvals.insert(sender);
            }
            // An approval for a proposal this node has not seen. Not an error
            // — the broadcasts race — but nothing to do with it either: a
            // proposal is what carries the terms, and approvals are counted
            // against terms this node has checked for itself.
            None => return err("no such proposal"),
        }
    }

    maybe_start(&app, &approval.proposal_digest).await
}

async fn handle_dkg_round1(
    State(app): State<AppState>,
    Json(envelope): Json<Envelope>,
) -> Response {
    let (sender, msg): (u32, dkg::DkgRound1Broadcast) =
        match authed(&app, "/dkg/round1", &envelope) {
            Ok(v) => v,
            Err(r) => return r,
        };
    // M-7: a round-1 package for index i must come from roster member i.
    // Without this an attacker squats an honest dealer's slot, its genuine
    // broadcast is dropped first-write-wins, and round 2 frames it.
    if let Err(r) = same_index(sender, msg.dealer_index) {
        return r;
    }
    // No auto-adoption (M-3). A forged round 1 used to start a ceremony on a
    // peer-asserted epoch, and the honest nodes then ran a legitimate DKG that
    // overwrote the key package. A ceremony starts from an approved proposal
    // or not at all.
    let mut guard = app.dkg_ceremony.lock().await;
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

    if complete && run_echo(&app, &mut guard).await {
        run_round2(&app, &mut guard).await;
        let _ = maybe_finalize(&app, &mut guard).await;
    }

    Json(DkgProgressResponse {
        accepted: true,
        phase: if complete { "round1_complete" } else { "round1" },
        round_complete: Some(complete),
        group_key: None,
    })
    .into_response()
}

async fn handle_dkg_round2(
    State(app): State<AppState>,
    Json(envelope): Json<Envelope>,
) -> Response {
    let (sender, msg): (u32, dkg::DkgRound2Msg) = match authed(&app, "/dkg/round2", &envelope) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(r) = same_index(sender, msg.dealer_index) {
        return r;
    }
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

/// A peer's echo of the round-1 digest (M-5).
///
/// This is where a dealer that sent different commitments to different
/// recipients is caught: the per-recipient checks all pass for such a dealer,
/// and only a cross-node comparison of the whole round-1 set sees it.
async fn handle_dkg_echo(
    State(app): State<AppState>,
    Json(envelope): Json<Envelope>,
) -> Response {
    let (sender, echo): (u32, agreement::DkgEcho) = match authed(&app, "/dkg/echo", &envelope) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(r) = same_index(sender, echo.sender_index) {
        return r;
    }

    let mut guard = app.dkg_ceremony.lock().await;
    let agreed = match guard.as_mut().map(|c| c.receive_echo(&echo)) {
        Some(Ok(a)) => a,
        Some(Err(e)) => return report_dkg(&app, e),
        None => return err("no DKG ceremony active"),
    };

    if agreed {
        tracing::info!("DKG round 1 agreed by every member; entering round 2");
        run_round2(&app, &mut guard).await;
        let _ = maybe_finalize(&app, &mut guard).await;
    }

    Json(DkgProgressResponse {
        accepted: true,
        phase: if agreed { "round1_agreed" } else { "echo" },
        round_complete: Some(agreed),
        group_key: None,
    })
    .into_response()
}

/// A peer raised a complaint (M-6).
///
/// Adjudicated locally — the ceremony checks the evidence against its own
/// round-1 record — and re-broadcast the first time it is seen, so a complaint
/// delivered to one node reaches the whole group instead of stopping that node
/// while the rest finalize.
async fn handle_dkg_complaint(
    State(app): State<AppState>,
    Json(envelope): Json<Envelope>,
) -> Response {
    let (sender, complaint): (u32, dkg::Complaint) =
        match authed(&app, "/dkg/complaint", &envelope) {
            Ok(v) => v,
            Err(r) => return r,
        };
    if let Err(r) = same_index(sender, complaint.complainant_index) {
        return r;
    }
    let mut guard = app.dkg_ceremony.lock().await;
    match guard.as_mut() {
        Some(c) => match c.receive_complaint(&complaint) {
            Ok(fresh) => {
                let phase = if c.abort_reason().is_some() {
                    "aborted"
                } else {
                    "complaint_recorded"
                };
                if fresh {
                    app.peers.broadcast("/dkg/complaint", &complaint);
                }
                Json(DkgProgressResponse {
                    accepted: true,
                    phase,
                    round_complete: None,
                    group_key: None,
                })
                .into_response()
            }
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
                round1_digest: c.round1_digest().map(hex::encode),
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
async fn handle_dkg_activate(
    State(app): State<AppState>,
    Json(envelope): Json<Envelope>,
) -> Response {
    let (sender, _req): (u32, serde_json::Value) = match authed(&app, "/dkg/activate", &envelope) {
        Ok(v) => v,
        Err(r) => return r,
    };
    tracing::info!("key package re-activation requested by roster member {}", sender);
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
        ed25519_pub: hex::encode(app.identity.ed25519_public()),
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
    ///
    /// Loopback by default. The endpoints are authenticated (M-2), but a
    /// daemon holding escrow authority should not be reachable from the world
    /// because it has an extra check; binding wider is an explicit decision.
    #[arg(long, default_value = "127.0.0.1:9200")]
    bind: String,

    /// This node's 1-indexed holder index. Must appear in --peer.
    #[arg(long)]
    index: u32,

    /// Data directory: node identity and key package.
    #[arg(long, default_value = "./narsild-data")]
    data_dir: PathBuf,

    /// A roster entry: `index=url=x25519_pubkey_hex=ed25519_pubkey_hex`.
    /// Repeat for every member of the group, this node included. Every node
    /// must be given the same set: its hash goes into the DKG prologue, the
    /// signing context and every request signature.
    #[arg(long = "peer", value_name = "INDEX=URL=X25519=ED25519")]
    peers: Vec<String>,

    /// Inner FROST threshold.
    #[arg(long, default_value_t = 3)]
    threshold: u32,

    /// Outer FROST threshold — the number of coefficients of the nested
    /// position's outer polynomial.
    ///
    /// No default, and at least 2 unless `--dev-single-signer` is given. At 1
    /// the outer polynomial is a constant, the nested position alone completes
    /// the outer signature, and the "threshold" in the outer group is
    /// decorative (M-2).
    #[arg(long)]
    outer_threshold: u32,

    /// Consent to a DKG that replaces an existing key package.
    ///
    /// Without it this node approves a rotation proposal from nobody, which
    /// means `t` compromised peers cannot talk the group into overwriting the
    /// shares that hold the escrow. Turning it on is how a planned reshare
    /// happens: the operator sets it, the group runs the ceremony, the
    /// operator turns it off.
    #[arg(long)]
    allow_rotation: bool,

    /// Permit `--outer-threshold 1`. Development only: it makes this group's
    /// nested position a single point of compromise for the outer signature.
    #[arg(long)]
    dev_single_signer: bool,

    /// A file of approved message digests, one 32-byte hex digest per line
    /// (`#` comments allowed) — see `policy::message_digest`.
    ///
    /// Without it the node runs a deny-all policy and signs nothing. The
    /// production policy is the bridge component: it reconstructs the expected
    /// message from the withdrawal event on this validator's own `pd`.
    #[arg(long, value_name = "PATH")]
    dev_allow_message_digests: Option<PathBuf>,

    /// The nested position's index in the outer signing set.
    #[arg(long, default_value_t = 1)]
    nested_position: u32,

    /// Print this node's roster keys and exit — `x25519 ed25519`, which is
    /// what peers put in their `--peer` entry for this node. Generates the
    /// identity if there is not one yet.
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
        println!(
            "{}={}",
            hex::encode(identity.x25519_public()),
            hex::encode(identity.ed25519_public())
        );
        return;
    }

    if cli.outer_threshold == 0 || (cli.outer_threshold < 2 && !cli.dev_single_signer) {
        eprintln!(
            "--outer-threshold {} is not a threshold: the nested position alone would \
             complete the outer signature. Use 2 or more, or pass --dev-single-signer \
             if this is a development group.",
            cli.outer_threshold
        );
        std::process::exit(1);
    }

    let policy: Arc<dyn policy::SigningPolicy> = match &cli.dev_allow_message_digests {
        Some(path) => match policy::AllowList::from_file(path) {
            Ok(p) => Arc::new(p),
            Err(e) => {
                eprintln!("cannot read the signing policy: {e}");
                std::process::exit(1);
            }
        },
        None => Arc::new(policy::DenyAll),
    };

    let roster = match Roster::parse(&cli.peers) {
        Ok(r) => Arc::new(r),
        Err(e) => {
            eprintln!("bad roster: {e}");
                eprintln!(
                "expected --peer INDEX=URL=X25519_PUBKEY_HEX=ED25519_PUBKEY_HEX, \
                 once per member"
            );
            std::process::exit(1);
        }
    };

    // A node that is not in its own roster would seal to a key it does not
    // hold, and every peer's package to it would be undecryptable. Catch it
    // here rather than at round 2.
    match roster.get(cli.index) {
        Ok(me)
            if me.x25519_pub == identity.x25519_public()
                && me.ed25519_pub == identity.ed25519_public() => {}
        Ok(me) => {
            eprintln!(
                "roster entry for index {} carries keys {}={}, but this node's identity \
                 at {} yields {}={}",
                cli.index,
                hex::encode(me.x25519_pub),
                hex::encode(me.ed25519_pub),
                identity.path().display(),
                hex::encode(identity.x25519_public()),
                hex::encode(identity.ed25519_public())
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

    let (epoch, manifest_hash, share, public_shares, group_pubkey) = match &package {
        Some(p) => {
            if p.holder_index != cli.index {
                eprintln!(
                    "key package was generated for holder {}, but --index is {}",
                    p.holder_index, cli.index
                );
                std::process::exit(1);
            }
            let manifest_hash = match p.manifest_hash() {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };
            (
                p.epoch,
                manifest_hash,
                p.share_at(cli.nested_position),
                p.public_shares_at(cli.nested_position).unwrap_or_default(),
                p.group_pubkey(),
            )
        }
        None => {
            tracing::warn!(
                "no key package in {}; this node can take part in a DKG but cannot sign",
                cli.data_dir.display()
            );
            (0, roster.hash(), None, Vec::new(), None)
        }
    };

    let authenticator = match Authenticator::new(roster.clone(), &identity, cli.index, &cli.data_dir)
    {
        Ok(a) => Arc::new(a),
        Err(e) => {
            eprintln!("cannot open the replay store: {e}");
            std::process::exit(1);
        }
    };

    let peers = PeerSet::new(roster.clone(), cli.index, authenticator.clone());
    let signer = LocalSigner::new(
        cli.index,
        cli.nested_position,
        epoch,
        manifest_hash,
        share,
        public_shares,
        group_pubkey,
    );
    let spent = match agreement::FileSpentSessions::open(&cli.data_dir) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("cannot open the spent-session store: {e}");
            std::process::exit(1);
        }
    };

    let signing = SigningService::new(
        signer,
        cli.threshold as usize,
        peers.clone(),
        policy,
        spent,
    );

    let state = AppState {
        signing,
        dkg_ceremony: Arc::new(Mutex::new(None)),
        proposals: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        allow_rotation: cli.allow_rotation,
        peers,
        auth: authenticator,
        identity,
        roster: roster.clone(),
        data_dir: cli.data_dir.clone(),
        holder_index: cli.index,
        nested_position: cli.nested_position,
        inner_threshold: cli.threshold,
        outer_threshold: cli.outer_threshold,
    };

    tracing::info!(
        "narsild starting: holder={} of {}, threshold={}, outer_threshold={}, epoch={}, \
         roster={}",
        cli.index,
        roster.len(),
        cli.threshold,
        cli.outer_threshold,
        epoch,
        hex::encode(roster.hash())
    );
    tracing::info!("signing policy: {}", state.signing.policy.describe());

    let app = Router::new()
        .route("/sign/round1", axum::routing::post(handle_round1))
        .route("/sign/commitment", axum::routing::post(handle_commitment))
        .route("/sign/status", axum::routing::post(handle_status))
        .route("/sign/round2", axum::routing::post(handle_round2))
        .route("/sign/share", axum::routing::post(handle_share))
        .route("/dkg/init", axum::routing::post(handle_dkg_init))
        .route("/dkg/propose", axum::routing::post(handle_dkg_propose))
        .route("/dkg/approve", axum::routing::post(handle_dkg_approve))
        .route("/dkg/round1", axum::routing::post(handle_dkg_round1))
        .route("/dkg/echo", axum::routing::post(handle_dkg_echo))
        .route("/dkg/round2", axum::routing::post(handle_dkg_round2))
        .route("/dkg/complaint", axum::routing::post(handle_dkg_complaint))
        .route("/dkg/activate", axum::routing::post(handle_dkg_activate))
        .route("/dkg/status", axum::routing::get(handle_dkg_status))
        .route("/health", axum::routing::get(handle_health))
        // An unauthenticated party can still make this node allocate a body
        // buffer; axum's 2 MiB default is more than any message here needs.
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cli.bind).await.unwrap();
    tracing::info!("narsild listening on {}", cli.bind);
    axum::serve(listener, app).await.unwrap();
}
