//! End-to-end tests: a three-node sealed DKG, then a nested FROST v2
//! signature that osst itself verifies.
//!
//! The ceremony runs in-process because [`crate::dkg::DkgCeremony`] has no
//! transport of its own: it produces messages and consumes messages, and the
//! delivery policy — broadcast for round 1, point-to-point for round 2 — lives
//! in the handlers. That is also why round 2 cannot accidentally be
//! broadcast: there is one function that sends it, and it takes a recipient.

use crate::codec::{point_from_hex, point_hex, scalar_from_hex};
use crate::dkg::{DkgCeremony, DkgError, DkgResult, DkgRound2Msg};
use crate::keypackage::KeyPackage;
use crate::roster::{Peer, Roster};
use crate::signing::{InnerCommitment, OuterCommitment, SigningRequest};
use osst::curve::{OsstPoint, OsstScalar};
use osst::frost::{self, SigningCommitments, SigningPackage};
use osst::nested::{self, InnerCommitments, InnerSigningParamsV2, NestedSigningRequest};
use osst::sealed::{x25519_public_from_seed, x25519_secret_from_seed};
use osst::{compute_lagrange_coefficients, OsstError, SecretShare, SigningContext};
use pasta_curves::pallas::{Point as PallasPoint, Scalar as PallasScalar};
use std::sync::Arc;

const N: u32 = 3;
const INNER_T: u32 = 2;
/// The outer polynomial has two coefficients, so the nested position's outer
/// share is a genuine evaluation `f(p) = a_0 + a_1·p` rather than a constant.
const OUTER_T: u32 = 2;
const NESTED_POSITION: u32 = 1;
const EPOCH: u64 = 7;
/// The attempt nonce every in-process ceremony here runs under (M-15).
const CEREMONY_NONCE: [u8; 32] = [0x9cu8; 32];

fn seed(i: u32) -> [u8; 32] {
    [i as u8; 32]
}

fn roster() -> Arc<Roster> {
    Arc::new(
        Roster::new(
            (1..=N)
                .map(|i| Peer {
                    index: i,
                    url: format!("http://node{i}:9200"),
                    x25519_pub: x25519_public_from_seed(&seed(i)),
                    ed25519_pub: crate::identity::NodeIdentity::from_seed_for_test(seed(i))
                        .ed25519_public(),
                })
                .collect(),
        )
        .unwrap(),
    )
}

// ---------------------------------------------------------------------------
// The DKG
// ---------------------------------------------------------------------------

/// Run the whole ceremony in-process and return each node's result.
///
/// `tamper` is given each round-2 message before delivery, so a test can
/// misroute or corrupt one.
fn run_dkg(
    roster: &Arc<Roster>,
    mut tamper: impl FnMut(&mut DkgRound2Msg),
) -> Result<Vec<DkgResult>, DkgError> {
    let mut ceremonies: Vec<DkgCeremony> = (1..=N)
        .map(|i| {
            DkgCeremony::new(
                i,
                roster.clone(),
                x25519_secret_from_seed(&seed(i)),
                EPOCH,
                CEREMONY_NONCE,
                INNER_T,
                OUTER_T,
            )
            .unwrap()
        })
        .collect();

    // Round 1 is public: every node's broadcast reaches every node.
    let broadcasts: Vec<_> = ceremonies.iter().map(|c| c.round1_broadcast()).collect();
    for ceremony in ceremonies.iter_mut() {
        for b in &broadcasts {
            ceremony.receive_round1(b)?;
        }
    }
    assert!(ceremonies.iter().all(|c| c.round1_complete()));

    // The echo round: every node publishes its digest of the round-1 set, and
    // nobody enters round 2 until they all match (M-5).
    let echoes: Vec<_> = ceremonies.iter().map(|c| c.echo().unwrap()).collect();
    for ceremony in ceremonies.iter_mut() {
        for e in &echoes {
            ceremony.receive_echo(e)?;
        }
    }
    assert!(ceremonies.iter().all(|c| c.round1_agreed()));

    // Round 2 is point-to-point: each sealed package goes to its recipient,
    // and nowhere else.
    let mut outgoing: Vec<DkgRound2Msg> = Vec::new();
    for ceremony in &ceremonies {
        outgoing.extend(ceremony.round2_messages()?);
    }
    for mut msg in outgoing {
        tamper(&mut msg);
        let recipient = msg.recipient_index;
        if recipient == 0 || recipient > N {
            continue;
        }
        ceremonies[recipient as usize - 1].receive_round2(&msg)?;
    }

    ceremonies.iter_mut().map(|c| c.finalize()).collect()
}

#[test]
fn a_three_node_sealed_dkg_agrees_on_one_group_key() {
    let roster = roster();
    let results = run_dkg(&roster, |_| {}).unwrap();

    assert_eq!(results.len(), N as usize);
    for r in &results {
        assert_eq!(r.epoch, EPOCH);
        assert_eq!(r.roster_hash, hex::encode(roster.hash()));
        assert_eq!(r.coefficient_shares.len(), OUTER_T as usize);
        assert_eq!(r.coeff_commitments, results[0].coeff_commitments);
        assert_eq!(r.verification_shares, results[0].verification_shares);
    }

    // The public data really commits to the private shares.
    for r in &results {
        for (j, share_hex) in r.coefficient_shares.iter().enumerate() {
            let share = scalar_from_hex(share_hex).unwrap();
            let expected = point_from_hex(&r.verification_shares[j][r.holder_index as usize - 1])
                .unwrap();
            assert_eq!(PallasPoint::generator().mul_scalar(&share), expected);
        }
    }
}

/// A round-2 package delivered to the wrong node is refused, and the refusal
/// is what aborts the ceremony rather than a silent drop.
#[test]
fn a_misrouted_sealed_package_does_not_open() {
    let roster = roster();
    let err = run_dkg(&roster, |msg| {
        // Redirect node 1's package for node 2 to node 3.
        if msg.dealer_index == 1 && msg.recipient_index == 2 {
            msg.recipient_index = 3;
        }
    })
    .unwrap_err();
    assert!(
        matches!(err, DkgError::Aborted(_)),
        "expected an abort, got {err}"
    );
}

/// A corrupted ciphertext is a complaint naming its dealer, not a share.
#[test]
fn a_corrupted_sealed_package_names_its_dealer() {
    let roster = roster();
    let err = run_dkg(&roster, |msg| {
        if msg.dealer_index == 2 && msg.recipient_index == 1 {
            let mut bytes = hex::decode(&msg.sealed[0].ciphertext).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 0xff;
            msg.sealed[0].ciphertext = hex::encode(bytes);
        }
    })
    .unwrap_err();
    match err {
        DkgError::Aborted(c) => assert_eq!(c.dealer_index, 2),
        other => panic!("expected an abort naming dealer 2, got {other}"),
    }
}

/// M-6: one complaint nobody else can check does not stop the ceremony, and
/// `inner_t` independent ones do.
///
/// The old behaviour believed any complaint from anyone, so a single packet
/// was a denial of service. The evidence osst 0.4.0 lets a complainant publish
/// for a round-2 failure is not publicly verifiable — `open_subshare` discards
/// the plaintext — so the sound policy for that class is a threshold of
/// independent accusers, not trust.
#[test]
fn an_unverifiable_complaint_needs_a_threshold_of_accusers() {
    let roster = roster();
    let mut ceremonies: Vec<DkgCeremony> = (1..=N).map(|i| ceremony_for(i, &roster)).collect();

    let broadcasts: Vec<_> = ceremonies.iter().map(|c| c.round1_broadcast()).collect();
    for ceremony in ceremonies.iter_mut() {
        for b in &broadcasts {
            ceremony.receive_round1(b).unwrap();
        }
    }

    let complaint_from = |accuser: u32, c: &DkgCeremony| crate::dkg::Complaint {
        complainant_index: accuser,
        dealer_index: 2,
        coeff_index: 0,
        epoch: EPOCH,
        session_id: c.session_id,
        roster_hash: hex::encode(roster.hash()),
        round: 2,
        commitment_digest: c.commitment_digest_of(0, 2).unwrap(),
        reason: crate::agreement::ComplaintReason::SealedOpenFailed,
        evidence: crate::agreement::ComplaintEvidence::SealedRejected {
            ciphertext_digest: hex::encode([7u8; 32]),
        },
    };

    // One accuser: recorded, re-broadcast, but not acted on.
    let first = complaint_from(1, &ceremonies[2]);
    assert!(ceremonies[2].receive_complaint(&first).unwrap());
    assert!(ceremonies[2].abort_reason().is_none());

    // The same complaint again is not a second accuser.
    assert!(!ceremonies[2].receive_complaint(&first).unwrap());
    assert!(ceremonies[2].abort_reason().is_none());

    // A second, independent accuser reaches the inner threshold.
    let second = complaint_from(3, &ceremonies[2]);
    assert!(ceremonies[2].receive_complaint(&second).unwrap());
    assert!(ceremonies[2].abort_reason().is_some());

    // And an aborted ceremony will not finalize into a key package.
    assert!(matches!(
        ceremonies[2].finalize().unwrap_err(),
        DkgError::AlreadyAborted(_)
    ));
}

/// M-6: a complaint whose own evidence contradicts it is ignored, and its
/// accuser is flagged rather than obeyed.
#[test]
fn a_complaint_that_names_the_wrong_commitment_is_ignored() {
    let roster = roster();
    let mut node = ceremony_for(3, &roster);
    for i in 1..=N {
        let b = if i == 3 {
            node.round1_broadcast()
        } else {
            ceremony_for(i, &roster).round1_broadcast()
        };
        node.receive_round1(&b).unwrap();
    }

    let bogus = crate::dkg::Complaint {
        complainant_index: 1,
        dealer_index: 2,
        coeff_index: 0,
        epoch: EPOCH,
        session_id: node.session_id,
        roster_hash: hex::encode(roster.hash()),
        round: 2,
        // A commitment this ceremony does not contain.
        commitment_digest: hex::encode([0xaa; 32]),
        reason: crate::agreement::ComplaintReason::InvalidSubShare,
        evidence: crate::agreement::ComplaintEvidence::SubShare {
            value_hex: hex::encode([3u8; 32]),
        },
    };

    node.receive_complaint(&bogus).unwrap();
    assert!(node.abort_reason().is_none(), "a false complaint stopped the ceremony");
    assert!(node.flagged_accusers().contains(&1));
}

/// M-6: a complaint from another ceremony does not replay into this one.
#[test]
fn a_complaint_from_another_ceremony_is_refused() {
    let roster = roster();
    let mut node = ceremony_for(1, &roster);
    let other = DkgCeremony::new(
        1,
        roster.clone(),
        x25519_secret_from_seed(&seed(1)),
        EPOCH,
        [0xeeu8; 32],
        INNER_T,
        OUTER_T,
    )
    .unwrap();

    let replayed = crate::dkg::Complaint {
        complainant_index: 2,
        dealer_index: 3,
        coeff_index: 0,
        epoch: EPOCH,
        session_id: other.session_id,
        roster_hash: hex::encode(roster.hash()),
        round: 2,
        commitment_digest: hex::encode([1u8; 32]),
        reason: crate::agreement::ComplaintReason::SealedOpenFailed,
        evidence: crate::agreement::ComplaintEvidence::SealedRejected {
            ciphertext_digest: hex::encode([2u8; 32]),
        },
    };
    assert!(matches!(
        node.receive_complaint(&replayed).unwrap_err(),
        DkgError::CeremonyMismatch(2)
    ));
    assert!(node.abort_reason().is_none());
}

/// Nodes that disagree about the roster derive different session ids, so
/// nothing they exchange opens. This is the URL-substitution defence.
#[test]
fn a_node_with_a_different_roster_cannot_join() {
    let honest = roster();
    let mut tampered_members: Vec<Peer> = honest.members().to_vec();
    tampered_members[2].url = "http://attacker:9200".into();
    let tampered = Arc::new(Roster::new(tampered_members).unwrap());

    let mut a = DkgCeremony::new(
        1,
        honest.clone(),
        x25519_secret_from_seed(&seed(1)),
        EPOCH,
        CEREMONY_NONCE,
        INNER_T,
        OUTER_T,
    )
    .unwrap();
    let b = DkgCeremony::new(
        2,
        tampered,
        x25519_secret_from_seed(&seed(2)),
        EPOCH,
        CEREMONY_NONCE,
        INNER_T,
        OUTER_T,
    )
    .unwrap();

    let err = a.receive_round1(&b.round1_broadcast()).unwrap_err();
    assert!(matches!(err, DkgError::RosterMismatch(2)), "got {err}");
}

// ---------------------------------------------------------------------------
// From DKG output to a nested signature
// ---------------------------------------------------------------------------

struct Group {
    roster: Arc<Roster>,
    packages: Vec<KeyPackage>,
    /// The outer group public key `Y = g^{a_0}`.
    group_pubkey: PallasPoint,
    /// Outer position 2's secret share, reconstructed in-process so the test
    /// can run a real two-signer outer round.
    outer_share_2: PallasScalar,
}

/// Reconstruct the outer polynomial from the inner shares — only a test may do
/// this, and only because it holds every node's material at once.
fn build_group() -> Group {
    let roster = roster();
    let results = run_dkg(&roster, |_| {}).unwrap();
    let packages: Vec<KeyPackage> = results.iter().map(|r| r.key_package()).collect();

    let indices: Vec<u32> = (1..=N).collect();
    let lambda = compute_lagrange_coefficients::<PallasScalar>(&indices).unwrap();

    let mut coefficients = Vec::with_capacity(OUTER_T as usize);
    for j in 0..OUTER_T as usize {
        let mut a_j = PallasScalar::zero();
        for (pos, p) in packages.iter().enumerate() {
            let share = scalar_from_hex(&p.coefficient_shares[j]).unwrap();
            a_j = a_j.add(&lambda[pos].mul(&share));
        }
        coefficients.push(a_j);
    }

    let group_pubkey = point_from_hex(&packages[0].coeff_commitments[0]).unwrap();
    assert_eq!(
        PallasPoint::generator().mul_scalar(&coefficients[0]),
        group_pubkey,
        "the reconstructed constant term must match the published group key"
    );

    // f(2) = a_0 + a_1·2
    let x = PallasScalar::from_u32(2);
    let mut outer_share_2 = PallasScalar::zero();
    let mut x_pow = PallasScalar::one();
    for a in &coefficients {
        outer_share_2 = outer_share_2.add(&a.mul(&x_pow));
        x_pow = x_pow.mul(&x);
    }

    Group {
        roster,
        packages,
        group_pubkey,
        outer_share_2,
    }
}

/// One inner holder's round-1 output.
struct InnerRound1 {
    nonces: nested::InnerNonces<PallasScalar>,
    commitments: InnerCommitments<PallasPoint>,
}

fn inner_round1(session_id: [u8; 32]) -> Vec<InnerRound1> {
    let mut rng = rand_core::OsRng;
    (1..=N)
        .map(|k| {
            let (nonces, commitments) =
                nested::inner_commit::<PallasPoint, _>(k, session_id, &mut rng);
            InnerRound1 {
                nonces,
                commitments,
            }
        })
        .collect()
}

fn wire_commitments(round1: &[InnerRound1], message: &[u8]) -> Vec<InnerCommitment> {
    round1
        .iter()
        .map(|r| InnerCommitment {
            session_id: r.commitments.session_id,
            message_hex: hex::encode(message),
            holder_index: r.commitments.holder_index,
            hiding: point_hex(&r.commitments.hiding),
            binding: point_hex(&r.commitments.binding),
        })
        .collect()
}

/// The full nested round: three inner holders occupy outer position 1, a
/// plain FROST signer occupies outer position 2, and the result is an ordinary
/// Schnorr signature under the DKG's group key.
#[test]
fn the_group_produces_a_nested_signature_that_osst_verifies() {
    let group = build_group();
    let message = b"release escrow 42 to zs1...".as_slice();
    let session_id = [0x5au8; 32];
    let manifest_hash = group.roster.hash();
    let ctx = SigningContext::new(EPOCH, manifest_hash, message);

    let round1 = inner_round1(session_id);
    let inner_commitments: Vec<InnerCommitments<PallasPoint>> =
        round1.iter().map(|r| r.commitments.clone()).collect();

    // The nested position's outer commitment pair.
    let (d_nested, e_nested) =
        nested::aggregate_inner_commitment_pair::<PallasPoint>(&session_id, &inner_commitments)
            .unwrap();

    // The other outer signer commits normally.
    let mut rng = rand_core::OsRng;
    let (nonces_2, commitments_2) = frost::commit::<PallasPoint, _>(2, &mut rng).unwrap();

    let package = SigningPackage::<PallasPoint>::new(
        ctx.encode(),
        vec![
            SigningCommitments {
                index: NESTED_POSITION,
                hiding: d_nested,
                binding: e_nested,
            },
            commitments_2.clone(),
        ],
    )
    .unwrap();

    let active: Vec<u32> = (1..=N).collect();
    let request = NestedSigningRequest {
        package: &package,
        group_pubkey: &group.group_pubkey,
        nested_index: NESTED_POSITION,
        session_id,
        inner_commitments: &inner_commitments,
        active_indices: &active,
    };

    // Each inner holder signs the context bytes, from its own share.
    let mut shares = Vec::new();
    for (k, r1) in round1.into_iter().enumerate() {
        let index = k as u32 + 1;
        let sigma = group.packages[k].share_at(NESTED_POSITION).unwrap();
        let share = SecretShare::new(index, sigma).unwrap();
        shares.push(
            nested::inner_sign_v2_with_context::<PallasPoint>(
                r1.nonces, &share, &ctx, &request,
            )
            .unwrap(),
        );
    }

    let params = InnerSigningParamsV2::<PallasScalar>::from_outer::<PallasPoint>(
        &package,
        &group.group_pubkey,
        NESTED_POSITION,
    )
    .unwrap();
    let public_shares = group.packages[0]
        .public_shares_at(NESTED_POSITION)
        .unwrap();

    let z_nested = nested::aggregate_inner_shares_verified::<PallasPoint>(
        &shares,
        &inner_commitments,
        &public_shares,
        &params,
        &active,
    )
    .expect("every inner share must verify");

    // The other outer signer's share, by the flat path.
    let share_2 = SecretShare::new(2, group.outer_share_2).unwrap();
    let z_2 = frost::sign_with_context::<PallasPoint>(
        &ctx,
        &package,
        nonces_2,
        &share_2,
        &group.group_pubkey,
    )
    .unwrap();

    let signature = frost::Signature::<PallasPoint> {
        r: package.group_commitment(),
        z: z_nested.add(&z_2.response),
    };

    assert!(
        frost::verify_signature::<PallasPoint>(&group.group_pubkey, &ctx.encode(), &signature),
        "the nested signature must verify as an ordinary Schnorr signature"
    );

    // And it is a signature over the epoch-bound bytes, not the bare message.
    assert!(!frost::verify_signature::<PallasPoint>(
        &group.group_pubkey,
        message,
        &signature
    ));
}

/// Epoch binding, stated as a refusal: a holder whose key package is from
/// epoch `e` will not contribute to a round a coordinator built for `e + 1`.
#[test]
fn a_holder_refuses_a_round_built_for_another_epoch() {
    let group = build_group();
    let message = b"release escrow 42".as_slice();
    let session_id = [0x11u8; 32];
    let manifest_hash = group.roster.hash();

    let round1 = inner_round1(session_id);
    let inner_commitments: Vec<InnerCommitments<PallasPoint>> =
        round1.iter().map(|r| r.commitments.clone()).collect();
    let (d, e) =
        nested::aggregate_inner_commitment_pair::<PallasPoint>(&session_id, &inner_commitments)
            .unwrap();

    // The coordinator builds its package for the NEXT epoch.
    let coordinator_ctx = SigningContext::new(EPOCH + 1, manifest_hash, message);
    let package = SigningPackage::<PallasPoint>::new(
        coordinator_ctx.encode(),
        vec![SigningCommitments {
            index: NESTED_POSITION,
            hiding: d,
            binding: e,
        }],
    )
    .unwrap();

    let active: Vec<u32> = (1..=N).collect();
    let request = NestedSigningRequest {
        package: &package,
        group_pubkey: &group.group_pubkey,
        nested_index: NESTED_POSITION,
        session_id,
        inner_commitments: &inner_commitments,
        active_indices: &active,
    };

    // The holder builds its context from its own key package's epoch.
    let mut round1 = round1;
    let holder = round1.remove(0);
    let own_ctx = SigningContext::new(group.packages[0].epoch, manifest_hash, message);
    let share = SecretShare::new(1, group.packages[0].share_at(NESTED_POSITION).unwrap()).unwrap();

    let err = nested::inner_sign_v2_with_context::<PallasPoint>(
        holder.nonces,
        &share,
        &own_ctx,
        &request,
    )
    .unwrap_err();
    assert_eq!(err, OsstError::MessageMismatch);
}

/// A roster change is a manifest change, and a manifest change is refused the
/// same way an epoch change is.
#[test]
fn a_holder_refuses_a_round_built_for_another_roster() {
    let group = build_group();
    let message = b"release escrow 42".as_slice();
    let session_id = [0x12u8; 32];

    let round1 = inner_round1(session_id);
    let inner_commitments: Vec<InnerCommitments<PallasPoint>> =
        round1.iter().map(|r| r.commitments.clone()).collect();
    let (d, e) =
        nested::aggregate_inner_commitment_pair::<PallasPoint>(&session_id, &inner_commitments)
            .unwrap();

    let package = SigningPackage::<PallasPoint>::new(
        SigningContext::new(EPOCH, [0xcc; 32], message).encode(),
        vec![SigningCommitments {
            index: NESTED_POSITION,
            hiding: d,
            binding: e,
        }],
    )
    .unwrap();

    let active: Vec<u32> = (1..=N).collect();
    let request = NestedSigningRequest {
        package: &package,
        group_pubkey: &group.group_pubkey,
        nested_index: NESTED_POSITION,
        session_id,
        inner_commitments: &inner_commitments,
        active_indices: &active,
    };

    let mut round1 = round1;
    let holder = round1.remove(0);
    let own_ctx = SigningContext::new(EPOCH, group.roster.hash(), message);
    let share = SecretShare::new(1, group.packages[0].share_at(NESTED_POSITION).unwrap()).unwrap();

    assert_eq!(
        nested::inner_sign_v2_with_context::<PallasPoint>(
            holder.nonces,
            &share,
            &own_ctx,
            &request
        )
        .unwrap_err(),
        OsstError::MessageMismatch
    );
}

/// A coordinator that asserts a challenge it did not derive from the package
/// is caught before any share is produced.
#[test]
fn a_coordinator_supplied_challenge_is_checked_against_the_package() {
    let group = build_group();
    let message = b"release escrow 42".as_slice();
    let session_id = [0x13u8; 32];
    let ctx = SigningContext::new(EPOCH, group.roster.hash(), message);

    let round1 = inner_round1(session_id);
    let inner_commitments: Vec<InnerCommitments<PallasPoint>> =
        round1.iter().map(|r| r.commitments.clone()).collect();
    let (d, e) =
        nested::aggregate_inner_commitment_pair::<PallasPoint>(&session_id, &inner_commitments)
            .unwrap();

    let package = SigningPackage::<PallasPoint>::new(
        ctx.encode(),
        vec![SigningCommitments {
            index: NESTED_POSITION,
            hiding: d,
            binding: e,
        }],
    )
    .unwrap();
    let honest = InnerSigningParamsV2::<PallasScalar>::from_outer::<PallasPoint>(
        &package,
        &group.group_pubkey,
        NESTED_POSITION,
    )
    .unwrap();

    let checked = InnerSigningParamsV2::<PallasScalar>::from_coordinator_checked::<PallasPoint>(
        honest.outer_binding(),
        &PallasScalar::from_u32(1), // a challenge of the coordinator's choosing
        honest.outer_lambda(),
        &package,
        &group.group_pubkey,
        NESTED_POSITION,
    );
    assert_eq!(checked.err(), Some(OsstError::ChallengeMismatch));

    // The honest triple is accepted.
    assert!(InnerSigningParamsV2::<PallasScalar>::from_coordinator_checked::<PallasPoint>(
        honest.outer_binding(),
        honest.outer_challenge(),
        honest.outer_lambda(),
        &package,
        &group.group_pubkey,
        NESTED_POSITION,
    )
    .is_ok());
}

/// The request the coordinator actually builds is the one the node accepts —
/// the wire shape and the crypto agree.
#[test]
fn the_coordinator_request_round_trips_through_the_wire_types() {
    let group = build_group();
    let message = b"release escrow 42".as_slice();
    let session_id = [0x14u8; 32];

    let round1 = inner_round1(session_id);
    let inner_commitments: Vec<InnerCommitments<PallasPoint>> =
        round1.iter().map(|r| r.commitments.clone()).collect();
    let nested_commitment =
        nested::aggregate_inner_commitment_pair::<PallasPoint>(&session_id, &inner_commitments)
            .unwrap();

    let out = crate::client::Round1Output {
        session_id,
        commitments: wire_commitments(&round1, message),
        nested_commitment,
    };
    let outer = crate::client::OuterRound {
        group_pubkey: group.group_pubkey,
        nested_index: NESTED_POSITION,
        other_commitments: Vec::new(),
        epoch: EPOCH,
        manifest_hash: group.roster.hash(),
    };

    let req = crate::client::build_request(&out, &outer, message, (1..=N).collect()).unwrap();
    let json = serde_json::to_string(&req).unwrap();
    let back: SigningRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(back.nested_index, NESTED_POSITION);
    assert_eq!(back.inner_commitments.len(), N as usize);
    assert_eq!(
        back.signed_bytes_hex,
        hex::encode(SigningContext::new(EPOCH, group.roster.hash(), message).encode())
    );

    // The node's own parse accepts it and derives the same scalars.
    let parsed = crate::signing::ParsedRequest::parse(&back).unwrap();
    let params = InnerSigningParamsV2::<PallasScalar>::from_outer::<PallasPoint>(
        &parsed.package,
        &parsed.group_pubkey,
        NESTED_POSITION,
    )
    .unwrap();
    assert_eq!(params.outer_challenge(), &parsed.outer_challenge);
    assert_eq!(params.outer_lambda(), &parsed.outer_lambda);
    assert_eq!(params.outer_binding(), &parsed.outer_binding);

    // And an outer commitment list is what it says it is.
    let echoed: Vec<OuterCommitment> = back.outer_commitments;
    assert_eq!(echoed.len(), 1);
    assert_eq!(echoed[0].index, NESTED_POSITION);
}

// ---------------------------------------------------------------------------
// The node's own anchoring checks
// ---------------------------------------------------------------------------

/// A [`crate::signing::LocalSigner`] loaded from holder `k`'s key package,
/// with live nonces for `session_id`.
fn local_signer(
    group: &Group,
    k: usize,
    session_id: [u8; 32],
    message: &[u8],
) -> crate::signing::LocalSigner {
    let package = &group.packages[k];
    let mut signer = crate::signing::LocalSigner::new(
        package.holder_index,
        NESTED_POSITION,
        package.epoch,
        package.manifest_hash().unwrap(),
        package.share_at(NESTED_POSITION),
        package.public_shares_at(NESTED_POSITION).unwrap(),
        package.group_pubkey(),
    );
    signer.commit(session_id, message);
    signer
}

/// Build the coordinator's round-2 request over a real inner round-1 set that
/// the given signers actually hold nonces for.
fn coordinator_request(
    group: &Group,
    session_id: [u8; 32],
    message: &[u8],
    signers: &mut [crate::signing::LocalSigner],
) -> SigningRequest {
    let commitments: Vec<InnerCommitment> = signers
        .iter_mut()
        .map(|s| s.commit(session_id, message))
        .collect();
    let nested_commitment =
        crate::signing::nested_commitment_pair(&session_id, &commitments).unwrap();
    let out = crate::client::Round1Output {
        session_id,
        commitments,
        nested_commitment,
    };
    let outer = crate::client::OuterRound {
        group_pubkey: group.group_pubkey,
        nested_index: NESTED_POSITION,
        other_commitments: Vec::new(),
        epoch: EPOCH,
        manifest_hash: group.roster.hash(),
    };
    crate::client::build_request(&out, &outer, message, (1..=N).collect()).unwrap()
}

/// M-4: the outer group key comes from this node's key package. A coordinator
/// that substitutes `Y'` gets a self-consistent package — `from_coordinator_checked`
/// recomputes rho, c and lambda *under the supplied Y* — so nothing downstream
/// catches it. This does.
#[test]
fn a_request_naming_another_group_key_is_refused() {
    let group = build_group();
    let message = b"release escrow 42".as_slice();
    let session_id = [0x21u8; 32];

    let mut signers: Vec<crate::signing::LocalSigner> = (0..N as usize)
        .map(|k| local_signer(&group, k, session_id, message))
        .collect();
    let honest = coordinator_request(&group, session_id, message, &mut signers);

    // The honest request signs.
    assert!(signers[0].sign(&honest).is_ok());

    // The same request with someone else's Y does not — and is refused before
    // the nonces are consumed, so the substitution cannot be used to burn a
    // holder's round.
    let mut tampered = honest.clone();
    let other_y = PallasPoint::generator().mul_scalar(&PallasScalar::from_u32(9));
    tampered.group_pubkey = point_hex(&other_y);
    assert!(matches!(
        signers[1].sign(&tampered),
        Err(crate::signing::SigningError::WrongGroupKey)
    ));
    // Still able to sign the honest request afterwards.
    assert!(signers[1].sign(&honest).is_ok());
}

/// M-15: a re-run of a failed ceremony at the same epoch is a different
/// ceremony. A node in attempt A does not accept attempt B's round 1, so a
/// recorded round-1/round-2 pair cannot be replayed into the re-run ahead of
/// the honest dealer's own.
#[test]
fn a_rerun_at_the_same_epoch_is_a_different_ceremony() {
    let roster = roster();
    let attempt_a = DkgCeremony::new(
        1,
        roster.clone(),
        x25519_secret_from_seed(&seed(1)),
        EPOCH,
        [0xa1u8; 32],
        INNER_T,
        OUTER_T,
    )
    .unwrap();
    let mut attempt_b = DkgCeremony::new(
        1,
        roster.clone(),
        x25519_secret_from_seed(&seed(1)),
        EPOCH,
        [0xb2u8; 32],
        INNER_T,
        OUTER_T,
    )
    .unwrap();

    assert_ne!(attempt_a.session_id, attempt_b.session_id);

    let stale = DkgCeremony::new(
        2,
        roster,
        x25519_secret_from_seed(&seed(2)),
        EPOCH,
        [0xa1u8; 32],
        INNER_T,
        OUTER_T,
    )
    .unwrap()
    .round1_broadcast();

    assert!(matches!(
        attempt_b.receive_round1(&stale).unwrap_err(),
        DkgError::CeremonyMismatch(2)
    ));
}

// ---------------------------------------------------------------------------
// The echo round (M-5) and slot squatting (M-7)
// ---------------------------------------------------------------------------

fn ceremony_for(index: u32, roster: &Arc<Roster>) -> DkgCeremony {
    DkgCeremony::new(
        index,
        roster.clone(),
        x25519_secret_from_seed(&seed(index)),
        EPOCH,
        CEREMONY_NONCE,
        INNER_T,
        OUTER_T,
    )
    .unwrap()
}

/// M-5: a dealer that sends different commitments to different recipients
/// passes every per-recipient check — the sealed sub-share is bound to the
/// commitment *as delivered to that recipient* — and splits the group. The
/// echo round is what sees it.
#[test]
fn an_equivocating_dealer_is_caught_by_the_echo_round() {
    let roster = roster();
    // Dealer 3 runs two ceremonies and hands each peer a different round 1.
    // Each package is internally valid: a real polynomial, a real proof of
    // knowledge, a real Feldman commitment.
    let for_alice = ceremony_for(3, &roster).round1_broadcast();
    let for_bob = ceremony_for(3, &roster).round1_broadcast();
    assert_ne!(
        for_alice.coefficients[0].commitments,
        for_bob.coefficients[0].commitments
    );

    let mut alice = ceremony_for(1, &roster);
    let mut bob = ceremony_for(2, &roster);
    let a1 = alice.round1_broadcast();
    let b2 = bob.round1_broadcast();
    for (c, from3) in [(&mut alice, &for_alice), (&mut bob, &for_bob)] {
        c.receive_round1(&a1).unwrap();
        c.receive_round1(&b2).unwrap();
        c.receive_round1(from3).unwrap();
    }
    assert!(alice.round1_complete() && bob.round1_complete());

    // They disagree about what round 1 was, and the echo says so by name.
    assert_ne!(alice.round1_digest(), bob.round1_digest());
    let bobs_echo = bob.echo().unwrap();
    let err = alice.receive_echo(&bobs_echo).unwrap_err();
    match err {
        DkgError::EchoMismatch { differing } => assert_eq!(differing, vec![2]),
        other => panic!("expected an echo mismatch, got {other}"),
    }

    // And nothing sealed leaves the node afterwards.
    assert!(alice.round2_messages().is_err());
}

/// M-5: round 2 does not start on a node that has not seen every echo, even
/// when its own round 1 is complete.
#[test]
fn round_two_does_not_start_before_the_group_agrees() {
    let roster = roster();
    let mut node = ceremony_for(1, &roster);
    for i in 1..=N {
        let b = ceremony_for(i, &roster).round1_broadcast();
        if i == 1 {
            node.receive_round1(&node.round1_broadcast()).unwrap();
        } else {
            node.receive_round1(&b).unwrap();
        }
    }
    assert!(node.round1_complete());
    assert!(matches!(
        node.round2_messages().unwrap_err(),
        DkgError::EchoIncomplete { .. }
    ));
}

/// M-7: a second round-1 package for a slot is an error, not a silent drop.
///
/// osst's `submit_commitment` is first-write-wins and returns `Ok(false)` for
/// a taken slot, which the old code read as success. Combined with the
/// unauthenticated endpoint, an attacker posting under an honest dealer's
/// index *first* had that dealer's genuine broadcast dropped, and round 2 then
/// produced a sealed package that failed the commitment digest check — framing
/// the honest dealer. Authentication stops the squat; this stops the silence.
#[test]
fn a_second_round_one_package_for_a_slot_is_refused() {
    let roster = roster();
    let mut node = ceremony_for(1, &roster);
    let squatter = ceremony_for(3, &roster).round1_broadcast();
    let genuine = ceremony_for(3, &roster).round1_broadcast();

    node.receive_round1(&squatter).unwrap();
    assert!(matches!(
        node.receive_round1(&genuine).unwrap_err(),
        DkgError::DuplicateRound1(3, _)
    ));
}

// ---------------------------------------------------------------------------
// The signing service's own refusals
// ---------------------------------------------------------------------------

/// A [`crate::signing::SigningService`] for holder `k` of a built group, with
/// a temporary data directory of its own.
fn service(
    group: &Group,
    k: usize,
    message: &[u8],
    tag: &str,
) -> (crate::signing::SigningService, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "narsild-svc-{}-{}-{}",
        std::process::id(),
        tag,
        k
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let package = &group.packages[k];
    let identity = crate::identity::NodeIdentity::from_seed_for_test(seed(package.holder_index));
    let auth = Arc::new(
        crate::auth::Authenticator::new(
            group.roster.clone(),
            &identity,
            package.holder_index,
            &dir,
        )
        .unwrap(),
    );
    let peers = crate::broadcast::PeerSet::new(group.roster.clone(), package.holder_index, auth);
    let signer = crate::signing::LocalSigner::new(
        package.holder_index,
        NESTED_POSITION,
        package.epoch,
        package.manifest_hash().unwrap(),
        package.share_at(NESTED_POSITION),
        package.public_shares_at(NESTED_POSITION).unwrap(),
        package.group_pubkey(),
    );
    let service = crate::signing::SigningService::new(
        signer,
        INNER_T as usize,
        peers,
        Arc::new(crate::policy::AllowList::from_messages(&[message])),
        Arc::new(crate::agreement::FileSpentSessions::open(&dir).unwrap()),
    );
    (service, dir)
}

/// M-13: a session id is good for one share. The second attempt is refused
/// rather than answered with a second response under the same nonce.
#[tokio::test]
async fn a_session_id_cannot_be_signed_twice() {
    let group = build_group();
    let message = b"release escrow 42".as_slice();
    let session_id = [0x31u8; 32];
    let (service, dir) = service(&group, 0, message, "spent");

    let mut signers: Vec<crate::signing::LocalSigner> = (0..N as usize)
        .map(|k| local_signer(&group, k, session_id, message))
        .collect();
    let req = coordinator_request(&group, session_id, message, &mut signers);

    // The node has to hold nonces for this session, which is what round 1 is.
    service.start_round1(session_id, message).await.unwrap();
    // Round 1 already sampled nonces over the coordinator's set; rebuild the
    // request over the node's own published commitment.
    let commitments = service.round1.contributions(&session_id).await;
    assert_eq!(commitments.len(), 1);

    // A second round 2 for the same session is refused before anything else.
    service.spent.mark_spent(&session_id).unwrap();
    assert!(matches!(
        service.start_round2(req).await,
        Err(crate::signing::SigningError::SessionSpent(_))
    ));

    let _ = std::fs::remove_dir_all(&dir);
}

/// M-2: the deny-all default is not a formality — a node with no policy
/// configured refuses to open a session at all, so it never samples nonces.
#[tokio::test]
async fn a_node_with_the_default_policy_will_not_start_a_round() {
    let group = build_group();
    let message = b"release escrow 42".as_slice();
    let (service, dir) = service(&group, 0, message, "policy");

    // Same service, but with the shipped default policy.
    let strict = crate::signing::SigningService {
        policy: Arc::new(crate::policy::DenyAll),
        ..service.clone()
    };
    assert!(matches!(
        strict.start_round1([0x41u8; 32], message).await,
        Err(crate::signing::SigningError::PolicyRefused)
    ));
    // And the allow-listed one does start.
    assert!(service.start_round1([0x42u8; 32], message).await.is_ok());
    // A message the list does not name is refused even there.
    assert!(matches!(
        service.start_round1([0x43u8; 32], b"something else").await,
        Err(crate::signing::SigningError::PolicyRefused)
    ));

    let _ = std::fs::remove_dir_all(&dir);
}
