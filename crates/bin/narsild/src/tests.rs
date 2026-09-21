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
                    identity_pub: PallasPoint::compress(
                        &crate::identity::NodeIdentity::from_seed_for_test(seed(i))
                            .ceremony_identity_public(),
                    )
                    .as_ref()
                    .try_into()
                    .unwrap(),
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
/// `tamper` is given each round-2 message before delivery, together with every
/// node's round-1 broadcast, so a test can misroute one, corrupt one, or seal
/// a sub-share that is not the evaluation it should be.
fn run_dkg(
    roster: &Arc<Roster>,
    tamper: impl FnMut(&mut DkgRound2Msg, &[crate::dkg::DkgRound1Broadcast]),
) -> Result<Vec<DkgResult>, DkgError> {
    let mut ceremonies = run_dkg_ceremonies(roster, tamper)?;
    ceremonies.iter_mut().map(|c| c.finalize()).collect()
}

/// [`run_dkg`], stopping before finalization so a test can inspect what each
/// node concluded — its abort reason, its complaint tally, the dealers it was
/// cheated by.
fn run_dkg_ceremonies(
    roster: &Arc<Roster>,
    mut tamper: impl FnMut(&mut DkgRound2Msg, &[crate::dkg::DkgRound1Broadcast]),
) -> Result<Vec<DkgCeremony>, DkgError> {
    let mut ceremonies: Vec<DkgCeremony> = (1..=N)
        .map(|i| {
            DkgCeremony::new(
                i,
                roster.clone(),
                x25519_secret_from_seed(&seed(i)),
                crate::identity::NodeIdentity::from_seed_for_test(seed(i))
                    .ceremony_identity_secret(),
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
        tamper(&mut msg, &broadcasts);
        let recipient = msg.recipient_index;
        if recipient == 0 || recipient > N {
            continue;
        }
        ceremonies[recipient as usize - 1].receive_round2(&msg)?;
    }

    // Complaints, if any, reach every other node — the re-broadcast half of
    // M-6 that a library cannot do for a caller.
    let complaints: Vec<_> = ceremonies
        .iter_mut()
        .flat_map(|c| c.take_complaints())
        .collect();
    for complaint in &complaints {
        for ceremony in ceremonies.iter_mut() {
            if ceremony.holder_index == complaint.accuser_index {
                continue;
            }
            ceremony.receive_complaint(complaint)?;
        }
    }

    Ok(ceremonies)
}

#[test]
fn a_three_node_sealed_dkg_agrees_on_one_group_key() {
    let roster = roster();
    let results = run_dkg(&roster, |_, _| {}).unwrap();

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
    let err = run_dkg(&roster, |msg, _| {
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
    let err = run_dkg(&roster, |msg, _| {
        if msg.dealer_index == 2 && msg.recipient_index == 1 {
            let mut bytes = hex::decode(&msg.sealed[0].ciphertext).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 0xff;
            msg.sealed[0].ciphertext = hex::encode(bytes);
        }
    })
    .unwrap_err();
    match err {
        DkgError::Aborted(crate::dkg::AbortReason::SealedPackage(i)) => assert_eq!(i, 2),
        other => panic!("expected an abort naming dealer 2, got {other}"),
    }
}

/// Dealer `dealer`'s commitment for coefficient `coeff`, from its round-1
/// broadcast — the commitment the whole group agreed on.
fn agreed_commitment(
    broadcasts: &[crate::dkg::DkgRound1Broadcast],
    dealer: u32,
    coeff: usize,
) -> osst::reshare::DealerCommitment<PallasPoint> {
    let b = broadcasts
        .iter()
        .find(|b| b.dealer_index == dealer)
        .expect("dealer is on the roster");
    osst::reshare::DealerCommitment {
        dealer_index: dealer,
        coefficients: b.coefficients[coeff]
            .commitments
            .iter()
            .map(|h| point_from_hex(h).unwrap())
            .collect(),
    }
}

/// Seal a scalar that is *not* `f_dealer(recipient)` under the dealer's own
/// static key, with the dealer's genuine commitment digest inside.
///
/// This is the only round-2 misbehaviour that is anyone's fault but the
/// transport's: the package opens, its indices agree, its D-2 digest is the
/// agreed one, and only the Feldman check catches it.
fn cheating_ciphertext(
    roster: &Arc<Roster>,
    dealer: u32,
    recipient: u32,
    commitment: &osst::reshare::DealerCommitment<PallasPoint>,
) -> String {
    let sealed_roster = roster.sealed_roster(EPOCH, &CEREMONY_NONCE).unwrap();
    let junk = osst::reshare::SubShare::<PallasScalar>::new(
        dealer,
        recipient,
        PallasScalar::from_u32(0xbadbad),
    )
    .unwrap();
    let sealed = osst::sealed::seal_subshare::<PallasPoint>(
        &x25519_secret_from_seed(&seed(dealer)),
        &sealed_roster,
        crate::dkg::ROUND_SUBSHARE,
        &junk,
        commitment,
    )
    .unwrap();
    hex::encode(sealed.ciphertext)
}

/// M-6 residual: a dealer that seals a sub-share failing the Feldman check
/// against its own agreed commitment is caught by every recipient, each one
/// raises evidence the others re-check, and the threshold of them disqualifies
/// it by name.
///
/// Through 0.5.0 this was the split-group case: `open_subshare_agreed`
/// discarded the plaintext, so a cheated node aborted alone while the rest
/// finalized. osst 0.5.1's `open_subshare_agreed_with_evidence` is what makes
/// the accusation checkable, and `ComplaintTally` is what stops one node's
/// word being enough.
#[test]
fn a_cheating_dealer_is_disqualified_once_the_threshold_of_members_says_so() {
    let roster = roster();
    let ceremonies = run_dkg_ceremonies(&roster, |msg, broadcasts| {
        // Dealer 2 cheats every recipient but itself, in coefficient 0.
        if msg.dealer_index == 2 && msg.recipient_index != 2 {
            let commitment = agreed_commitment(broadcasts, 2, 0);
            msg.sealed[0].ciphertext =
                cheating_ciphertext(&roster, 2, msg.recipient_index, &commitment);
        }
    })
    .unwrap();

    // Nodes 1 and 3 were cheated: INNER_T = 2 distinct accusers, so dealer 2
    // goes, and every node — the cheat's own included — says so by name.
    for c in &ceremonies {
        assert_eq!(
            c.abort_reason(),
            Some(&crate::dkg::AbortReason::Dealer(2)),
            "node {} did not name the cheating dealer",
            c.holder_index
        );
    }

    // And nobody finalizes: the ceremony is over, not quietly smaller.
    for c in ceremonies.iter() {
        assert!(!c.round2_complete() || c.abort_reason().is_some());
    }
}

/// M-6 residual, the other half: one accuser is not evidence.
///
/// A `BadSubShare` complaint is checkable but not attributable — a fabricated
/// scalar fails the Feldman check exactly as a real one does, so the verdict
/// is `Upheld` for a lie too. The ceremony must therefore *not* abort on one,
/// and the accuser must be visible as the single member claiming it.
#[test]
fn a_lone_false_accuser_does_not_abort_the_ceremony() {
    use osst::dkg as odkg;

    let roster = roster();
    let mut ceremonies = run_dkg_ceremonies(&roster, |_, _| {}).unwrap();
    assert!(ceremonies.iter().all(|c| c.abort_reason().is_none()));

    // Member 1 makes one up against dealer 2, which dealt honestly to
    // everyone, and signs it with its own roster identity key.
    let broadcast = ceremonies[1].round1_broadcast();
    let commitment = agreed_commitment(std::slice::from_ref(&broadcast), 2, 0);
    let evidence = odkg::BadSubShareEvidence {
        dealer_index: 2,
        recipient_index: 1,
        session_id: ceremonies[0].session_id,
        round: crate::dkg::ROUND_SUBSHARE,
        subshare: PallasScalar::from_u32(7).to_bytes(),
        agreed_digest: odkg::commitment_digest(&commitment),
        sealed_digest: [0x5au8; 32],
    };
    let fabricated = odkg::Complaint::<PallasPoint>::sign(
        EPOCH,
        ceremonies[0].session_id,
        crate::dkg::ROUND_SUBSHARE,
        1,
        odkg::ComplaintEvidence::BadSubShare { evidence },
        &crate::identity::NodeIdentity::from_seed_for_test(seed(1)).ceremony_identity_secret(),
        &mut rand_core::OsRng,
    )
    .unwrap();
    let wire = crate::dkg::ComplaintMsg::encode(&fabricated).unwrap();

    // It round-trips, and it is authentic: the signature checks and the
    // Feldman check fails, because a made-up scalar is not a valid sub-share.
    let json = serde_json::to_string(&wire).unwrap();
    let back: crate::dkg::ComplaintMsg = serde_json::from_str(&json).unwrap();
    assert_eq!(back, wire);

    for node in [0usize, 2] {
        assert!(
            ceremonies[node].receive_complaint(&back).unwrap(),
            "first sight: re-broadcast"
        );
        assert!(
            !ceremonies[node].receive_complaint(&back).unwrap(),
            "seen: do not loop"
        );
        assert_eq!(
            ceremonies[node].abort_reason(),
            None,
            "one accuser must not disqualify an honest dealer"
        );
    }

    // The node that was supposedly cheated is the only one saying so, and it
    // is the only one that cannot finalize.
    assert!(ceremonies[2].excluded_dealers().is_empty());
    assert!(ceremonies[2].finalize().is_ok(), "an honest node finalizes");

    // A second, independent accuser is what it would take. Member 3 says the
    // same thing and dealer 2 goes.
    let evidence3 = odkg::BadSubShareEvidence {
        dealer_index: 2,
        recipient_index: 3,
        session_id: ceremonies[0].session_id,
        round: crate::dkg::ROUND_SUBSHARE,
        subshare: PallasScalar::from_u32(9).to_bytes(),
        agreed_digest: odkg::commitment_digest(&commitment),
        sealed_digest: [0x5bu8; 32],
    };
    let second = odkg::Complaint::<PallasPoint>::sign(
        EPOCH,
        ceremonies[0].session_id,
        crate::dkg::ROUND_SUBSHARE,
        3,
        odkg::ComplaintEvidence::BadSubShare { evidence: evidence3 },
        &crate::identity::NodeIdentity::from_seed_for_test(seed(3)).ceremony_identity_secret(),
        &mut rand_core::OsRng,
    )
    .unwrap();
    ceremonies[0]
        .receive_complaint(&crate::dkg::ComplaintMsg::encode(&second).unwrap())
        .unwrap();
    assert_eq!(
        ceremonies[0].abort_reason(),
        Some(&crate::dkg::AbortReason::Dealer(2)),
        "INNER_T distinct accusers is the gate, and it was reached"
    );
}

/// A complaint whose evidence names a commitment this node has never agreed on
/// cannot be adjudicated, and is dropped rather than believed.
#[test]
fn a_complaint_about_a_commitment_we_never_agreed_on_is_dropped() {
    use osst::dkg as odkg;

    let roster = roster();
    let mut ceremonies = run_dkg_ceremonies(&roster, |_, _| {}).unwrap();

    let stranger = agreed_commitment(&[ceremony_for(2, &roster).round1_broadcast()], 2, 0);
    let evidence = odkg::BadSubShareEvidence {
        dealer_index: 2,
        recipient_index: 1,
        session_id: ceremonies[0].session_id,
        round: crate::dkg::ROUND_SUBSHARE,
        subshare: PallasScalar::from_u32(7).to_bytes(),
        agreed_digest: odkg::commitment_digest(&stranger),
        sealed_digest: [0u8; 32],
    };
    let complaint = odkg::Complaint::<PallasPoint>::sign(
        EPOCH,
        ceremonies[0].session_id,
        crate::dkg::ROUND_SUBSHARE,
        1,
        odkg::ComplaintEvidence::BadSubShare { evidence },
        &crate::identity::NodeIdentity::from_seed_for_test(seed(1)).ceremony_identity_secret(),
        &mut rand_core::OsRng,
    )
    .unwrap();
    assert!(matches!(
        ceremonies[2].receive_complaint(&crate::dkg::ComplaintMsg::encode(&complaint).unwrap()),
        Err(DkgError::ComplaintBeforeAgreement(1))
    ));
    assert_eq!(ceremonies[2].abort_reason(), None);
}

/// M-6: a complaint is a signed, ceremony-bound, publicly checkable value, and
/// every node reaches the same verdict from it.
///
/// osst owns the verification and the adjudication; what is tested here is
/// narsild's half — the wire codec, the roster identity key it verifies
/// against, the re-broadcast signal, and that an upheld complaint stops this
/// node while an unfounded one flags its accuser instead.
#[test]
fn a_complaint_is_verified_against_the_roster_and_adjudicated() {
    use osst::dkg as odkg;

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

    // Dealer 2's genuine package, with a proof of knowledge that does verify.
    let honest = ceremony_for(2, &roster).round1_broadcast();
    let commitment = osst::reshare::DealerCommitment::<PallasPoint> {
        dealer_index: 2,
        coefficients: honest.coefficients[0]
            .commitments
            .iter()
            .map(|h| point_from_hex(h).unwrap())
            .collect(),
    };
    let genuine_package = odkg::Round1Package {
        commitment: commitment.clone(),
        proof_of_knowledge: odkg::ProofOfKnowledge {
            r: point_from_hex(&honest.coefficients[0].pok_r).unwrap(),
            z: scalar_from_hex(&honest.coefficients[0].pok_z).unwrap(),
        },
    };

    let accuser = crate::identity::NodeIdentity::from_seed_for_test(seed(1));
    let mut rng = rand_core::OsRng;

    // An accusation against a package whose proof verifies: authentic, and
    // wrong. The accuser is flagged; the ceremony carries on.
    let unfounded = odkg::Complaint::<PallasPoint>::sign(
        EPOCH,
        node.session_id,
        1,
        1,
        odkg::ComplaintEvidence::ForgedProofOfKnowledge {
            package: genuine_package,
        },
        &accuser.ceremony_identity_secret(),
        &mut rng,
    )
    .unwrap();
    let wire = crate::dkg::ComplaintMsg::encode(&unfounded).unwrap();

    // The wire form round-trips, and it is what reaches a peer.
    let json = serde_json::to_string(&wire).unwrap();
    let back: crate::dkg::ComplaintMsg = serde_json::from_str(&json).unwrap();
    assert_eq!(back, wire);

    assert!(node.receive_complaint(&back).unwrap(), "first sight: re-broadcast");
    assert!(!node.receive_complaint(&back).unwrap(), "seen: do not loop");
    assert!(node.abort_reason().is_none(), "an unfounded complaint stopped the ceremony");
    assert!(node.flagged_accusers().contains(&1));

    // A forged proof of knowledge: upheld, and the ceremony stops.
    let forged = odkg::Round1Package {
        commitment,
        proof_of_knowledge: odkg::ProofOfKnowledge {
            r: PallasPoint::generator(),
            z: PallasScalar::from_u32(1),
        },
    };
    let upheld = odkg::Complaint::<PallasPoint>::sign(
        EPOCH,
        node.session_id,
        1,
        2,
        odkg::ComplaintEvidence::ForgedProofOfKnowledge { package: forged },
        &crate::identity::NodeIdentity::from_seed_for_test(seed(2)).ceremony_identity_secret(),
        &mut rng,
    )
    .unwrap();
    node.receive_complaint(&crate::dkg::ComplaintMsg::encode(&upheld).unwrap())
        .unwrap();
    assert_eq!(
        node.abort_reason(),
        Some(&crate::dkg::AbortReason::Dealer(2))
    );
}

/// M-6: a complaint signed by a key the roster does not name is not a
/// complaint. The identity key comes from the roster, never from the message.
#[test]
fn a_complaint_signed_by_a_stranger_is_refused() {
    use osst::dkg as odkg;

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

    let stranger = crate::identity::NodeIdentity::from_seed_for_test([0xee; 32]);
    let mut rng = rand_core::OsRng;
    let forged = odkg::Complaint::<PallasPoint>::sign(
        EPOCH,
        node.session_id,
        1,
        1, // claims to be member 1
        odkg::ComplaintEvidence::ForgedProofOfKnowledge {
            package: odkg::Round1Package {
                commitment: osst::reshare::DealerCommitment::<PallasPoint> {
                    dealer_index: 2,
                    coefficients: vec![PallasPoint::generator(); INNER_T as usize],
                },
                proof_of_knowledge: odkg::ProofOfKnowledge {
                    r: PallasPoint::generator(),
                    z: PallasScalar::from_u32(1),
                },
            },
        },
        &stranger.ceremony_identity_secret(),
        &mut rng,
    )
    .unwrap();

    assert!(matches!(
        node.receive_complaint(&crate::dkg::ComplaintMsg::encode(&forged).unwrap()),
        Err(DkgError::InvalidComplaint(1))
    ));
    assert!(node.abort_reason().is_none());
}

/// M-6: a complaint from another ceremony does not replay into this one — the
/// binding is osst's, and this is the check that it reaches narsild.
#[test]
fn a_complaint_from_another_ceremony_is_refused() {
    use osst::dkg as odkg;

    let roster = roster();
    let mut node = ceremony_for(1, &roster);
    let other = DkgCeremony::new(
        1,
        roster.clone(),
        x25519_secret_from_seed(&seed(1)),
        crate::identity::NodeIdentity::from_seed_for_test(seed(1)).ceremony_identity_secret(),
        EPOCH,
        [0xeeu8; 32],
        INNER_T,
        OUTER_T,
    )
    .unwrap();

    let mut rng = rand_core::OsRng;
    let replayed = odkg::Complaint::<PallasPoint>::sign(
        EPOCH,
        other.session_id,
        1,
        2,
        odkg::ComplaintEvidence::ForgedProofOfKnowledge {
            package: odkg::Round1Package {
                commitment: osst::reshare::DealerCommitment::<PallasPoint> {
                    dealer_index: 3,
                    coefficients: vec![PallasPoint::generator(); INNER_T as usize],
                },
                proof_of_knowledge: odkg::ProofOfKnowledge {
                    r: PallasPoint::generator(),
                    z: PallasScalar::from_u32(1),
                },
            },
        },
        &crate::identity::NodeIdentity::from_seed_for_test(seed(2)).ceremony_identity_secret(),
        &mut rng,
    )
    .unwrap();

    assert!(matches!(
        node.receive_complaint(&crate::dkg::ComplaintMsg::encode(&replayed).unwrap()),
        Err(DkgError::InvalidComplaint(2))
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
        crate::identity::NodeIdentity::from_seed_for_test(seed(1))
            .ceremony_identity_secret(),
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
        crate::identity::NodeIdentity::from_seed_for_test(seed(2))
            .ceremony_identity_secret(),
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
    let results = run_dkg(&roster, |_, _| {}).unwrap();
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

/// The round-0 precommitments for a round-1 set.
fn precommit_pairs(round1: &[InnerRound1]) -> Vec<(u32, [u8; 32])> {
    round1
        .iter()
        .map(|r| {
            (
                r.commitments.holder_index,
                nested::inner_precommit::<PallasPoint>(&r.commitments),
            )
        })
        .collect()
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

fn wire_precommits(
    round1: &[InnerRound1],
    message: &[u8],
    session_id: [u8; 32],
) -> Vec<crate::signing::InnerPrecommit> {
    precommit_pairs(round1)
        .into_iter()
        .map(|(holder_index, precommit)| crate::signing::InnerPrecommit {
            session_id,
            message_hex: hex::encode(message),
            holder_index,
            precommit: hex::encode(precommit),
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
    let precommits = precommit_pairs(&round1);

    // The nested position's outer commitment pair.
    let (d_nested, e_nested) =
        nested::aggregate_inner_commitment_pair::<PallasPoint>(
            &session_id,
            &precommits,
            &inner_commitments,
        )
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
        nested_index: NESTED_POSITION,
        session_id,
        inner_precommits: &precommits,
        inner_commitments: &inner_commitments,
        active_indices: &active,
        inner_threshold: INNER_T,
    };

    // Each inner holder signs the context bytes, from its own share.
    let mut shares = Vec::new();
    for (k, r1) in round1.into_iter().enumerate() {
        let index = k as u32 + 1;
        let sigma = group.packages[k].share_at(NESTED_POSITION).unwrap();
        let share = SecretShare::new(index, sigma).unwrap();
        shares.push(
            nested::inner_sign_v2_with_context::<PallasPoint>(
                r1.nonces, &share, &group.group_pubkey, &ctx, &request,
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
        r: package.group_commitment(&group.group_pubkey),
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
    let precommits = precommit_pairs(&round1);
    let (d, e) =
        nested::aggregate_inner_commitment_pair::<PallasPoint>(
            &session_id,
            &precommits,
            &inner_commitments,
        )
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
        nested_index: NESTED_POSITION,
        session_id,
        inner_precommits: &precommits,
        inner_commitments: &inner_commitments,
        active_indices: &active,
        inner_threshold: INNER_T,
    };

    // The holder builds its context from its own key package's epoch.
    let mut round1 = round1;
    let holder = round1.remove(0);
    let own_ctx = SigningContext::new(group.packages[0].epoch, manifest_hash, message);
    let share = SecretShare::new(1, group.packages[0].share_at(NESTED_POSITION).unwrap()).unwrap();

    let err = nested::inner_sign_v2_with_context::<PallasPoint>(
        holder.nonces,
        &share,
        &group.group_pubkey,
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
    let precommits = precommit_pairs(&round1);
    let (d, e) =
        nested::aggregate_inner_commitment_pair::<PallasPoint>(
            &session_id,
            &precommits,
            &inner_commitments,
        )
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
        nested_index: NESTED_POSITION,
        session_id,
        inner_precommits: &precommits,
        inner_commitments: &inner_commitments,
        active_indices: &active,
        inner_threshold: INNER_T,
    };

    let mut round1 = round1;
    let holder = round1.remove(0);
    let own_ctx = SigningContext::new(EPOCH, group.roster.hash(), message);
    let share = SecretShare::new(1, group.packages[0].share_at(NESTED_POSITION).unwrap()).unwrap();

    assert_eq!(
        nested::inner_sign_v2_with_context::<PallasPoint>(
            holder.nonces,
            &share,
            &group.group_pubkey,
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
    let precommits = precommit_pairs(&round1);
    let (d, e) =
        nested::aggregate_inner_commitment_pair::<PallasPoint>(
            &session_id,
            &precommits,
            &inner_commitments,
        )
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

    // The node does the comparison itself, against the triple it derived from
    // the package and its OWN group key. `from_coordinator_checked` is
    // deprecated in 0.5.0 and for the right reason: it recomputes everything
    // using the *supplied* group key, so a substituted `Y` passes it — which
    // is exactly the mistake M-4 was.
    let asserted_challenge = PallasScalar::from_u32(1);
    assert_ne!(
        honest.outer_challenge(),
        &asserted_challenge,
        "a coordinator-asserted challenge is not the derived one"
    );

    // And the derivation is a function of the package and the group key, so
    // two nodes with the same key package agree on it.
    let again = InnerSigningParamsV2::<PallasScalar>::from_outer::<PallasPoint>(
        &package,
        &group.group_pubkey,
        NESTED_POSITION,
    )
    .unwrap();
    assert_eq!(again.outer_challenge(), honest.outer_challenge());
    assert_eq!(again.outer_binding(), honest.outer_binding());
    assert_eq!(again.outer_lambda(), honest.outer_lambda());

    // A different group key gives a different challenge — the degree of
    // freedom M-4 refuses to concede.
    let other_y = PallasPoint::generator().mul_scalar(&PallasScalar::from_u32(9));
    let under_other_y = InnerSigningParamsV2::<PallasScalar>::from_outer::<PallasPoint>(
        &package,
        &other_y,
        NESTED_POSITION,
    )
    .unwrap();
    assert_ne!(under_other_y.outer_challenge(), honest.outer_challenge());
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
    let precommits = precommit_pairs(&round1);
    let nested_commitment =
        nested::aggregate_inner_commitment_pair::<PallasPoint>(
            &session_id,
            &precommits,
            &inner_commitments,
        )
            .unwrap();

    let out = crate::client::Round1Output {
        session_id,
        precommits: wire_precommits(&round1, message, session_id),
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
        INNER_T,
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
    let precommits: Vec<crate::signing::InnerPrecommit> = signers
        .iter_mut()
        .map(|s| s.commit(session_id, message))
        .collect();
    let commitments: Vec<InnerCommitment> = signers
        .iter()
        .map(|s| s.reveal(&session_id).unwrap())
        .collect();
    let nested_commitment =
        crate::signing::nested_commitment_pair(&session_id, &precommits, &commitments).unwrap();
    let out = crate::client::Round1Output {
        session_id,
        precommits,
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

    // The honest request signs. `MemorySpentSessions` is osst's own test
    // store; the durable one is exercised in `agreement` and in
    // `a_session_id_cannot_be_signed_twice`.
    let mut store = nested::MemorySpentSessions::new();
    assert!(signers[0].sign(&mut store, &honest).is_ok());

    // The same request with someone else's Y does not — and is refused before
    // the nonces are consumed, so the substitution cannot be used to burn a
    // holder's round.
    let mut tampered = honest.clone();
    let other_y = PallasPoint::generator().mul_scalar(&PallasScalar::from_u32(9));
    tampered.group_pubkey = point_hex(&other_y);
    assert!(matches!(
        signers[1].sign(&mut store, &tampered),
        Err(crate::signing::SigningError::WrongGroupKey)
    ));
    // Still able to sign the honest request afterwards.
    assert!(signers[1].sign(&mut store, &honest).is_ok());
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
        crate::identity::NodeIdentity::from_seed_for_test(seed(1))
            .ceremony_identity_secret(),
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
        crate::identity::NodeIdentity::from_seed_for_test(seed(1))
            .ceremony_identity_secret(),
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
        crate::identity::NodeIdentity::from_seed_for_test(seed(2))
            .ceremony_identity_secret(),
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
        crate::identity::NodeIdentity::from_seed_for_test(seed(index))
            .ceremony_identity_secret(),
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
        INNER_T,
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

    // The node has to hold nonces for this session, which is what round 0 is.
    service.start_round1(session_id, message).await.unwrap();
    assert_eq!(
        service.round0.contributions(&session_id).await.len(),
        1,
        "our own precommitment is published"
    );
    // The reveal is held back until the precommit round closes: one node in
    // process against a threshold of two, so nothing is revealed yet.
    assert!(service.round1.contributions(&session_id).await.is_empty());

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

/// M-17: what a peer is told is a code from a closed set, and nothing about
/// which check failed.
#[tokio::test]
async fn an_error_response_tells_a_peer_only_a_code() {
    use axum::body::to_bytes;

    let detailed = crate::signing::SigningError::MessageChanged(
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
    );
    let detail = detailed.to_string();
    assert!(detail.contains("deadbeef"), "the local detail is still detailed");

    let response = crate::err(detailed);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json.as_object().unwrap().len(), 1);
    let code = json["error"].as_str().unwrap();
    assert!(
        crate::ERROR_CODES.contains(&code),
        "{code:?} is not one of the published error codes"
    );
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(!text.contains("deadbeef"), "the session id leaked: {text}");
    assert!(!text.contains("opened for"), "the check that failed leaked: {text}");
}

/// M-18: session state is bounded. Past the cap a new session is refused
/// rather than allocated for — and it is the *nonce sampling* that matters,
/// which is why the refusal comes before round 1 does anything.
#[tokio::test]
async fn session_state_is_bounded() {
    let group = build_group();
    let message = b"release escrow 42".as_slice();
    let (service, dir) = service(&group, 0, message, "bounded");

    let cap = crate::accumulator::MAX_SESSIONS;
    for i in 0..cap {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&(i as u64).to_le_bytes());
        service.start_round1(id, message).await.unwrap();
    }
    assert_eq!(
        service.signer.lock().await.live_nonce_count(),
        cap,
        "one nonce pair per open session"
    );

    let mut over = [0xffu8; 32];
    over[0] = 1;
    assert!(matches!(
        service.start_round1(over, message).await,
        Err(crate::signing::SigningError::TooManySessions)
    ));
    // And nothing was sampled for the refused session.
    assert_eq!(service.signer.lock().await.live_nonce_count(), cap);

    let _ = std::fs::remove_dir_all(&dir);
}
