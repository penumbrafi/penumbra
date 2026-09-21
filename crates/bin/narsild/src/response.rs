//! Every response body this daemon can emit, as a named type.
//!
//! # Why these are types and not `json!` literals (M-1)
//!
//! `/dkg/status` used to serialize the ceremony's [`crate::dkg::DkgResult`]
//! whole, and that struct's fourth field is this node's Shamir share of every
//! outer coefficient. Collecting the status page from any `t` nodes
//! reconstructed the group signing key — finding D-1 of the prior audit,
//! reintroduced through an unauthenticated HTTP GET.
//!
//! A `json!` literal cannot be audited: there is no list of the shapes a
//! handler can produce, so "does any response carry secret material" is a
//! question about every line of every handler rather than about one file. So
//! every response is a struct here, [`ALL_RESPONSE_FIELDS`] enumerates what
//! they may contain, and `response::tests::no_response_type_can_carry_a_secret`
//! serializes one of each and fails if a field name outside that list appears.
//!
//! The rule the list encodes: a response may carry indices, counts, phases,
//! digests, and group-public values (commitments, verification shares, nonce
//! commitments, published responses). It may never carry a scalar that is part
//! of this node's key material or its live nonce state.

use serde::Serialize;

/// `/sign/round1`: this node's nonce commitments for a session. `hiding` and
/// `binding` are `D_k` and `E_k` — commitments, not the nonces themselves.
#[derive(Debug, Serialize)]
pub struct Round1Response {
    pub holder_index: u32,
    pub hiding: String,
    pub binding: String,
    pub collected: usize,
    pub threshold: usize,
}

/// `/sign/commitment`, `/sign/share`: what an accumulator did with a peer's
/// contribution.
#[derive(Debug, Serialize)]
pub struct AccumulateResponse {
    pub accepted: bool,
    pub collected: usize,
    pub threshold: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_met: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// The aggregated nested response, once a verified quorum is in. This is
    /// `z_nested`, a published FROST response: public by construction, and the
    /// value the coordinator exists to collect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub z_nested: Option<String>,
}

impl AccumulateResponse {
    pub fn pending(collected: usize, threshold: usize) -> Self {
        Self {
            accepted: true,
            collected,
            threshold,
            threshold_met: None,
            reason: None,
            z_nested: None,
        }
    }

    pub fn complete(collected: usize, threshold: usize) -> Self {
        Self {
            threshold_met: Some(true),
            ..Self::pending(collected, threshold)
        }
    }

    pub fn duplicate(collected: usize, threshold: usize) -> Self {
        Self {
            accepted: false,
            reason: Some("duplicate"),
            ..Self::pending(collected, threshold)
        }
    }
}

/// One accumulator's progress.
#[derive(Debug, Serialize)]
pub struct RoundStatus {
    pub collected: usize,
    pub threshold: usize,
    pub ready: bool,
}

/// The nested position's aggregated outer commitment pair.
#[derive(Debug, Serialize)]
pub struct NestedCommitment {
    pub hiding: String,
    pub binding: String,
}

/// `/sign/status`.
#[derive(Debug, Serialize)]
pub struct SigningStatusResponse {
    pub session_id: String,
    pub nested_index: u32,
    pub round1: RoundStatus,
    pub round2: RoundStatus,
    /// The published round-1 commitment set — `(D_k, E_k)` per holder.
    pub commitments: Vec<crate::signing::InnerCommitment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nested_commitment: Option<NestedCommitment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub z_nested: Option<String>,
}

/// `/sign/round2`: this node's own inner share. `response` is `z_k`, the
/// published FROST response — the whole point of the request.
#[derive(Debug, Serialize)]
pub struct Round2Response {
    pub holder_index: u32,
    pub response: String,
    pub collected: usize,
    pub threshold: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub z_nested: Option<String>,
}

/// The public half of a completed DKG. Deliberately *not* [`crate::dkg::DkgResult`]:
/// that type carries this node's coefficient shares, and this one has nowhere
/// to put them.
#[derive(Debug, Serialize)]
pub struct PublicDkgResult {
    pub holder_index: u32,
    pub epoch: u64,
    pub roster_hash: String,
    /// `g^{a_j}` per outer coefficient. Identical on every node.
    pub coeff_commitments: Vec<String>,
    /// Digest of the verification-share table, rather than the table: a status
    /// page is a liveness check, not a key-material distribution channel.
    pub verification_share_digest: String,
    pub inner_threshold: u32,
    pub inner_n: u32,
    pub outer_threshold: u32,
}

/// `/dkg/status`.
#[derive(Debug, Serialize)]
pub struct DkgStatusResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder_index: Option<u32>,
    pub phase: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub round1_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aborted_against_dealer: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<PublicDkgResult>,
}

/// `/dkg/init`, `/dkg/start`.
#[derive(Debug, Serialize)]
pub struct DkgStartedResponse {
    pub status: &'static str,
    pub epoch: u64,
    pub session_id: String,
    pub holder_index: u32,
    pub coefficients: usize,
}

/// `/dkg/round1`, `/dkg/round2`, `/dkg/echo`, `/dkg/complaint`.
#[derive(Debug, Serialize)]
pub struct DkgProgressResponse {
    pub accepted: bool,
    pub phase: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub round_complete: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_key: Option<String>,
}

/// `/dkg/propose`.
#[derive(Debug, Serialize)]
#[allow(dead_code)] // wired up by the /dkg/propose handler (M-3)
pub struct DkgProposalResponse {
    pub accepted: bool,
    pub approvals: usize,
    pub needed: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposal_digest: Option<String>,
}

/// `/dkg/activate`.
#[derive(Debug, Serialize)]
pub struct ActivateResponse {
    pub status: &'static str,
    pub epoch: u64,
    pub holder_index: u32,
    pub nested_position: u32,
}

/// `/health`.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub holder_index: u32,
    pub nested_position: u32,
    pub epoch: u64,
    pub epoch_hwm: u64,
    pub has_share: bool,
    pub roster_hash: String,
    pub x25519_pub: String,
    pub ed25519_pub: String,
    pub peers: usize,
}

/// An error, as peers see it: a code from a closed set and nothing else (M-17).
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: &'static str,
}

/// Every field name any response type above may serialize.
///
/// The audit list. Adding a field to a response means adding it here, which is
/// the point at which somebody has to look at whether it is secret.
#[allow(dead_code)] // the audit list; read by the tests below
pub const ALL_RESPONSE_FIELDS: &[&str] = &[
    "accepted",
    "active",
    "aborted_against_dealer",
    "approvals",
    "binding",
    "coefficients",
    "coeff_commitments",
    "collected",
    "commitments",
    "epoch",
    "epoch_hwm",
    "ed25519_pub",
    "error",
    "group_key",
    "has_share",
    "hiding",
    "holder_index",
    "inner_n",
    "inner_threshold",
    "needed",
    "message_hex",
    "nested_commitment",
    "nested_index",
    "nested_position",
    "outer_threshold",
    "peers",
    "phase",
    "proposal_digest",
    "ready",
    "reason",
    "response",
    "result",
    "roster_hash",
    "round1",
    "round1_digest",
    "round2",
    "round_complete",
    "session_id",
    "status",
    "threshold",
    "threshold_met",
    "verification_share_digest",
    "x25519_pub",
    "z_nested",
];

#[cfg(test)]
mod tests {
    use super::*;


    /// Walk a serialized value and collect every object key.
    fn keys(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, sub) in map {
                    out.push(k.clone());
                    keys(sub, out);
                }
            }
            serde_json::Value::Array(items) => {
                for sub in items {
                    keys(sub, out);
                }
            }
            _ => {}
        }
    }

    fn sample_responses() -> Vec<serde_json::Value> {
        let commitment = crate::signing::InnerCommitment {
            session_id: [1u8; 32],
            message_hex: hex::encode(b"m"),
            holder_index: 1,
            hiding: "aa".into(),
            binding: "bb".into(),
        };
        vec![
            serde_json::to_value(Round1Response {
                holder_index: 1,
                hiding: "aa".into(),
                binding: "bb".into(),
                collected: 1,
                threshold: 2,
            })
            .unwrap(),
            serde_json::to_value(AccumulateResponse::pending(1, 2)).unwrap(),
            serde_json::to_value(AccumulateResponse::complete(2, 2)).unwrap(),
            serde_json::to_value(AccumulateResponse::duplicate(2, 2)).unwrap(),
            serde_json::to_value(SigningStatusResponse {
                session_id: hex::encode([1u8; 32]),
                nested_index: 1,
                round1: RoundStatus { collected: 1, threshold: 2, ready: false },
                round2: RoundStatus { collected: 0, threshold: 2, ready: false },
                commitments: vec![commitment],
                nested_commitment: Some(NestedCommitment {
                    hiding: "cc".into(),
                    binding: "dd".into(),
                }),
                z_nested: Some("ee".into()),
            })
            .unwrap(),
            serde_json::to_value(Round2Response {
                holder_index: 1,
                response: "ff".into(),
                collected: 1,
                threshold: 2,
                z_nested: None,
            })
            .unwrap(),
            serde_json::to_value(DkgStatusResponse {
                active: true,
                epoch: Some(3),
                session_id: Some(hex::encode([2u8; 32])),
                holder_index: Some(1),
                phase: "round2",
                round1_digest: Some(hex::encode([3u8; 32])),
                aborted_against_dealer: None,
                result: Some(PublicDkgResult {
                    holder_index: 1,
                    epoch: 3,
                    roster_hash: hex::encode([4u8; 32]),
                    coeff_commitments: vec!["aa".into()],
                    verification_share_digest: hex::encode([5u8; 32]),
                    inner_threshold: 2,
                    inner_n: 3,
                    outer_threshold: 2,
                }),
            })
            .unwrap(),
            serde_json::to_value(DkgStartedResponse {
                status: "round1_broadcast",
                epoch: 3,
                session_id: hex::encode([2u8; 32]),
                holder_index: 1,
                coefficients: 2,
            })
            .unwrap(),
            serde_json::to_value(DkgProgressResponse {
                accepted: true,
                phase: "round1",
                round_complete: Some(false),
                group_key: None,
            })
            .unwrap(),
            serde_json::to_value(DkgProposalResponse {
                accepted: true,
                approvals: 1,
                needed: 2,
                proposal_digest: Some(hex::encode([6u8; 32])),
            })
            .unwrap(),
            serde_json::to_value(ActivateResponse {
                status: "activated",
                epoch: 3,
                holder_index: 1,
                nested_position: 1,
            })
            .unwrap(),
            serde_json::to_value(HealthResponse {
                status: "ok",
                holder_index: 1,
                nested_position: 1,
                epoch: 3,
                epoch_hwm: 3,
                has_share: true,
                roster_hash: hex::encode([4u8; 32]),
                x25519_pub: hex::encode([7u8; 32]),
                ed25519_pub: hex::encode([8u8; 32]),
                peers: 2,
            })
            .unwrap(),
            serde_json::to_value(ErrorResponse { error: "rejected" }).unwrap(),
        ]
    }

    /// M-1: no response type has a field outside the audited list.
    #[test]
    fn no_response_type_can_carry_a_secret() {
        for value in sample_responses() {
            let mut found = Vec::new();
            keys(&value, &mut found);
            for k in found {
                assert!(
                    ALL_RESPONSE_FIELDS.contains(&k.as_str()),
                    "response field {k:?} is not on the audited list in response.rs; \
                     if it is public, add it there — if it is not, it must not be sent"
                );
            }
        }
    }

    /// The names the audit list must never grow.
    #[test]
    fn the_audited_list_names_nothing_secret() {
        for forbidden in [
            "coefficient_shares",
            "share",
            "shares",
            "scalar",
            "secret",
            "seed",
            "nonces",
            "x25519_secret",
            "ed25519_secret",
            "verification_shares",
        ] {
            assert!(
                !ALL_RESPONSE_FIELDS.contains(&forbidden),
                "{forbidden:?} must not be a response field"
            );
        }
    }

    /// The regression test for M-1 proper: the ceremony result type does not
    /// serialize its coefficient shares at all, whatever a handler does with it.
    #[test]
    fn a_dkg_result_does_not_serialize_its_coefficient_shares() {
        let secret = hex::encode([0x42u8; 32]);
        let result = crate::dkg::DkgResult {
            holder_index: 1,
            epoch: 3,
            session_id: [9u8; 32],
            roster_hash: hex::encode([4u8; 32]),
            coefficient_shares: vec![secret.clone()],
            coeff_commitments: vec!["aa".into()],
            verification_shares: vec![vec!["bb".into()]],
            inner_threshold: 2,
            inner_n: 3,
            outer_threshold: 2,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains(&secret), "the share leaked: {json}");
        assert!(!json.contains("coefficient_shares"), "{json}");
    }
}
