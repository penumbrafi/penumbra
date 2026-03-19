//! distributed interleaved DKG for nested FROST
//!
//! each narsild node acts as one dealer in `outer_t` independent Feldman VSS
//! ceremonies. the result: every node holds an InnerShare — shamir shares of
//! each outer polynomial coefficient. nobody learns the coefficients.
//!
//! protocol:
//!   round 1: each node generates outer_t dealers, broadcasts Feldman commitments
//!   round 2: each node sends subshares to every other node
//!   round 3: each node verifies subshares, aggregates into final share
//!
//! uses osst::dkg::Dealer for the Feldman VSS (Pallas curve).

use crate::accumulator::{AccumulateResult, Contribution, Aggregate, ThresholdAccumulator};
use crate::broadcast::PeerSet;
use osst::curve::OsstPoint;
use osst::dkg;
use osst::reshare::DealerCommitment;
use pasta_curves::pallas::Point as PallasPoint;
use pasta_curves::pallas::Scalar as PallasScalar;
use pasta_curves::group::{ff::{Field, PrimeField}, GroupEncoding};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Feldman commitment for one coefficient's DKG from one dealer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgCommitmentMsg {
    /// which outer polynomial coefficient (0-indexed)
    pub coeff_index: u32,
    /// dealer's node index (1-indexed)
    pub dealer_index: u32,
    /// g^{coeff_j} for each polynomial term (compressed points, hex)
    pub commitments: Vec<String>,
}

/// subshare from one dealer to one recipient for one coefficient
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgSubshareMsg {
    pub coeff_index: u32,
    pub dealer_index: u32,
    pub recipient_index: u32,
    /// f_i(j) scalar value (hex)
    pub value_hex: String,
}

/// round 1 broadcast: all commitments from one node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgRound1Broadcast {
    pub dealer_index: u32,
    /// commitments for each coefficient (outer_t entries)
    pub coefficients: Vec<DkgCommitmentMsg>,
}

/// round 2 message: subshares for a specific recipient
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgRound2Msg {
    pub dealer_index: u32,
    pub recipient_index: u32,
    /// subshares for each coefficient
    pub subshares: Vec<DkgSubshareMsg>,
}

/// DKG result for one node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgResult {
    /// this node's index (1-indexed)
    pub holder_index: u32,
    /// shamir share of each outer polynomial coefficient
    /// coefficient_shares[j] = this node's share of coefficient j
    pub coefficient_shares: Vec<String>, // hex scalars
    /// g^{a_j} for each coefficient (public, same for all nodes)
    pub coeff_commitments: Vec<String>, // hex points
    /// inner threshold
    pub inner_threshold: u32,
    /// inner n
    pub inner_n: u32,
    /// outer threshold
    pub outer_threshold: u32,
}

/// DKG ceremony state
pub struct DkgCeremony {
    pub holder_index: u32,
    pub inner_n: u32,
    pub inner_t: u32,
    pub outer_t: u32,
    /// our dealers (one per outer coefficient)
    dealers: Vec<dkg::Dealer<PallasPoint>>,
    /// collected commitments: coeff_index → dealer_index → DealerCommitment
    commitments: HashMap<u32, HashMap<u32, DealerCommitment<PallasPoint>>>,
    /// collected subshares: coeff_index → dealer_index → scalar
    subshares: HashMap<u32, HashMap<u32, PallasScalar>>,
    /// final result
    pub result: Option<DkgResult>,
    peers: PeerSet,
}

impl DkgCeremony {
    pub fn new(
        holder_index: u32,
        inner_n: u32,
        inner_t: u32,
        outer_t: u32,
        peers: PeerSet,
    ) -> Self {
        let mut rng = rand_core::OsRng;
        let dealers: Vec<dkg::Dealer<PallasPoint>> = (0..outer_t)
            .map(|_| dkg::Dealer::new(holder_index, inner_t, &mut rng))
            .collect();

        Self {
            holder_index,
            inner_n,
            inner_t,
            outer_t,
            dealers,
            commitments: HashMap::new(),
            subshares: HashMap::new(),
            result: None,
            peers,
        }
    }

    /// round 1: broadcast our Feldman commitments for all coefficients
    pub fn round1_broadcast(&self) -> DkgRound1Broadcast {
        let coefficients: Vec<DkgCommitmentMsg> = self.dealers.iter().enumerate().map(|(j, dealer)| {
            let commitment = dealer.commitment();
            DkgCommitmentMsg {
                coeff_index: j as u32,
                dealer_index: self.holder_index,
                commitments: commitment.coefficients.iter()
                    .map(|p| hex::encode(OsstPoint::compress(p)))
                    .collect(),
            }
        }).collect();

        let broadcast = DkgRound1Broadcast {
            dealer_index: self.holder_index,
            coefficients,
        };

        // also store our own commitments
        // (done in receive_round1)

        broadcast
    }

    /// receive round 1 commitments from a peer (or ourselves)
    pub fn receive_round1(&mut self, msg: &DkgRound1Broadcast) -> bool {
        for coeff_msg in &msg.coefficients {
            let points: Vec<PallasPoint> = coeff_msg.commitments.iter()
                .filter_map(|hex_str| {
                    let bytes = hex::decode(hex_str).ok()?;
                    if bytes.len() != 32 { return None; }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    let ct = PallasPoint::from_bytes(&arr.into());
                    if bool::from(ct.is_some()) { Some(ct.unwrap()) } else { None }
                })
                .collect();

            if points.len() != self.inner_t as usize {
                tracing::warn!("DKG: wrong number of commitment points from dealer {}",
                    coeff_msg.dealer_index);
                continue;
            }

            let commitment = DealerCommitment {
                dealer_index: coeff_msg.dealer_index,
                coefficients: points,
            };
            self.commitments
                .entry(coeff_msg.coeff_index)
                .or_default()
                .insert(coeff_msg.dealer_index, commitment);
        }

        // check if we have all commitments
        self.all_commitments_received()
    }

    /// check if all round 1 commitments are in
    fn all_commitments_received(&self) -> bool {
        for j in 0..self.outer_t {
            let count = self.commitments.get(&j).map(|m| m.len()).unwrap_or(0);
            if count < self.inner_n as usize {
                return false;
            }
        }
        true
    }

    /// round 2: generate and send subshares to each peer
    pub fn round2_generate(&self) -> Vec<DkgRound2Msg> {
        let mut messages = Vec::new();

        for recipient in 1..=self.inner_n {
            let subshares: Vec<DkgSubshareMsg> = self.dealers.iter().enumerate().map(|(j, dealer)| {
                let subshare = dealer.generate_subshare(recipient);
                DkgSubshareMsg {
                    coeff_index: j as u32,
                    dealer_index: self.holder_index,
                    recipient_index: recipient,
                    value_hex: hex::encode(subshare.value().to_repr().as_ref()),
                }
            }).collect();

            messages.push(DkgRound2Msg {
                dealer_index: self.holder_index,
                recipient_index: recipient,
                subshares,
            });
        }

        messages
    }

    /// receive round 2 subshares addressed to us
    pub fn receive_round2(&mut self, msg: &DkgRound2Msg) -> Result<bool, String> {
        if msg.recipient_index != self.holder_index {
            return Err("subshare not addressed to us".into());
        }

        for sub in &msg.subshares {
            let scalar = scalar_from_hex(&sub.value_hex)
                .ok_or_else(|| format!("bad scalar from dealer {}", sub.dealer_index))?;

            // verify against commitment
            let commitment = self.commitments
                .get(&sub.coeff_index)
                .and_then(|m| m.get(&sub.dealer_index))
                .ok_or_else(|| format!("no commitment for coeff {} dealer {}",
                    sub.coeff_index, sub.dealer_index))?;

            if !commitment.verify_subshare(self.holder_index, &scalar) {
                return Err(format!("INVALID subshare from dealer {} for coeff {}",
                    sub.dealer_index, sub.coeff_index));
            }

            self.subshares
                .entry(sub.coeff_index)
                .or_default()
                .insert(sub.dealer_index, scalar);
        }

        Ok(self.all_subshares_received())
    }

    fn all_subshares_received(&self) -> bool {
        for j in 0..self.outer_t {
            let count = self.subshares.get(&j).map(|m| m.len()).unwrap_or(0);
            if count < self.inner_n as usize {
                return false;
            }
        }
        true
    }

    /// round 3: aggregate subshares into final InnerShare
    pub fn finalize(&mut self) -> Result<DkgResult, String> {
        if !self.all_subshares_received() {
            return Err("not all subshares received".into());
        }

        let mut coefficient_shares = Vec::with_capacity(self.outer_t as usize);
        let mut coeff_commitments = Vec::with_capacity(self.outer_t as usize);

        for j in 0..self.outer_t {
            // aggregate subshares for coefficient j
            let subs = self.subshares.get(&j).unwrap();
            let comms = self.commitments.get(&j).unwrap();

            let mut agg: dkg::Aggregator<PallasPoint> = dkg::Aggregator::new(self.holder_index);
            for (&dealer_idx, scalar) in subs {
                let commitment = comms.get(&dealer_idx).unwrap();
                let subshare = osst::reshare::SubShare::new(dealer_idx, self.holder_index, *scalar);
                agg.add_subshare(subshare, commitment)
                    .map_err(|e| format!("aggregation error: {:?}", e))?;
            }

            let share = agg.finalize(self.inner_n)
                .map_err(|e| format!("finalize error: {:?}", e))?;
            coefficient_shares.push(hex::encode(share.to_repr().as_ref()));

            // coefficient commitment: g^{a_j} = Σ_k g^{f_k(0)}
            coeff_commitments.push(hex::encode(agg.derive_group_key().compress()));
        }

        let result = DkgResult {
            holder_index: self.holder_index,
            coefficient_shares,
            coeff_commitments,
            inner_threshold: self.inner_t,
            inner_n: self.inner_n,
            outer_threshold: self.outer_t,
        };

        self.result = Some(result.clone());
        Ok(result)
    }
}

impl DkgResult {
    /// evaluate the inner share at a specific outer position.
    /// returns the signing share σ_k = Σ_j (coeff_share_j * position^j)
    ///
    /// this is the share used for nested FROST signing at the given position.
    pub fn eval_at(&self, position: u32) -> Option<PallasScalar> {
        let x = PallasScalar::from(position as u64);
        let mut result = PallasScalar::zero();
        let mut x_pow = PallasScalar::one();

        for share_hex in &self.coefficient_shares {
            let scalar = scalar_from_hex(share_hex)?;
            result = result + scalar * x_pow;
            x_pow = x_pow * x;
        }

        Some(result)
    }
}

fn scalar_from_hex(hex_str: &str) -> Option<PallasScalar> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 { return None; }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let ct = PallasScalar::from_repr(arr.into());
    if bool::from(ct.is_some()) { Some(ct.unwrap()) } else { None }
}
