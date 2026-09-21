//! threshold accumulator — generic "collect T from peers until threshold" service
//!
//! every narsild protocol (OSST authorization, FROST commitment, FROST signing)
//! follows the same pattern:
//!
//! 1. receive or initiate a session
//! 2. produce our local contribution
//! 3. broadcast to peers
//! 4. collect contributions from peers
//! 5. when threshold met, aggregate and return result
//!
//! this module captures that pattern as a composable service.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, watch};

/// How long a session may sit before it is collected (M-18).
///
/// Session state was never expired and never bounded, and
/// `receive_commitment` sampled **secret nonces** for any session id a caller
/// announced — so an unauthenticated party made the node generate and retain
/// unbounded live nonce material. Authentication (M-2) means only a roster
/// member can do that now; this means it does not accumulate even then.
pub const SESSION_TTL: Duration = Duration::from_secs(600);

/// How many sessions may be live at once.
pub const MAX_SESSIONS: usize = 64;

/// a contribution to a threshold accumulation session
pub trait Contribution: Clone + Send + Sync + 'static {
    /// unique identifier for the contributor (e.g. holder_index)
    type Id: Ord + Clone + Send + Sync;
    fn contributor_id(&self) -> Self::Id;
}

/// result of accumulation reaching threshold
pub trait Aggregate: Clone + Send + Sync + 'static {}

/// The collected contributions are themselves a perfectly good aggregate, and
/// for both FROST rounds they are the right one: round 1's product is the
/// commitment set, and round 2's shares must be verified against that set
/// before they are summed, which needs more context than an aggregation
/// closure has.
impl<C: Contribution> Aggregate for Vec<C> {}

/// How a session turns its collected contributions into a result.
type AggregateFn<C, A> = Box<dyn Fn(&[C]) -> A + Send + Sync>;

/// session state for one accumulation
pub struct Session<C: Contribution, A: Aggregate> {
    created_at: Instant,
    contributions: BTreeMap<C::Id, C>,
    threshold: usize,
    aggregate_fn: AggregateFn<C, A>,
    result: Option<A>,
    notify: watch::Sender<usize>,
}

/// the accumulator: manages sessions, deduplicates, checks threshold
pub struct ThresholdAccumulator<K, C, A>
where
    K: Ord + Clone + Send + Sync + 'static,
    C: Contribution,
    A: Aggregate,
{
    sessions: Arc<Mutex<BTreeMap<K, Session<C, A>>>>,
    threshold: usize,
}

impl<K, C, A> Clone for ThresholdAccumulator<K, C, A>
where
    K: Ord + Clone + Send + Sync + 'static,
    C: Contribution,
    A: Aggregate,
{
    fn clone(&self) -> Self {
        Self {
            sessions: Arc::clone(&self.sessions),
            threshold: self.threshold,
        }
    }
}

/// outcome of adding a contribution
pub enum AccumulateResult<A: Aggregate> {
    /// contribution accepted, waiting for more
    Pending { collected: usize, threshold: usize },
    /// threshold met, here's the aggregate
    Complete(A),
    /// duplicate contribution, ignored
    Duplicate,
}

impl<K, C, A> ThresholdAccumulator<K, C, A>
where
    K: Ord + Clone + Send + Sync + 'static,
    C: Contribution,
    A: Aggregate,
{
    pub fn new(threshold: usize) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            threshold,
        }
    }

    /// Ensure a session exists, with the aggregation to run once the
    /// threshold is met. Idempotent: a session that already exists keeps the
    /// aggregation it was created with.
    /// Returns `false` if the accumulator is at capacity and this key is new —
    /// the caller must refuse the request rather than grow without bound.
    pub async fn ensure_session(
        &self,
        key: K,
        aggregate_fn: impl Fn(&[C]) -> A + Send + Sync + 'static,
    ) -> bool {
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, s| s.created_at.elapsed() < SESSION_TTL);
        if sessions.len() >= MAX_SESSIONS && !sessions.contains_key(&key) {
            return false;
        }
        sessions.entry(key).or_insert_with(|| {
            let (tx, _rx) = watch::channel(0usize);
            Session {
                created_at: Instant::now(),
                contributions: BTreeMap::new(),
                threshold: self.threshold,
                aggregate_fn: Box::new(aggregate_fn),
                result: None,
                notify: tx,
            }
        });
        true
    }

    /// How many sessions are live. For the health endpoint and the tests.
    #[allow(dead_code)]
    pub async fn session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// add a contribution. deduplicates, checks threshold, aggregates.
    pub async fn accumulate(&self, key: &K, contribution: C) -> AccumulateResult<A> {
        let mut sessions = self.sessions.lock().await;
        let session = match sessions.get_mut(key) {
            Some(s) => s,
            None => return AccumulateResult::Pending { collected: 0, threshold: self.threshold },
        };

        // already complete?
        if let Some(ref a) = session.result {
            return AccumulateResult::Complete(a.clone());
        }

        // dedup
        let id = contribution.contributor_id();
        if session.contributions.contains_key(&id) {
            return AccumulateResult::Duplicate;
        }

        session.contributions.insert(id, contribution);
        let collected = session.contributions.len();
        let _ = session.notify.send(collected);

        if collected >= session.threshold {
            let contribs: Vec<C> = session.contributions.values().cloned().collect();
            let result = (session.aggregate_fn)(&contribs);
            session.result = Some(result.clone());
            AccumulateResult::Complete(result)
        } else {
            AccumulateResult::Pending { collected, threshold: session.threshold }
        }
    }

    /// get current state of a session
    pub async fn status(&self, key: &K) -> Option<(usize, usize, Option<A>)> {
        let sessions = self.sessions.lock().await;
        sessions.get(key).map(|s| {
            (s.contributions.len(), s.threshold, s.result.clone())
        })
    }

    /// get all contributions for a session
    pub async fn contributions(&self, key: &K) -> Vec<C> {
        let sessions = self.sessions.lock().await;
        sessions.get(key)
            .map(|s| s.contributions.values().cloned().collect())
            .unwrap_or_default()
    }
}
