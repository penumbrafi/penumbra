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

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use tokio::sync::{Mutex, watch};

/// a contribution to a threshold accumulation session
pub trait Contribution: Clone + Send + Sync + 'static {
    /// unique identifier for the contributor (e.g. holder_index)
    type Id: Eq + Hash + Clone + Send + Sync;
    fn contributor_id(&self) -> Self::Id;
}

/// result of accumulation reaching threshold
pub trait Aggregate: Clone + Send + Sync + 'static {}

/// session state for one accumulation
pub struct Session<C: Contribution, A: Aggregate> {
    contributions: HashMap<C::Id, C>,
    threshold: usize,
    aggregate_fn: Box<dyn Fn(&[C]) -> A + Send + Sync>,
    result: Option<A>,
    notify: watch::Sender<usize>,
}

/// handle for observing session progress
pub struct SessionHandle {
    pub watch: watch::Receiver<usize>,
}

/// the accumulator: manages sessions, deduplicates, checks threshold
pub struct ThresholdAccumulator<K, C, A>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    C: Contribution,
    A: Aggregate,
{
    sessions: Arc<Mutex<HashMap<K, Session<C, A>>>>,
    threshold: usize,
}

impl<K, C, A> Clone for ThresholdAccumulator<K, C, A>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
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
    K: Eq + Hash + Clone + Send + Sync + 'static,
    C: Contribution,
    A: Aggregate,
{
    pub fn new(threshold: usize) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            threshold,
        }
    }

    /// ensure a session exists, returns (created, handle)
    pub async fn ensure_session(
        &self,
        key: K,
        aggregate_fn: impl Fn(&[C]) -> A + Send + Sync + 'static,
    ) -> SessionHandle {
        let mut sessions = self.sessions.lock().await;
        let session = sessions.entry(key).or_insert_with(|| {
            let (tx, _rx) = watch::channel(0usize);
            Session {
                contributions: HashMap::new(),
                threshold: self.threshold,
                aggregate_fn: Box::new(aggregate_fn),
                result: None,
                notify: tx,
            }
        });
        SessionHandle {
            watch: session.notify.subscribe(),
        }
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
