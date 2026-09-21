//! What osst cannot own: durable state.
//!
//! # What used to be here, and where it went
//!
//! Against osst 0.4.0 this module held narsild's own canonical round-1 digest,
//! its own echo set, and its own complaint type with an adjudication rule —
//! all written to the shapes osst was expected to grow. osst 0.5.0 grew them,
//! and they are gone from here rather than duplicated:
//!
//! | was here | is now |
//! | --- | --- |
//! | `round1_digest` | [`osst::dkg::round1_echo_digest`], via `DkgState::agreed_round1` |
//! | `EchoSet` / `EchoVerdict` | [`osst::dkg::AgreedRound1::confirm_all`] |
//! | `Complaint` + `adjudicate` | [`osst::dkg::Complaint`] and `ComplaintVerdict` |
//! | `SpentSessions` trait | [`osst::nested::SpentSessions`] |
//!
//! What a library cannot supply is storage that outlives the process, and
//! osst says so: its own `MemorySpentSessions` is documented as "exactly the
//! thing M-13 is about". So that is what is left here.

use std::io::Write as _;

// ---------------------------------------------------------------------------
// Spent sessions (M-13)
// ---------------------------------------------------------------------------

/// File the spent session ids are appended to, inside the data directory.
pub const SPENT_FILE: &str = "spent-sessions.log";

/// The durable half of osst's [`osst::nested::SpentSessions`] (M-13).
///
/// osst 0.5.0 owns the trait and the discipline: `inner_sign_v2_spending`
/// records `(session_id, holder_index)` *before* it computes anything, and
/// takes the session id from the holder's own nonces rather than from the
/// request. What osst cannot own is storage, and its `MemorySpentSessions`
/// says so in its own documentation — it is "exactly the thing M-13 is about,
/// state that does not survive the process".
///
/// This is the storage. An append-only log, `fsync`'d per entry, read back at
/// startup.
///
/// # The caveat this does not remove
///
/// Restoring the data directory from a filesystem snapshot rolls this file
/// back with everything else, and a session signed after the snapshot becomes
/// signable again. What the log buys is that an *ordinary* restart — a crash,
/// a redeploy, an OOM kill — is safe. A node restored from a snapshot must be
/// rotated out, not restarted. See the README.
/// The shipped implementation: an append-only log, fsync'd per entry.
pub struct FileSpentSessions {
    path: std::path::PathBuf,
    live: std::sync::Mutex<std::collections::BTreeSet<[u8; 32]>>,
}

impl FileSpentSessions {
    pub fn open(data_dir: &std::path::Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join(SPENT_FILE);
        let mut live = std::collections::BTreeSet::new();
        if path.exists() {
            for line in std::fs::read_to_string(&path)?.lines() {
                if let Some(id) = hex::decode(line.trim())
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                {
                    live.insert(id);
                }
            }
        }
        Ok(Self {
            path,
            live: std::sync::Mutex::new(live),
        })
    }
}

impl FileSpentSessions {
    /// Whether a share has already been released for this session.
    pub fn is_spent(&self, session_id: &[u8; 32]) -> bool {
        self.live
            .lock()
            .expect("spent-session store poisoned")
            .contains(session_id)
    }

    /// Record a session as spent, durably.
    pub fn mark_spent(&self, session_id: &[u8; 32]) -> std::io::Result<()> {
        let mut live = self.live.lock().expect("spent-session store poisoned");
        // The disk write comes first: a crash between marking in memory and
        // marking on disk is exactly the window this exists to close.
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{}", hex::encode(session_id))?;
        f.sync_all()?;
        live.insert(*session_id);
        Ok(())
    }
}

/// [`FileSpentSessions`] as osst sees it.
///
/// osst's trait takes `&mut self`, and this store lives behind an `Arc` shared
/// by every request; the wrapper is the adapter, and it is thin on purpose —
/// the durability is all in [`FileSpentSessions`].
pub struct SpentSessionStore {
    inner: std::sync::Arc<FileSpentSessions>,
}

impl SpentSessionStore {
    pub fn new(inner: std::sync::Arc<FileSpentSessions>) -> Self {
        Self { inner }
    }
}

impl osst::nested::SpentSessions for SpentSessionStore {
    fn spend(&mut self, session_id: &[u8; 32], _holder_index: u32) -> Result<(), osst::OsstError> {
        // One holder per process, so the holder index adds nothing to the key
        // here — and leaving it out means a session id is spent for this node
        // whatever index it is asked to sign under.
        if self.inner.is_spent(session_id) {
            return Err(osst::OsstError::SessionSpent);
        }
        self.inner.mark_spent(session_id).map_err(|e| {
            tracing::error!("cannot record a spent session: {}", e);
            // A write failure must never read as "recorded": the caller signs
            // on Ok.
            osst::OsstError::SessionSpent
        })
    }

    fn is_spent(&self, session_id: &[u8; 32], _holder_index: u32) -> bool {
        self.inner.is_spent(session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osst::nested::SpentSessions as _;

    /// M-13: a session id is usable once, and the record survives a restart.
    ///
    /// The restart is the case an in-memory store loses, and losing it is a
    /// share disclosure: two responses under one nonce give the share by
    /// elementary algebra.
    #[test]
    fn a_spent_session_stays_spent_across_a_restart() {
        let dir = std::env::temp_dir().join(format!("narsild-spent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let store = std::sync::Arc::new(FileSpentSessions::open(&dir).unwrap());
        let mut osst_view = SpentSessionStore::new(store.clone());

        assert!(!osst_view.is_spent(&[1u8; 32], 1));
        osst_view.spend(&[1u8; 32], 1).unwrap();
        assert!(osst_view.is_spent(&[1u8; 32], 1));
        assert!(!osst_view.is_spent(&[2u8; 32], 1));

        // Spending it again is refused, which is what `inner_sign_v2_spending`
        // turns into a refusal to sign.
        assert!(matches!(
            osst_view.spend(&[1u8; 32], 1),
            Err(osst::OsstError::SessionSpent)
        ));

        let reopened = FileSpentSessions::open(&dir).unwrap();
        assert!(reopened.is_spent(&[1u8; 32]));
        assert!(!reopened.is_spent(&[2u8; 32]));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
