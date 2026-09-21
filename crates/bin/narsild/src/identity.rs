//! Static node identity.
//!
//! Each narsild node owns one 32-byte identity seed, generated at first start
//! into its data directory with mode 0600. The X25519 static key used to seal
//! DKG round-2 sub-shares is derived from it with
//! [`osst::sealed::x25519_secret_from_seed`] — a KDF, so the seed can go on
//! serving as this node's long-term identity without the decryption key and
//! the seed being the same value.
//!
//! The public half is what peers put in their roster. It is stable for the
//! life of the data directory: rotating it means re-distributing the roster
//! and re-running the DKG.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// File name of the identity seed inside the data directory.
pub const IDENTITY_FILE: &str = "identity.key";

/// Unix mode the seed file must have: owner read/write only.
#[cfg(unix)]
pub const IDENTITY_MODE: u32 = 0o600;

/// A node's long-term identity.
pub struct NodeIdentity {
    seed: [u8; 32],
    path: PathBuf,
}

impl NodeIdentity {
    /// Load the identity from `data_dir`, generating one on first start.
    ///
    /// A freshly generated file is created with mode 0600. An existing file
    /// with looser permissions is refused rather than silently tightened: a
    /// key that has been world-readable is not a secret any more, and quietly
    /// fixing the mode would hide that.
    pub fn load_or_create(data_dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(data_dir)?;
        let path = data_dir.join(IDENTITY_FILE);

        if path.exists() {
            Self::check_mode(&path)?;
            let raw = fs::read(&path)?;
            let seed: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: identity seed must be exactly 32 bytes", path.display()),
                )
            })?;
            return Ok(Self { seed, path });
        }

        let mut seed = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
        write_private(&path, &seed)?;
        tracing::info!("generated a new node identity at {}", path.display());
        Ok(Self { seed, path })
    }

    /// Build an identity from a seed without touching the filesystem — tests.
    #[cfg(test)]
    pub fn from_seed_for_test(seed: [u8; 32]) -> Self {
        Self {
            seed,
            path: PathBuf::from("<test>"),
        }
    }

    /// Where the seed lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// This node's X25519 static secret, for `osst::sealed`.
    pub fn x25519_secret(&self) -> [u8; 32] {
        osst::sealed::x25519_secret_from_seed(&self.seed)
    }

    /// This node's X25519 static public key — what goes in peers' rosters.
    pub fn x25519_public(&self) -> [u8; 32] {
        osst::sealed::x25519_public_from_seed(&self.seed)
    }

    #[cfg(unix)]
    fn check_mode(path: &Path) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{}: identity seed is mode {:o}, must be {:o} — \
                     it has been readable by other users, so rotate it",
                    path.display(),
                    mode,
                    IDENTITY_MODE
                ),
            ));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn check_mode(_path: &Path) -> io::Result<()> {
        Ok(())
    }
}

/// Write `bytes` to `path` with owner-only permissions.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(IDENTITY_MODE)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_x25519_key_is_derived_not_the_seed_itself() {
        let id = NodeIdentity::from_seed_for_test([3u8; 32]);
        assert_ne!(id.x25519_secret(), [3u8; 32]);
        assert_ne!(id.x25519_public(), [3u8; 32]);
    }

    #[test]
    fn an_identity_persists_across_loads() {
        let dir = std::env::temp_dir().join(format!("narsild-id-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let first = NodeIdentity::load_or_create(&dir).unwrap();
        let again = NodeIdentity::load_or_create(&dir).unwrap();
        assert_eq!(first.x25519_public(), again.x25519_public());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(first.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, IDENTITY_MODE);
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
