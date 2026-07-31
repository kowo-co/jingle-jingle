//! Keyfile handling: 32 bytes of OS randomness, mode 0600.
//!
//! The keyfile is full-entropy key material, which is why HKDF (not a
//! memory-hard KDF) is the right derivation step to open the vault — there is
//! no low-entropy passphrase to stretch.
//!
//! Two on-disk formats exist and `load` transparently accepts either:
//!
//!   * **v1** — the raw 32-byte root key. This is the default `jingle init`
//!     writes, and it keeps working forever with no flag and no prompt. Its
//!     weakness is total: anyone who can read the file has the whole vault.
//!   * **v2** — the same root key sealed under a passphrase-derived KEK (see
//!     [`crate::keywrap`]). `jingle protect` migrates v1→v2; `jingle unprotect`
//!     reverses it. Loading a v2 keyfile requires a passphrase (see
//!     [`crate::passphrase`]).
//!
//! Detection is by the v2 magic header; a 32-byte file without it is v1. Every
//! caller above `load` is oblivious to which format is on disk.

use std::fs;
use std::io::Write;
use std::path::Path;

use zeroize::Zeroizing;

use crate::{Error, Result};

pub const KEY_LEN: usize = 32;

/// Which on-disk keyfile format a path holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Raw 32-byte root key (the historical, default format).
    V1Raw,
    /// Passphrase-wrapped root key (`jingle protect`).
    V2Wrapped,
}

/// Inspect a keyfile's format from its header alone — no passphrase, no
/// decryption. Used by `jingle doctor` to report posture.
pub fn detect(path: &Path) -> Result<Format> {
    let bytes = fs::read(path)?;
    if crate::keywrap::is_wrapped(&bytes) {
        Ok(Format::V2Wrapped)
    } else if bytes.len() == KEY_LEN {
        Ok(Format::V1Raw)
    } else {
        Err(Error::Keyfile(format!(
            "keyfile {} is neither a 32-byte v1 key nor a v2 wrapped keyfile (size {})",
            path.display(),
            bytes.len()
        )))
    }
}

/// Create a new keyfile with fresh OS randomness. Refuses to overwrite unless
/// `force` is set. The file is created with permissions 0600 on Unix.
pub fn create(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(Error::Keyfile(format!(
            "keyfile already exists at {} (use --force to replace it; this makes the old vault unreadable)",
            path.display()
        )));
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
        // The directory holding the keyfile must be private, or another user
        // could swap the keyfile out from under us — and `load` refuses a
        // group/world-writable parent. Tighten it to 0700 when it is loose
        // (an inherited umask of 002 makes fresh dirs group-writable) so we
        // never create a keyfile our own loader would then reject.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = crate::perms::file_mode(parent) {
                if crate::perms::group_world_writable(mode) {
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
                }
            }
        }
    }

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(key.as_mut())
        .map_err(|e| Error::Other(format!("failed to gather OS randomness: {e}")))?;

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(key.as_ref())?;
    f.sync_all()?;

    // In case the file pre-existed with looser permissions (--force path).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Load the keyfile, refusing group/world-accessible files on Unix.
///
/// For a v2 (wrapped) keyfile the root key is resolved in this order:
///   1. the unlock agent's socket (`agent_sock`), if a live agent is holding
///      the key — no prompt;
///   2. `$JINGLE_PASSPHRASE_CMD` (via [`crate::passphrase::acquire`]);
///   3. an interactive TTY prompt;
///   4. an actionable error naming `jingle unlock`.
///
/// `agent_sock` is `None` for callers that must never consult the agent
/// (`jingle protect`, which operates on a v1 key, and the unit tests). A v1 raw
/// keyfile never consults the agent regardless: the wrapped-format branch below
/// is the only place the agent is reached.
pub fn load(path: &Path, agent_sock: Option<&Path>) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let meta = fs::metadata(path).map_err(|_| {
        Error::Keyfile(format!(
            "keyfile not found at {} (run `jingle init` first, or set JINGLE_KEYFILE)",
            path.display()
        ))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(Error::Keyfile(format!(
                "keyfile {} is group/world accessible (mode {:o}); fix with: chmod 600 {}",
                path.display(),
                mode & 0o777,
                path.display()
            )));
        }
    }

    // A tight keyfile inside a directory another user can write is not
    // protected: they can rename it aside and drop in their own. Enforce the
    // parent directory just as strictly as the keyfile itself.
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if let Some(mode) = crate::perms::file_mode(parent) {
            if crate::perms::group_world_writable(mode) {
                return Err(Error::Keyfile(format!(
                    "keyfile's parent directory {} is group/world writable (mode {:o}); another user could replace the keyfile. fix with: chmod 700 {}",
                    parent.display(),
                    mode,
                    parent.display()
                )));
            }
        }
    }

    let bytes = Zeroizing::new(fs::read(path)?);
    // Lock the raw file bytes into RAM before they land anywhere durable.
    crate::harden::mlock(bytes.as_ref());

    // v2: the magic header means the root key is sealed under a passphrase.
    // Unwrap it; everything above this call is unchanged whichever format wins.
    if crate::keywrap::is_wrapped(&bytes) {
        // 1. A live unlock agent short-circuits every prompt.
        if let Some(sock) = agent_sock {
            if let Some(key) = crate::agent::try_fetch_key(sock)? {
                return Ok(key);
            }
        }
        // 2/3/4. Passphrase command, then TTY prompt, then an actionable error.
        let passphrase = crate::passphrase::acquire(false)?;
        return crate::keywrap::unwrap(&bytes, &passphrase);
    }

    // v1: a bare 32-byte key. Load it exactly as before.
    if bytes.len() == KEY_LEN {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&bytes);
        crate::harden::mlock(key.as_ref());
        return Ok(key);
    }

    let _ = meta;
    Err(Error::Keyfile(format!(
        "keyfile {} has unexpected size {} (expected a 32-byte v1 key or a v2 wrapped keyfile)",
        path.display(),
        bytes.len()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        create(&path, false).unwrap();
        let key = load(&path, None).unwrap();
        assert_eq!(key.len(), KEY_LEN);
        // Refuses to overwrite without force.
        assert!(create(&path, false).is_err());
        create(&path, true).unwrap();
        let key2 = load(&path, None).unwrap();
        assert_ne!(key.as_ref(), key2.as_ref());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_world_writable_parent_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        create(&path, false).unwrap();
        // A keyfile with tight perms is still unsafe if its directory is
        // writable by others: they can rename it aside and drop in their own.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = load(&path, None).unwrap_err();
        assert!(matches!(err, Error::Keyfile(_)));
        assert!(format!("{err}").contains("parent directory"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_loose_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        create(&path, false).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load(&path, None).unwrap_err();
        assert!(matches!(err, Error::Keyfile(_)));
    }
}
