//! Filesystem permission checks shared by the loader and `jingle doctor`.
//!
//! Two postures matter:
//!   * the keyfile and its directory are *enforced* — a group/world accessible
//!     keyfile, or a directory another user can write (and so swap the keyfile
//!     out from under us), is a hard failure;
//!   * the vault and audit log are *reported* — a loose mode warns but never
//!     aborts, so upgrading an existing install can't brick it.
//!
//! The message style matches `keyfile::load`: state the octal mode and give the
//! exact `chmod` to run.

use std::path::Path;
use std::sync::{Mutex, OnceLock};

/// Mode bits (`& 0o7777`) of `path`, or `None` on non-Unix or if `path` is
/// missing / unstattable.
pub fn file_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .ok()
            .map(|m| m.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Any group- or world-access bit set.
pub fn group_world_accessible(mode: u32) -> bool {
    mode & 0o077 != 0
}

/// Any group- or world-*write* bit set.
pub fn group_world_writable(mode: u32) -> bool {
    mode & 0o022 != 0
}

fn warned() -> &'static Mutex<std::collections::HashSet<String>> {
    static S: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

/// Warn (at most once per path, per process) if `path` is group/world
/// accessible. Used for the vault and audit log, where a loose mode is a
/// warning rather than a hard failure. No-op if the file is missing or the
/// mode is tight.
pub fn warn_if_loose(path: &Path, label: &str) {
    let Some(mode) = file_mode(path) else { return };
    if !group_world_accessible(mode) {
        return;
    }
    let key = path.display().to_string();
    let mut set = warned().lock().unwrap_or_else(|e| e.into_inner());
    if set.insert(key) {
        eprintln!(
            "jingle: warning: {label} {} is group/world accessible (mode {:o}); fix with: chmod 600 {}",
            path.display(),
            mode,
            path.display()
        );
    }
}
