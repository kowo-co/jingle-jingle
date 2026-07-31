//! Path resolution: CLI flags > environment variables > XDG defaults.

use std::path::PathBuf;

use crate::{Error, Result};

pub const ENV_KEYFILE: &str = "JINGLE_KEYFILE";
pub const ENV_DATA_DIR: &str = "JINGLE_DATA_DIR";
/// Explicit path to the unlock-agent socket. Overrides the derived location;
/// its parent directory is tightened to 0700 when the agent binds it.
pub const ENV_AGENT_SOCK: &str = "JINGLE_AGENT_SOCK";
/// Per-user runtime directory (tmpfs, cleared on reboot) — the preferred home
/// for the agent socket when it is set.
pub const ENV_RUNTIME_DIR: &str = "XDG_RUNTIME_DIR";

#[derive(Debug, Clone)]
pub struct Paths {
    pub keyfile: PathBuf,
    pub vault: PathBuf,
    pub audit: PathBuf,
    /// Unix socket the unlock agent listens on. Never contains a secret; the
    /// key it serves lives only in the agent's memory.
    pub agent_sock: PathBuf,
}

/// Resolve the keyfile, vault, and audit-log paths.
///
/// Precedence: explicit CLI flag, then `JINGLE_KEYFILE` / `JINGLE_DATA_DIR`
/// environment variables, then platform defaults (`~/.config/jingle/key`,
/// `~/.local/share/jingle/vault.jingle` on Linux). The audit log always lives
/// next to the vault so a relocated vault keeps its trail.
pub fn resolve(vault_flag: Option<PathBuf>, keyfile_flag: Option<PathBuf>) -> Result<Paths> {
    let dirs = directories::ProjectDirs::from("", "", "jingle");

    let keyfile = match keyfile_flag {
        Some(p) => p,
        None => match std::env::var_os(ENV_KEYFILE) {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => dirs
                .as_ref()
                .map(|d| d.config_dir().join("key"))
                .ok_or_else(|| Error::Other("cannot determine a config directory".into()))?,
        },
    };

    let vault = match vault_flag {
        Some(p) => p,
        None => {
            let data_dir = match std::env::var_os(ENV_DATA_DIR) {
                Some(p) if !p.is_empty() => PathBuf::from(p),
                _ => dirs
                    .as_ref()
                    .map(|d| d.data_dir().to_path_buf())
                    .ok_or_else(|| Error::Other("cannot determine a data directory".into()))?,
            };
            data_dir.join("vault.jingle")
        }
    };

    let audit = vault.with_file_name("audit.jsonl");
    let agent_sock = resolve_agent_sock(&vault);

    Ok(Paths {
        keyfile,
        vault,
        audit,
        agent_sock,
    })
}

/// Where the unlock agent's socket lives. Precedence:
///   1. `$JINGLE_AGENT_SOCK` — an explicit path (used by tests and power users);
///   2. `$XDG_RUNTIME_DIR/jingle/agent.sock` — a per-user tmpfs directory that
///      the OS clears on reboot, which is exactly the reboot-relocks-the-vault
///      behaviour we want;
///   3. `<data dir>/agent/agent.sock` — alongside the vault, for boxes with no
///      runtime dir. A stale socket surviving a reboot here is detected and
///      removed on the next call, so persistence is harmless.
///
/// In every case the socket sits inside its own directory so that directory can
/// be tightened to 0700 without disturbing the vault's directory.
fn resolve_agent_sock(vault: &std::path::Path) -> PathBuf {
    if let Some(p) = std::env::var_os(ENV_AGENT_SOCK).filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
    }
    if let Some(rt) = std::env::var_os(ENV_RUNTIME_DIR).filter(|p| !p.is_empty()) {
        return PathBuf::from(rt).join("jingle").join("agent.sock");
    }
    let data_dir = vault.parent().unwrap_or_else(|| std::path::Path::new("."));
    data_dir.join("agent").join("agent.sock")
}
