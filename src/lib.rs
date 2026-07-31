//! jingle — an agent-native credential keychain.
//!
//! Design invariant: secret bytes cross the process boundary only via
//! (a) child-process environment in `jingle exec`,
//! (b) the OS clipboard in `jingle copy`,
//! (c) the short-lived 6-digit code in `jingle totp`,
//! (d) the explicitly flagged `jingle generate --print`.
//! Every other command may emit names, paths, and `[REDACTED]` — never values.

pub mod agent;
pub mod audit;
pub mod cli;
pub mod commands;
pub mod crypto;
pub mod genpass;
pub mod harden;
pub mod keyfile;
pub mod keywrap;
pub mod model;
pub mod output;
pub mod passphrase;
pub mod paths;
pub mod perms;
pub mod redact;
pub mod totp;
pub mod vault;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("entry '{0}' not found")]
    NotFound(String),

    #[error("entry '{entry}' has no secret field '{field}'")]
    FieldNotFound { entry: String, field: String },

    #[error("entry '{0}' already exists")]
    AlreadyExists(String),

    #[error("vault integrity failure: {0}")]
    Tamper(String),

    #[error(
        "entry '{0}' is locked; pass --confirm-locked {0} to allow this access (the attempt has been audited)"
    )]
    Locked(String),

    #[error("clipboard unavailable: {0}")]
    Clipboard(String),

    #[error("{0}")]
    Usage(String),

    #[error("keyfile error: {0}")]
    Keyfile(String),

    #[error("passphrase error: {0}")]
    Passphrase(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Stable process exit code for scripting agents.
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Usage(_) => 2,
            Error::NotFound(_) | Error::FieldNotFound { .. } => 3,
            Error::Tamper(_) => 4,
            Error::Locked(_) => 5,
            Error::Clipboard(_) => 6,
            _ => 1,
        }
    }

    /// Stable machine-readable error code for `--json` mode.
    pub fn code_str(&self) -> &'static str {
        match self {
            Error::NotFound(_) => "not_found",
            Error::FieldNotFound { .. } => "field_not_found",
            Error::AlreadyExists(_) => "already_exists",
            Error::Tamper(_) => "tamper",
            Error::Locked(_) => "locked",
            Error::Clipboard(_) => "clipboard_unavailable",
            Error::Usage(_) => "usage",
            Error::Keyfile(_) => "keyfile",
            Error::Passphrase(_) => "passphrase",
            Error::Io(_) => "io",
            Error::Json(_) => "serialization",
            Error::Other(_) => "error",
        }
    }
}
