//! The complete CLI grammar. By construction, NO argument anywhere in this
//! grammar accepts a secret value: secrets enter via stdin (`--stdin`) or
//! internal generation (`--generate`), never argv — argv is visible in
//! process lists, shell history, and agent transcripts.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

use crate::genpass::Charset;

#[derive(Parser, Debug)]
#[command(
    name = "jingle",
    version,
    about = "Agent-native credential keychain: store and use secrets without them entering your context",
    long_about = "jingle stores account credentials (passwords, TOTP seeds, API keys) in an \
encrypted vault and lets agents USE them without ever seeing them.\n\n\
Secret values never appear on stdout: consume them with `jingle exec` \
(child-process env injection) or `jingle copy` (clipboard). Secret values are \
never accepted as command-line arguments: provide them on stdin (--stdin) or \
generate them internally (--generate)."
)]
pub struct Cli {
    /// Emit machine-readable JSON (secrets are redacted in all modes)
    #[arg(long, global = true)]
    pub json: bool,

    /// Vault file path (default: platform data dir, or $JINGLE_DATA_DIR)
    #[arg(long, global = true, value_name = "PATH")]
    pub vault: Option<PathBuf>,

    /// Keyfile path (default: platform config dir, or $JINGLE_KEYFILE)
    #[arg(long, global = true, value_name = "PATH")]
    pub keyfile: Option<PathBuf>,

    /// Suppress non-essential output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum CharsetArg {
    /// Letters, digits, and shell-safe symbols
    Full,
    /// Letters and digits only
    #[value(alias = "no-symbols")]
    Alnum,
    /// Digits only (PINs)
    Digits,
}

impl From<CharsetArg> for Charset {
    fn from(c: CharsetArg) -> Charset {
        match c {
            CharsetArg::Full => Charset::Full,
            CharsetArg::Alnum => Charset::Alnum,
            CharsetArg::Digits => Charset::Digits,
        }
    }
}

/// How a secret value enters jingle. Exactly one source is required.
#[derive(Args, Debug)]
#[command(group(ArgGroup::new("source").required(true).multiple(false).args(["stdin", "generate"])))]
pub struct SecretSource {
    /// Read the secret from stdin (pipe it in; max 4 KiB, trailing newline trimmed)
    #[arg(long)]
    pub stdin: bool,

    /// Generate a strong random secret internally (it is stored, never shown)
    #[arg(long)]
    pub generate: bool,

    /// Length of the generated secret [default: 24]
    #[arg(long, requires = "generate")]
    pub length: Option<usize>,

    /// Character set for the generated secret [default: full]
    #[arg(long, value_enum, requires = "generate")]
    pub charset: Option<CharsetArg>,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Create the keyfile and an empty vault
    Init {
        /// Replace an existing keyfile/vault (DESTROYS access to the old vault)
        #[arg(long)]
        force: bool,
    },

    /// Create an entry (secret via --stdin or --generate, never argv)
    Add {
        /// Entry name (unique handle, e.g. "github" or "aws/prod")
        name: String,
        /// Service name or domain
        #[arg(long)]
        service: Option<String>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        /// Free-form notes (treated as untrusted data on display)
        #[arg(long)]
        notes: Option<String>,
        /// Comma-separated tags
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Secret field to set on the new entry
        #[arg(long, default_value = "password")]
        field: String,
        #[command(flatten)]
        source: SecretSource,
    },

    /// Set or replace a secret field on an entry (field "totp" validates base32/otpauth)
    Set {
        name: String,
        /// Field name: password, totp, api_key, or any custom name
        field: String,
        #[command(flatten)]
        source: SecretSource,
    },

    /// Remove a secret field from an entry
    Unset {
        name: String,
        field: String,
        /// Skip the confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Generate a strong password: into an entry (--entry) or to stdout (--print)
    #[command(group(ArgGroup::new("dest").required(true).multiple(false).args(["entry", "print"])))]
    Generate {
        /// Store the generated value on this entry (prints only a confirmation)
        #[arg(long, value_name = "NAME")]
        entry: Option<String>,
        /// Secret field to store into (with --entry)
        #[arg(long, default_value = "password", requires = "entry")]
        field: String,
        /// Print the generated value to stdout (it WILL enter your context)
        #[arg(long)]
        print: bool,
        #[arg(long, default_value_t = 24)]
        length: usize,
        #[arg(long, value_enum, default_value_t = CharsetArg::Full)]
        charset: CharsetArg,
    },

    /// List entries (metadata only — secret values are never shown)
    #[command(alias = "ls")]
    List {
        /// Only entries carrying this tag
        #[arg(long)]
        tag: Option<String>,
        /// Only entries whose service contains this string
        #[arg(long)]
        service: Option<String>,
    },

    /// Show one entry's metadata (secret fields listed by name, values redacted)
    Show { name: String },

    /// Run a command with secrets injected as environment variables
    ///
    /// Example: jingle exec -s github=GH_PASS -s aws/prod:api_key=AWS_KEY -- ./deploy.sh
    Exec {
        /// Mapping REF=ENVVAR where REF is "entry" (implies field "password") or "entry:field"
        #[arg(
            short = 's',
            long = "secret",
            value_name = "REF=ENVVAR",
            required = true
        )]
        secrets: Vec<String>,
        /// Allow access to a locked entry by repeating its exact name
        #[arg(long, value_name = "NAME")]
        confirm_locked: Vec<String>,
        /// Start from an empty environment (plus PATH/HOME and the mappings)
        #[arg(long)]
        no_inherit_env: bool,
        /// Allow a mapping to overwrite an env var that already exists
        #[arg(long)]
        allow_overwrite: bool,
        /// Disable the leak tripwire that redacts injected secret values from
        /// the child's stdout/stderr. Only needed when the child emits binary
        /// data that a byte-for-byte substitution could corrupt (an image, a
        /// tarball, a length-prefixed protocol). Passing this streams the
        /// child's output through untouched, so a secret it prints reaches
        /// your terminal verbatim.
        #[arg(long)]
        no_leak_guard: bool,
        /// The command to run (everything after --)
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },

    /// Copy a secret to the clipboard (auto-clears after --clear-after seconds)
    Copy {
        name: String,
        #[arg(long, default_value = "password")]
        field: String,
        /// Seconds until the clipboard is cleared (0 disables auto-clear)
        #[arg(long, default_value_t = 30)]
        clear_after: u64,
        /// Allow access to a locked entry by repeating its exact name
        #[arg(long, value_name = "NAME")]
        confirm_locked: Vec<String>,
    },

    /// Print the current TOTP code for an entry (the seed itself never prints)
    Totp {
        name: String,
        /// Allow access to a locked entry by repeating its exact name
        #[arg(long, value_name = "NAME")]
        confirm_locked: Vec<String>,
    },

    /// Delete an entry
    Rm {
        name: String,
        /// Skip the confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Edit an entry's metadata (secret fields are edited with `set`/`unset`)
    Edit {
        name: String,
        #[arg(long)]
        service: Option<String>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long, value_delimiter = ',')]
        tags: Option<Vec<String>>,
        /// Rename the entry
        #[arg(long, value_name = "NEW_NAME")]
        rename: Option<String>,
    },

    /// Lock an entry: secret egress then requires --confirm-locked
    Lock { name: String },

    /// Unlock a previously locked entry
    Unlock {
        name: String,
        /// Skip the confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Write an encrypted backup of the vault (same key; NOT a plaintext export)
    Export {
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },

    /// Merge entries from an encrypted jingle vault file
    Import {
        file: PathBuf,
        /// Replace entries whose names collide (default: skip them)
        #[arg(long)]
        overwrite: bool,
    },

    /// Show the audit log and verify its hash chain
    Audit {
        /// Show at most this many recent records
        #[arg(short = 'n', long, default_value_t = 50)]
        limit: usize,
    },

    /// (internal) clear the clipboard after a delay if it still holds the copied value
    #[command(name = "__clear-clipboard", hide = true)]
    ClearClipboard {
        #[arg(long)]
        after: u64,
    },
}
