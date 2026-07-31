#![allow(dead_code)]

use std::path::PathBuf;

use assert_cmd::Command;
use tempfile::TempDir;

/// A hermetic jingle installation in a tempdir: keyfile, vault, and audit log
/// are all isolated via JINGLE_KEYFILE / JINGLE_DATA_DIR.
pub struct TestVault {
    pub dir: TempDir,
}

impl TestVault {
    pub fn new() -> Self {
        let tv = TestVault {
            dir: tempfile::tempdir().unwrap(),
        };
        tv.cmd().arg("init").assert().success();
        tv
    }

    pub fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("jingle").unwrap();
        c.env("JINGLE_DATA_DIR", self.dir.path().join("data"));
        c.env("JINGLE_KEYFILE", self.dir.path().join("key"));
        // Pin the unlock-agent socket into this vault's tempdir so tests never
        // collide with each other's agents (or a real one on the dev box). This
        // takes precedence over $XDG_RUNTIME_DIR in path resolution.
        c.env("JINGLE_AGENT_SOCK", self.agent_sock_path());
        c
    }

    /// The unlock-agent socket path this vault's commands use.
    pub fn agent_sock_path(&self) -> PathBuf {
        self.dir.path().join("agent").join("agent.sock")
    }

    pub fn keyfile_path(&self) -> PathBuf {
        self.dir.path().join("key")
    }

    pub fn vault_path(&self) -> PathBuf {
        self.dir.path().join("data").join("vault.jingle")
    }

    pub fn backup_path(&self) -> PathBuf {
        self.dir.path().join("data").join("vault.jingle.bak")
    }

    pub fn audit_path(&self) -> PathBuf {
        self.dir.path().join("data").join("audit.jsonl")
    }

    /// Create an entry whose password arrives via stdin (never argv).
    pub fn add_with_secret(&self, name: &str, secret: &str) {
        self.cmd()
            .args(["add", name, "--stdin"])
            .write_stdin(secret)
            .assert()
            .success();
    }

    /// Shell invocation that prints the value of env var `var` to stdout
    /// (which `jingle exec` passes through, so tests assert on captured
    /// stdout). Multi-arg on Windows: cmd.exe cannot parse the
    /// backslash-escaped quotes Rust's process spawning produces, so no
    /// single argument may contain spaces or quotes.
    pub fn echo_env_command(var: &str) -> Vec<String> {
        #[cfg(unix)]
        {
            vec!["sh".into(), "-c".into(), format!("printf %s \"${var}\"")]
        }
        #[cfg(windows)]
        {
            vec!["cmd".into(), "/C".into(), "echo".into(), format!("%{var}%")]
        }
    }
}
