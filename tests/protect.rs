//! End-to-end tests for the wrapped (v2) keyfile: migration, unlock, and the
//! hard v1 compatibility gate.
//!
//! The passphrase reaches jingle through `$JINGLE_PASSPHRASE_CMD` (its stdout),
//! which is the non-interactive intake path — the TTY echo-off path can't be
//! driven from a test. The command-based tests are Unix-only because they lean
//! on `sh`/`printf`; the format itself is exercised cross-platform by the unit
//! tests in `src/keywrap.rs`, and the v1 gate below runs everywhere.

mod common;

use std::path::{Path, PathBuf};

use common::TestVault;
use predicates::prelude::*;

/// The passphrase our test command emits (no trailing newline from `%s`).
#[cfg(unix)]
const PASS: &str = "printf %s correct-horse-battery-staple";
#[cfg(unix)]
const WRONG: &str = "printf %s not-the-passphrase";

fn with_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut os = p.as_os_str().to_os_string();
    os.push(suffix);
    os.into()
}

// ---- The hard compatibility gate (all platforms) --------------------------

#[test]
fn v1_keyfile_is_raw_32_bytes_and_needs_no_passphrase() {
    let tv = TestVault::new();
    tv.add_with_secret("gh", "s3cr3t");

    // No flag, no prompt, no env: every command just works.
    tv.cmd()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("gh"));

    let meta = std::fs::metadata(tv.keyfile_path()).unwrap();
    assert_eq!(meta.len(), 32, "v1 keyfile must stay a bare 32-byte key");
}

#[test]
fn doctor_reports_v1_and_warns_disk_access_is_total_compromise() {
    let tv = TestVault::new();
    let out = tv.cmd().arg("doctor").arg("--json").output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["keyfile_format"], serde_json::json!("v1"));
    let warnings = v["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("total compromise")),
        "expected a v1 total-compromise warning, got {warnings:?}"
    );

    // Human output names the format too.
    tv.cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("keyfile format: v1"));
}

// ---- Migration and unlock (Unix, via $JINGLE_PASSPHRASE_CMD) ---------------

#[cfg(unix)]
#[test]
fn protect_migrates_to_v2_keeps_a_backup_and_opens_with_passphrase() {
    let tv = TestVault::new();
    tv.add_with_secret("gh", "s3cr3t");

    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .arg("protect")
        .assert()
        .success()
        .stdout(predicate::str::contains("v1 → v2"));

    // The live keyfile is now a v2 wrapped image.
    let bytes = std::fs::read(tv.keyfile_path()).unwrap();
    assert!(bytes.len() > 32, "v2 keyfile is a header + sealed key");
    assert_eq!(&bytes[0..4], b"JKW1", "v2 magic");

    // The non-destructive backup is the original raw key, at 0600.
    let bak = with_suffix(&tv.keyfile_path(), ".v1.bak");
    assert!(bak.exists());
    assert_eq!(std::fs::metadata(&bak).unwrap().len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&bak).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "backup must be 0600");
    }

    // With the passphrase, the vault opens and the entry is intact.
    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .args(["show", "gh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("gh"));
}

#[cfg(unix)]
#[test]
fn v2_open_without_a_passphrase_source_fails_actionably() {
    let tv = TestVault::new();
    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .arg("protect")
        .assert()
        .success();

    // No passphrase source and no terminal: the error must name BOTH ways in.
    tv.cmd()
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::contains("JINGLE_PASSPHRASE_CMD"))
        .stderr(predicate::str::contains("terminal"));
}

#[cfg(unix)]
#[test]
fn wrong_passphrase_is_a_distinct_error_not_the_vault_tamper_error() {
    let tv = TestVault::new();
    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .arg("protect")
        .assert()
        .success();

    let assert = tv
        .cmd()
        .env("JINGLE_PASSPHRASE_CMD", WRONG)
        .arg("list")
        .assert()
        .failure()
        // Exit code 4 is the vault tamper code; a wrong passphrase must not use it.
        .code(predicate::ne(4));
    assert
        .stderr(predicate::str::contains("passphrase"))
        .stderr(predicate::str::contains("tamper").not());
}

#[cfg(unix)]
#[test]
fn unprotect_reverts_to_v1_and_needs_no_passphrase_afterward() {
    let tv = TestVault::new();
    tv.add_with_secret("gh", "s3cr3t");
    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .arg("protect")
        .assert()
        .success();

    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .arg("unprotect")
        .assert()
        .success()
        .stdout(predicate::str::contains("v2 → v1"));

    // Back to a raw 32-byte key.
    assert_eq!(std::fs::metadata(tv.keyfile_path()).unwrap().len(), 32);
    let v2bak = with_suffix(&tv.keyfile_path(), ".v2.bak");
    assert!(
        v2bak.exists(),
        "unprotect keeps the old wrapped key as backup"
    );

    // And the vault opens again with no passphrase at all, entry intact.
    tv.cmd()
        .args(["show", "gh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("gh"));
}

#[cfg(unix)]
#[test]
fn aborted_protect_leaves_the_v1_keyfile_untouched() {
    let tv = TestVault::new();
    tv.add_with_secret("gh", "s3cr3t");
    let original = std::fs::read(tv.keyfile_path()).unwrap();

    // Corrupt the vault so the verify-first "open the real vault" step fails.
    std::fs::write(tv.vault_path(), b"not a vault").unwrap();

    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .arg("protect")
        .assert()
        .failure();

    // The migration aborted: the live keyfile is byte-for-byte the original v1.
    let after = std::fs::read(tv.keyfile_path()).unwrap();
    assert_eq!(
        after, original,
        "aborted protect must not touch the keyfile"
    );
    assert_eq!(after.len(), 32);

    // No staged temp keyfile was left behind.
    let leftovers: Vec<_> = std::fs::read_dir(tv.keyfile_path().parent().unwrap())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".key-"))
        .collect();
    assert!(leftovers.is_empty(), "temp keyfile should be cleaned up");
}

#[cfg(unix)]
#[test]
fn doctor_reports_v2_after_protect_without_prompting() {
    let tv = TestVault::new();
    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .arg("protect")
        .assert()
        .success();

    // doctor inspects the header only — no passphrase env, no TTY, still fine.
    let out = tv.cmd().arg("doctor").arg("--json").output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["keyfile_format"], serde_json::json!("v2"));
    let warnings = v["warnings"].as_array().unwrap();
    assert!(
        !warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("total compromise")),
        "v2 must not carry the v1 total-compromise warning"
    );
}

#[cfg(unix)]
#[test]
fn a_failing_passphrase_command_reports_clearly() {
    let tv = TestVault::new();
    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .arg("protect")
        .assert()
        .success();

    // A command that exits non-zero must surface as a passphrase error, not a
    // hang and not the vault tamper error.
    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", "exit 3")
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::contains("JINGLE_PASSPHRASE_CMD"));
}
