//! End-to-end tests for the unlock agent: `jingle unlock` / `jingle lock` /
//! `jingle unlock --status`, and the key-resolution order they enable.
//!
//! All of these are Unix-only: the agent is a unix-socket daemon, and the
//! passphrase reaches `jingle unlock` through `$JINGLE_PASSPHRASE_CMD` (the
//! non-interactive intake path — the TTY echo-off path can't be driven from a
//! test). The socket is pinned into each vault's tempdir by the common harness
//! (`JINGLE_AGENT_SOCK`), so these tests are hermetic and never touch a real
//! agent on the box.

#![cfg(unix)]

mod common;

use std::time::{Duration, Instant};

use common::TestVault;
use predicates::prelude::*;

const PASS: &str = "printf %s correct-horse-battery-staple";
const SECRET: &str = "sup3r-s3cret-value";

/// A vault with one entry, migrated to a wrapped (v2) keyfile.
fn protected_vault() -> TestVault {
    let tv = TestVault::new();
    tv.add_with_secret("github", SECRET);
    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .arg("protect")
        .assert()
        .success();
    tv
}

/// The pid of the live agent, via `unlock --status --json`.
fn agent_pid(tv: &TestVault) -> Option<u64> {
    let out = tv
        .cmd()
        .args(["unlock", "--status", "--json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    if v["live"].as_bool() == Some(true) {
        v["pid"].as_u64()
    } else {
        None
    }
}

// ---- unlock then exec needs no passphrase ---------------------------------

#[test]
fn unlock_then_exec_needs_no_passphrase() {
    let tv = protected_vault();

    // Unlock once (the passphrase is supplied here, and only here).
    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .arg("unlock")
        .assert()
        .success()
        .stdout(predicate::str::contains("unlocked"));

    // Now exec with NO passphrase source at all: the agent serves the key.
    let shell = TestVault::echo_env_command("GH_PASS");
    let mut cmd = tv.cmd();
    cmd.env_remove("JINGLE_PASSPHRASE_CMD");
    cmd.args(["exec", "--no-leak-guard", "-s", "github=GH_PASS", "--"]);
    cmd.args(&shell);
    let out = cmd.assert().success().get_output().clone();
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), SECRET);

    // A second call still needs no passphrase — the agent persists.
    tv.cmd()
        .args(["show", "github"])
        .assert()
        .success()
        .stdout(predicate::str::contains("github"));

    // Tidy up so the detached agent doesn't linger past the test.
    tv.cmd().arg("lock").assert().success();
}

// ---- lock then exec fails with the actionable message ---------------------

#[test]
fn lock_then_exec_fails_naming_jingle_unlock() {
    let tv = protected_vault();
    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .arg("unlock")
        .assert()
        .success();

    // Lock it: the agent is gone.
    tv.cmd()
        .arg("lock")
        .assert()
        .success()
        .stdout(predicate::str::contains("locked"));

    // With no agent, no passphrase command, and no TTY, the error must name the
    // fix: `jingle unlock`.
    tv.cmd()
        .env_remove("JINGLE_PASSPHRASE_CMD")
        .args(["show", "github"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("jingle unlock"));
}

// ---- status reporting ------------------------------------------------------

#[test]
fn status_reports_live_then_not_running() {
    let tv = protected_vault();

    // Before unlocking: not running.
    tv.cmd()
        .args(["unlock", "--status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("not running"));

    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .args(["unlock", "--ttl", "8h"])
        .assert()
        .success();

    // Live, with a remaining TTL under the 8h ceiling.
    let out = tv
        .cmd()
        .args(["unlock", "--status", "--json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["live"], serde_json::json!(true));
    let remaining = v["remaining_secs"].as_u64().unwrap();
    assert!(
        remaining > 0 && remaining <= 8 * 3600,
        "remaining={remaining}"
    );
    assert!(v["pid"].as_u64().unwrap() > 0);

    // After locking: not running again.
    tv.cmd().arg("lock").assert().success();
    tv.cmd()
        .args(["unlock", "--status", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"live\":false"));
}

// ---- socket posture: 0600 inside a 0700 directory -------------------------

#[test]
fn socket_and_directory_have_tight_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let tv = protected_vault();
    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .arg("unlock")
        .assert()
        .success();

    let sock = tv.agent_sock_path();
    let dir = sock.parent().unwrap();

    // The socket is 0600 and its directory 0700. File permissions are defence
    // in depth behind the SO_PEERCRED check, but the two must agree: on a shared
    // box a wrong-uid peer is refused by the peer check regardless, and here we
    // confirm the bits never contradict it. (A true cross-uid connect can't be
    // driven in CI without a second uid.)
    let sock_mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(sock_mode, 0o600, "socket must be 0600");
    let dir_mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700, "socket directory must be 0700");

    tv.cmd().arg("lock").assert().success();
}

// ---- TTL expiry ------------------------------------------------------------

#[test]
fn agent_expires_after_ttl_and_removes_its_socket() {
    let tv = protected_vault();

    // A 2-second lifetime.
    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .args(["unlock", "--ttl", "2"])
        .assert()
        .success();
    assert!(tv.agent_sock_path().exists(), "socket exists while live");

    // Wait for expiry (poll so the test is not needlessly slow).
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(8) {
        if !tv.agent_sock_path().exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !tv.agent_sock_path().exists(),
        "expired agent must remove its socket"
    );

    // And with no agent and no passphrase source, egress now fails actionably.
    tv.cmd()
        .env_remove("JINGLE_PASSPHRASE_CMD")
        .args(["show", "github"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("jingle unlock"));
}

// ---- stale socket left by a dead agent ------------------------------------

#[test]
fn stale_socket_is_cleaned_up_not_hung_on() {
    let tv = protected_vault();
    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .args(["unlock", "--ttl", "8h"])
        .assert()
        .success();

    // Kill the agent hard (SIGKILL) so it cannot unlink its socket — exactly the
    // "agent died without cleanup" case. The socket file is left behind.
    let pid = agent_pid(&tv).expect("agent should be live");
    std::process::Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .status()
        .unwrap();
    // Give the kernel a moment to reap it.
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        tv.agent_sock_path().exists(),
        "a SIGKILLed agent leaves its socket behind"
    );

    // A command must NOT hang on the dead socket. With the passphrase command
    // available it falls straight through and succeeds; the stale socket is
    // removed on the way.
    let start = Instant::now();
    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .args(["show", "github"])
        .assert()
        .success();
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "must not block on a stale socket"
    );
    assert!(
        !tv.agent_sock_path().exists(),
        "the stale socket should have been removed"
    );
}

// ---- v1 passthrough: the agent is never involved --------------------------

#[test]
fn unlock_refuses_a_v1_keyfile() {
    let tv = TestVault::new(); // v1 by default
    tv.cmd()
        .arg("unlock")
        .assert()
        .failure()
        .stderr(predicate::str::contains("v1"));

    // No socket was created.
    assert!(!tv.agent_sock_path().exists());
}

#[test]
fn v1_vault_works_with_no_agent_and_no_passphrase() {
    let tv = TestVault::new();
    tv.add_with_secret("gh", "s3cr3t");

    // Every command just works — no agent, no prompt, exactly as today.
    tv.cmd()
        .args(["show", "gh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("gh"));

    // status still answers cleanly (there simply is no agent).
    tv.cmd()
        .args(["unlock", "--status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("not running"));
}

// ---- doctor reports agent state -------------------------------------------

#[test]
fn doctor_reports_agent_live_and_ttl() {
    let tv = protected_vault();
    tv.cmd()
        .env("JINGLE_PASSPHRASE_CMD", PASS)
        .args(["unlock", "--ttl", "8h"])
        .assert()
        .success();

    let out = tv.cmd().arg("doctor").arg("--json").output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["agent"]["live"], serde_json::json!(true));
    assert!(v["agent"]["remaining_secs"].as_u64().unwrap() > 0);

    // Human output names it too.
    tv.cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("unlock agent: live"));

    tv.cmd().arg("lock").assert().success();
    let out = tv.cmd().arg("doctor").arg("--json").output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["agent"]["live"], serde_json::json!(false));
}

// ---- entry lock/unlock still works (the NAME forms) -----------------------

#[test]
fn entry_lock_unlock_still_works_with_a_name() {
    let tv = TestVault::new();
    tv.add_with_secret("gh", "s3cr3t");

    // `lock <name>` locks the entry (not the vault).
    tv.cmd().args(["lock", "gh"]).assert().success();
    tv.cmd()
        .args(["show", "gh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[locked]").or(predicate::str::contains("locked")));

    // `unlock <name> --yes` unlocks the entry.
    tv.cmd().args(["unlock", "gh", "--yes"]).assert().success();

    // Mixing entry form with vault-only flags is a usage error.
    tv.cmd()
        .args(["unlock", "gh", "--ttl", "1h"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--ttl"));
}
