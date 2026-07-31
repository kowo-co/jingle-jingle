mod common;

use common::TestVault;
use predicates::prelude::*;

#[test]
fn doctor_reports_posture_and_exits_zero() {
    let tv = TestVault::new();
    tv.cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("security posture"))
        .stdout(predicate::str::contains("keyfile"))
        .stdout(predicate::str::contains("vault"))
        .stdout(predicate::str::contains("audit log"))
        .stdout(predicate::str::contains("mlock"));
}

#[test]
fn doctor_json_is_wellformed_and_exits_zero() {
    let tv = TestVault::new();
    let out = tv.cmd().arg("doctor").arg("--json").output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v.get("dumpable").is_some());
    assert!(v.get("mlock").is_some());
    assert!(v.get("same_directory").is_some());
    assert!(v["keyfile"].get("mode").is_some());
    assert!(v["vault"].get("mode").is_some());
    assert!(v["audit"].get("mode").is_some());
    assert!(v.get("warnings").is_some());
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_reports_dumpable_disabled_on_linux() {
    let tv = TestVault::new();
    let out = tv.cmd().arg("doctor").arg("--json").output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    // PR_SET_DUMPABLE(0) runs at the top of main, so the live process is not
    // dumpable.
    assert_eq!(v["dumpable"]["value"], serde_json::json!(false));
}

// The default hermetic install keeps the keyfile and vault in separate
// directories, so doctor should not raise the same-directory warning.
#[test]
fn doctor_flags_separate_directories_as_ok() {
    let tv = TestVault::new();
    let out = tv.cmd().arg("doctor").arg("--json").output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["same_directory"], serde_json::json!(false));
}

#[cfg(unix)]
#[test]
fn doctor_warns_on_loose_vault_permissions_without_failing() {
    use std::os::unix::fs::PermissionsExt;
    let tv = TestVault::new();
    std::fs::set_permissions(tv.vault_path(), std::fs::Permissions::from_mode(0o644)).unwrap();

    let out = tv.cmd().arg("doctor").arg("--json").output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let warnings = v["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("vault")),
        "expected a vault warning, got {warnings:?}"
    );
    // A loose vault is a warning, never a hard failure: other commands still run.
    tv.cmd().arg("list").assert().success();
}
