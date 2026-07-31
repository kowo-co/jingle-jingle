mod common;

use common::TestVault;
use predicates::prelude::*;

#[test]
fn injects_secret_into_child_env() {
    let tv = TestVault::new();
    tv.add_with_secret("github", "sup3r-s3cret-value");
    let shell = TestVault::echo_env_command("GH_PASS");

    // Echoing the secret back is exactly what the leak guard redacts, so this
    // injection check runs with the guard off.
    let mut cmd = tv.cmd();
    cmd.args(["exec", "--no-leak-guard", "-s", "github=GH_PASS", "--"]);
    cmd.args(&shell);
    let out = cmd.assert().success().get_output().clone();
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim(),
        "sup3r-s3cret-value"
    );
}

#[test]
fn maps_specific_fields() {
    let tv = TestVault::new();
    tv.add_with_secret("acct", "the-password");
    tv.cmd()
        .args(["set", "acct", "api_key", "--stdin"])
        .write_stdin("the-api-key")
        .assert()
        .success();

    let shell = TestVault::echo_env_command("K");
    let mut cmd = tv.cmd();
    cmd.args(["exec", "--no-leak-guard", "-s", "acct:api_key=K", "--"]);
    cmd.args(&shell);
    let out = cmd.assert().success().get_output().clone();
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), "the-api-key");
}

#[cfg(unix)]
#[test]
fn scrubs_jingle_env_from_child() {
    let tv = TestVault::new();
    tv.add_with_secret("e", "s");
    let outfile = tv.dir.path().join("dump.txt");
    let mut cmd = tv.cmd();
    cmd.args(["exec", "-s", "e=SECRET", "--", "sh", "-c"]);
    cmd.arg(format!(
        "printf %s \"[$JINGLE_KEYFILE][$JINGLE_DATA_DIR]\" > \"{}\"",
        outfile.display()
    ));
    cmd.assert().success();
    assert_eq!(std::fs::read_to_string(&outfile).unwrap(), "[][]");
}

#[cfg(unix)]
#[test]
fn propagates_child_exit_code() {
    let tv = TestVault::new();
    tv.add_with_secret("e", "s");
    tv.cmd()
        .args(["exec", "-s", "e=S", "--", "sh", "-c", "exit 7"])
        .assert()
        .code(7);
}

#[test]
fn refuses_env_collision_without_allow_overwrite() {
    let tv = TestVault::new();
    tv.add_with_secret("e", "stored-collide-value");
    let shell = TestVault::echo_env_command("COLLIDE");

    let mut cmd = tv.cmd();
    cmd.env("COLLIDE", "pre-existing");
    cmd.args(["exec", "-s", "e=COLLIDE", "--"]);
    cmd.args(&shell);
    cmd.assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("--allow-overwrite"));

    let mut cmd = tv.cmd();
    cmd.env("COLLIDE", "pre-existing");
    cmd.args([
        "exec",
        "--no-leak-guard",
        "--allow-overwrite",
        "-s",
        "e=COLLIDE",
        "--",
    ]);
    cmd.args(&shell);
    let out = cmd.assert().success().get_output().clone();
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim(),
        "stored-collide-value"
    );
}

#[test]
fn locked_entries_refuse_and_confirm() {
    let tv = TestVault::new();
    tv.add_with_secret("prod", "prod-secret");
    tv.cmd().args(["lock", "prod"]).assert().success();

    let shell = TestVault::echo_env_command("P");

    let mut cmd = tv.cmd();
    cmd.args(["exec", "-s", "prod=P", "--"]);
    cmd.args(&shell);
    cmd.assert()
        .failure()
        .code(5)
        .stderr(predicate::str::contains("locked"))
        .stdout(predicate::str::contains("prod-secret").not()); // child must not run

    // Confirmation must repeat the exact name; a different name doesn't count.
    let mut cmd = tv.cmd();
    cmd.args(["exec", "--confirm-locked", "other", "-s", "prod=P", "--"]);
    cmd.args(&shell);
    cmd.assert()
        .failure()
        .code(5)
        .stdout(predicate::str::contains("prod-secret").not());

    let mut cmd = tv.cmd();
    cmd.args([
        "exec",
        "--no-leak-guard",
        "--confirm-locked",
        "prod",
        "-s",
        "prod=P",
        "--",
    ]);
    cmd.args(&shell);
    let out = cmd.assert().success().get_output().clone();
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), "prod-secret");
}

#[test]
fn unknown_entry_or_field_is_exit_3() {
    let tv = TestVault::new();
    tv.add_with_secret("known", "s");
    let shell = TestVault::echo_env_command("X");

    let mut cmd = tv.cmd();
    cmd.args(["exec", "-s", "missing=X", "--"]);
    cmd.args(&shell);
    cmd.assert().failure().code(3);

    let mut cmd = tv.cmd();
    cmd.args(["exec", "-s", "known:no_such_field=X", "--"]);
    cmd.args(&shell);
    cmd.assert().failure().code(3);
}

#[test]
fn bad_mapping_specs_are_usage_errors() {
    let tv = TestVault::new();
    tv.add_with_secret("e", "s");
    for bad in ["no-equals", "e=lower_case", "e=1STARTS_DIGIT", "=X", "e="] {
        let mut cmd = tv.cmd();
        cmd.args(["exec", "-s", bad, "--", "true"]);
        cmd.assert().failure().code(2);
    }
    // Duplicate env var target.
    let mut cmd = tv.cmd();
    cmd.args(["exec", "-s", "e=SAME", "-s", "e=SAME", "--", "true"]);
    cmd.assert().failure().code(2);
}

// ---- leak tripwire ----------------------------------------------------------

const LEAKY: &str = "sup3r-s3cret-value-xyz"; // 22 bytes, well over the 8-byte floor

#[cfg(unix)]
#[test]
fn leak_on_stdout_is_redacted_and_audited() {
    let tv = TestVault::new();
    tv.add_with_secret("github", LEAKY);

    let mut cmd = tv.cmd();
    cmd.args([
        "exec",
        "-s",
        "github=GH_PASS",
        "--",
        "sh",
        "-c",
        "printf %s \"$GH_PASS\"",
    ]);
    let out = cmd.assert().success().get_output().clone();

    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("[REDACTED by jingle]"),
        "stdout: {stdout:?}"
    );
    assert!(
        !stdout.contains(LEAKY),
        "secret leaked verbatim: {stdout:?}"
    );

    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("github:password"), "warning: {stderr:?}");
    assert!(
        stderr.contains("stdout"),
        "warning names stream: {stderr:?}"
    );
    assert!(!stderr.contains(LEAKY), "warning must not echo value");

    let audit = std::fs::read_to_string(tv.audit_path()).unwrap();
    assert!(audit.contains("\"outcome\":\"leaked\""), "audit: {audit}");
    assert!(!audit.contains(LEAKY), "audit must never hold the value");
}

#[cfg(unix)]
#[test]
fn leak_on_stderr_is_redacted_and_audited() {
    let tv = TestVault::new();
    tv.add_with_secret("github", LEAKY);

    let mut cmd = tv.cmd();
    cmd.args([
        "exec",
        "-s",
        "github=GH_PASS",
        "--",
        "sh",
        "-c",
        "printf %s \"$GH_PASS\" 1>&2",
    ]);
    let out = cmd.assert().success().get_output().clone();

    assert!(String::from_utf8(out.stdout).unwrap().is_empty());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("[REDACTED by jingle]"),
        "stderr: {stderr:?}"
    );
    assert!(
        !stderr.contains(LEAKY),
        "secret leaked verbatim: {stderr:?}"
    );
    assert!(
        stderr.contains("child stderr"),
        "warning names stream: {stderr:?}"
    );

    let audit = std::fs::read_to_string(tv.audit_path()).unwrap();
    assert!(audit.contains("\"outcome\":\"leaked\""), "audit: {audit}");
}

#[cfg(unix)]
#[test]
fn secret_split_across_read_chunks_is_still_caught() {
    // Print ~8190 filler bytes then the secret so the value straddles the
    // 8192-byte read boundary of the redactor's stream loop.
    let tv = TestVault::new();
    tv.add_with_secret("github", LEAKY);

    let mut cmd = tv.cmd();
    cmd.args([
        "exec",
        "-s",
        "github=GH_PASS",
        "--",
        "sh",
        "-c",
        "printf '%8190s' '' | tr ' ' A; printf %s \"$GH_PASS\"",
    ]);
    let out = cmd.assert().success().get_output().clone();

    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("[REDACTED by jingle]"),
        "boundary split missed"
    );
    assert!(!stdout.contains(LEAKY), "secret survived across the split");
    // All the filler bytes must pass through untouched around the redaction.
    assert!(
        stdout.matches('A').count() >= 8190,
        "filler must pass through"
    );
}

#[cfg(unix)]
#[test]
fn clean_output_has_no_warning_and_passes_through() {
    let tv = TestVault::new();
    tv.add_with_secret("github", LEAKY);

    let mut cmd = tv.cmd();
    cmd.args([
        "exec",
        "-s",
        "github=GH_PASS",
        "--",
        "sh",
        "-c",
        "printf %s hello-clean-world",
    ]);
    let out = cmd.assert().success().get_output().clone();

    assert_eq!(String::from_utf8(out.stdout).unwrap(), "hello-clean-world");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        !stderr.contains("[REDACTED by jingle]"),
        "false positive: {stderr:?}"
    );
    assert!(
        !stderr.contains("leaked"),
        "false positive warning: {stderr:?}"
    );

    let audit = std::fs::read_to_string(tv.audit_path()).unwrap();
    assert!(
        !audit.contains("\"outcome\":\"leaked\""),
        "false leak audit: {audit}"
    );
}

#[cfg(unix)]
#[test]
fn exit_code_passes_through_the_guard() {
    // Long-enough secret so the guarded (piped) path is exercised, and the
    // child never prints it — pure exit-code passthrough.
    let tv = TestVault::new();
    tv.add_with_secret("e", "long-enough-secret-123");
    tv.cmd()
        .args(["exec", "-s", "e=S", "--", "sh", "-c", "exit 7"])
        .assert()
        .code(7);
}

#[cfg(unix)]
#[test]
fn no_leak_guard_passes_the_secret_through_untouched() {
    let tv = TestVault::new();
    tv.add_with_secret("github", LEAKY);

    let mut cmd = tv.cmd();
    cmd.args([
        "exec",
        "--no-leak-guard",
        "-s",
        "github=GH_PASS",
        "--",
        "sh",
        "-c",
        "printf %s \"$GH_PASS\"",
    ]);
    let out = cmd.assert().success().get_output().clone();

    assert_eq!(String::from_utf8(out.stdout).unwrap(), LEAKY);
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(!stderr.contains("[REDACTED by jingle]"));
    let audit = std::fs::read_to_string(tv.audit_path()).unwrap();
    assert!(!audit.contains("\"outcome\":\"leaked\""));
}
