//! `jingle doctor` — report the security posture so a human can answer
//! "is this actually locked down?".
//!
//! Purely informational: it stats files and queries process state, never reads
//! key material, and always exits 0. Anything weak is surfaced as a warning in
//! both human and `--json` output.

use std::path::Path;

use serde_json::json;

use crate::commands::Ctx;
use crate::harden::MlockState;
use crate::{Result, harden, perms};

/// Posture of one tracked file.
struct FilePosture {
    label: &'static str,
    path: String,
    exists: bool,
    mode: Option<u32>,
    /// Human-readable issues (empty == fine).
    issues: Vec<String>,
}

impl FilePosture {
    fn inspect(label: &'static str, path: &Path) -> Self {
        let mode = perms::file_mode(path);
        let exists = path.exists();
        let mut issues = Vec::new();
        if let Some(m) = mode {
            if perms::group_world_accessible(m) {
                issues.push(format!(
                    "group/world accessible (mode {m:o}); fix with: chmod 600 {}",
                    path.display()
                ));
            }
        }
        FilePosture {
            label,
            path: path.display().to_string(),
            exists,
            mode,
            issues,
        }
    }

    fn mode_str(&self) -> String {
        match self.mode {
            Some(m) => format!("{m:o}"),
            None if !self.exists => "-".into(),
            None => "n/a".into(),
        }
    }

    fn json(&self) -> serde_json::Value {
        json!({
            "path": self.path,
            "exists": self.exists,
            "mode": self.mode.map(|m| format!("{m:o}")),
            "issues": self.issues,
        })
    }
}

pub fn run(ctx: &Ctx) -> Result<()> {
    let keyfile = FilePosture::inspect("keyfile", &ctx.paths.keyfile);
    let vault = FilePosture::inspect("vault", &ctx.paths.vault);
    let audit = FilePosture::inspect("audit log", &ctx.paths.audit);

    // Keyfile parent directory: another user who can write it can swap the
    // keyfile out. `keyfile::load` treats this as a hard failure; here we just
    // report it.
    let key_dir = ctx
        .paths
        .keyfile
        .parent()
        .filter(|p| !p.as_os_str().is_empty());
    let key_dir_mode = key_dir.and_then(perms::file_mode);
    let key_dir_writable = key_dir_mode
        .map(perms::group_world_writable)
        .unwrap_or(false);

    let dumpable = harden::dumpable();
    let mlock = harden::probe_mlock();

    let same_dir = same_directory(&ctx.paths.keyfile, &ctx.paths.vault);

    // Collect warnings in the order a human should read them.
    let mut warnings: Vec<String> = Vec::new();
    for f in [&keyfile, &vault, &audit] {
        for issue in &f.issues {
            warnings.push(format!("{}: {issue}", f.label));
        }
    }
    if let (Some(dir), true) = (key_dir, key_dir_writable) {
        warnings.push(format!(
            "keyfile directory {} is group/world writable (mode {:o}); another user could replace the keyfile. fix with: chmod 700 {}",
            dir.display(),
            key_dir_mode.unwrap_or(0),
            dir.display()
        ));
    }
    if dumpable == Some(true) {
        warnings.push(
            "process is dumpable: a same-uid process could ptrace jingle and core dumps are allowed"
                .into(),
        );
    }
    if mlock == MlockState::Failed {
        warnings.push(
            "mlock unavailable (RLIMIT_MEMLOCK too low); key pages may be swapped to disk — raise it with `ulimit -l unlimited`".into(),
        );
    }
    if same_dir {
        warnings.push(format!(
            "keyfile and vault share a directory ({}); a single `cp -r` of it copies both and is a total compromise — keep the keyfile on separate storage",
            ctx.paths
                .keyfile
                .parent()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        ));
    }

    if ctx.json {
        println!(
            "{}",
            json!({
                "dumpable": {
                    "supported": dumpable.is_some(),
                    "value": dumpable,
                },
                "mlock": mlock.as_str(),
                "same_directory": same_dir,
                "keyfile": keyfile.json(),
                "keyfile_dir": {
                    "path": key_dir.map(|p| p.display().to_string()),
                    "mode": key_dir_mode.map(|m| format!("{m:o}")),
                    "group_world_writable": key_dir_writable,
                },
                "vault": vault.json(),
                "audit": audit.json(),
                "warnings": warnings,
            })
        );
        return Ok(());
    }

    println!("jingle security posture");
    println!();
    print_file(&keyfile);
    print_file(&vault);
    print_file(&audit);
    println!();
    println!(
        "  core dumps / same-uid ptrace: {}",
        match dumpable {
            Some(false) => "disabled (good)".to_string(),
            Some(true) => "ENABLED — process is dumpable".to_string(),
            None => "n/a (non-Linux)".to_string(),
        }
    );
    println!(
        "  key pages locked into RAM (mlock): {}",
        match mlock {
            MlockState::Locked => "available (good)".to_string(),
            MlockState::Failed => "UNAVAILABLE — RLIMIT_MEMLOCK too low".to_string(),
            MlockState::Unsupported => "unsupported on this platform".to_string(),
        }
    );
    println!(
        "  keyfile & vault directory: {}",
        if same_dir {
            "SHARED — key and vault sit together".to_string()
        } else {
            "separate (good)".to_string()
        }
    );

    println!();
    if warnings.is_empty() {
        println!("No issues found.");
    } else {
        println!("{} warning(s):", warnings.len());
        for w in &warnings {
            eprintln!("jingle: warning: {w}");
        }
    }
    Ok(())
}

fn print_file(f: &FilePosture) {
    let status = if !f.exists {
        "(missing)"
    } else if f.issues.is_empty() {
        "ok"
    } else {
        "WEAK"
    };
    println!(
        "  {:<10} mode {:<5} {}  {}",
        f.label,
        f.mode_str(),
        status,
        f.path
    );
}

/// Do the keyfile and vault live in the same directory? Compares canonical
/// parent paths, falling back to a lexical parent comparison when a path does
/// not yet exist.
fn same_directory(keyfile: &Path, vault: &Path) -> bool {
    let kp = keyfile.parent();
    let vp = vault.parent();
    match (kp, vp) {
        (Some(a), Some(b)) => {
            let ca = std::fs::canonicalize(a).ok();
            let cb = std::fs::canonicalize(b).ok();
            match (ca, cb) {
                (Some(x), Some(y)) => x == y,
                _ => a == b,
            }
        }
        _ => false,
    }
}
