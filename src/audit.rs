//! Append-only audit log: one JSONL record per secret access, refusal, or
//! integrity event. Records are hash-chained (each carries the SHA-256 of the
//! previous line) so truncation or editing is tamper-evident. Records are
//! built from entry/field NAMES and outcomes only — secret values cannot
//! appear by construction.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{Error, Result};

pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Distinct-entry egress threshold for the burst tripwire.
pub const BURST_DISTINCT_ENTRIES: usize = 5;
pub const BURST_WINDOW_SECS: i64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts: String,
    pub cmd: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked: Option<bool>,
    pub prev: String,
}

pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: &Path) -> Self {
        AuditLog {
            path: path.to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a record, chaining it to the current last line.
    pub fn append(
        &self,
        cmd: &str,
        entry: Option<&str>,
        field: Option<&str>,
        outcome: &str,
        locked: Option<bool>,
    ) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        // A world-writable audit log lets the tamper-evidence trail be rewritten
        // in place. Warn (once) but keep appending — never break an upgrade.
        crate::perms::warn_if_loose(&self.path, "audit log");
        let prev = match last_line(&self.path)? {
            Some(line) => hash_line(&line),
            None => GENESIS_PREV.to_owned(),
        };
        let record = AuditRecord {
            ts: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_else(|_| "?".into()),
            cmd: cmd.to_owned(),
            entry: entry.map(crate::redact::sanitize),
            field: field.map(crate::redact::sanitize),
            outcome: outcome.to_owned(),
            locked,
            prev,
        };
        let mut line = serde_json::to_string(&record)?;
        line.push('\n');

        let mut opts = fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&self.path)?;
        f.write_all(line.as_bytes())?;
        f.flush()?;
        Ok(())
    }

    /// Record a secret egress and fire the burst tripwire if this access
    /// pushes the last 60 seconds over the distinct-entry threshold.
    /// Returns the set size if the tripwire fired.
    pub fn record_egress(
        &self,
        cmd: &str,
        entry: &str,
        field: Option<&str>,
        locked: bool,
    ) -> Result<Option<usize>> {
        self.append(cmd, Some(entry), field, "ok", Some(locked))?;
        let distinct = self.distinct_recent_egress()?;
        if distinct > BURST_DISTINCT_ENTRIES {
            self.append("tripwire", None, None, "burst_warning", None)?;
            return Ok(Some(distinct));
        }
        Ok(None)
    }

    fn distinct_recent_egress(&self) -> Result<usize> {
        let now = OffsetDateTime::now_utc();
        let mut names = std::collections::BTreeSet::new();
        for (_, rec) in self.read_records()?.into_iter().rev().take(500) {
            let Ok(ts) = OffsetDateTime::parse(&rec.ts, &Rfc3339) else {
                continue;
            };
            if (now - ts).whole_seconds() > BURST_WINDOW_SECS {
                break;
            }
            if rec.outcome == "ok"
                && matches!(
                    rec.cmd.as_str(),
                    "exec" | "copy" | "totp" | "generate-print"
                )
            {
                if let Some(name) = rec.entry {
                    names.insert(name);
                }
            }
        }
        Ok(names.len())
    }

    /// All (raw line, parsed record) pairs. Unparseable lines become chain
    /// breaks in `verify`, so they are surfaced rather than skipped silently.
    pub fn read_records(&self) -> Result<Vec<(String, AuditRecord)>> {
        let content = match fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let rec: AuditRecord = serde_json::from_str(line).unwrap_or(AuditRecord {
                ts: "?".into(),
                cmd: "?".into(),
                entry: None,
                field: None,
                outcome: "unparseable".into(),
                locked: None,
                prev: "?".into(),
            });
            out.push((line.to_owned(), rec));
        }
        Ok(out)
    }

    /// Verify the hash chain. Returns the 0-based indices of records whose
    /// `prev` doesn't match the hash of the preceding line.
    pub fn verify(&self) -> Result<Vec<usize>> {
        let records = self.read_records()?;
        let mut breaks = Vec::new();
        let mut expected = GENESIS_PREV.to_owned();
        for (i, (line, rec)) in records.iter().enumerate() {
            if rec.prev != expected {
                breaks.push(i);
            }
            expected = hash_line(line);
        }
        Ok(breaks)
    }
}

pub fn hash_line(line: &str) -> String {
    let digest = Sha256::digest(line.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Read the last non-empty line of a file without loading the whole file.
fn last_line(path: &Path) -> Result<Option<String>> {
    let mut f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let len = f.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    const TAIL: u64 = 64 * 1024;
    let start = len.saturating_sub(TAIL);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = String::new();
    f.read_to_string(&mut buf)?;
    Ok(buf
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .map(str::to_owned))
}

impl Error {
    /// Outcome string for audit records derived from an error.
    pub fn audit_outcome(&self) -> &'static str {
        match self {
            Error::NotFound(_) | Error::FieldNotFound { .. } => "not_found",
            Error::Tamper(_) => "tamper",
            Error::Locked(_) => "refused_locked",
            _ => "error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_verifies_and_detects_edits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::new(&path);
        log.append("exec", Some("gh"), Some("password"), "ok", Some(false))
            .unwrap();
        log.append("totp", Some("gh"), Some("totp"), "ok", Some(false))
            .unwrap();
        log.append("copy", Some("aws"), None, "refused_locked", Some(true))
            .unwrap();
        assert!(log.verify().unwrap().is_empty());

        // Delete the middle line -> break detected.
        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert_eq!(log.verify().unwrap(), vec![1]);
    }

    #[test]
    fn burst_tripwire_fires_on_distinct_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::new(&path);
        for i in 0..BURST_DISTINCT_ENTRIES {
            let fired = log
                .record_egress("exec", &format!("entry{i}"), Some("password"), false)
                .unwrap();
            assert!(fired.is_none(), "fired too early at {i}");
        }
        let fired = log
            .record_egress("exec", "one-too-many", Some("password"), false)
            .unwrap();
        assert_eq!(fired, Some(BURST_DISTINCT_ENTRIES + 1));
        // Repeated access to the SAME entry does not trip it further entries.
        let again = log
            .record_egress("exec", "one-too-many", Some("password"), false)
            .unwrap();
        assert!(again.is_some()); // still inside the window with 6 distinct
    }

    #[test]
    fn records_never_contain_unsanitized_control_chars() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::new(&path);
        log.append("exec", Some("evil\x1b[31m"), None, "ok", None)
            .unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(!content.contains('\x1b'));
    }
}
