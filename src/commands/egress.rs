//! Secret egress: `exec` (env injection), `copy` (clipboard), `totp`.
//! Every access — granted or refused — is written to the audit log.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};

use serde_json::json;
use sha2::{Digest, Sha256};

use crate::commands::Ctx;
use crate::model::Entry;
use crate::{Error, Result, output, redact, totp as totp_mod};

/// Env var used to hand the expected-value hash to the detached
/// `__clear-clipboard` helper. An env var (not argv) because /proc/pid/cmdline
/// is world-readable on Linux while environ is same-user only.
pub const CLEAR_HASH_ENV: &str = "JINGLE_CLEAR_HASH";

struct Mapping {
    entry: String,
    field: String,
    env_var: String,
}

fn parse_mapping(spec: &str) -> Result<Mapping> {
    let (reference, env_var) = spec.split_once('=').ok_or_else(|| {
        Error::Usage(format!(
            "invalid --secret '{}': expected REF=ENVVAR (e.g. github=GH_PASS or github:api_key=GH_KEY)",
            redact::sanitize(spec)
        ))
    })?;
    let (entry, field) = match reference.split_once(':') {
        Some((e, f)) => (e, f),
        None => (reference, "password"),
    };
    if entry.is_empty() || field.is_empty() {
        return Err(Error::Usage(format!(
            "invalid --secret '{}': empty entry or field",
            redact::sanitize(spec)
        )));
    }
    let valid_env = !env_var.is_empty()
        && !env_var.as_bytes()[0].is_ascii_digit()
        && env_var
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if !valid_env {
        return Err(Error::Usage(format!(
            "invalid environment variable name '{}': use [A-Z_][A-Z0-9_]*",
            redact::sanitize(env_var)
        )));
    }
    Ok(Mapping {
        entry: entry.to_owned(),
        field: field.to_owned(),
        env_var: env_var.to_owned(),
    })
}

/// Locked-entry gate. `--confirm-locked` must repeat the exact (case-sensitive)
/// entry name: deliberate friction that an injected "run it again with the
/// bypass flag" instruction has to reproduce precisely, and which always
/// leaves an audit trail (the refusal is recorded by the caller).
fn check_locked(entry: &Entry, confirm_locked: &[String]) -> Result<()> {
    if entry.locked && !confirm_locked.iter().any(|n| n == &entry.name) {
        return Err(Error::Locked(redact::sanitize(&entry.name)));
    }
    Ok(())
}

fn warn_burst(fired: Option<usize>) {
    if let Some(n) = fired {
        eprintln!(
            "jingle: WARNING: secrets from {n} distinct entries were accessed within the last 60s — \
if you did not intend a bulk access, inspect `jingle audit` (possible prompt-injection/exfiltration)"
        );
    }
}

/// Audit a refused/failed egress attempt, then return the error.
fn audited_failure(ctx: &Ctx, entry: Option<&str>, field: Option<&str>, err: Error) -> Error {
    let _ = ctx
        .audit()
        .append(ctx.cmd_label, entry, field, err.audit_outcome(), None);
    err
}

/// Placeholder written to the caller's stream in place of a leaked secret.
const REDACTION: &[u8] = b"[REDACTED by jingle]";

/// Secrets shorter than this are never watched for on the child's output.
///
/// A short value (a 4-digit PIN, a 6-character password) collides with
/// ordinary output constantly — the bytes "1234" or "hunter" appear in logs,
/// hashes, and prose all the time. Guarding such a value would splice
/// `[REDACTED by jingle]` into unrelated output far more often than it would
/// catch a real leak, corrupting the stream for no security gain. Eight bytes
/// is the floor below which false positives dominate; above it a match is
/// overwhelmingly likely to be the injected credential itself.
const MIN_SCAN_LEN: usize = 8;

pub fn exec(
    ctx: &Ctx,
    specs: &[String],
    confirm_locked: &[String],
    no_inherit_env: bool,
    allow_overwrite: bool,
    no_leak_guard: bool,
    command: &[OsString],
) -> Result<i32> {
    let mappings: Vec<Mapping> = specs
        .iter()
        .map(|s| parse_mapping(s))
        .collect::<Result<_>>()?;

    {
        let mut seen = std::collections::BTreeSet::new();
        for m in &mappings {
            if !seen.insert(&m.env_var) {
                return Err(Error::Usage(format!(
                    "environment variable {} is mapped more than once",
                    m.env_var
                )));
            }
        }
    }

    let vault = ctx.load_vault()?;

    // Resolve and authorize every mapping BEFORE building the child env, so a
    // refusal never launches a partially injected process.
    let mut resolved: Vec<(&Mapping, &Entry)> = Vec::with_capacity(mappings.len());
    for m in &mappings {
        let entry = vault
            .find(&m.entry)
            .map_err(|e| audited_failure(ctx, Some(&m.entry), Some(&m.field), e))?;
        check_locked(entry, confirm_locked)
            .map_err(|e| audited_failure(ctx, Some(&m.entry), Some(&m.field), e))?;
        entry
            .secret(&m.field)
            .map_err(|e| audited_failure(ctx, Some(&m.entry), Some(&m.field), e))?;
        resolved.push((m, entry));
    }

    // Child env: parent env minus every JINGLE_* variable (so the child can't
    // discover the keyfile/vault location), or a minimal env with
    // --no-inherit-env; then the requested mappings.
    let mut env: BTreeMap<OsString, OsString> = BTreeMap::new();
    if no_inherit_env {
        for keep in ["PATH", "HOME", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT"] {
            if let Some(v) = std::env::var_os(keep) {
                env.insert(keep.into(), v);
            }
        }
    } else {
        for (k, v) in std::env::vars_os() {
            let name = k.to_string_lossy();
            if name.starts_with("JINGLE_") {
                continue;
            }
            env.insert(k, v);
        }
    }

    for (m, entry) in &resolved {
        let var: OsString = m.env_var.clone().into();
        if env.contains_key(&var) && !allow_overwrite {
            return Err(Error::Usage(format!(
                "environment variable {} already exists; pass --allow-overwrite to replace it",
                m.env_var
            )));
        }
        env.insert(var, entry.secret(&m.field)?.expose().into());
    }

    // Record each grant. Done before spawn: the access decision is made.
    for (m, entry) in &resolved {
        let fired = ctx
            .audit()
            .record_egress("exec", &entry.name, Some(&m.field), entry.locked)?;
        warn_burst(fired);
    }

    let program = &command[0];

    // Build the leak-tripwire watch-list: every injected value long enough to
    // scan safely (see MIN_SCAN_LEN). If the guard is disabled, or nothing is
    // long enough to watch, take the transparent inherit-stdio path — identical
    // TTY, interleaving, and exit-code behaviour to a bare exec.
    let watched: Vec<Watched> = if no_leak_guard {
        Vec::new()
    } else {
        resolved
            .iter()
            .filter_map(|(m, entry)| {
                let value = entry.secret(&m.field).ok()?.expose().as_bytes().to_vec();
                if value.len() < MIN_SCAN_LEN {
                    None
                } else {
                    Some(Watched {
                        value,
                        entry: entry.name.clone(),
                        field: m.field.clone(),
                    })
                }
            })
            .collect()
    };

    if watched.is_empty() {
        let status = Command::new(program)
            .args(&command[1..])
            .env_clear()
            .envs(&env)
            .status()
            .map_err(|e| {
                Error::Other(format!("failed to run {}: {e}", program.to_string_lossy()))
            })?;
        return Ok(exit_code_of(status));
    }

    // Guarded path: pipe the child's stdout/stderr through a streaming redactor
    // and only then hand the (redacted) bytes to the real streams. stdin stays
    // inherited so interactive input still works.
    let max_len = watched.iter().map(|w| w.value.len()).max().unwrap_or(0);

    let mut child = Command::new(program)
        .args(&command[1..])
        .env_clear()
        .envs(&env)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Other(format!("failed to run {}: {e}", program.to_string_lossy())))?;

    let child_out = child.stdout.take().expect("child stdout was piped");
    let child_err = child.stderr.take().expect("child stderr was piped");

    // Drain both streams concurrently so a chatty child can't deadlock by
    // filling one pipe while we block on the other.
    let (out_res, err_res) = std::thread::scope(|s| {
        let err_handle = s.spawn(|| pump(child_err, io::stderr(), &watched, max_len));
        let out_res = pump(child_out, io::stdout(), &watched, max_len);
        let err_res = err_handle.join().expect("stderr redaction thread panicked");
        (out_res, err_res)
    });
    let out_leaks = out_res.map_err(|e| Error::Other(format!("streaming child stdout: {e}")))?;
    let err_leaks = err_res.map_err(|e| Error::Other(format!("streaming child stderr: {e}")))?;

    let status = child
        .wait()
        .map_err(|e| Error::Other(format!("waiting on {}: {e}", program.to_string_lossy())))?;

    report_leaks(ctx, &watched, &out_leaks, "stdout");
    report_leaks(ctx, &watched, &err_leaks, "stderr");

    Ok(exit_code_of(status))
}

/// One injected secret value to watch for on the child's output, plus the
/// names to report (never the value) if it leaks.
struct Watched {
    value: Vec<u8>,
    entry: String,
    field: String,
}

/// Streaming redactor: feed it output chunks and it emits the same bytes with
/// every occurrence of a watched value replaced by [REDACTION], remembering
/// which values it saw. It buffers a small tail between chunks so a value
/// straddling a read boundary is still caught.
struct Redactor<'a> {
    watched: &'a [Watched],
    /// Bytes not yet safe to emit: a secret could still complete inside them
    /// once the next chunk arrives.
    buf: Vec<u8>,
    /// Length of the longest watched value; sets the retained-tail size.
    max_len: usize,
    /// Indices into `watched` that were matched at least once.
    leaked: BTreeSet<usize>,
}

impl<'a> Redactor<'a> {
    fn new(watched: &'a [Watched], max_len: usize) -> Self {
        Redactor {
            watched,
            buf: Vec::new(),
            max_len,
            leaked: BTreeSet::new(),
        }
    }

    /// Feed one chunk. Emits every byte that cannot be part of a value
    /// straddling into the next chunk, retaining a tail of `max_len - 1` bytes.
    fn feed<W: Write>(&mut self, chunk: &[u8], out: &mut W) -> io::Result<()> {
        self.buf.extend_from_slice(chunk);
        let keep = self.max_len.saturating_sub(1);
        if self.buf.len() > keep {
            let limit = self.buf.len() - keep;
            self.emit(limit, out)?;
        }
        Ok(())
    }

    /// Flush everything still buffered. Call once at EOF.
    fn finish<W: Write>(&mut self, out: &mut W) -> io::Result<()> {
        let limit = self.buf.len();
        self.emit(limit, out)
    }

    /// Redact and emit every value whose match *starts* in `buf[..limit]`, then
    /// drop the consumed prefix. A match may run past `limit` into the retained
    /// tail; the whole matched span is consumed. Because any start position
    /// below `limit` is at least `max_len` bytes from the buffer's end, every
    /// such match is fully present — no match is ever emitted half-redacted.
    fn emit<W: Write>(&mut self, limit: usize, out: &mut W) -> io::Result<()> {
        let mut pos = 0;
        while pos < limit {
            match self.next_match(pos, limit) {
                Some((start, idx, len)) => {
                    out.write_all(&self.buf[pos..start])?;
                    out.write_all(REDACTION)?;
                    self.leaked.insert(idx);
                    pos = start + len;
                }
                None => {
                    out.write_all(&self.buf[pos..limit])?;
                    pos = limit;
                }
            }
        }
        self.buf.drain(..pos);
        Ok(())
    }

    /// The earliest watched value whose match starts in `[from, limit)`. Ties
    /// prefer the longest value so overlapping/nested secrets redact fully.
    fn next_match(&self, from: usize, limit: usize) -> Option<(usize, usize, usize)> {
        let mut best: Option<(usize, usize, usize)> = None;
        for (idx, w) in self.watched.iter().enumerate() {
            let Some(rel) = find(&self.buf[from..], &w.value) else {
                continue;
            };
            let start = from + rel;
            if start >= limit {
                continue;
            }
            let better = match best {
                None => true,
                Some((bstart, _, blen)) => {
                    start < bstart || (start == bstart && w.value.len() > blen)
                }
            };
            if better {
                best = Some((start, idx, w.value.len()));
            }
        }
        best
    }
}

/// First index of `needle` within `haystack` (naive; needles are short).
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Copy `src` to `dst`, redacting watched values as they stream past. Returns
/// the set of watched indices that leaked.
fn pump<R: Read, W: Write>(
    mut src: R,
    mut dst: W,
    watched: &[Watched],
    max_len: usize,
) -> io::Result<BTreeSet<usize>> {
    let mut red = Redactor::new(watched, max_len);
    let mut chunk = [0u8; 8192];
    loop {
        let n = src.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        red.feed(&chunk[..n], &mut dst)?;
        dst.flush()?;
    }
    red.finish(&mut dst)?;
    dst.flush()?;
    Ok(red.leaked)
}

/// For each watched value that appeared on `stream`, warn once on stderr
/// (naming entry:field and the stream, never the value) and append one audit
/// record with the `leaked` outcome so `jingle audit` surfaces it.
fn report_leaks(ctx: &Ctx, watched: &[Watched], leaks: &BTreeSet<usize>, stream: &str) {
    for &idx in leaks {
        let w = &watched[idx];
        eprintln!(
            "jingle: WARNING: secret {}:{} leaked to child {stream} and was replaced with \
'[REDACTED by jingle]' before reaching your terminal — the child printed an injected \
credential; treat it as compromised, rotate it, and inspect `jingle audit`",
            redact::sanitize(&w.entry),
            redact::sanitize(&w.field),
        );
        let _ = ctx
            .audit()
            .append("exec", Some(&w.entry), Some(&w.field), "leaked", None);
    }
}

#[cfg(unix)]
fn exit_code_of(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
}

#[cfg(not(unix))]
fn exit_code_of(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

pub fn copy(
    ctx: &Ctx,
    name: &str,
    field: &str,
    clear_after: u64,
    confirm_locked: &[String],
) -> Result<()> {
    let vault = ctx.load_vault()?;
    let entry = vault
        .find(name)
        .map_err(|e| audited_failure(ctx, Some(name), Some(field), e))?;
    check_locked(entry, confirm_locked)
        .map_err(|e| audited_failure(ctx, Some(name), Some(field), e))?;
    let secret = entry
        .secret(field)
        .map_err(|e| audited_failure(ctx, Some(name), Some(field), e))?;

    let mut clipboard = arboard::Clipboard::new().map_err(|e| Error::Clipboard(e.to_string()))?;
    clipboard
        .set_text(secret.expose().to_owned())
        .map_err(|e| Error::Clipboard(e.to_string()))?;

    let fired = ctx
        .audit()
        .record_egress("copy", &entry.name, Some(field), entry.locked)?;
    warn_burst(fired);

    let mut cleared_note = String::from("auto-clear disabled");
    if clear_after > 0 {
        match spawn_clear_helper(secret.expose(), clear_after) {
            Ok(()) => cleared_note = format!("clears in {clear_after}s"),
            Err(e) => {
                eprintln!("jingle: warning: could not schedule clipboard auto-clear: {e}");
                cleared_note = "auto-clear FAILED to schedule".into();
            }
        }
    }

    let display_name = redact::sanitize(&entry.name);
    output::ok(
        ctx.json,
        ctx.quiet,
        &format!("Copied {field} of '{display_name}' to the clipboard ({cleared_note})"),
        json!({
            "name": display_name,
            "field": field,
            "clear_after": if clear_after > 0 { Some(clear_after) } else { None },
        }),
    );
    Ok(())
}

/// Re-launch ourselves detached; the helper clears the clipboard only if it
/// still holds the value we set (compared by SHA-256 carried in the env).
fn spawn_clear_helper(secret: &str, after: u64) -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    let hash: String = Sha256::digest(secret.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut cmd = Command::new(exe);
    cmd.arg("__clear-clipboard")
        .arg("--after")
        .arg(after.to_string())
        .env(CLEAR_HASH_ENV, hash)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS | CREATE_NO_WINDOW
        cmd.creation_flags(0x0000_0008 | 0x0800_0000);
    }
    cmd.spawn()?;
    Ok(())
}

/// The hidden helper: sleep, then clear the clipboard iff it still holds the
/// value whose hash we were given.
pub fn clear_clipboard(after: u64) -> Result<()> {
    let expected = std::env::var(CLEAR_HASH_ENV)
        .map_err(|_| Error::Usage("missing clear-hash environment".into()))?;
    std::thread::sleep(std::time::Duration::from_secs(after));
    let mut clipboard = arboard::Clipboard::new().map_err(|e| Error::Clipboard(e.to_string()))?;
    let current = clipboard.get_text().unwrap_or_default();
    let current_hash: String = Sha256::digest(current.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if current_hash == expected {
        clipboard
            .clear()
            .map_err(|e| Error::Clipboard(e.to_string()))?;
        // On X11 the clipboard lives in the setting process; give the owner
        // change a moment to propagate before exiting.
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Ok(())
}

pub fn totp(ctx: &Ctx, name: &str, confirm_locked: &[String]) -> Result<()> {
    let vault = ctx.load_vault()?;
    let entry = vault
        .find(name)
        .map_err(|e| audited_failure(ctx, Some(name), Some("totp"), e))?;
    check_locked(entry, confirm_locked)
        .map_err(|e| audited_failure(ctx, Some(name), Some("totp"), e))?;
    let seed = entry
        .secret("totp")
        .map_err(|e| audited_failure(ctx, Some(name), Some("totp"), e))?;

    let (code, remaining) = totp_mod::code_now(seed)?;

    let fired = ctx
        .audit()
        .record_egress("totp", &entry.name, Some("totp"), entry.locked)?;
    warn_burst(fired);

    // Sanctioned egress: the code is dead in <=30 seconds; the seed never prints.
    if ctx.json {
        println!("{}", json!({ "code": code, "expires_in": remaining }));
    } else {
        println!("{code} ({remaining}s remaining)");
    }
    Ok(())
}

#[cfg(test)]
mod redactor_tests {
    use super::*;

    fn watch(values: &[&str]) -> Vec<Watched> {
        values
            .iter()
            .map(|v| Watched {
                value: v.as_bytes().to_vec(),
                entry: "e".into(),
                field: "password".into(),
            })
            .collect()
    }

    /// Stream `input` through the redactor `chunk` bytes at a time.
    fn run(watched: &[Watched], input: &[u8], chunk: usize) -> (Vec<u8>, BTreeSet<usize>) {
        let max_len = watched.iter().map(|w| w.value.len()).max().unwrap();
        let mut red = Redactor::new(watched, max_len);
        let mut out = Vec::new();
        for c in input.chunks(chunk) {
            red.feed(c, &mut out).unwrap();
        }
        red.finish(&mut out).unwrap();
        let leaked = red.leaked.clone();
        (out, leaked)
    }

    #[test]
    fn redacts_a_whole_secret() {
        let w = watch(&["supersecretvalue"]);
        let (out, leaked) = run(&w, b"before-supersecretvalue-after", 64);
        assert_eq!(out, b"before-[REDACTED by jingle]-after");
        assert!(leaked.contains(&0));
    }

    #[test]
    fn catches_secret_split_across_chunks() {
        // One byte at a time is the worst-case boundary split: the secret is
        // never present in any single feed.
        let w = watch(&["supersecretvalue"]);
        let (out, leaked) = run(&w, b"before-supersecretvalue-after", 1);
        assert_eq!(out, b"before-[REDACTED by jingle]-after");
        assert!(leaked.contains(&0));
    }

    #[test]
    fn clean_output_is_passed_through_untouched() {
        let w = watch(&["supersecretvalue"]);
        let input = b"totally clean output, nothing to redact here at all";
        let (out, leaked) = run(&w, input, 4);
        assert_eq!(out, input);
        assert!(leaked.is_empty());
    }

    #[test]
    fn redacts_every_occurrence() {
        let w = watch(&["TOKEN1234567"]);
        let (out, leaked) = run(&w, b"x TOKEN1234567 y TOKEN1234567 z", 3);
        assert_eq!(out, b"x [REDACTED by jingle] y [REDACTED by jingle] z");
        assert!(leaked.contains(&0));
    }

    #[test]
    fn tracks_which_of_several_secrets_leaked() {
        let w = watch(&["first-secret-aaa", "second-secret-bb"]);
        let (out, leaked) = run(&w, b"only second-secret-bb shows", 5);
        assert_eq!(out, b"only [REDACTED by jingle] shows");
        assert!(!leaked.contains(&0));
        assert!(leaked.contains(&1));
    }
}
