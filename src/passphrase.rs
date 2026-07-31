//! Passphrase intake for the wrapped (v2) keyfile.
//!
//! There are exactly two ways a passphrase enters jingle, and neither is argv
//! or a plain environment variable holding the secret:
//!
//!   1. **Interactive TTY** — prompted on the controlling terminal with echo
//!      disabled, so it never lands in shell history or a scrollback buffer.
//!   2. **`$JINGLE_PASSPHRASE_CMD`** — the *command* whose stdout is the
//!      passphrase. This is the non-interactive path: point it at a systemd
//!      credential, a hardware-token helper, a password-manager CLI — anything
//!      that sources the secret from somewhere an attacker who copied your home
//!      directory does not also have. (Pointing it at `cat ~/.passphrase` gains
//!      you nothing; the README says so plainly.)
//!
//! With neither available, a v2 keyfile fails with a message naming both paths.

use std::io::Read;

use zeroize::Zeroizing;

use crate::{Error, Result};

/// Environment variable naming a command whose stdout is the passphrase.
/// It holds a *command*, never the passphrase itself.
pub const ENV_PASSPHRASE_CMD: &str = "JINGLE_PASSPHRASE_CMD";

const NO_SOURCE_MSG: &str = "this keyfile is passphrase-protected (v2) but no passphrase source is available. \
Run `jingle unlock` once to hold the key in the unlock agent (then this and \
later commands need no passphrase), or run jingle from an interactive terminal \
so it can prompt you, or set JINGLE_PASSPHRASE_CMD to a command whose stdout is \
the passphrase (e.g. a systemd credential or a hardware-token helper).";

/// Acquire a passphrase. When `confirm` is set (creating a new wrapped keyfile)
/// the interactive path prompts twice and requires the entries to match; the
/// command path ignores it (a script cannot re-type).
pub fn acquire(confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(cmd) = passphrase_cmd() {
        return from_command(&cmd);
    }
    from_tty(confirm)
}

/// The value of `$JINGLE_PASSPHRASE_CMD`, if set and non-empty.
fn passphrase_cmd() -> Option<std::ffi::OsString> {
    match std::env::var_os(ENV_PASSPHRASE_CMD) {
        Some(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// Run `$JINGLE_PASSPHRASE_CMD` through the platform shell and take its stdout
/// as the passphrase (one trailing newline trimmed).
fn from_command(cmd: &std::ffi::OsStr) -> Result<Zeroizing<Vec<u8>>> {
    let mut command = shell_command(cmd);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());
    let out = command
        .output()
        .map_err(|e| Error::Passphrase(format!("failed to run {ENV_PASSPHRASE_CMD}: {e}")))?;
    if !out.status.success() {
        return Err(Error::Passphrase(format!(
            "{ENV_PASSPHRASE_CMD} exited with {} and produced no passphrase",
            out.status
        )));
    }
    let mut bytes = Zeroizing::new(out.stdout);
    trim_one_newline(&mut bytes);
    if bytes.is_empty() {
        return Err(Error::Passphrase(format!(
            "{ENV_PASSPHRASE_CMD} produced an empty passphrase"
        )));
    }
    crate::harden::mlock(bytes.as_ref());
    Ok(bytes)
}

#[cfg(unix)]
fn shell_command(cmd: &std::ffi::OsStr) -> std::process::Command {
    let mut c = std::process::Command::new("sh");
    c.arg("-c").arg(cmd);
    c
}

#[cfg(windows)]
fn shell_command(cmd: &std::ffi::OsStr) -> std::process::Command {
    let mut c = std::process::Command::new("cmd");
    c.arg("/C").arg(cmd);
    c
}

fn trim_one_newline(bytes: &mut Vec<u8>) {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
}

// ---- Interactive TTY path -------------------------------------------------

#[cfg(unix)]
fn from_tty(confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    use std::fs::OpenOptions;
    use std::io::IsTerminal;

    // If nothing on the standard streams is a terminal, there is no interactive
    // user to prompt: fail fast with the actionable message rather than blocking
    // on a /dev/tty read that would never be answered. (stderr being a terminal
    // is enough — that keeps `printf pw | jingle add x --stdin` promptable even
    // though its stdin is a pipe.)
    let interactive = std::io::stdin().is_terminal()
        || std::io::stdout().is_terminal()
        || std::io::stderr().is_terminal();
    if !interactive {
        return Err(Error::Passphrase(NO_SOURCE_MSG.into()));
    }

    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| Error::Passphrase(NO_SOURCE_MSG.into()))?;

    let first = read_line_noecho(&mut tty, "Passphrase: ")?;
    if first.is_empty() {
        return Err(Error::Passphrase("passphrase is empty".into()));
    }
    if confirm {
        let again = read_line_noecho(&mut tty, "Confirm passphrase: ")?;
        if again.as_slice() != first.as_slice() {
            return Err(Error::Passphrase("passphrases did not match".into()));
        }
    }
    crate::harden::mlock(first.as_ref());
    Ok(first)
}

/// Prompt on `tty` with terminal echo disabled and read one line (its trailing
/// newline stripped). Echo is always restored, including on error.
#[cfg(unix)]
fn read_line_noecho(tty: &mut std::fs::File, prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::Write;
    use std::os::unix::io::AsRawFd;

    write!(tty, "{prompt}")?;
    tty.flush()?;

    let fd = tty.as_raw_fd();
    // Disable ECHO for the duration of the read, remembering the prior state.
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    let have_termios = unsafe { libc::tcgetattr(fd, &mut term) } == 0;
    let saved = term;
    if have_termios {
        term.c_lflag &= !libc::ECHO;
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, &term);
        }
    }

    let result = read_line_bytes(tty);

    if have_termios {
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, &saved);
        }
    }
    // Echo was suppressed, so the user's Enter produced no visible newline.
    let _ = writeln!(tty);

    result
}

/// Read bytes up to (and discarding) the first newline. Byte-at-a-time so we
/// never pull more of the input stream than the one line we were asked for.
#[cfg(unix)]
fn read_line_bytes(tty: &mut std::fs::File) -> Result<Zeroizing<Vec<u8>>> {
    use zeroize::Zeroize;
    let mut buf = Zeroizing::new(Vec::with_capacity(64));
    let mut byte = [0u8; 1];
    loop {
        let n = tty.read(&mut byte)?;
        if n == 0 || byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    byte.zeroize();
    Ok(buf)
}

// Non-Unix interactive fallback: read from stdin. Terminal echo suppression is
// not implemented off-Unix; the operator should prefer $JINGLE_PASSPHRASE_CMD
// there. Still never touches argv or a plain env var.
#[cfg(not(unix))]
fn from_tty(confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::IsTerminal;
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return Err(Error::Passphrase(NO_SOURCE_MSG.into()));
    }
    let first = read_stdin_line("Passphrase: ")?;
    if first.is_empty() {
        return Err(Error::Passphrase("passphrase is empty".into()));
    }
    if confirm {
        let again = read_stdin_line("Confirm passphrase: ")?;
        if again.as_slice() != first.as_slice() {
            return Err(Error::Passphrase("passphrases did not match".into()));
        }
    }
    Ok(first)
}

#[cfg(not(unix))]
fn read_stdin_line(prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::Write;
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let mut bytes = Zeroizing::new(line.into_bytes());
    trim_one_newline(&mut bytes);
    Ok(bytes)
}
