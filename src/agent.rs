//! The unlock agent: an ssh-agent-shaped daemon that holds the unwrapped root
//! key in memory so a wrapped (v2) vault stays usable without a passphrase on
//! every call.
//!
//! `jingle unlock` prompts once, unwraps the v2 root key, then forks a detached
//! process (this module's [`spawn`]) that keeps the key in `mlock`'d memory and
//! serves it over a unix socket. Subsequent commands call [`try_fetch_key`],
//! which connects to that socket and receives the key — no prompt. The agent
//! expires after a TTL, at which point it zeroizes the key and unlinks its
//! socket; `jingle lock` ([`shutdown`]) ends it early.
//!
//! The model is deliberately copied from ssh-agent because its failure modes
//! are well understood:
//!
//!   * **Authorization is the peer check, not the file mode.** The socket is
//!     0600 inside a 0700 directory, but the server independently verifies the
//!     connecting peer's uid (`SO_PEERCRED` on Linux, `getpeereid` elsewhere)
//!     and refuses any uid that is not ours. If the bits and the peer check ever
//!     disagree, the peer check wins.
//!   * **Stale sockets never hang a caller.** A crashed agent leaves its socket
//!     file behind; a connect to it fails fast with `ECONNREFUSED`, and the
//!     client removes the dead file and falls through to the passphrase path
//!     rather than blocking.
//!   * **The key is never written anywhere.** It lives only in the agent's
//!     address space, which is marked non-dumpable (`PR_SET_DUMPABLE(0)`) and
//!     `mlock`'d off swap.
//!
//! Out of scope by design: no network transport, no agent forwarding, no
//! multi-user support. One socket, one uid, one key.

use std::time::Duration;

use crate::keyfile::KEY_LEN;

/// A live agent's state, reported by `jingle unlock --status` and `jingle
/// doctor`.
#[derive(Debug, Clone, Copy)]
pub struct Status {
    /// The agent process id.
    pub pid: u32,
    /// Time left before the agent expires and zeroizes the key.
    pub remaining: Duration,
}

// Wire protocol. A request is a single byte; a response is one status byte
// (`RESP_OK`) optionally followed by a fixed-size payload. Everything is
// framed by fixed lengths so a partial read can never be mistaken for success.
#[cfg(unix)]
const REQ_GET_KEY: u8 = 0x01;
#[cfg(unix)]
const REQ_STATUS: u8 = 0x02;
#[cfg(unix)]
const REQ_SHUTDOWN: u8 = 0x03;
#[cfg(unix)]
const RESP_OK: u8 = 0x00;

/// Clamp any requested TTL to a sane ceiling so `Instant + ttl` cannot overflow
/// and a fat-fingered `--ttl` cannot pin a key in memory for years.
pub const MAX_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60); // 30 days
/// Default agent lifetime when `--ttl` is not given.
pub const DEFAULT_TTL: Duration = Duration::from_secs(8 * 60 * 60); // 8 hours

// ===========================================================================
// Unix implementation
// ===========================================================================

#[cfg(unix)]
mod imp {
    use std::io::{self, ErrorKind, Read, Write};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;
    use std::time::{Duration, Instant};

    use zeroize::Zeroizing;

    use super::{
        DEFAULT_TTL, KEY_LEN, MAX_TTL, REQ_GET_KEY, REQ_SHUTDOWN, REQ_STATUS, RESP_OK, Status,
    };
    use crate::{Error, Result};

    const IO_TIMEOUT: Duration = Duration::from_secs(5);

    /// This process's real uid.
    fn our_uid() -> u32 {
        unsafe { libc::getuid() }
    }

    /// The uid of the process on the other end of `stream`, from the kernel —
    /// never from anything the peer sent us.
    #[cfg(target_os = "linux")]
    fn peer_uid(stream: &UnixStream) -> Option<u32> {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let r = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if r == 0 { Some(cred.uid) } else { None }
    }

    /// Non-Linux unixes (macOS, the BSDs) spell the same query `getpeereid`.
    #[cfg(not(target_os = "linux"))]
    fn peer_uid(stream: &UnixStream) -> Option<u32> {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let r = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
        if r == 0 { Some(uid) } else { None }
    }

    /// Connect to the agent socket, returning the stream only if a live agent
    /// owned by us answers. Any other outcome yields `None`:
    ///   * no socket file, or `ECONNREFUSED` (a stale socket from a dead agent) —
    ///     the stale file is unlinked so the next caller starts clean;
    ///   * a peer whose uid is not ours — refused, and left in place (not ours
    ///     to remove).
    ///
    /// A `None` return always means "no usable agent"; callers fall through to
    /// the passphrase path. It never blocks: `connect(2)` on a unix socket with
    /// no listener fails immediately, and every subsequent read/write carries a
    /// timeout.
    fn connect(sock: &Path) -> Option<UnixStream> {
        if !sock.exists() {
            return None;
        }
        match UnixStream::connect(sock) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                match peer_uid(&stream) {
                    Some(u) if u == our_uid() => Some(stream),
                    // A socket answered by another uid is not our agent. Do not
                    // trust it and do not delete it.
                    _ => None,
                }
            }
            // The file exists but nothing is listening: a dead agent left it
            // behind. Remove it so it stops shadowing future unlocks, and treat
            // it as "no agent".
            Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                let _ = std::fs::remove_file(sock);
                None
            }
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            // Anything else (e.g. the path is not a socket): don't hang, don't
            // guess — just fall through to the passphrase path.
            Err(_) => None,
        }
    }

    /// Ask a live agent for the root key. `Ok(None)` means no usable agent was
    /// reachable — the caller then tries `$JINGLE_PASSPHRASE_CMD`, a TTY prompt,
    /// and finally the actionable error. Any protocol/IO hiccup also degrades to
    /// `Ok(None)` so a wedged agent can never fail an otherwise-answerable call.
    pub fn try_fetch_key(sock: &Path) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>> {
        let Some(mut stream) = connect(sock) else {
            return Ok(None);
        };
        if stream.write_all(&[REQ_GET_KEY]).is_err() {
            return Ok(None);
        }
        let mut resp = [0u8; 1];
        if stream.read_exact(&mut resp).is_err() || resp[0] != RESP_OK {
            return Ok(None);
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        if stream.read_exact(key.as_mut()).is_err() {
            return Ok(None);
        }
        crate::harden::mlock(key.as_ref());
        Ok(Some(key))
    }

    /// Query a live agent's status, or `None` if none is running.
    pub fn status(sock: &Path) -> Result<Option<Status>> {
        let Some(mut stream) = connect(sock) else {
            return Ok(None);
        };
        if stream.write_all(&[REQ_STATUS]).is_err() {
            return Ok(None);
        }
        let mut resp = [0u8; 1];
        if stream.read_exact(&mut resp).is_err() || resp[0] != RESP_OK {
            return Ok(None);
        }
        let mut buf = [0u8; 12];
        if stream.read_exact(&mut buf).is_err() {
            return Ok(None);
        }
        let remaining = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let pid = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        Ok(Some(Status {
            pid,
            remaining: Duration::from_secs(remaining),
        }))
    }

    /// Terminate a running agent now: it zeroizes the key and unlinks the
    /// socket. Returns `true` if an agent was actually shut down, `false` if
    /// none was running (in which case any stale socket is cleaned up too).
    pub fn shutdown(sock: &Path) -> Result<bool> {
        let Some(mut stream) = connect(sock) else {
            // Not running. `connect` already removed a stale socket; make sure
            // nothing is left behind regardless.
            let _ = std::fs::remove_file(sock);
            return Ok(false);
        };
        let _ = stream.write_all(&[REQ_SHUTDOWN]);
        let mut resp = [0u8; 1];
        let _ = stream.read_exact(&mut resp);
        // The agent unlinks its own socket as it exits; wait briefly for that,
        // then force-remove so `lock` leaves nothing behind even if the agent
        // was too wedged to clean up.
        wait_gone(sock, Duration::from_secs(2));
        let _ = std::fs::remove_file(sock);
        Ok(true)
    }

    /// Prompt-once unlock: fork a detached agent that serves `root` for `ttl`.
    /// The parent returns only once the socket is accepting connections, so a
    /// caller that sees success can immediately use the agent. The parent's copy
    /// of the key is zeroized before it returns; the daemon's copy lives on.
    pub fn spawn(root: Zeroizing<[u8; KEY_LEN]>, ttl: Duration, sock: &Path) -> Result<()> {
        let ttl = ttl.min(MAX_TTL);
        prepare_socket_dir(sock)?;
        // Any stale socket must go before we fork; the daemon will bind fresh.
        let _ = std::fs::remove_file(sock);

        // Flush our own buffers so the child does not inherit and re-emit them.
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();

        match unsafe { libc::fork() } {
            -1 => Err(Error::Other(format!(
                "failed to fork the unlock agent: {}",
                io::Error::last_os_error()
            ))),
            0 => {
                // Child. Detach into a daemon and serve — never returns.
                daemonize_and_serve(root, ttl, sock);
            }
            pid => {
                // Parent. Our copy of the key is no longer needed.
                drop(root);
                // Reap the intermediate child (it exits right after the second
                // fork) so it does not linger as a zombie.
                let mut status = 0;
                unsafe {
                    libc::waitpid(pid, &mut status, 0);
                }
                // Wait for the daemon to actually be listening before we claim
                // success.
                if wait_ready(sock, Duration::from_secs(5)) {
                    Ok(())
                } else {
                    Err(Error::Other(
                        "the unlock agent did not come up within 5s (its socket never started accepting)".into(),
                    ))
                }
            }
        }
    }

    /// Create the socket's parent directory and tighten it to 0700 so no other
    /// user can even see the socket, let alone connect.
    fn prepare_socket_dir(sock: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = sock
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| Error::Other("agent socket path has no parent directory".into()))?;
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    /// Turn the current (already forked) process into a detached daemon and run
    /// the serve loop. Double-fork + `setsid` so the daemon is not a session
    /// leader and can never reacquire a controlling terminal; stdio is
    /// redirected to `/dev/null` so the parent's captured pipes see EOF and any
    /// stray output is discarded. Never returns.
    fn daemonize_and_serve(root: Zeroizing<[u8; KEY_LEN]>, ttl: Duration, sock: &Path) -> ! {
        unsafe {
            libc::setsid();
        }
        match unsafe { libc::fork() } {
            0 => {}
            // The intermediate child exits immediately; `_exit` avoids running
            // any at-exit handlers or flushing shared buffers twice.
            _ => unsafe { libc::_exit(0) },
        }
        // Grandchild: the actual daemon.
        redirect_std_to_devnull();
        // Re-assert hardening: PR_SET_DUMPABLE is preserved across fork on Linux
        // but we re-set it defensively, and mlock is NOT inherited, so the key
        // must be re-locked in this address space.
        crate::harden::harden_process();
        // A tight umask so the bound socket is not momentarily group/world
        // readable before we chmod it.
        unsafe {
            libc::umask(0o077);
        }
        let deadline = Instant::now() + ttl;
        serve(root, deadline, sock);
    }

    fn redirect_std_to_devnull() {
        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
        if fd >= 0 {
            unsafe {
                libc::dup2(fd, 0);
                libc::dup2(fd, 1);
                libc::dup2(fd, 2);
                if fd > 2 {
                    libc::close(fd);
                }
            }
        }
    }

    /// The daemon's serve loop. Holds the key in this address space, answers
    /// requests one at a time, and expires exactly at `deadline` even if no
    /// client ever connects. Never returns: it `exit`s after zeroizing the key
    /// and unlinking the socket.
    fn serve(key: Zeroizing<[u8; KEY_LEN]>, deadline: Instant, sock: &Path) -> ! {
        // Keep the key off swap in this (post-fork) address space.
        crate::harden::mlock(key.as_ref());

        let listener = match bind_listener(sock) {
            Ok(l) => l,
            // Someone raced us to the socket, or the directory vanished. There
            // is nothing to serve; leave whatever is there untouched and exit.
            Err(_) => unsafe { libc::_exit(1) },
        };
        let fd = listener.as_raw_fd();
        let _ = listener.set_nonblocking(true);
        let uid = our_uid();

        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            // Sleep in poll until either a client knocks or the TTL runs out,
            // whichever comes first — no busy-waiting, exact expiry.
            let remaining_ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let r = unsafe { libc::poll(&mut pfd, 1, remaining_ms) };
            if r <= 0 {
                // Timeout (r == 0) → recheck the deadline. EINTR (r < 0) → retry.
                continue;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    if handle_conn(stream, uid, &key, deadline) == Handled::Shutdown {
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(_) => continue,
            }
        }

        // Expired or shut down: zeroize (Zeroizing's drop) and remove the socket
        // so nothing stale is left to shadow the next unlock.
        drop(key);
        let _ = std::fs::remove_file(sock);
        unsafe { libc::_exit(0) }
    }

    fn bind_listener(sock: &Path) -> io::Result<UnixListener> {
        use std::os::unix::fs::PermissionsExt;
        // Remove any leftover before binding (bind fails on an existing path).
        let _ = std::fs::remove_file(sock);
        let listener = UnixListener::bind(sock)?;
        // File permissions are defence in depth behind the peer check, but set
        // them tight anyway: 0600 so the bits and the SO_PEERCRED check agree.
        std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600))?;
        Ok(listener)
    }

    #[derive(PartialEq, Eq)]
    enum Handled {
        Continue,
        Shutdown,
    }

    /// Serve a single connection. The first and only authorization is the peer's
    /// uid: a peer that is not us gets nothing, whatever the socket's mode bits
    /// say. Read/write timeouts keep one slow client from wedging the loop.
    fn handle_conn(
        mut stream: UnixStream,
        uid: u32,
        key: &Zeroizing<[u8; KEY_LEN]>,
        deadline: Instant,
    ) -> Handled {
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

        // The authorization gate. If we cannot determine the peer, refuse.
        if peer_uid(&stream) != Some(uid) {
            return Handled::Continue;
        }

        let mut req = [0u8; 1];
        if stream.read_exact(&mut req).is_err() {
            return Handled::Continue;
        }
        match req[0] {
            REQ_GET_KEY => {
                let _ = stream.write_all(&[RESP_OK]);
                let _ = stream.write_all(key.as_ref());
                Handled::Continue
            }
            REQ_STATUS => {
                let remaining = deadline.saturating_duration_since(Instant::now()).as_secs();
                let pid = std::process::id();
                let mut buf = [0u8; 13];
                buf[0] = RESP_OK;
                buf[1..9].copy_from_slice(&remaining.to_le_bytes());
                buf[9..13].copy_from_slice(&pid.to_le_bytes());
                let _ = stream.write_all(&buf);
                Handled::Continue
            }
            REQ_SHUTDOWN => {
                let _ = stream.write_all(&[RESP_OK]);
                Handled::Shutdown
            }
            _ => Handled::Continue,
        }
    }

    /// Poll until `sock` is accepting connections or `timeout` elapses.
    fn wait_ready(sock: &Path, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if UnixStream::connect(sock).is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// Poll until `sock` is gone or `timeout` elapses.
    fn wait_gone(sock: &Path, timeout: Duration) {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if !sock.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The default TTL, exposed for the CLI layer's help text.
    pub fn default_ttl() -> Duration {
        DEFAULT_TTL
    }
}

// ===========================================================================
// Non-Unix stub: no agent, everything degrades to the passphrase path.
// ===========================================================================

#[cfg(not(unix))]
mod imp {
    use std::path::Path;
    use std::time::Duration;

    use zeroize::Zeroizing;

    use super::{DEFAULT_TTL, KEY_LEN, Status};
    use crate::{Error, Result};

    pub fn try_fetch_key(_sock: &Path) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>> {
        Ok(None)
    }

    pub fn status(_sock: &Path) -> Result<Option<Status>> {
        Ok(None)
    }

    pub fn shutdown(_sock: &Path) -> Result<bool> {
        Ok(false)
    }

    pub fn spawn(_root: Zeroizing<[u8; KEY_LEN]>, _ttl: Duration, _sock: &Path) -> Result<()> {
        Err(Error::Other(
            "the unlock agent is only supported on Unix; use $JINGLE_PASSPHRASE_CMD instead".into(),
        ))
    }

    pub fn default_ttl() -> Duration {
        DEFAULT_TTL
    }
}

pub use imp::{default_ttl, shutdown, spawn, status, try_fetch_key};
