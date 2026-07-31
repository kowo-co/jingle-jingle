//! Process hardening: keep live key material out of reach of other processes
//! on the same box.
//!
//! Two exposures that filesystem permissions and `Zeroizing` do not address:
//!
//! 1. A same-uid process can `ptrace(2)` jingle and read the 32-byte root key
//!    and the derived XChaCha key straight out of its address space, and a core
//!    dump writes the same bytes to disk. `PR_SET_DUMPABLE(0)` closes both on
//!    Linux: same-uid ptrace is refused and core dumps are suppressed.
//! 2. Key pages can be paged out to swap. `mlock(2)` pins them in RAM.
//!
//! Everything here is best-effort and degrades cleanly: no-op on platforms that
//! lack the primitive, and a soft warn-and-continue when the kernel refuses
//! (an over-tight `RLIMIT_MEMLOCK` must never abort the program).

#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};

/// Outcome of an `mlock` attempt, surfaced by `jingle doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlockState {
    /// Pages are locked into RAM (or the range was empty).
    Locked,
    /// The kernel refused (commonly `RLIMIT_MEMLOCK`); continued anyway.
    Failed,
    /// The platform has no `mlock` — nothing was attempted.
    Unsupported,
}

impl MlockState {
    pub fn as_str(self) -> &'static str {
        match self {
            MlockState::Locked => "locked",
            MlockState::Failed => "failed",
            MlockState::Unsupported => "unsupported",
        }
    }
}

#[cfg(unix)]
static MLOCK_WARNED: AtomicBool = AtomicBool::new(false);

/// Disable core dumps and same-uid ptrace as early as possible. Call this
/// before any key material is read. No-op on non-Linux platforms.
pub fn harden_process() {
    #[cfg(target_os = "linux")]
    {
        // prctl(PR_SET_DUMPABLE, 0). Ignore the result: on the platforms where
        // this matters it does not fail, and there is nothing useful to do if
        // it somehow does — doctor reports the live state either way.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
}

/// The live `PR_GET_DUMPABLE` state, if the platform can report it.
/// `Some(false)` means core dumps / same-uid ptrace are disabled (the goal).
pub fn dumpable() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        let r = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        if r < 0 { None } else { Some(r != 0) }
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Lock a byte range into RAM so it cannot be written to swap. Best-effort:
/// on failure it warns exactly once (per process) and returns `Failed` so the
/// caller keeps going. Locking is by page, so this pins the page(s) the slice
/// occupies; a subsequent move of the value is not tracked.
pub fn mlock(bytes: &[u8]) -> MlockState {
    #[cfg(unix)]
    {
        if bytes.is_empty() {
            return MlockState::Locked;
        }
        let ret = unsafe { libc::mlock(bytes.as_ptr() as *const libc::c_void, bytes.len()) };
        if ret == 0 {
            MlockState::Locked
        } else {
            if !MLOCK_WARNED.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "jingle: warning: could not lock key pages into RAM (mlock: {}); \
                     key material may be swapped to disk. Raise RLIMIT_MEMLOCK to fix \
                     (e.g. `ulimit -l unlimited`).",
                    std::io::Error::last_os_error()
                );
            }
            MlockState::Failed
        }
    }
    #[cfg(not(unix))]
    {
        let _ = bytes;
        MlockState::Unsupported
    }
}

/// Probe whether `mlock` works right now, without disturbing the warn-once
/// state or leaving anything locked. Used by `jingle doctor` to report posture.
pub fn probe_mlock() -> MlockState {
    #[cfg(unix)]
    {
        let buf = [0u8; 32];
        let ptr = buf.as_ptr() as *const libc::c_void;
        let ret = unsafe { libc::mlock(ptr, buf.len()) };
        if ret == 0 {
            unsafe {
                libc::munlock(ptr, buf.len());
            }
            MlockState::Locked
        } else {
            MlockState::Failed
        }
    }
    #[cfg(not(unix))]
    {
        MlockState::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn empty_range_is_trivially_locked() {
        assert_eq!(mlock(&[]), MlockState::Locked);
    }

    #[test]
    fn probe_does_not_panic_and_reports_a_state() {
        let s = probe_mlock();
        assert!(matches!(
            s,
            MlockState::Locked | MlockState::Failed | MlockState::Unsupported
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dumpable_reports_on_linux() {
        harden_process();
        // After hardening, dumping must be disabled.
        assert_eq!(dumpable(), Some(false));
    }
}
