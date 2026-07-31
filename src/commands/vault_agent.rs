//! `jingle unlock` / `jingle lock` / `jingle unlock --status` for the *vault*
//! (as opposed to a single locked entry): drive the unlock agent from
//! [`crate::agent`].
//!
//! These are the no-NAME forms of `lock`/`unlock`. With a NAME the same verbs
//! lock or unlock an individual entry (see [`super::crud::set_locked`]); the
//! dispatcher in [`super`] routes on the presence of the name.

use std::time::Duration;

use serde_json::json;

use crate::agent;
use crate::commands::Ctx;
use crate::keyfile::{self, Format};
use crate::{Error, Result, output};

/// Parse a `--ttl` value: a bare integer is seconds, or an integer with a
/// trailing `s`/`m`/`h`/`d` suffix. Zero and empty are rejected — an agent with
/// no lifetime is a footgun, not a feature.
pub fn parse_ttl(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Error::Usage("--ttl is empty".into()));
    }
    let (num, unit_secs): (&str, u64) = match s.as_bytes()[s.len() - 1] {
        b's' | b'S' => (&s[..s.len() - 1], 1),
        b'm' | b'M' => (&s[..s.len() - 1], 60),
        b'h' | b'H' => (&s[..s.len() - 1], 3600),
        b'd' | b'D' => (&s[..s.len() - 1], 86400),
        b'0'..=b'9' => (s, 1),
        _ => {
            return Err(Error::Usage(format!(
                "invalid --ttl '{s}': use a number of seconds, or a value like 30m, 8h, 2d"
            )));
        }
    };
    let n: u64 = num.trim().parse().map_err(|_| {
        Error::Usage(format!(
            "invalid --ttl '{s}': use a number of seconds, or a value like 30m, 8h, 2d"
        ))
    })?;
    let secs = n.checked_mul(unit_secs).ok_or_else(|| {
        Error::Usage(format!(
            "--ttl '{s}' is absurdly large; pick something under 30 days"
        ))
    })?;
    if secs == 0 {
        return Err(Error::Usage("--ttl must be greater than zero".into()));
    }
    Ok(Duration::from_secs(secs))
}

/// `jingle unlock` (no NAME): prompt once, unwrap the v2 root key, and start a
/// detached agent that holds it for `ttl` (default 8h).
pub fn unlock_vault(ctx: &Ctx, ttl: Option<Duration>) -> Result<()> {
    let kf = &ctx.paths.keyfile;

    // Only a wrapped keyfile has anything to unlock. A v1 raw key already opens
    // the vault with no passphrase, so an agent would hold a key that is sitting
    // in the clear on disk anyway — refuse, and say why.
    match keyfile::detect(kf)? {
        Format::V1Raw => {
            return Err(Error::Usage(
                "the keyfile is a raw v1 key; there is nothing to unlock — the vault already \
                 opens with no passphrase. `jingle unlock` applies only to a passphrase-wrapped \
                 (v2) keyfile; run `jingle protect` first if you want at-rest protection."
                    .into(),
            ));
        }
        Format::V2Wrapped => {}
    }

    // Already unlocked? Report and stop before prompting for a passphrase we do
    // not need.
    if let Some(st) = agent::status(&ctx.paths.agent_sock)? {
        output::ok(
            ctx.json,
            ctx.quiet,
            &format!(
                "Vault is already unlocked; the agent expires in {} (run `jingle lock` to end it now).",
                human_remaining(st.remaining)
            ),
            json!({
                "unlocked": true,
                "already": true,
                "pid": st.pid,
                "remaining_secs": st.remaining.as_secs(),
                "socket": ctx.paths.agent_sock.display().to_string(),
            }),
        );
        return Ok(());
    }

    let ttl = ttl.unwrap_or_else(agent::default_ttl);

    // Prompt once and unwrap. `None` here means the agent is deliberately NOT
    // consulted — we are the ones creating it.
    let root = keyfile::load(kf, None)?;

    agent::spawn(root, ttl, &ctx.paths.agent_sock)?;
    ctx.audit().append("unlock", None, None, "ok", None)?;

    // Report the live TTL as the agent sees it.
    let remaining = agent::status(&ctx.paths.agent_sock)?
        .map(|s| s.remaining)
        .unwrap_or(ttl);
    output::ok(
        ctx.json,
        ctx.quiet,
        &format!(
            "Vault unlocked. The unlock agent holds the key for {} — subsequent commands need no \
             passphrase. Run `jingle lock` to end it sooner; a reboot ends it too.",
            human_remaining(remaining)
        ),
        json!({
            "unlocked": true,
            "ttl_secs": ttl.as_secs(),
            "remaining_secs": remaining.as_secs(),
            "socket": ctx.paths.agent_sock.display().to_string(),
        }),
    );
    Ok(())
}

/// `jingle lock` (no NAME): terminate the unlock agent now.
pub fn lock_vault(ctx: &Ctx) -> Result<()> {
    let terminated = agent::shutdown(&ctx.paths.agent_sock)?;
    if terminated {
        ctx.audit().append("lock", None, None, "ok", None)?;
        output::ok(
            ctx.json,
            ctx.quiet,
            "Vault locked: the unlock agent was terminated, the key zeroized, and the socket removed.",
            json!({ "locked": true, "was_running": true }),
        );
    } else {
        output::ok(
            ctx.json,
            ctx.quiet,
            "No unlock agent was running (nothing to lock).",
            json!({ "locked": true, "was_running": false }),
        );
    }
    Ok(())
}

/// `jingle unlock --status`: report the agent's liveness and remaining TTL.
pub fn status(ctx: &Ctx) -> Result<()> {
    match agent::status(&ctx.paths.agent_sock)? {
        Some(st) => output::ok(
            ctx.json,
            ctx.quiet,
            &format!(
                "unlock agent: live (pid {}), expires in {}",
                st.pid,
                human_remaining(st.remaining)
            ),
            json!({
                "live": true,
                "pid": st.pid,
                "remaining_secs": st.remaining.as_secs(),
                "socket": ctx.paths.agent_sock.display().to_string(),
            }),
        ),
        None => output::ok(
            ctx.json,
            ctx.quiet,
            "unlock agent: not running (run `jingle unlock` to start one)",
            json!({
                "live": false,
                "socket": ctx.paths.agent_sock.display().to_string(),
            }),
        ),
    }
    Ok(())
}

/// Render a remaining duration as a compact `7h 59m` / `45s`.
pub fn human_remaining(d: Duration) -> String {
    let secs = d.as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ttl_units() {
        assert_eq!(parse_ttl("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_ttl("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_ttl("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_ttl("8h").unwrap(), Duration::from_secs(28800));
        assert_eq!(parse_ttl("2d").unwrap(), Duration::from_secs(172800));
        assert_eq!(parse_ttl(" 8H ").unwrap(), Duration::from_secs(28800));
    }

    #[test]
    fn parse_ttl_rejects_junk_and_zero() {
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("0").is_err());
        assert!(parse_ttl("0h").is_err());
        assert!(parse_ttl("abc").is_err());
        assert!(parse_ttl("12x").is_err());
        assert!(parse_ttl("h").is_err());
    }

    #[test]
    fn human_remaining_shapes() {
        assert_eq!(human_remaining(Duration::from_secs(28740)), "7h 59m");
        assert_eq!(human_remaining(Duration::from_secs(125)), "2m 5s");
        assert_eq!(human_remaining(Duration::from_secs(45)), "45s");
    }
}
